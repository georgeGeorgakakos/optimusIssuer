// Package auth authenticates the human operators who use the optimusIssuer
// user interface. They log in to Keycloak with a browser; the machine
// identities in this system are DIDs, but a person approving an issuance is
// better served by an interactive login than by a key file.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

type ctxKey int

const operatorKey ctxKey = 1

// Operator is an authenticated human.
type Operator struct {
	Subject  string   `json:"sub"`
	Username string   `json:"preferred_username"`
	Email    string   `json:"email"`
	Roles    []string `json:"-"`
}

// HasRole reports whether the operator holds a realm role.
func (o *Operator) HasRole(role string) bool {
	for _, r := range o.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Verifier validates Keycloak access tokens against the realm's public keys.
// The key set is fetched once and cached, so a Keycloak outage does not stop
// an already-running instance from authenticating operators.
type Verifier struct {
	Issuer   string
	Audience string
	JWKSURL  string
	Disabled bool

	mu      sync.RWMutex
	keys    *jose.JSONWebKeySet
	fetched time.Time
	ttl     time.Duration
	http    *http.Client
}

// NewVerifier builds a verifier. When issuer is empty the verifier is disabled
// and every request is treated as an anonymous local operator, which is
// intended for development only.
func NewVerifier(issuer, audience string) *Verifier {
	v := &Verifier{
		Issuer:   issuer,
		Audience: audience,
		ttl:      time.Hour,
		http:     &http.Client{Timeout: 10 * time.Second},
		Disabled: issuer == "",
	}
	if issuer != "" {
		v.JWKSURL = strings.TrimSuffix(issuer, "/") + "/protocol/openid-connect/certs"
	}
	return v
}

func (v *Verifier) keySet(ctx context.Context, force bool) (*jose.JSONWebKeySet, error) {
	v.mu.RLock()
	fresh := v.keys != nil && time.Since(v.fetched) < v.ttl
	ks := v.keys
	v.mu.RUnlock()
	if fresh && !force {
		return ks, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		// Serve a stale key set rather than failing closed: a Keycloak outage
		// should not lock operators out of a running instance.
		if ks != nil {
			return ks, nil
		}
		return nil, fmt.Errorf("auth: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("auth: decode JWKS: %w", err)
	}
	v.mu.Lock()
	v.keys, v.fetched = &set, time.Now()
	v.mu.Unlock()
	return &set, nil
}

type claims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience audience `json:"aud"`
	Expiry   int64    `json:"exp"`
	Username string   `json:"preferred_username"`
	Email    string   `json:"email"`
	Realm    struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// audience accepts both the string and array forms Keycloak may emit.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// Verify parses and checks a bearer token.
func (v *Verifier) Verify(ctx context.Context, token string) (*Operator, error) {
	sig, err := jose.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("auth: malformed token: %w", err)
	}
	ks, err := v.keySet(ctx, false)
	if err != nil {
		return nil, err
	}
	payload, err := verifyAgainst(sig, ks)
	if err != nil {
		// A key rotation produces an unknown kid; refetch once before failing.
		if ks, ferr := v.keySet(ctx, true); ferr == nil {
			payload, err = verifyAgainst(sig, ks)
		}
		if err != nil {
			return nil, err
		}
	}

	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("auth: decode claims: %w", err)
	}
	if v.Issuer != "" && c.Issuer != v.Issuer {
		return nil, fmt.Errorf("auth: token issued by %q, expected %q", c.Issuer, v.Issuer)
	}
	if v.Audience != "" && !contains(c.Audience, v.Audience) {
		return nil, fmt.Errorf("auth: token audience does not include %q", v.Audience)
	}
	if c.Expiry > 0 && time.Now().After(time.Unix(c.Expiry, 0).Add(60*time.Second)) {
		return nil, fmt.Errorf("auth: token expired")
	}
	return &Operator{
		Subject:  c.Subject,
		Username: c.Username,
		Email:    c.Email,
		Roles:    c.Realm.Roles,
	}, nil
}

func verifyAgainst(sig *jose.JSONWebSignature, ks *jose.JSONWebKeySet) ([]byte, error) {
	for _, k := range ks.Keys {
		if payload, err := sig.Verify(k); err == nil {
			return payload, nil
		}
	}
	return nil, fmt.Errorf("auth: no key in the set verifies this token")
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// Middleware rejects requests without a valid operator token.
func (v *Verifier) Middleware(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v.Disabled {
				op := &Operator{Subject: "local", Username: "local-operator",
					Roles: []string{"issuer:operator", "issuer:admin"}}
				next.ServeHTTP(w, WithOperator(r, op))
				return
			}
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				writeErr(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			op, err := v.Verify(r.Context(), strings.TrimPrefix(header, "Bearer "))
			if err != nil {
				writeErr(w, http.StatusUnauthorized, err.Error())
				return
			}
			if requiredRole != "" && !op.HasRole(requiredRole) {
				writeErr(w, http.StatusForbidden,
					fmt.Sprintf("role %s is required", requiredRole))
				return
			}
			next.ServeHTTP(w, WithOperator(r, op))
		})
	}
}

// WithOperator attaches an operator to the request context.
func WithOperator(r *http.Request, op *Operator) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), operatorKey, op))
}

// FromContext returns the authenticated operator, if any.
func FromContext(ctx context.Context) *Operator {
	op, _ := ctx.Value(operatorKey).(*Operator)
	return op
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
