// Package api implements the optimusIssuer HTTP surface.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/georgeGeorgakakos/optimusIssuer/internal/audit"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/auth"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/credential"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/did"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/store"
)

// Config holds the runtime policy this service applies.
type Config struct {
	// MaxValidityDays caps what an operator may grant in one credential.
	MaxValidityDays int
	// DefaultValidityDays is applied when a request names none.
	DefaultValidityDays int
	// RequireSecondApproval forces two distinct operators to approve any
	// credential containing a wildcard capability.
	RequireSecondApproval bool
	// AllowedActions bounds what may be granted at all. Empty means no bound.
	AllowedActions []string
}

// Service is the application core. It holds the signer and a client for one
// OptimusDB agent, and keeps no state of its own.
type Service struct {
	Signer *credential.Signer
	Store  *store.Client
	Audit  *audit.Log
	Cfg    Config
}

// New builds a service.
func New(s *credential.Signer, st *store.Client, al *audit.Log, cfg Config) *Service {
	if cfg.MaxValidityDays == 0 {
		cfg.MaxValidityDays = 365
	}
	if cfg.DefaultValidityDays == 0 {
		cfg.DefaultValidityDays = 90
	}
	return &Service{Signer: s, Store: st, Audit: al, Cfg: cfg}
}

// ── requests ────────────────────────────────────────────────────────────────

// SubmitRequest records an unauthenticated credential request.
//
// Anyone may submit one: the payload contains no secret, only a public DID and
// a statement of what the applicant would like. Nothing is granted here.
func (s *Service) SubmitRequest(ctx context.Context, in *credential.Request) (*credential.Request, error) {
	if !did.Valid(in.SubjectDID) {
		return nil, fmt.Errorf("subject_did is not a valid Ed25519 did:key")
	}
	if in.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if len(in.RequestedCapabilities) == 0 {
		return nil, fmt.Errorf("at least one requested capability is required")
	}
	for _, c := range in.RequestedCapabilities {
		if c.Action == "" || c.Store == "" {
			return nil, fmt.Errorf("capability %+v has an empty field", c)
		}
	}

	in.ID = "req-" + uuid.NewString()[:8]
	in.RequestType = "CredentialRequest"
	in.Status = "pending"
	in.RequestedAt = time.Now().UTC().Format(time.RFC3339)
	if in.RequestedValidityDays == 0 {
		in.RequestedValidityDays = s.Cfg.DefaultValidityDays
	}

	doc := map[string]interface{}{
		"_id":                    in.ID,
		"record_type":            "credential_request",
		"subject_did":            in.SubjectDID,
		"name":                   in.Name,
		"organisation":           in.Organisation,
		"contact":                in.Contact,
		"deployment":             in.Deployment,
		"justification":          in.Justification,
		"requested_capabilities": in.RequestedCapabilities,
		"requested_validity_days": in.RequestedValidityDays,
		"status":                 in.Status,
		"requested_at":           in.RequestedAt,
	}
	if err := s.Store.Put(ctx, store.StoreIssuance, doc); err != nil {
		return nil, fmt.Errorf("record request: %w", err)
	}
	s.Audit.Write(ctx, audit.Entry{
		Action: "request.submit", Subject: in.SubjectDID, RequestID: in.ID,
		Detail: in.Name,
	})
	return in, nil
}

// ListRequests returns requests, newest first, optionally filtered by status.
func (s *Service) ListRequests(ctx context.Context, status string) ([]credential.Request, error) {
	criteria := map[string]interface{}{"record_type": "credential_request"}
	if status != "" {
		criteria["status"] = status
	}
	docs, err := s.Store.Get(ctx, store.StoreIssuance, criteria)
	if err != nil {
		return nil, err
	}
	out := make([]credential.Request, 0, len(docs))
	for _, d := range docs {
		var r credential.Request
		if err := remap(d, &r); err != nil {
			continue
		}
		if r.ID == "" {
			if id, ok := d["_id"].(string); ok {
				r.ID = id
			}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt > out[j].RequestedAt })
	return out, nil
}

// ── issuance ────────────────────────────────────────────────────────────────

// IssueInput is what an operator confirms when approving.
//
// Capabilities are taken from this structure rather than from the request,
// deliberately: a request is a proposal, and an operator narrowing it must not
// be overridden by what the applicant asked for.
type IssueInput struct {
	SubjectDID   string                  `json:"subject_did"`
	Name         string                  `json:"name"`
	Organisation string                  `json:"organisation,omitempty"`
	Capabilities []credential.Capability `json:"capabilities"`
	ValidityDays int                     `json:"validity_days"`
	RequestID    string                  `json:"request_id,omitempty"`
	Reason       string                  `json:"reason,omitempty"`
}

// Issue signs a credential and records the issuance.
func (s *Service) Issue(ctx context.Context, in IssueInput, op *auth.Operator) (*credential.Credential, error) {
	if in.ValidityDays <= 0 {
		in.ValidityDays = s.Cfg.DefaultValidityDays
	}
	if in.ValidityDays > s.Cfg.MaxValidityDays {
		return nil, fmt.Errorf("validity of %d days exceeds the maximum of %d",
			in.ValidityDays, s.Cfg.MaxValidityDays)
	}
	if err := s.checkPolicy(in); err != nil {
		return nil, err
	}

	vc, err := s.Signer.Issue(credential.IssueOptions{
		SubjectDID:   in.SubjectDID,
		Name:         in.Name,
		Organisation: in.Organisation,
		Capabilities: in.Capabilities,
		ValidFor:     time.Duration(in.ValidityDays) * 24 * time.Hour,
	})
	if err != nil {
		return nil, err
	}

	// Verify what we just signed, using the same code path an agent uses.
	// A canonicalisation defect fails here, at issuance, rather than in the
	// field where it would look like a forged signature.
	if err := credential.Verify(vc, credential.DefaultSkew); err != nil {
		return nil, fmt.Errorf("self-verification failed, refusing to issue: %w", err)
	}

	rec := map[string]interface{}{
		"_id":           vc.ID,
		"record_type":   "issued_credential",
		"subject_did":   vc.Subject.ID,
		"subject_name":  in.Name,
		"issuer":        vc.Issuer,
		"capabilities":  vc.Subject.Capabilities,
		"issued_at":     vc.IssuanceDate,
		"expires_at":    vc.ExpirationDate,
		"status":        "active",
		"request_id":    in.RequestID,
		"issued_by":     operatorName(op),
		"reason":        in.Reason,
	}
	if err := s.Store.Put(ctx, store.StoreIssuance, rec); err != nil {
		return nil, fmt.Errorf("record issuance: %w", err)
	}

	if in.RequestID != "" {
		_ = s.Store.Put(ctx, store.StoreIssuance, map[string]interface{}{
			"_id":                  in.RequestID,
			"record_type":          "credential_request",
			"status":               "issued",
			"decided_at":           time.Now().UTC().Format(time.RFC3339),
			"decided_by":           operatorName(op),
			"issued_credential_id": vc.ID,
		})
	}

	s.Audit.Write(ctx, audit.Entry{
		Action: "credential.issue", Operator: operatorName(op),
		Subject: vc.Subject.ID, CredentialID: vc.ID,
		Detail: fmt.Sprintf("%d capabilities, %d days", len(in.Capabilities), in.ValidityDays),
	})
	return vc, nil
}

// checkPolicy applies the deployment's bounds on what may be granted.
func (s *Service) checkPolicy(in IssueInput) error {
	if len(in.Capabilities) == 0 {
		return fmt.Errorf("at least one capability is required")
	}
	if len(s.Cfg.AllowedActions) > 0 {
		for _, c := range in.Capabilities {
			if c.Action == "*" {
				continue
			}
			found := false
			for _, a := range s.Cfg.AllowedActions {
				if a == c.Action {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("action %q is not permitted by this issuer's policy", c.Action)
			}
		}
	}
	return nil
}

// HasWildcard reports whether any capability uses a wildcard, which the user
// interface highlights and which may require a second approval.
func HasWildcard(caps []credential.Capability) bool {
	for _, c := range caps {
		if c.Action == "*" || c.Store == "*" {
			return true
		}
	}
	return false
}

// ── revocation ──────────────────────────────────────────────────────────────

// Revoke withdraws a credential before its expiry by writing a revocation
// record into the trust store, where it replicates to every agent.
//
// This is not immediate. Between this write and each agent refreshing its
// cache, the credential remains usable. That window is the cost of verification
// that works while partitioned, and short credential lifetimes are the primary
// mitigation.
func (s *Service) Revoke(ctx context.Context, credentialID, subjectDID, reason string,
	op *auth.Operator) (*credential.Revocation, error) {

	if credentialID == "" {
		return nil, fmt.Errorf("credential_id is required")
	}
	rev := &credential.Revocation{
		ID:           "revocation:" + credentialID,
		RecordType:   "revocation",
		CredentialID: credentialID,
		SubjectDID:   subjectDID,
		RevokedBy:    s.Signer.DID(),
		Reason:       reason,
		RevokedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.Store.PutTyped(ctx, store.StoreTrust, rev); err != nil {
		return nil, fmt.Errorf("write revocation: %w", err)
	}
	_ = s.Store.Put(ctx, store.StoreIssuance, map[string]interface{}{
		"_id":         credentialID,
		"record_type": "issued_credential",
		"status":      "revoked",
		"revoked_at":  rev.RevokedAt,
		"revoked_by":  operatorName(op),
	})
	s.Audit.Write(ctx, audit.Entry{
		Action: "credential.revoke", Operator: operatorName(op),
		CredentialID: credentialID, Detail: reason,
	})
	return rev, nil
}

// ── trust list ──────────────────────────────────────────────────────────────

// ListTrusted returns the issuers the swarm currently accepts.
func (s *Service) ListTrusted(ctx context.Context) ([]credential.TrustedIssuer, error) {
	docs, err := s.Store.Get(ctx, store.StoreTrust,
		map[string]interface{}{"record_type": "trusted_issuer"})
	if err != nil {
		return nil, err
	}
	out := make([]credential.TrustedIssuer, 0, len(docs))
	for _, d := range docs {
		var t credential.TrustedIssuer
		if err := remap(d, &t); err == nil {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// UpsertTrusted adds or updates a trusted issuer record.
//
// Adding an issuer is the most consequential action available in this service:
// it delegates the ability to grant capabilities to another party. It requires
// the admin role and is always audited.
func (s *Service) UpsertTrusted(ctx context.Context, t credential.TrustedIssuer,
	op *auth.Operator) (*credential.TrustedIssuer, error) {

	if !did.Valid(t.ID) {
		return nil, fmt.Errorf("issuer id must be a valid Ed25519 did:key")
	}
	if len(t.MayIssue) == 0 {
		t.MayIssue = []string{credential.TypeCapability}
	}
	if t.Status == "" {
		t.Status = "active"
	}
	t.RecordType = "trusted_issuer"
	if t.AddedAt == "" {
		t.AddedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if t.AddedBy == "" {
		t.AddedBy = operatorName(op)
	}
	if err := s.Store.PutTyped(ctx, store.StoreTrust, t); err != nil {
		return nil, fmt.Errorf("write trusted issuer: %w", err)
	}
	s.Audit.Write(ctx, audit.Entry{
		Action: "trust.upsert", Operator: operatorName(op),
		Subject: t.ID, Detail: fmt.Sprintf("%s, status %s", t.Name, t.Status),
	})
	return &t, nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

func remap(in map[string]interface{}, out interface{}) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func operatorName(op *auth.Operator) string {
	if op == nil {
		return "unknown"
	}
	if op.Username != "" {
		return op.Username
	}
	return op.Subject
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
