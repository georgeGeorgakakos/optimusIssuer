package api

import (
	"encoding/json"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/georgeGeorgakakos/optimusIssuer/internal/auth"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/credential"
)

const (
	RoleOperator = "issuer:operator"
	RoleAdmin    = "issuer:admin"
)

// Router builds the HTTP surface.
//
// Three tiers:
//   - public: health, and request submission, which grants nothing
//   - operator: listing, approving, issuing and revoking
//   - admin: modifying the trust list, which delegates issuing authority
func Router(s *Service, v *auth.Verifier, ui fs.FS, allowedOrigins []string) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	if len(allowedOrigins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   allowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Authorization", "Content-Type"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}

	r.Route("/api/v1/issuer", func(r chi.Router) {

		// ── public ──────────────────────────────────────────────────────────
		r.Get("/health", s.handleHealth)
		r.Get("/info", s.handleInfo)
		r.Post("/requests", s.handleSubmitRequest)

		// ── operator ────────────────────────────────────────────────────────
		r.Group(func(r chi.Router) {
			r.Use(v.Middleware(RoleOperator))
			r.Get("/requests", s.handleListRequests)
			r.Post("/requests/{id}/approve", s.handleApprove)
			r.Post("/requests/{id}/reject", s.handleReject)
			r.Post("/credentials", s.handleIssue)
			r.Get("/credentials", s.handleListCredentials)
			r.Post("/credentials/{id}/revoke", s.handleRevoke)
			r.Get("/trust", s.handleListTrust)
			r.Get("/audit", s.handleAudit)
		})

		// ── admin ───────────────────────────────────────────────────────────
		r.Group(func(r chi.Router) {
			r.Use(v.Middleware(RoleAdmin))
			r.Post("/trust", s.handleUpsertTrust)
		})
	})

	if ui != nil {
		// chi's /* wildcard does not match the bare root path, so register it
		// explicitly. Without the first line, / returns 404 while /index.html
		// serves correctly — which is a confusing way to discover this.
		r.Handle("/", spaHandler(ui))
		r.Handle("/*", spaHandler(ui))
	}
	return r
}

// spaHandler serves the built single-page application. Any path that is not a
// real file is served index.html, so a client-side route such as /trust
// resolves on a hard refresh instead of returning 404.
func spaHandler(ui fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")

		// Serve the file when it exists; otherwise fall through to index.html.
		// Reading and writing it directly avoids http.FileServer's directory
		// handling, which is what produced the redirect loop.
		if p != "" && p != "." {
			if f, err := ui.Open(p); err == nil {
				defer f.Close()
				if st, err := f.Stat(); err == nil && !st.IsDir() {
					w.Header().Set("Content-Type", contentTypeFor(p))
					_, _ = io.Copy(w, f)
					return
				}
			}
		}

		index, err := fs.ReadFile(ui, "index.html")
		if err != nil {
			http.Error(w, "the user interface was not built into this binary; "+
				"run npm run build in web/ and rebuild the image", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
}

func contentTypeFor(p string) string {
	// The standard library's table covers images, fonts and everything else a
	// Vite build emits. The explicit cases exist because some minimal
	// container images ship no /etc/mime.types, which leaves that table thin.
	switch strings.ToLower(path.Ext(p)) {
	case ".js", ".mjs":
		return "application/javascript"
	case ".css":
		return "text/css; charset=utf-8"
	case ".html":
		return "text/html; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".ico":
		return "image/x-icon"
	case ".woff2":
		return "font/woff2"
	case ".json":
		return "application/json"
	}
	if t := mime.TypeByExtension(path.Ext(p)); t != "" {
		return t
	}
	return "application/octet-stream"
}

// ── handlers ────────────────────────────────────────────────────────────────

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	out := map[string]interface{}{
		"status":     "ok",
		"issuer_did": s.Signer.DID(),
		"time":       time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.Store.Health(r.Context()); err != nil {
		out["agent"] = "unreachable"
		out["agent_error"] = err.Error()
		writeJSON(w, http.StatusServiceUnavailable, out)
		return
	}
	out["agent"] = "reachable"
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"issuer_did":            s.Signer.DID(),
		"max_validity_days":     s.Cfg.MaxValidityDays,
		"default_validity_days": s.Cfg.DefaultValidityDays,
		"allowed_actions":       s.Cfg.AllowedActions,
	})
}

func (s *Service) handleSubmitRequest(w http.ResponseWriter, r *http.Request) {
	var in credential.Request
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	out, err := s.SubmitRequest(r.Context(), &in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"request_id": out.ID,
		"status":     out.Status,
		"message": "An operator must approve this request before a credential is signed. " +
			"Nothing has been granted.",
	})
}

func (s *Service) handleListRequests(w http.ResponseWriter, r *http.Request) {
	out, err := s.ListRequests(r.Context(), r.URL.Query().Get("status"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"count": len(out), "requests": out})
}

func (s *Service) handleApprove(w http.ResponseWriter, r *http.Request) {
	var in IssueInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	in.RequestID = chi.URLParam(r, "id")
	op := auth.FromContext(r.Context())

	if s.Cfg.RequireSecondApproval && HasWildcard(in.Capabilities) {
		writeError(w, http.StatusConflict,
			"this credential contains a wildcard capability and requires a second "+
				"operator's approval; record the first approval and ask a colleague to confirm")
		return
	}

	vc, err := s.Issue(r.Context(), in, op)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, vc)
}

func (s *Service) handleReject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	id := chi.URLParam(r, "id")
	op := auth.FromContext(r.Context())

	err := s.Store.Put(r.Context(), "kbissuance", map[string]interface{}{
		"_id":             id,
		"record_type":     "credential_request",
		"status":          "rejected",
		"decided_at":      time.Now().UTC().Format(time.RFC3339),
		"decided_by":      operatorName(op),
		"decision_reason": body.Reason,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"request_id": id, "status": "rejected"})
}

func (s *Service) handleIssue(w http.ResponseWriter, r *http.Request) {
	var in IssueInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	vc, err := s.Issue(r.Context(), in, auth.FromContext(r.Context()))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, vc)
}

func (s *Service) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	docs, err := s.Store.Get(r.Context(), "kbissuance",
		map[string]interface{}{"record_type": "issued_credential"})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count": len(docs), "credentials": docs,
	})
}

func (s *Service) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SubjectDID string `json:"subject_did"`
		Reason     string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	rev, err := s.Revoke(r.Context(), chi.URLParam(r, "id"), body.SubjectDID,
		body.Reason, auth.FromContext(r.Context()))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"revocation": rev,
		"note": "Revocation takes effect as the record replicates to each agent. " +
			"Until then the credential remains usable.",
	})
}

func (s *Service) handleListTrust(w http.ResponseWriter, r *http.Request) {
	out, err := s.ListTrusted(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"count": len(out), "issuers": out})
}

func (s *Service) handleUpsertTrust(w http.ResponseWriter, r *http.Request) {
	var in credential.TrustedIssuer
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	out, err := s.UpsertTrusted(r.Context(), in, auth.FromContext(r.Context()))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handleAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": s.Audit.Recent(200),
	})
}
