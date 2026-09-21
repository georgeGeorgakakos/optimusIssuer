// Command issuerd runs the optimusIssuer service.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/georgeGeorgakakos/optimusIssuer/internal/api"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/audit"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/auth"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/credential"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/keys"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/store"
)

// The built single-page application is embedded so that the container serves
// the interface without a second process or a sidecar.
//
// The directive below must sit on the line immediately above the variable,
// with no blank line between them. Without it webdist is a valid but EMPTY
// embed.FS: the program still compiles, because the embed import is used by
// the type, fs.Sub succeeds on an empty filesystem, and the service starts
// cleanly while serving no interface at all. Nothing warns you.
//
//go:embed all:webdist
var webdist embed.FS

func main() {
	var (
		addr       = flag.String("addr", ":8090", "listen address")
		keyPath    = flag.String("key", "/etc/issuer/key/issuer.key", "issuer key file")
		agentURL   = flag.String("agent", "http://optimusdb1:8089", "OptimusDB agent base URL")
		agentCtx   = flag.String("agent-context", "swarmkb", "agent API context")
		oidcIssuer = flag.String("oidc-issuer", "", "Keycloak realm URL; empty disables operator auth")
		oidcAud    = flag.String("oidc-audience", "optimusissuer", "expected audience claim")
		maxDays    = flag.Int("max-validity-days", 365, "longest credential this issuer will sign")
		defDays    = flag.Int("default-validity-days", 90, "default credential validity")
		twoPerson  = flag.Bool("require-second-approval", true,
			"require a second operator for credentials containing a wildcard")
		allowed = flag.String("allowed-actions", "",
			"comma separated allow-list of actions this issuer may grant; empty means no bound")
		corsOrigins = flag.String("cors-origins", "", "comma separated allowed origins for the UI")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	priv, kf, err := keys.Load(*keyPath)
	if err != nil {
		logger.Error("cannot load the issuer key", "error", err)
		os.Exit(1)
	}
	signer, err := credential.NewSigner(priv)
	if err != nil {
		logger.Error("cannot derive the issuer identity", "error", err)
		os.Exit(1)
	}
	logger.Info("issuer identity loaded", "did", signer.DID(), "label", kf.Label)

	st := store.New(*agentURL, *agentCtx)
	if err := st.Health(context.Background()); err != nil {
		// Not fatal: the agents may start after this service. Issuance will
		// fail until they are reachable, which the health endpoint reports.
		logger.Warn("agent not reachable at start-up", "agent", *agentURL, "error", err)
	}

	al := audit.New(1000, logger)
	cfg := api.Config{
		MaxValidityDays:       *maxDays,
		DefaultValidityDays:   *defDays,
		RequireSecondApproval: *twoPerson,
	}
	if *allowed != "" {
		cfg.AllowedActions = strings.Split(*allowed, ",")
	}
	svc := api.New(signer, st, al, cfg)

	verifier := auth.NewVerifier(*oidcIssuer, *oidcAud)
	if verifier.Disabled {
		logger.Warn("operator authentication is DISABLED; do not run this way in production")
	}

	ui, err := fs.Sub(webdist, "webdist")
	if err != nil {
		logger.Warn("no embedded user interface", "error", err)
		ui = nil
	}

	var origins []string
	if *corsOrigins != "" {
		origins = strings.Split(*corsOrigins, ",")
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.Router(svc, verifier, ui, origins),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("optimusIssuer listening", "addr", *addr, "agent", *agentURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	logger.Info("optimusIssuer stopped")
}
