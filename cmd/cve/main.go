package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/urfave/cli/v3"
	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/frontend"
	"github.com/JetManiack/mcp-cve/internal/health"
	"github.com/JetManiack/mcp-cve/internal/humanauth"
	"github.com/JetManiack/mcp-cve/internal/mcpserver"
	"github.com/JetManiack/mcp-cve/internal/nvd"
	"github.com/JetManiack/mcp-cve/internal/restapi"
	"github.com/JetManiack/mcp-cve/internal/storage"
	cvetools "github.com/JetManiack/mcp-cve/internal/tools/cve"
)

var version = "dev"

const historyPruneInterval = time.Hour
const syncInterval = time.Hour

func newRootCommand() *cli.Command {
	return &cli.Command{
		Name:    "cve",
		Usage:   "MCP server tracking NVD CVEs and serving them to AI agents",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "listen-addr",
				Value:   ":8080",
				Sources: cli.EnvVars("LISTEN_ADDR"),
			},
			&cli.StringFlag{
				Name:    "db-dsn",
				Value:   "data/cve.db",
				Usage:   "SQLite file path, or a postgres:// connection string",
				Sources: cli.EnvVars("DB_DSN"),
			},
			&cli.StringFlag{
				Name:    "nvd-api-key",
				Usage:   "NVD API key (optional; without one the sync rate is 5 req/30s)",
				Sources: cli.EnvVars("NVD_API_KEY"),
			},
			&cli.DurationFlag{
				Name:    "history-retention",
				Usage:   "delete tool-call history older than this (e.g. 720h); zero keeps everything",
				Sources: cli.EnvVars("HISTORY_RETENTION"),
			},
			&cli.BoolFlag{
				Name:  "auth-stub",
				Usage: "use a fixed always-admin test identity instead of real OIDC auth — local development only",
			},
			&cli.StringFlag{
				Name:    "oidc-issuer",
				Usage:   "Keycloak realm issuer URL",
				Sources: cli.EnvVars("OIDC_ISSUER"),
			},
			&cli.StringFlag{
				Name:    "oidc-client-id",
				Sources: cli.EnvVars("OIDC_CLIENT_ID"),
			},
			&cli.StringFlag{
				Name:    "oidc-client-secret",
				Sources: cli.EnvVars("OIDC_CLIENT_SECRET"),
			},
			&cli.StringFlag{
				Name:    "public-url",
				Usage:   "this server's externally-reachable base URL (used to build the OIDC redirect URI)",
				Sources: cli.EnvVars("PUBLIC_URL"),
			},
			&cli.StringFlag{
				Name:    "admin-group",
				Value:   "admins",
				Sources: cli.EnvVars("ADMIN_GROUP"),
			},
			&cli.StringFlag{
				Name:    "session-encryption-key",
				Usage:   "base64-encoded 32-byte key for encrypting session refresh tokens (openssl rand -base64 32)",
				Sources: cli.EnvVars("SESSION_ENCRYPTION_KEY"),
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			dsn := cmd.String("db-dsn")
			db, err := storage.Open(dsn)
			if err != nil {
				slog.Error("storage.Open failed at boot; serving /livez and /readyz (not ready) while retrying", "error", err)
				return serveDegradedUntilReady(ctx, cmd, dsn, err)
			}
			return serveReady(ctx, cmd, db)
		},
	}
}

func buildAppHandler(ctx context.Context, cmd *cli.Command, db *gorm.DB) (http.Handler, health.ReadyChecker, *mcpserver.MCPServer, error) {
	var authProvider humanauth.Provider
	var oidcHandlers humanauth.OIDCHandlers
	useOIDC := !cmd.Bool("auth-stub")

	if useOIDC {
		if cmd.String("oidc-issuer") == "" || cmd.String("oidc-client-id") == "" ||
			cmd.String("oidc-client-secret") == "" || cmd.String("public-url") == "" ||
			cmd.String("session-encryption-key") == "" {
			return nil, health.ReadyChecker{}, nil, errors.New(
				"OIDC auth requires --oidc-issuer, --oidc-client-id, --oidc-client-secret, --public-url, and --session-encryption-key (or pass --auth-stub for local development)",
			)
		}
		encryptionKey, err := base64.StdEncoding.DecodeString(cmd.String("session-encryption-key"))
		if err != nil {
			return nil, health.ReadyChecker{}, nil, fmt.Errorf("--session-encryption-key must be valid base64: %w", err)
		}
		if len(encryptionKey) != 32 {
			return nil, health.ReadyChecker{}, nil, fmt.Errorf(
				"--session-encryption-key must decode to exactly 32 bytes, got %d (generate one with: openssl rand -base64 32)",
				len(encryptionKey),
			)
		}
		cfg := humanauth.OIDCConfig{
			Issuer:        cmd.String("oidc-issuer"),
			ClientID:      cmd.String("oidc-client-id"),
			ClientSecret:  cmd.String("oidc-client-secret"),
			PublicURL:     cmd.String("public-url"),
			AdminGroup:    cmd.String("admin-group"),
			EncryptionKey: encryptionKey,
		}
		provider, handlers, err := humanauth.NewOIDCHandlers(ctx, db, cfg)
		if err != nil {
			return nil, health.ReadyChecker{}, nil, fmt.Errorf("configure OIDC: %w", err)
		}
		authProvider = provider
		oidcHandlers = handlers
	} else {
		authProvider = humanauth.StubProvider{}
		slog.Warn("human auth running in STUB mode — do not deploy to production")
	}

	frontendHandler, err := frontend.Handler()
	if err != nil {
		return nil, health.ReadyChecker{}, nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, health.ReadyChecker{}, nil, fmt.Errorf("get pooled db handle: %w", err)
	}
	readyChecker := health.ReadyChecker{
		Ping:            sqlDB.PingContext,
		MigrationsReady: true,
		OIDCReady:       true,
	}

	mcpSrv := mcpserver.New(db, []mcpserver.ToolRegistrar{
		cvetools.NewRegistrar(),
	})

	r := chi.NewRouter()
	r.Get("/livez", health.Livez)
	r.Get("/readyz", readyChecker.Readyz)
	if useOIDC {
		r.HandleFunc("/auth/login", oidcHandlers.Login)
		r.HandleFunc("/auth/callback", oidcHandlers.Callback)
		r.HandleFunc("/auth/logout", oidcHandlers.Logout)
	}
	r.Mount("/mcp", mcpSrv.Handler())
	r.Mount("/api", restapi.NewHandler(db, authProvider))
	r.Mount("/", frontendHandler)

	return r, readyChecker, mcpSrv, nil
}

func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func serveReady(ctx context.Context, cmd *cli.Command, db *gorm.DB) error {
	appHandler, _, mcpSrv, err := buildAppHandler(ctx, cmd, db)
	if err != nil {
		return err
	}

	go pruneHistoryUntilDone(ctx, db, cmd.Duration("history-retention"))
	go runSyncLoop(ctx, db, cmd.String("nvd-api-key"), mcpSrv)

	server := newServer(cmd.String("listen-addr"), appHandler)
	serveErr := make(chan error, 1)
	go func() {
		slog.Info("starting server", "addr", server.Addr, "version", version)
		serveErr <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		return shutdown(server)
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func serveDegradedUntilReady(ctx context.Context, cmd *cli.Command, dsn string, firstErr error) error {
	var mu sync.RWMutex
	checker := health.ReadyChecker{
		Ping:            func(context.Context) error { return firstErr },
		MigrationsReady: false,
		OIDCReady:       false,
	}
	var appHandler atomic.Pointer[http.Handler]

	r := chi.NewRouter()
	r.Get("/livez", health.Livez)
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		c := checker
		mu.RUnlock()
		c.Readyz(w, r)
	})
	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := appHandler.Load(); h != nil {
			(*h).ServeHTTP(w, r)
			return
		}
		http.Error(w, "starting up: database not yet available", http.StatusServiceUnavailable)
	}))

	server := newServer(cmd.String("listen-addr"), r)
	serveErr := make(chan error, 1)
	go func() {
		slog.Info("starting server (degraded: database not yet available)", "addr", server.Addr, "version", version)
		serveErr <- server.ListenAndServe()
	}()

	dbReady := make(chan *gorm.DB, 1)
	go retryOpenUntilReady(ctx, dsn, &mu, &checker, dbReady)

	for {
		select {
		case <-ctx.Done():
			return shutdown(server)
		case err := <-serveErr:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case db := <-dbReady:
			handler, readyChecker, mcpSrv, err := buildAppHandler(ctx, cmd, db)
			if err != nil {
				if shutdownErr := shutdown(server); shutdownErr != nil {
					slog.Error("shutdown after failed route build", "error", shutdownErr)
				}
				return err
			}
			h := handler
			appHandler.Store(&h)
			mu.Lock()
			checker = readyChecker
			mu.Unlock()
			go pruneHistoryUntilDone(ctx, db, cmd.Duration("history-retention"))
			go runSyncLoop(ctx, db, cmd.String("nvd-api-key"), mcpSrv)
			slog.Info("database became available; now serving normally")
		}
	}
}

func retryOpenUntilReady(ctx context.Context, dsn string, mu *sync.RWMutex, checker *health.ReadyChecker, ready chan<- *gorm.DB) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		db, err := storage.Open(dsn)
		if err == nil {
			ready <- db
			return
		}

		slog.Error("storage.Open retry failed", "error", err)
		mu.Lock()
		checker.Ping = func(context.Context) error { return err }
		mu.Unlock()

		backoff = min(backoff*2, maxBackoff)
	}
}

func runSyncLoop(ctx context.Context, db *gorm.DB, apiKey string, mcpSrv *mcpserver.MCPServer) {
	client := nvd.NewClient(apiKey)

	var notifier nvd.WatchNotifier
	if mcpSrv != nil {
		notifier = mcpSrv.NotifyWatchHit
	}

	syncer := nvd.NewSyncer(db, client, notifier)

	if err := syncer.RunInitialLoad(ctx); err != nil {
		if ctx.Err() != nil {
			return
		}
		slog.Error("NVD initial load failed", "error", err)
	}

	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := syncer.RunIncrementalSync(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.Error("NVD incremental sync failed", "error", err)
			}
		}
	}
}

func pruneHistoryUntilDone(ctx context.Context, db *gorm.DB, retention time.Duration) {
	if retention <= 0 {
		return
	}
	slog.Info("history pruning enabled", "retention", retention)

	ticker := time.NewTicker(historyPruneInterval)
	defer ticker.Stop()
	for {
		deleted, err := storage.PruneToolCalls(db, retention)
		if err != nil {
			slog.Error("history pruning failed", "error", err)
		} else if deleted > 0 {
			slog.Info("pruned expired history", "rows", deleted)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func shutdown(server *http.Server) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newRootCommand().Run(ctx, os.Args); err != nil {
		slog.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}
