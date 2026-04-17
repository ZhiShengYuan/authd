package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	_ "github.com/mirror-guard/auth-backend/internal/apidoc"
	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/handler"
	"github.com/mirror-guard/auth-backend/internal/observability"
	"github.com/mirror-guard/auth-backend/internal/state"
	"github.com/mirror-guard/auth-backend/internal/ticket"
)

const (
	pathChallenges       = "/api/challenges"
	pathChallengesVerify = "/api/challenges/verify"
	pathTickets          = "/api/tickets"
	pathTicketsVerify    = "/api/tickets/verify"
	pathHealthz          = "/healthz"
	pathMetrics          = "/metrics"
)

var (
	// serveFn and shutdownFn are package-local seams used by tests.
	// Defaults preserve production behavior by delegating to http.Server methods.
	serveFn    = func(srv *http.Server, ln net.Listener) error { return srv.Serve(ln) }
	shutdownFn = func(srv *http.Server, ctx context.Context) error { return srv.Shutdown(ctx) }
)

// @title Mirror Guard Auth Gateway API
// @version 1.0
// @description Internal JSON API for challenge and ticket workflows.
// @license.name Apache-2.0
// @license.url https://www.apache.org/licenses/LICENSE-2.0.html
func main() {
	configPath := flag.String("config", "./configs/config.example.json", "path to config file")
	flag.Parse()

	if err := run(*configPath); err != nil {
		slog.Error("gateway exited with error", "error", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	version := "dev"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		version = info.Main.Version
	}
	observability.Init("mirror-guard-auth-gateway", version)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	mux, stopMux := buildMux(cfg)
	defer stopMux()

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	ln, err := createListener(cfg.Server.ListenNetwork, cfg.Server.ListenAddress)
	if err != nil {
		return err
	}

	serveErr := make(chan error, 1)
	go func() {
		if serveErrRun := serveFn(srv, ln); serveErrRun != nil && !errors.Is(serveErrRun, http.ErrServerClosed) {
			serveErr <- serveErrRun
		}
	}()

	slog.Info("auth-gateway started",
		"network", cfg.Server.ListenNetwork,
		"address", cfg.Server.ListenAddress,
		"challenges", pathChallenges,
		"challenges_verify", pathChallengesVerify,
		"tickets", pathTickets,
		"tickets_verify", pathTicketsVerify,
		"healthz", pathHealthz,
		"metrics", pathMetrics,
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if shutdownErr := shutdownFn(srv, ctx); shutdownErr != nil {
					return fmt.Errorf("shutdown server: %w", shutdownErr)
				}
				if cfg.Server.ListenNetwork == "unix" {
					_ = os.Remove(cfg.Server.ListenAddress)
				}
				return nil
			}
		case err = <-serveErr:
			if err != nil {
				return fmt.Errorf("serve: %w", err)
			}
		}
	}
}

func buildMux(cfgs ...*config.Config) (*http.ServeMux, func()) {
	mux := http.NewServeMux()
	cfg := defaultMuxConfig()
	if len(cfgs) > 0 && cfgs[0] != nil {
		cfg = cfgs[0]
	}
	store := state.NewStore()
	ticketManager := ticket.NewManager(cfg.Security.GlobalSecret, cfg.Security.TicketTTLSeconds)
	ticketManager.StartCleanup(30 * time.Second)
	challengeConfig := handler.NewChallengeConfigHandler(cfg, store)
	challengeVerify := handler.NewChallengeVerifyHandler(cfg, store)
	ticketIssue := handler.NewTicketIssueHandler(cfg, ticketManager)
	ticketVerify := handler.NewTicketVerifyHandler(cfg, ticketManager)

	mux.Handle(pathChallenges, challengeConfig)
	mux.Handle(pathChallengesVerify, challengeVerify)
	mux.Handle(pathTickets, ticketIssue)
	mux.Handle(pathTicketsVerify, ticketVerify)
	mux.Handle(pathHealthz, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	mux.Handle(pathMetrics, observability.MetricsHandler())

	return mux, func() {
		store.Stop()
		ticketManager.Stop()
	}
}

func defaultMuxConfig() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			CookieName:          "auth_token",
			CookieTTLSeconds:    15,
			NonceTTLSeconds:     30,
			PowMinDifficulty:    4,
			PowMaxDifficulty:    10,
			ChallengeTTLSeconds: 30,
			TicketTTLSeconds:    300,
		},
	}
}

func createListener(network, address string) (net.Listener, error) {
	if network == "unix" {
		_ = os.Remove(address)
		ln, err := net.Listen("unix", address)
		if err != nil {
			return nil, fmt.Errorf("listen unix %s: %w", address, err)
		}
		if err := os.Chmod(address, 0o770); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("chmod unix socket %s: %w", address, err)
		}
		return ln, nil
	}
	return net.Listen(network, address)
}
