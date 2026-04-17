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
	"github.com/mirror-guard/auth-backend/internal/cookie"
	"github.com/mirror-guard/auth-backend/internal/handler"
	"github.com/mirror-guard/auth-backend/internal/observability"
	"github.com/mirror-guard/auth-backend/internal/pipeline"
	"github.com/mirror-guard/auth-backend/internal/policy"
	"github.com/mirror-guard/auth-backend/internal/state"
)

const (
	pathAuthInline = "/api/auth_inline"
	pathChallenge  = "/api/challenge"
	pathVerifyPoW  = "/api/verify_pow"
	pathHealthz    = "/healthz"
	pathMetrics    = "/metrics"
)

var (
	activeChallengeHandler *handler.ChallengeHandler
	activeVerifyPoWHandler *handler.VerifyPoWHandler
	// serveFn and shutdownFn are package-local seams used by tests.
	// Defaults preserve production behavior by delegating to http.Server methods.
	serveFn    = func(srv *http.Server, ln net.Listener) error { return srv.Serve(ln) }
	shutdownFn = func(srv *http.Server, ctx context.Context) error { return srv.Shutdown(ctx) }
)

// @title Mirror Guard Auth Gateway API
// @version 1.0
// @description Authentication gateway endpoints for inline authorization, challenge issuance, and PoW verification.
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

	pol, err := policy.LoadExternal(cfg.Policy.ExternalListsPath)
	if err != nil {
		return fmt.Errorf("load external policy: %w", err)
	}
	policyMgr := policy.NewManager(pol)

	mux, p, authH := buildMux(policyMgr.Get(), cfg)
	defer p.Close()

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
		"auth_inline", pathAuthInline,
		"challenge", pathChallenge,
		"verify_pow", pathVerifyPoW,
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
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
			case syscall.SIGHUP:
				newCfg, reloadErr := config.LoadConfig(configPath)
				if reloadErr != nil {
					slog.Error("config reload failed", "error", reloadErr)
					continue
				}
				newPol, reloadPolicyErr := policy.LoadExternal(newCfg.Policy.ExternalListsPath)
				if reloadPolicyErr != nil {
					slog.Error("policy reload failed", "error", reloadPolicyErr)
					continue
				}
				policyMgr.Set(newPol)
				p.Reload(newPol)
				authH.SetPolicy(newPol)
				p.SetConfig(newCfg)
				if activeChallengeHandler != nil {
					activeChallengeHandler.SetConfig(newCfg)
				}
				if activeVerifyPoWHandler != nil {
					activeVerifyPoWHandler.SetConfig(newCfg)
				}

				if securityConfigChanged(cfg, newCfg) {
					cookieMgr := cookie.NewManager(newCfg.Security.GlobalSecret, newCfg.Security.CookieName, newCfg.Security.CookieTTLSeconds)
					p.SetCookieManager(cookieMgr)
					if activeVerifyPoWHandler != nil {
						activeVerifyPoWHandler.SetCookieManager(cookieMgr)
					}
				}
				cfg = newCfg
				slog.Info("config and policy reloaded")
			}
		case err = <-serveErr:
			if err != nil {
				return fmt.Errorf("serve: %w", err)
			}
		}
	}
}

func buildMux(pol *policy.Set, cfgs ...*config.Config) (*http.ServeMux, *pipeline.Pipeline, *handler.AuthInlineHandler) {
	mux := http.NewServeMux()
	cfg := defaultMuxConfig()
	if len(cfgs) > 0 && cfgs[0] != nil {
		cfg = cfgs[0]
	}
	store := state.NewStore()
	cookieMgr := cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds)

	authInline := handler.NewAuthInlineHandler(pol)
	challenge := handler.NewChallengeHandler(cfg, store)
	verifyPoW := handler.NewVerifyPoWHandler(cfg, store, cookieMgr)
	p := pipeline.NewPipeline(pol, authInline, cfg, store, cookieMgr)
	activeChallengeHandler = challenge
	activeVerifyPoWHandler = verifyPoW

	mux.Handle(pathAuthInline, p)
	mux.Handle(pathChallenge, challenge)
	mux.Handle(pathVerifyPoW, verifyPoW)
	mux.Handle(pathHealthz, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	mux.Handle(pathMetrics, observability.MetricsHandler())

	return mux, p, authInline
}

func securityConfigChanged(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	return oldCfg.Security.GlobalSecret != newCfg.Security.GlobalSecret ||
		oldCfg.Security.CookieName != newCfg.Security.CookieName ||
		oldCfg.Security.CookieTTLSeconds != newCfg.Security.CookieTTLSeconds
}

func defaultMuxConfig() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			CookieName:       "auth_token",
			CookieTTLSeconds: 15,
			NonceTTLSeconds:  30,
			PowMinDifficulty: 4,
			PowMaxDifficulty: 10,
			PowWindowSeconds: 60,
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
