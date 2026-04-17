package handler

import (
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/observability"
	"github.com/mirror-guard/auth-backend/internal/pow"
	"github.com/mirror-guard/auth-backend/internal/state"
	"github.com/mirror-guard/auth-backend/internal/subnet"
	"go.opentelemetry.io/otel"
)

type ChallengeHandler struct {
	mu     sync.RWMutex
	config *config.Config
	store  *state.Store
}

var randReadFn = func(b []byte) (int, error) {
	return rand.Read(b)
}

func NewChallengeHandler(cfg *config.Config, store *state.Store) *ChallengeHandler {
	return NewChallengeHandlerWithDeps(cfg, store)
}

func NewChallengeHandlerWithDeps(cfg *config.Config, store *state.Store) *ChallengeHandler {
	if cfg == nil {
		cfg = defaultHandlerConfig()
	}
	if store == nil {
		store = state.NewStore()
	}
	return &ChallengeHandler{config: cfg, store: store}
}

func (h *ChallengeHandler) SetConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	h.mu.Lock()
	h.config = cfg
	h.mu.Unlock()
}

func (h *ChallengeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	cfg := h.config
	store := h.store
	h.mu.RUnlock()

	start := time.Now()
	ctx, span := otel.Tracer("mirror-guard-auth-gateway/handler").Start(r.Context(), "challenge.ServeHTTP")
	defer span.End()
	r = r.WithContext(ctx)
	action := "reject"
	defer func() {
		observability.RecordHandlerLatency("challenge", action, time.Since(start))
	}()

	if r.Method != http.MethodGet {
		action = "reject"
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := requestClientIP(r)
	subnetKey := subnet.DefaultKey(clientIP)
	if subnetKey == "" {
		action = "reject"
		http.Error(w, "invalid client ip", http.StatusBadRequest)
		return
	}

	target := strings.TrimSpace(r.Header.Get("X-URL"))
	if target == "" {
		if c, err := r.Cookie("pow_target"); err == nil && c != nil && c.Value != "" {
			decoded, decodeErr := url.QueryUnescape(c.Value)
			if decodeErr == nil {
				target = decoded
			}
		}
	}

	if target == "" {
		action = "reject"
		http.Error(w, "missing X-URL header", http.StatusBadRequest)
		return
	}

	requestsInWindow := store.QuotaStore.Get(subnetKey)
	difficulty := pow.Difficulty(requestsInWindow, cfg.Security.PowMinDifficulty, cfg.Security.PowMaxDifficulty)

	salt := make([]byte, 16)
	if _, err := randReadFn(salt); err != nil {
		action = "fallback"
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), target, subnetKey, time.Now().Unix(), salt)

	resp := struct {
		Prefix     string `json:"prefix"`
		Difficulty int    `json:"difficulty"`
		Target     string `json:"target"`
	}{
		Prefix:     prefix,
		Difficulty: difficulty,
		Target:     target,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
	action = "challenge"
}

func requestClientIP(r *http.Request) string {
	clientIP := strings.TrimSpace(r.Header.Get("X-Real-IP"))
	if clientIP != "" {
		return clientIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func defaultHandlerConfig() *config.Config {
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
