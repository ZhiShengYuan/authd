package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/cookie"
	"github.com/mirror-guard/auth-backend/internal/observability"
	"github.com/mirror-guard/auth-backend/internal/pow"
	"github.com/mirror-guard/auth-backend/internal/state"
	"github.com/mirror-guard/auth-backend/internal/subnet"
	"go.opentelemetry.io/otel"
)

type VerifyPoWHandler struct {
	mu            sync.RWMutex
	config        *config.Config
	store         *state.Store
	cookieMgr     *cookie.Manager
	cookieIssueFn func(subnetKey, uaDigest, path string) (token string, tokenID string, err error)
}

type powSubmission struct {
	Prefix    string `json:"prefix"`
	Nonce     string `json:"nonce"`
	TargetURI string `json:"target_uri"`
}

func NewVerifyPoWHandler(cfg *config.Config, store *state.Store, cookieMgr *cookie.Manager) *VerifyPoWHandler {
	return NewVerifyPoWHandlerWithDeps(cfg, store, cookieMgr)
}

func NewVerifyPoWHandlerWithDeps(cfg *config.Config, store *state.Store, cookieMgr *cookie.Manager) *VerifyPoWHandler {
	if cfg == nil {
		cfg = defaultHandlerConfig()
	}
	if store == nil {
		store = state.NewStore()
	}
	if cookieMgr == nil {
		cookieMgr = cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds)
	}
	return &VerifyPoWHandler{
		config:        cfg,
		store:         store,
		cookieMgr:     cookieMgr,
		cookieIssueFn: cookieMgr.Issue,
	}
}

func (h *VerifyPoWHandler) SetConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	h.mu.Lock()
	h.config = cfg
	h.mu.Unlock()
}

func (h *VerifyPoWHandler) SetCookieManager(cookieMgr *cookie.Manager) {
	if cookieMgr == nil {
		return
	}
	h.mu.Lock()
	h.cookieMgr = cookieMgr
	h.cookieIssueFn = cookieMgr.Issue
	h.mu.Unlock()
}

// @Summary Verify proof-of-work submission
// @Description Validates submitted PoW, prevents nonce replay, then redirects with an auth cookie. Requires X-Real-IP header; X-UA is optional. Accepts JSON body (modeled in OpenAPI spec). The runtime also accepts application/x-www-form-urlencoded form submissions with the same field names, but this is not modeled in the spec for Swagger 2.0 compatibility.
// @Tags auth
// @Accept json
// @Produce json
// @Param X-Real-IP header string true "Client IP address"
// @Param X-UA header string false "Client user agent"
// @Param body body apidoc.VerifyPoWRequest true "PoW submission"
// @Success 302 {string} string "Redirect to target with cookie (Set-Cookie and Location headers)"
// @Failure 400 {object} apidoc.VerifyPoWError "JSON-shaped error body via http.Error"
// @Failure 403 {object} apidoc.VerifyPoWError "JSON-shaped error body via http.Error"
// @Failure 405 {string} string "Method not allowed"
// @Failure 503 {string} string "Service unavailable — may be JSON-shaped error or plain text"
// @Router /api/verify_pow [post]
func (h *VerifyPoWHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	cfg := h.config
	store := h.store
	cookieMgr := h.cookieMgr
	cookieIssueFn := h.cookieIssueFn
	h.mu.RUnlock()

	start := time.Now()
	ctx, span := otel.Tracer("mirror-guard-auth-gateway/handler").Start(r.Context(), "verify_pow.ServeHTTP")
	defer span.End()
	r = r.WithContext(ctx)
	action := "reject"
	defer func() {
		observability.RecordHandlerLatency("verify_pow", action, time.Since(start))
	}()

	defer func() {
		if r := recover(); r != nil {
			action = "fallback"
			slog.Error("verify_pow handler panicked", "panic", r)
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}()

	if r.Method != http.MethodPost {
		action = "reject"
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	prefix, nonce, targetURI, ok := parseSubmission(r)
	if !ok {
		action = "reject"
		http.Error(w, `{"error":"missing required fields"}`, http.StatusBadRequest)
		return
	}

	prefixData, err := pow.VerifyPrefixIntegrity(prefix, []byte(cfg.Security.GlobalSecret), cfg.Security.NonceTTLSeconds)
	if err != nil {
		action = "reject"
		http.Error(w, `{"error":"invalid or expired prefix"}`, http.StatusForbidden)
		return
	}

	requestSubnet := subnet.DefaultKey(requestClientIP(r))
	if requestSubnet == "" || prefixData.SubnetKey != requestSubnet {
		action = "reject"
		http.Error(w, `{"error":"subnet mismatch"}`, http.StatusForbidden)
		return
	}

	if cfg.Security.PowMinDifficulty < 0 || cfg.Security.PowMaxDifficulty < 0 || cfg.Security.PowMinDifficulty > cfg.Security.PowMaxDifficulty {
		action = "reject"
		http.Error(w, `{"error":"invalid proof of work difficulty"}`, http.StatusForbidden)
		return
	}

	requestsInWindow := store.QuotaStore.Get(requestSubnet)
	difficulty := pow.Difficulty(requestsInWindow, cfg.Security.PowMinDifficulty, cfg.Security.PowMaxDifficulty)
	if difficulty <= 0 {
		action = "reject"
		http.Error(w, `{"error":"invalid proof of work difficulty"}`, http.StatusForbidden)
		return
	}
	if !pow.Verify(prefix, nonce, difficulty) {
		action = "reject"
		http.Error(w, `{"error":"invalid proof of work"}`, http.StatusForbidden)
		return
	}

	isNew, lockErr := store.NonceStore.CheckAndLock(requestSubnet, nonce, time.Duration(cfg.Security.NonceTTLSeconds)*time.Second)
	if lockErr != nil {
		action = "fallback"
		http.Error(w, `{"error":"internal state unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	if !isNew {
		action = "reject"
		observability.RecordNonceReplay()
		http.Error(w, `{"error":"replay detected"}`, http.StatusForbidden)
		return
	}

	if targetURI == "" {
		targetURI = prefixData.TargetURI
	}
	uaDigest := cookie.UADigest(r.Header.Get("X-UA"))
	token, _, issueErr := cookieIssueFn(requestSubnet, uaDigest, targetURI)
	if issueErr != nil {
		action = "fallback"
		http.Error(w, "internal server error", http.StatusServiceUnavailable)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieMgr.CookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   cookieMgr.TTLSeconds(),
	})
	w.Header().Set("Location", targetURI)
	w.WriteHeader(http.StatusFound)
	action = "allow"
}

func parseSubmission(r *http.Request) (prefix, nonce, targetURI string, ok bool) {
	if err := r.ParseForm(); err == nil {
		prefix = r.Form.Get("prefix")
		nonce = r.Form.Get("nonce")
		targetURI = r.Form.Get("target_uri")
		if prefix != "" && nonce != "" {
			return prefix, nonce, targetURI, true
		}
	}

	var body powSubmission
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return "", "", "", false
	}
	if body.Prefix == "" || body.Nonce == "" {
		return "", "", "", false
	}

	return body.Prefix, body.Nonce, body.TargetURI, true
}
