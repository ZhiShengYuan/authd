package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/pow"
	"github.com/mirror-guard/auth-backend/internal/state"
	"github.com/mirror-guard/auth-backend/internal/subnet"
)

func TestChallengeReturnsJSONForHeaderTarget(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", PowMinDifficulty: 4, PowMaxDifficulty: 10, PowWindowSeconds: 60}}
	h := NewChallengeHandlerWithDeps(cfg, store)

	req := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	req.Header.Set("X-Real-IP", "192.168.1.10")
	req.Header.Set("X-URL", "/protected/file.iso")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp struct {
		Prefix     string `json:"prefix"`
		Difficulty int    `json:"difficulty"`
		Target     string `json:"target"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Target != "/protected/file.iso" {
		t.Fatalf("unexpected target %q", resp.Target)
	}
	if resp.Difficulty != 4 {
		t.Fatalf("unexpected difficulty %d", resp.Difficulty)
	}
	if _, err := pow.VerifyPrefixIntegrity(resp.Prefix, []byte(cfg.Security.GlobalSecret), 30); err != nil {
		t.Fatalf("prefix integrity failed: %v", err)
	}
}

func TestChallengeFallsBackToPowTargetCookie(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)
	h := NewChallengeHandlerWithDeps(defaultHandlerConfig(), store)

	req := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	req.Header.Set("X-Real-IP", "192.168.1.20")
	req.AddCookie(&http.Cookie{Name: "pow_target", Value: "%2Fprotected%2Fpkg.tar.gz"})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Target != "/protected/pkg.tar.gz" {
		t.Fatalf("unexpected target %q", resp.Target)
	}
}

func TestChallengeDifficultyUsesQuotaFrequency(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", PowMinDifficulty: 4, PowMaxDifficulty: 10, PowWindowSeconds: 60}}
	h := NewChallengeHandlerWithDeps(cfg, store)

	key := subnet.DefaultKey("192.168.1.30")
	for i := 0; i < 7; i++ {
		if _, err := store.QuotaStore.Increment(key, time.Minute); err != nil {
			t.Fatalf("increment quota: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	req.Header.Set("X-Real-IP", "192.168.1.30")
	req.Header.Set("X-URL", "/protected/file.iso")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var resp struct {
		Difficulty int `json:"difficulty"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Difficulty != 7 {
		t.Fatalf("expected difficulty 7, got %d", resp.Difficulty)
	}
}

func TestChallengeRejectsMethodPost(t *testing.T) {
	h := NewChallengeHandlerWithDeps(defaultHandlerConfig(), state.NewStore())
	t.Cleanup(h.store.Stop)

	req := httptest.NewRequest(http.MethodPost, "/api/challenge", nil)
	req.Header.Set("X-Real-IP", "192.168.1.10")
	req.Header.Set("X-URL", "/protected/file.iso")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("expected Allow=%q, got %q", http.MethodGet, got)
	}
	if !strings.Contains(rr.Body.String(), "method not allowed") {
		t.Fatalf("expected method error body, got %q", rr.Body.String())
	}
}

func TestChallengeRejectsInvalidClientIP(t *testing.T) {
	h := NewChallengeHandlerWithDeps(defaultHandlerConfig(), state.NewStore())
	t.Cleanup(h.store.Stop)

	req := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	req.Header.Del("X-Real-IP")
	req.RemoteAddr = "not-a-hostport"
	req.Header.Set("X-URL", "/protected/file.iso")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid client ip") {
		t.Fatalf("expected invalid client ip body, got %q", rr.Body.String())
	}
}

func TestChallengeRejectsMissingHeaderAndCookie(t *testing.T) {
	h := NewChallengeHandlerWithDeps(defaultHandlerConfig(), state.NewStore())
	t.Cleanup(h.store.Stop)

	req := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	req.Header.Set("X-Real-IP", "192.168.1.40")
	req.Header.Del("X-URL")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "missing X-URL header") {
		t.Fatalf("expected missing X-URL body, got %q", rr.Body.String())
	}
}

func TestChallengeInvalidPowTargetCookieEncoding(t *testing.T) {
	h := NewChallengeHandlerWithDeps(defaultHandlerConfig(), state.NewStore())
	t.Cleanup(h.store.Stop)

	req := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	req.Header.Set("X-Real-IP", "192.168.1.41")
	req.AddCookie(&http.Cookie{Name: "pow_target", Value: "%zz"})
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "missing X-URL header") {
		t.Fatalf("expected missing X-URL body for undecodable cookie, got %q", rr.Body.String())
	}
}

func TestChallengeReturnsInternalServerErrorWhenRandReadFails(t *testing.T) {
	h := NewChallengeHandlerWithDeps(defaultHandlerConfig(), state.NewStore())
	t.Cleanup(h.store.Stop)

	originalRandReadFn := randReadFn
	randReadFn = func([]byte) (int, error) {
		return 0, errors.New("entropy unavailable")
	}
	t.Cleanup(func() {
		randReadFn = originalRandReadFn
	})

	req := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	req.Header.Set("X-Real-IP", "192.168.1.42")
	req.Header.Set("X-URL", "/protected/file.iso")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d, got %d", http.StatusInternalServerError, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "internal server error") {
		t.Fatalf("expected internal server error body, got %q", rr.Body.String())
	}
}

func TestChallengeSetConfigNilNoOp(t *testing.T) {
	original := defaultHandlerConfig()
	h := NewChallengeHandlerWithDeps(original, state.NewStore())
	t.Cleanup(h.store.Stop)

	h.SetConfig(nil)

	if h.config != original {
		t.Fatalf("expected config pointer to remain unchanged")
	}
}

func TestNewChallengeHandlerWithDepsNilConfigUsesDefault(t *testing.T) {
	h := NewChallengeHandlerWithDeps(nil, state.NewStore())
	t.Cleanup(h.store.Stop)

	if h.config == nil {
		t.Fatal("expected default config to be set")
	}
	defaults := defaultHandlerConfig()
	if h.config.Security.CookieName != defaults.Security.CookieName || h.config.Security.PowMinDifficulty != defaults.Security.PowMinDifficulty || h.config.Security.PowMaxDifficulty != defaults.Security.PowMaxDifficulty {
		t.Fatalf("expected default security config, got %#v", h.config.Security)
	}
}

func TestNewChallengeHandlerDelegatesToWithDeps(t *testing.T) {
	h := NewChallengeHandler(nil, nil)
	if h == nil {
		t.Fatal("expected non-nil challenge handler")
	}
	if h.config == nil {
		t.Fatal("expected default config through NewChallengeHandler")
	}
	if h.store == nil {
		t.Fatal("expected store through NewChallengeHandler")
	}
	t.Cleanup(h.store.Stop)
}

func TestChallengeSetConfigReplacesConfig(t *testing.T) {
	h := NewChallengeHandlerWithDeps(defaultHandlerConfig(), state.NewStore())
	t.Cleanup(h.store.Stop)

	updated := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "cookie_alt", CookieTTLSeconds: 20, NonceTTLSeconds: 40, PowMinDifficulty: 2, PowMaxDifficulty: 5, PowWindowSeconds: 30}}
	h.SetConfig(updated)

	if h.config != updated {
		t.Fatal("expected SetConfig to replace handler config")
	}
}

func TestNewChallengeHandlerWithDepsNilStoreCreatesStore(t *testing.T) {
	h := NewChallengeHandlerWithDeps(defaultHandlerConfig(), nil)
	if h.store == nil {
		t.Fatal("expected store to be created")
	}
	t.Cleanup(h.store.Stop)

	if h.store.QuotaStore == nil || h.store.NonceStore == nil || h.store.CookieConsumptionStore == nil {
		t.Fatalf("expected initialized store components, got %#v", h.store)
	}
}

func TestRequestClientIPHeaderVsRemoteAddr(t *testing.T) {
	t.Run("uses x-real-ip when set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Real-IP", " 203.0.113.10 ")
		req.RemoteAddr = "198.51.100.3:9000"

		if got := requestClientIP(req); got != "203.0.113.10" {
			t.Fatalf("expected X-Real-IP to win, got %q", got)
		}
	})

	t.Run("falls back to remote addr host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Del("X-Real-IP")
		req.RemoteAddr = "198.51.100.3:9000"

		if got := requestClientIP(req); got != "198.51.100.3" {
			t.Fatalf("expected remote host fallback, got %q", got)
		}
	})
}

func TestDefaultHandlerConfigExpectedDefaults(t *testing.T) {
	cfg := defaultHandlerConfig()
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}

	if cfg.Security.CookieName != "auth_token" {
		t.Fatalf("expected default cookie name auth_token, got %q", cfg.Security.CookieName)
	}
	if cfg.Security.CookieTTLSeconds != 15 {
		t.Fatalf("expected default cookie ttl 15, got %d", cfg.Security.CookieTTLSeconds)
	}
	if cfg.Security.NonceTTLSeconds != 30 {
		t.Fatalf("expected default nonce ttl 30, got %d", cfg.Security.NonceTTLSeconds)
	}
	if cfg.Security.PowMinDifficulty != 4 {
		t.Fatalf("expected default min difficulty 4, got %d", cfg.Security.PowMinDifficulty)
	}
	if cfg.Security.PowMaxDifficulty != 10 {
		t.Fatalf("expected default max difficulty 10, got %d", cfg.Security.PowMaxDifficulty)
	}
	if cfg.Security.PowWindowSeconds != 60 {
		t.Fatalf("expected default pow window 60, got %d", cfg.Security.PowWindowSeconds)
	}
}

func TestChallengePowTargetCookieWithEscapedWhitespaceTargetSucceeds(t *testing.T) {
	h := NewChallengeHandlerWithDeps(defaultHandlerConfig(), state.NewStore())
	t.Cleanup(h.store.Stop)

	req := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	req.Header.Set("X-Real-IP", "192.168.1.51")
	req.AddCookie(&http.Cookie{Name: "pow_target", Value: url.QueryEscape("   ")})
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rr.Code)
	}

	var resp struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Target != "   " {
		t.Fatalf("expected decoded whitespace target, got %q", resp.Target)
	}
}
