package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/cookie"
	"github.com/mirror-guard/auth-backend/internal/pow"
	"github.com/mirror-guard/auth-backend/internal/state"
	"github.com/mirror-guard/auth-backend/internal/subnet"
	"github.com/mirror-guard/auth-backend/internal/testutil"
)

func TestVerifyPoWAcceptsFormBodyAndRedirects(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, store, cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))

	subnetKey := subnet.DefaultKey("192.168.1.10")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnetKey, time.Now().Unix(), []byte{0xaa, 0xbb, 0xcc, 0xdd})
	nonce := findNonceForDifficulty(t, prefix, 1)

	body := "prefix=" + prefix + "&nonce=" + nonce + "&target_uri=/protected/file.iso"
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Real-IP", "192.168.1.10")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/protected/file.iso" {
		t.Fatalf("unexpected redirect %q", rr.Header().Get("Location"))
	}
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected Set-Cookie")
	}
}

func TestVerifyPoWAcceptsJSONBody(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, store, cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))

	subnetKey := subnet.DefaultKey("192.168.1.11")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/asset.tar", subnetKey, time.Now().Unix(), []byte{0x01, 0x02, 0x03, 0x04})
	nonce := findNonceForDifficulty(t, prefix, 1)

	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/protected/asset.tar"}`, prefix, nonce)
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.11")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
}

func TestVerifyPoWRejectsSubnetMismatch(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, store, cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))

	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnet.DefaultKey("192.168.2.10"), time.Now().Unix(), []byte{0xaa, 0xbb, 0xcc, 0xdd})
	nonce := findNonceForDifficulty(t, prefix, 1)

	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/protected/file.iso"}`, prefix, nonce)
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.12")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestVerifyPoWRejectsReplayNonce(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, store, cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))

	subnetKey := subnet.DefaultKey("192.168.1.13")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnetKey, time.Now().Unix(), []byte{0xde, 0xad, 0xbe, 0xef})
	nonce := findNonceForDifficulty(t, prefix, 1)

	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/protected/file.iso"}`, prefix, nonce)

	req1 := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Real-IP", "192.168.1.13")
	req1.Header.Set("X-UA", "Mozilla/5.0")
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusFound {
		t.Fatalf("first call expected 302, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Real-IP", "192.168.1.13")
	req2.Header.Set("X-UA", "Mozilla/5.0")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("second call expected 403, got %d", rr2.Code)
	}
}

func TestVerifyPoWRejectsSubnetMismatchBetweenPrefixAndRequestIP(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, store, cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))

	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnet.DefaultKey("10.10.10.10"), time.Now().Unix(), []byte{0xa1, 0xb2, 0xc3, 0xd4})
	nonce := findNonceForDifficulty(t, prefix, 1)

	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/protected/file.iso"}`, prefix, nonce)
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "10.10.11.11")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for subnet mismatch, got %d", rr.Code)
	}
}

func TestVerifyPoWRejectsExpiredPrefix(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 1, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, store, cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))

	subnetKey := subnet.DefaultKey("192.168.33.10")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnetKey, time.Now().Add(-3*time.Second).Unix(), []byte{0xde, 0xad, 0xfa, 0xce})
	nonce := findNonceForDifficulty(t, prefix, 1)

	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/protected/file.iso"}`, prefix, nonce)
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.33.10")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for expired prefix, got %d", rr.Code)
	}
}

func TestVerifyPoWRejectsReplayedNonce(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, store, cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))

	subnetKey := subnet.DefaultKey("192.168.44.10")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnetKey, time.Now().Unix(), []byte{0xfa, 0xfb, 0xfc, 0xfd})
	nonce := findNonceForDifficulty(t, prefix, 1)
	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/protected/file.iso"}`, prefix, nonce)

	req1 := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Real-IP", "192.168.44.10")
	req1.Header.Set("X-UA", "Mozilla/5.0")
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusFound {
		t.Fatalf("first call expected 302, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Real-IP", "192.168.44.10")
	req2.Header.Set("X-UA", "Mozilla/5.0")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("second call expected 403 replay rejection, got %d", rr2.Code)
	}
}

func TestVerifyPoWRejectsInvalidDifficultyConfiguration(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: -1, PowMaxDifficulty: -1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, store, cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))

	subnetKey := subnet.DefaultKey("192.168.45.10")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnetKey, time.Now().Unix(), []byte{0x11, 0x22, 0x33, 0x44})
	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/protected/file.iso"}`, prefix, "0")

	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.45.10")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for invalid difficulty config, got %d", rr.Code)
	}
}

func TestVerifyPoWRejectsMethodGet(t *testing.T) {
	h := NewVerifyPoWHandlerWithDeps(defaultHandlerConfig(), state.NewStore(), cookie.NewManager("0123456789abcdef0123456789abcdef", "auth_token", 15))
	t.Cleanup(h.store.Stop)

	req := httptest.NewRequest(http.MethodGet, "/api/verify_pow", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("expected Allow=%q, got %q", http.MethodPost, got)
	}
	if !strings.Contains(rr.Body.String(), "method not allowed") {
		t.Fatalf("expected method not allowed body, got %q", rr.Body.String())
	}
}

func TestVerifyPoWRejectsMissingFieldsInFormBody(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, state.NewStore(), cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))
	t.Cleanup(h.store.Stop)

	body := "prefix=abc&nonce=123"
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Real-IP", "192.168.1.60")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d", http.StatusForbidden, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `{"error":"invalid or expired prefix"}`) {
		t.Fatalf("expected invalid or expired prefix body, got %q", rr.Body.String())
	}
}

func TestVerifyPoWRejectsMissingFieldsInJSONBody(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, state.NewStore(), cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))
	t.Cleanup(h.store.Stop)

	body := `{"prefix":"p"}`
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.61")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `{"error":"missing required fields"}`) {
		t.Fatalf("expected missing required fields body, got %q", rr.Body.String())
	}
}

func TestVerifyPoWRejectsInvalidJSONBody(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, state.NewStore(), cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))
	t.Cleanup(h.store.Stop)

	body := `{"prefix":`
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.62")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestVerifyPoWRejectsInvalidPrefixIntegrity(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, state.NewStore(), cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))
	t.Cleanup(h.store.Stop)

	subnetKey := subnet.DefaultKey("192.168.1.63")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnetKey, time.Now().Unix(), []byte{0xaa, 0xbb, 0xcc, 0xdd})
	tampered := prefix[:len(prefix)-1] + "0"
	if tampered == prefix {
		tampered = prefix[:len(prefix)-1] + "1"
	}

	body := fmt.Sprintf(`{"prefix":"%s","nonce":"0","target_uri":"/protected/file.iso"}`, tampered)
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.63")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d", http.StatusForbidden, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `{"error":"invalid or expired prefix"}`) {
		t.Fatalf("expected invalid prefix body, got %q", rr.Body.String())
	}
}

func TestVerifyPoWRejectsDifficultyLessOrEqualZero(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 0, PowMaxDifficulty: 0, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, state.NewStore(), cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))
	t.Cleanup(h.store.Stop)

	subnetKey := subnet.DefaultKey("192.168.1.64")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnetKey, time.Now().Unix(), []byte{0xaa, 0xbb, 0x00, 0x11})
	body := fmt.Sprintf(`{"prefix":"%s","nonce":"0","target_uri":"/protected/file.iso"}`, prefix)

	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.64")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d", http.StatusForbidden, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `{"error":"invalid proof of work difficulty"}`) {
		t.Fatalf("expected invalid difficulty body, got %q", rr.Body.String())
	}
}

func TestVerifyPoWRejectsInvalidPoW(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 2, PowMaxDifficulty: 2, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, state.NewStore(), cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))
	t.Cleanup(h.store.Stop)

	subnetKey := subnet.DefaultKey("192.168.1.65")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnetKey, time.Now().Unix(), []byte{0xab, 0xcd, 0xef, 0x01})

	body := fmt.Sprintf(`{"prefix":"%s","nonce":"definitely-wrong","target_uri":"/protected/file.iso"}`, prefix)
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.65")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d", http.StatusForbidden, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `{"error":"invalid proof of work"}`) {
		t.Fatalf("expected invalid proof of work body, got %q", rr.Body.String())
	}
}

func TestVerifyPoWReturnsServiceUnavailableWhenNonceStoreUnavailable(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	store := state.NewStore()
	t.Cleanup(store.Stop)
	store.NonceStore = nil

	h := NewVerifyPoWHandlerWithDeps(cfg, store, cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))

	subnetKey := subnet.DefaultKey("192.168.1.66")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnetKey, time.Now().Unix(), []byte{0x01, 0x02, 0x03, 0x04})
	nonce := testutil.FindNonce(prefix, 1)
	if nonce == "" {
		t.Fatal("expected nonce for difficulty 1")
	}
	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/protected/file.iso"}`, prefix, nonce)

	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.66")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, rr.Code)
	}
}

func TestVerifyPoWReturnsServiceUnavailableWhenCheckAndLockErrors(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	store := state.NewStore()
	t.Cleanup(store.Stop)
	h := NewVerifyPoWHandlerWithDeps(cfg, store, cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))

	subnetKey := subnet.DefaultKey("192.168.1.166")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnetKey, time.Now().Unix(), []byte{0x05, 0x06, 0x07, 0x08})
	nonce := testutil.FindNonce(prefix, 1)
	if nonce == "" {
		t.Fatal("expected nonce for difficulty 1")
	}

	injectInvalidNonceLockEntry(t, store.NonceStore, subnetKey+":"+nonce)

	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/protected/file.iso"}`, prefix, nonce)
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.166")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `{"error":"internal state unavailable"}`) {
		t.Fatalf("expected internal state unavailable body, got %q", rr.Body.String())
	}
}

func TestVerifyPoWReturnsServiceUnavailableWhenCookieManagerIsNil(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, state.NewStore(), cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))
	t.Cleanup(h.store.Stop)

	subnetKey := subnet.DefaultKey("192.168.1.67")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/protected/file.iso", subnetKey, time.Now().Unix(), []byte{0x11, 0x12, 0x13, 0x14})
	nonce := testutil.FindNonce(prefix, 1)
	if nonce == "" {
		t.Fatal("expected nonce for difficulty 1")
	}
	h.cookieMgr = nil

	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/protected/file.iso"}`, prefix, nonce)
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.67")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, rr.Code)
	}
	if rr.Body.String() != "" {
		t.Fatalf("expected empty body from panic recovery fallback, got %q", rr.Body.String())
	}
}

func TestVerifyPoWSetConfigNilNoOp(t *testing.T) {
	original := defaultHandlerConfig()
	h := NewVerifyPoWHandlerWithDeps(original, state.NewStore(), cookie.NewManager("0123456789abcdef0123456789abcdef", "auth_token", 15))
	t.Cleanup(h.store.Stop)

	h.SetConfig(nil)

	if h.config != original {
		t.Fatal("expected config pointer unchanged when cfg is nil")
	}
}

func TestVerifyPoWSetCookieManagerNilNoOp(t *testing.T) {
	original := cookie.NewManager("0123456789abcdef0123456789abcdef", "auth_token", 15)
	h := NewVerifyPoWHandlerWithDeps(defaultHandlerConfig(), state.NewStore(), original)
	t.Cleanup(h.store.Stop)

	h.SetCookieManager(nil)

	if h.cookieMgr != original {
		t.Fatal("expected cookie manager pointer unchanged when nil manager provided")
	}
}

func TestNewVerifyPoWHandlerWithDepsNilDependencies(t *testing.T) {
	h := NewVerifyPoWHandlerWithDeps(nil, nil, nil)
	if h.config == nil {
		t.Fatal("expected default config when cfg is nil")
	}
	if h.store == nil {
		t.Fatal("expected store when store is nil")
	}
	t.Cleanup(h.store.Stop)
	if h.cookieMgr == nil {
		t.Fatal("expected cookie manager when cookie manager is nil")
	}

	defaults := defaultHandlerConfig()
	if h.config.Security.CookieName != defaults.Security.CookieName || h.config.Security.CookieTTLSeconds != defaults.Security.CookieTTLSeconds {
		t.Fatalf("expected default config values, got %#v", h.config.Security)
	}
}

func TestNewVerifyPoWHandlerDelegatesToWithDeps(t *testing.T) {
	h := NewVerifyPoWHandler(nil, nil, nil)
	if h == nil {
		t.Fatal("expected non-nil verify pow handler")
	}
	if h.config == nil || h.store == nil || h.cookieMgr == nil {
		t.Fatalf("expected initialized dependencies, got config=%v store=%v cookieMgr=%v", h.config != nil, h.store != nil, h.cookieMgr != nil)
	}
	t.Cleanup(h.store.Stop)
}

func TestVerifyPoWSetConfigReplacesConfig(t *testing.T) {
	h := NewVerifyPoWHandlerWithDeps(defaultHandlerConfig(), state.NewStore(), cookie.NewManager("0123456789abcdef0123456789abcdef", "auth_token", 15))
	t.Cleanup(h.store.Stop)

	updated := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "token_v2", CookieTTLSeconds: 33, NonceTTLSeconds: 55, PowMinDifficulty: 1, PowMaxDifficulty: 3, PowWindowSeconds: 42}}
	h.SetConfig(updated)

	if h.config != updated {
		t.Fatal("expected SetConfig to replace config pointer")
	}
}

func TestVerifyPoWSetCookieManagerReplacesManager(t *testing.T) {
	original := cookie.NewManager("0123456789abcdef0123456789abcdef", "auth_token", 15)
	h := NewVerifyPoWHandlerWithDeps(defaultHandlerConfig(), state.NewStore(), original)
	t.Cleanup(h.store.Stop)

	replacement := cookie.NewManager("0123456789abcdef0123456789abcdef", "auth_token_next", 25)
	h.SetCookieManager(replacement)

	if h.cookieMgr != replacement {
		t.Fatal("expected SetCookieManager to replace manager pointer")
	}
}

func TestVerifyPoWEmptyTargetURIFallsBackToPrefixTarget(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, state.NewStore(), cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))
	t.Cleanup(h.store.Stop)

	subnetKey := subnet.DefaultKey("192.168.1.69")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/prefix-fallback", subnetKey, time.Now().Unix(), []byte{0x31, 0x32, 0x33, 0x34})
	nonce := testutil.FindNonce(prefix, 1)
	if nonce == "" {
		t.Fatal("expected nonce for difficulty 1")
	}
	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":""}`, prefix, nonce)

	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.69")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "/prefix-fallback" {
		t.Fatalf("expected fallback redirect to prefix target, got %q", got)
	}
}

func TestVerifyPoWReturnsServiceUnavailableWhenCookieIssueFails(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, state.NewStore(), cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))
	t.Cleanup(h.store.Stop)

	h.cookieIssueFn = func(subnetKey, uaDigest, path string) (string, string, error) {
		return "", "", errors.New("forced issue failure")
	}

	subnetKey := subnet.DefaultKey("192.168.1.70")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/cookie-issue-failure", subnetKey, time.Now().Unix(), []byte{0x41, 0x42, 0x43, 0x44})
	nonce := testutil.FindNonce(prefix, 1)
	if nonce == "" {
		t.Fatal("expected nonce for difficulty 1")
	}
	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/cookie-issue-failure"}`, prefix, nonce)

	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.70")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "internal server error") {
		t.Fatalf("expected internal server error body, got %q", rr.Body.String())
	}
}

func TestParseSubmissionFormBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader("prefix=p1&nonce=n1&target_uri=%2Fok"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	prefix, nonce, targetURI, ok := parseSubmission(req)
	if !ok {
		t.Fatal("expected parseSubmission to accept form body")
	}
	if prefix != "p1" || nonce != "n1" || targetURI != "/ok" {
		t.Fatalf("unexpected parse result: prefix=%q nonce=%q target_uri=%q", prefix, nonce, targetURI)
	}
}

func TestParseSubmissionJSONBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(`{"prefix":"p2","nonce":"n2","target_uri":"/json"}`))
	req.Header.Set("Content-Type", "application/json")

	prefix, nonce, targetURI, ok := parseSubmission(req)
	if !ok {
		t.Fatal("expected parseSubmission to accept json body")
	}
	if prefix != "p2" || nonce != "n2" || targetURI != "/json" {
		t.Fatalf("unexpected parse result: prefix=%q nonce=%q target_uri=%q", prefix, nonce, targetURI)
	}
}

func TestParseSubmissionInvalidJSONBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(`{"prefix":`))
	req.Header.Set("Content-Type", "application/json")

	_, _, _, ok := parseSubmission(req)
	if ok {
		t.Fatal("expected parseSubmission to reject invalid json")
	}
}

func TestParseSubmissionFallsBackToJSONWhenParseFormFails(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow?bad=%zz", strings.NewReader(`{"prefix":"pj","nonce":"nj","target_uri":"/json-fallback"}`))
	req.Header.Set("Content-Type", "application/json")

	prefix, nonce, targetURI, ok := parseSubmission(req)
	if !ok {
		t.Fatal("expected parseSubmission to fall back to JSON decode when ParseForm errors")
	}
	if prefix != "pj" || nonce != "nj" || targetURI != "/json-fallback" {
		t.Fatalf("unexpected parse result: prefix=%q nonce=%q target_uri=%q", prefix, nonce, targetURI)
	}
}

func TestParseSubmissionPartialJSONFieldsAllowsEmptyTargetURI(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(`{"prefix":"p3","nonce":"n3"}`))
	req.Header.Set("Content-Type", "application/json")

	prefix, nonce, targetURI, ok := parseSubmission(req)
	if !ok {
		t.Fatal("expected parseSubmission to accept body when prefix and nonce are present")
	}
	if prefix != "p3" || nonce != "n3" || targetURI != "" {
		t.Fatalf("unexpected parse result: prefix=%q nonce=%q target_uri=%q", prefix, nonce, targetURI)
	}
}

func TestParseSubmissionJSONAllowsEmptyTargetURI(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(`{"prefix":"p4","nonce":"n4","target_uri":""}`))
	req.Header.Set("Content-Type", "application/json")

	prefix, nonce, targetURI, ok := parseSubmission(req)
	if !ok {
		t.Fatal("expected parseSubmission to accept empty target_uri when prefix and nonce are present")
	}
	if prefix != "p4" || nonce != "n4" || targetURI != "" {
		t.Fatalf("unexpected parse result: prefix=%q nonce=%q target_uri=%q", prefix, nonce, targetURI)
	}
}

func TestVerifyPoWTargetURIRedirectsFromSubmission(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	h := NewVerifyPoWHandlerWithDeps(cfg, state.NewStore(), cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds))
	t.Cleanup(h.store.Stop)

	subnetKey := subnet.DefaultKey("192.168.1.68")
	prefix := pow.GeneratePrefix([]byte(cfg.Security.GlobalSecret), "/prefix-target", subnetKey, time.Now().Unix(), []byte{0x21, 0x22, 0x23, 0x24})
	nonce := testutil.FindNonce(prefix, 1)
	if nonce == "" {
		t.Fatal("expected nonce for difficulty 1")
	}
	body := fmt.Sprintf(`{"prefix":"%s","nonce":"%s","target_uri":"/submission-target"}`, prefix, nonce)

	req := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "192.168.1.68")
	req.Header.Set("X-UA", "Mozilla/5.0")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "/submission-target" {
		t.Fatalf("expected redirect to submission target, got %q", got)
	}
}

func findNonceForDifficulty(t *testing.T, prefix string, difficulty int) string {
	t.Helper()
	nonce := testutil.FindNonce(prefix, difficulty)
	if nonce != "" {
		return nonce
	}
	t.Fatalf("failed to find nonce for difficulty %d", difficulty)
	return ""
}

func injectInvalidNonceLockEntry(t *testing.T, nonceStore *state.NonceStore, key string) {
	t.Helper()
	if nonceStore == nil {
		t.Fatal("nonceStore must not be nil")
	}

	v := reflect.ValueOf(nonceStore).Elem().FieldByName("locks")
	locksPtr := (*sync.Map)(unsafe.Pointer(v.UnsafeAddr()))
	locksPtr.Store(key, "invalid-type")
}
