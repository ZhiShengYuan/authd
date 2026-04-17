package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/policy"
	"github.com/mirror-guard/auth-backend/internal/testutil"
)

func TestHealthzReturnsOK(t *testing.T) {
	mux, _, _ := buildMux(&policy.Set{})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestDefaultMuxConfig(t *testing.T) {
	cfg := defaultMuxConfig()
	if cfg.Security.CookieName != "auth_token" {
		t.Fatalf("unexpected cookie name: %q", cfg.Security.CookieName)
	}
	if cfg.Security.CookieTTLSeconds != 15 {
		t.Fatalf("unexpected cookie ttl: %d", cfg.Security.CookieTTLSeconds)
	}
	if cfg.Security.NonceTTLSeconds != 30 {
		t.Fatalf("unexpected nonce ttl: %d", cfg.Security.NonceTTLSeconds)
	}
	if cfg.Security.PowMinDifficulty != 4 {
		t.Fatalf("unexpected min difficulty: %d", cfg.Security.PowMinDifficulty)
	}
	if cfg.Security.PowMaxDifficulty != 10 {
		t.Fatalf("unexpected max difficulty: %d", cfg.Security.PowMaxDifficulty)
	}
	if cfg.Security.PowWindowSeconds != 60 {
		t.Fatalf("unexpected pow window: %d", cfg.Security.PowWindowSeconds)
	}
}

func TestBuildMuxUsesProvidedAndDefaultConfig(t *testing.T) {
	t.Run("default config path", func(t *testing.T) {
		mux, p, auth := buildMux(&policy.Set{}, nil)
		if mux == nil || p == nil || auth == nil {
			t.Fatalf("buildMux returned nil component")
		}
		defer p.Close()

		ts := httptest.NewServer(mux)
		defer ts.Close()

		resp, err := http.Get(ts.URL + pathHealthz)
		if err != nil {
			t.Fatalf("GET /healthz failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected /healthz 200, got %d", resp.StatusCode)
		}

		metricsResp, err := http.Get(ts.URL + pathMetrics)
		if err != nil {
			t.Fatalf("GET /metrics failed: %v", err)
		}
		defer metricsResp.Body.Close()
		if metricsResp.StatusCode != http.StatusOK {
			t.Fatalf("expected /metrics 200, got %d", metricsResp.StatusCode)
		}
	})

	t.Run("explicit config path", func(t *testing.T) {
		cfg := testutil.NewTestConfig()
		cfg.Security.CookieName = "custom_cookie"
		mux, p, auth := buildMux(&policy.Set{}, cfg)
		if mux == nil || p == nil || auth == nil {
			t.Fatalf("buildMux returned nil component")
		}
		defer p.Close()

		ts := httptest.NewServer(mux)
		defer ts.Close()

		resp, err := http.Get(ts.URL + pathChallenge)
		if err != nil {
			t.Fatalf("GET /api/challenge failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected /api/challenge 400 for missing X-URL, got %d", resp.StatusCode)
		}
	})
}

func TestSecurityConfigChanged(t *testing.T) {
	base := testutil.NewTestConfig()

	tests := []struct {
		name string
		old  *config.Config
		new  *config.Config
		want bool
	}{
		{name: "nil old", old: nil, new: base, want: false},
		{name: "nil new", old: base, new: nil, want: false},
		{name: "same", old: cloneConfig(base), new: cloneConfig(base), want: false},
		{
			name: "different secret",
			old:  cloneConfig(base),
			new: func() *config.Config {
				c := cloneConfig(base)
				c.Security.GlobalSecret = "fedcba9876543210fedcba9876543210"
				return c
			}(),
			want: true,
		},
		{
			name: "different cookie name",
			old:  cloneConfig(base),
			new: func() *config.Config {
				c := cloneConfig(base)
				c.Security.CookieName = "new_cookie"
				return c
			}(),
			want: true,
		},
		{
			name: "different cookie ttl",
			old:  cloneConfig(base),
			new: func() *config.Config {
				c := cloneConfig(base)
				c.Security.CookieTTLSeconds = 99
				return c
			}(),
			want: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := securityConfigChanged(tc.old, tc.new)
			if got != tc.want {
				t.Fatalf("securityConfigChanged()=%v want %v", got, tc.want)
			}
		})
	}
}

func TestCreateListener(t *testing.T) {
	t.Run("tcp listener", func(t *testing.T) {
		ln, err := createListener("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("createListener tcp: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		if ln.Addr() == nil {
			t.Fatalf("expected non-nil tcp addr")
		}
	})

	t.Run("unix listener", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "gateway.sock")
		ln, err := createListener("unix", sock)
		if err != nil {
			t.Fatalf("createListener unix: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		st, err := os.Stat(sock)
		if err != nil {
			t.Fatalf("stat unix socket: %v", err)
		}
		if st.Mode()&os.ModeSocket == 0 {
			t.Fatalf("expected unix socket mode, got %v", st.Mode())
		}
	})

	t.Run("unix chmod failure", func(t *testing.T) {
		addr := "@auth-gateway-chmod-fail-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		ln, err := createListener("unix", addr)
		if err == nil {
			_ = ln.Close()
			t.Fatalf("expected chmod failure for abstract unix socket")
		}
		if !strings.Contains(err.Error(), "chmod unix socket") {
			t.Fatalf("expected chmod unix socket error, got %v", err)
		}
	})

	t.Run("unix listen failure", func(t *testing.T) {
		badPath := filepath.Join(t.TempDir(), "missing", "gateway.sock")
		ln, err := createListener("unix", badPath)
		if err == nil {
			_ = ln.Close()
			t.Fatalf("expected unix listen failure")
		}
		if !strings.Contains(err.Error(), "listen unix") {
			t.Fatalf("expected listen unix error prefix, got %v", err)
		}
	})
}

func TestRunErrorPathsBeforeServeLoop(t *testing.T) {
	t.Run("load config failure", func(t *testing.T) {
		err := run(filepath.Join(t.TempDir(), "missing-config.json"))
		if err == nil {
			t.Fatalf("expected error")
		}
		if !strings.Contains(err.Error(), "load config") {
			t.Fatalf("expected load config prefix, got %v", err)
		}
	})

	t.Run("policy load failure", func(t *testing.T) {
		tmp := t.TempDir()
		policyPath := filepath.Join(tmp, "bad-policy.json")
		if writeErr := os.WriteFile(policyPath, []byte("{"), 0o600); writeErr != nil {
			t.Fatalf("write bad policy: %v", writeErr)
		}

		cfg := testutil.NewTestConfig()
		cfg.Server.ListenNetwork = "unix"
		cfg.Server.ListenAddress = filepath.Join(tmp, "unused.sock")
		cfg.Policy.ExternalListsPath = policyPath
		configPath := filepath.Join(tmp, "config.json")
		writeConfigFile(t, configPath, cfg)

		err := run(configPath)
		if err == nil {
			t.Fatalf("expected error")
		}
		if !strings.Contains(err.Error(), "load external policy") {
			t.Fatalf("expected policy load prefix, got %v", err)
		}
	})

	t.Run("listener creation failure", func(t *testing.T) {
		tmp := t.TempDir()
		policyPath := filepath.Join(tmp, "policy.json")
		writePolicyFile(t, policyPath, map[string]any{})

		cfg := testutil.NewTestConfig()
		cfg.Server.ListenNetwork = "invalid-network"
		cfg.Server.ListenAddress = "ignored"
		cfg.Policy.ExternalListsPath = policyPath
		configPath := filepath.Join(tmp, "config.json")
		writeConfigFile(t, configPath, cfg)

		err := run(configPath)
		if err == nil {
			t.Fatalf("expected error")
		}
		if !strings.Contains(err.Error(), "unknown network") && !strings.Contains(err.Error(), "unknown protocol") {
			t.Fatalf("expected network error, got %v", err)
		}
	})
}

func TestRunSignalHandlingAndReload(t *testing.T) {
	t.Run("SIGTERM shutdown and unix socket cleanup", func(t *testing.T) {
		configPath, sockPath := writeRunnableConfigAndPolicy(t)

		errCh := make(chan error, 1)
		go func() { errCh <- run(configPath) }()

		waitForUnixHTTPReady(t, sockPath, errCh)
		sendSignal(t, syscall.SIGTERM)

		err := waitForRunResult(t, errCh)
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
		if _, statErr := os.Stat(sockPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("expected unix socket removed, stat err=%v", statErr)
		}
	})

	t.Run("SIGINT shutdown", func(t *testing.T) {
		configPath, sockPath := writeRunnableConfigAndPolicy(t)

		errCh := make(chan error, 1)
		go func() { errCh <- run(configPath) }()

		waitForUnixHTTPReady(t, sockPath, errCh)
		sendSignal(t, syscall.SIGINT)

		err := waitForRunResult(t, errCh)
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})

	t.Run("SIGHUP config reload failure continues", func(t *testing.T) {
		tmp := t.TempDir()
		sockPath := filepath.Join(tmp, "gateway.sock")
		policyPath := filepath.Join(tmp, "policy.json")
		writePolicyFile(t, policyPath, map[string]any{})

		cfg := testutil.NewTestConfig()
		cfg.Server.ListenNetwork = "unix"
		cfg.Server.ListenAddress = sockPath
		cfg.Policy.ExternalListsPath = policyPath
		configPath := filepath.Join(tmp, "config.json")
		writeConfigFile(t, configPath, cfg)

		errCh := make(chan error, 1)
		go func() { errCh <- run(configPath) }()

		waitForUnixHTTPReady(t, sockPath, errCh)
		if writeErr := os.WriteFile(configPath, []byte("{"), 0o600); writeErr != nil {
			t.Fatalf("write invalid config: %v", writeErr)
		}

		sendSignal(t, syscall.SIGHUP)
		mustGetHealthz(t, sockPath)

		sendSignal(t, syscall.SIGTERM)
		err := waitForRunResult(t, errCh)
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})

	t.Run("SIGHUP policy reload failure keeps old policy/config", func(t *testing.T) {
		tmp := t.TempDir()
		sockPath := filepath.Join(tmp, "gateway.sock")
		goodPolicyPath := filepath.Join(tmp, "policy-good.json")
		badPolicyPath := filepath.Join(tmp, "policy-bad.json")
		writePolicyFile(t, goodPolicyPath, map[string]any{})
		if writeErr := os.WriteFile(badPolicyPath, []byte("{"), 0o600); writeErr != nil {
			t.Fatalf("write bad policy: %v", writeErr)
		}

		cfg := testutil.NewTestConfig()
		cfg.Server.ListenNetwork = "unix"
		cfg.Server.ListenAddress = sockPath
		cfg.Policy.ExternalListsPath = goodPolicyPath
		cfg.Security.CookieName = "auth_token"
		configPath := filepath.Join(tmp, "config.json")
		writeConfigFile(t, configPath, cfg)

		errCh := make(chan error, 1)
		go func() { errCh <- run(configPath) }()

		waitForUnixHTTPReady(t, sockPath, errCh)

		reloaded := cloneConfig(cfg)
		reloaded.Policy.ExternalListsPath = badPolicyPath
		reloaded.Security.CookieName = "new_cookie_name"
		writeConfigFile(t, configPath, reloaded)

		sendSignal(t, syscall.SIGHUP)
		assertPoWFlowCookieName(t, sockPath, "auth_token")

		sendSignal(t, syscall.SIGTERM)
		err := waitForRunResult(t, errCh)
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})

	t.Run("SIGHUP reload success updates security settings", func(t *testing.T) {
		tmp := t.TempDir()
		sockPath := filepath.Join(tmp, "gateway.sock")
		policyPath := filepath.Join(tmp, "policy.json")
		writePolicyFile(t, policyPath, map[string]any{})

		cfg := testutil.NewTestConfig()
		cfg.Server.ListenNetwork = "unix"
		cfg.Server.ListenAddress = sockPath
		cfg.Policy.ExternalListsPath = policyPath
		cfg.Security.CookieName = "auth_token"
		cfg.Security.GlobalSecret = "0123456789abcdef0123456789abcdef"
		configPath := filepath.Join(tmp, "config.json")
		writeConfigFile(t, configPath, cfg)

		errCh := make(chan error, 1)
		go func() { errCh <- run(configPath) }()

		waitForUnixHTTPReady(t, sockPath, errCh)
		assertPoWFlowCookieName(t, sockPath, "auth_token")

		reloaded := cloneConfig(cfg)
		reloaded.Security.CookieName = "reloaded_auth"
		reloaded.Security.CookieTTLSeconds = 45
		reloaded.Security.GlobalSecret = "fedcba9876543210fedcba9876543210"
		writeConfigFile(t, configPath, reloaded)

		sendSignal(t, syscall.SIGHUP)
		waitForPoWFlowCookieName(t, sockPath, "reloaded_auth")

		sendSignal(t, syscall.SIGTERM)
		err := waitForRunResult(t, errCh)
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})
}

func TestRunServeErrorPath(t *testing.T) {
	origServeFn := serveFn
	serveErrInjected := errors.New("injected serve failure")
	serveFn = func(_ *http.Server, _ net.Listener) error {
		return serveErrInjected
	}
	t.Cleanup(func() { serveFn = origServeFn })

	configPath, sockPath := writeRunnableConfigAndPolicy(t)
	errCh := make(chan error, 1)
	go func() { errCh <- run(configPath) }()

	err := waitForRunResultWithTimeout(t, errCh, 5*time.Second)
	if err == nil {
		t.Fatalf("expected serve error")
	}
	if !strings.Contains(err.Error(), "serve:") {
		t.Fatalf("expected serve prefix, got %v", err)
	}
	if !errors.Is(err, serveErrInjected) {
		t.Fatalf("expected wrapped serve error %v, got %v", serveErrInjected, err)
	}
	if _, statErr := os.Stat(sockPath); statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unexpected unix socket stat error: %v", statErr)
	}
}

func TestRunIntegrationExercisesPolicyAndHandlerBranches(t *testing.T) {
	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "gateway.sock")
	policyPath := filepath.Join(tmp, "policy.json")
	writePolicyFile(t, policyPath, map[string]any{
		"whitelist_cidrs": []string{"203.0.113.0/24"},
		"blacklist_cidrs": []string{"198.51.100.0/24"},
		"rules": []map[string]any{
			{"name": "redir", "path_prefix": "/jump", "action": "redirect", "redirect_url": "https://redir.example/"},
			{"name": "deny", "path_prefix": "/deny", "action": "reject"},
		},
		"quota_defaults": map[string]any{"default_limit": 100, "default_window": "60s"},
	})

	cfg := testutil.NewTestConfig()
	cfg.Server.ListenNetwork = "unix"
	cfg.Server.ListenAddress = sockPath
	cfg.Policy.ExternalListsPath = policyPath
	configPath := filepath.Join(tmp, "config.json")
	writeConfigFile(t, configPath, cfg)

	errCh := make(chan error, 1)
	go func() { errCh <- run(configPath) }()

	waitForUnixHTTPReady(t, sockPath, errCh)
	client := unixHTTPClient(sockPath)
	defer client.CloseIdleConnections()

	makeReq := func(method, path, ip, target, ua string, body *strings.Reader) *http.Response {
		t.Helper()
		var reqBody *strings.Reader
		if body == nil {
			reqBody = strings.NewReader("")
		} else {
			reqBody = body
		}
		req, err := http.NewRequest(method, "http://unix"+path, reqBody)
		if err != nil {
			t.Fatalf("new request %s %s: %v", method, path, err)
		}
		if ip != "" {
			req.Header.Set("X-Real-IP", ip)
		}
		if target != "" {
			req.Header.Set("X-URL", target)
		}
		if ua != "" {
			req.Header.Set("X-UA", ua)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %s %s: %v", method, path, err)
		}
		return resp
	}

	resp := makeReq(http.MethodGet, pathAuthInline, "192.0.2.10", "/protected/file.iso", "Mozilla/5.0", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected browser protected request 401, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Auth-Action"); got != "challenge" {
		t.Fatalf("expected challenge header, got %q", got)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.2.11", "/repo/cli.iso", "curl/8.0", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected non-browser protected request 200, got %d", resp.StatusCode)
	}
	if len(resp.Cookies()) == 0 {
		t.Fatal("expected non-browser direct-sign to issue cookie")
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "198.51.100.7", "/any/path", "Mozilla/5.0", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected blacklisted IP 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "203.0.113.9", "/any/path", "Mozilla/5.0", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected whitelisted IP 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.2.12", "/jump/path", "curl/8.0", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect rule 302, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://redir.example/" {
		t.Fatalf("expected redirect location, got %q", got)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.2.13", "/deny/path", "curl/8.0", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected deny rule 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodPost, pathChallenge, "192.0.2.14", "/any", "Mozilla/5.0", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected challenge method guard 405, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathChallenge, "bad-ip", "/any", "Mozilla/5.0", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected challenge invalid IP 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathChallenge, "192.0.2.15", "", "Mozilla/5.0", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected challenge missing target 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathVerifyPoW, "192.0.2.16", "/any", "Mozilla/5.0", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected verify_pow method guard 405, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	malformed := strings.NewReader(`{"prefix":`)
	resp = makeReq(http.MethodPost, pathVerifyPoW, "192.0.2.16", "/any", "Mozilla/5.0", malformed)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected malformed verify body 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	invalid := strings.NewReader(`{"prefix":"invalid","nonce":"0","target_uri":"/any"}`)
	resp = makeReq(http.MethodPost, pathVerifyPoW, "192.0.2.16", "/any", "Mozilla/5.0", invalid)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected invalid prefix verify body 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathChallenge, "192.0.2.16", "/protected/asset.bin", "Mozilla/5.0", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected challenge success 200, got %d", resp.StatusCode)
	}
	var challengePayload struct {
		Prefix     string `json:"prefix"`
		Difficulty int    `json:"difficulty"`
		Target     string `json:"target"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&challengePayload); err != nil {
		_ = resp.Body.Close()
		t.Fatalf("decode challenge payload: %v", err)
	}
	_ = resp.Body.Close()
	if challengePayload.Prefix == "" || challengePayload.Difficulty <= 0 {
		t.Fatalf("invalid challenge payload: %+v", challengePayload)
	}
	if challengePayload.Target != "/protected/asset.bin" {
		t.Fatalf("expected challenge target /protected/asset.bin, got %q", challengePayload.Target)
	}

	nonce := testutil.FindNonce(challengePayload.Prefix, challengePayload.Difficulty)
	if nonce == "" {
		t.Fatal("expected to find valid nonce")
	}

	subnetMismatchBody := strings.NewReader(`{"prefix":"` + challengePayload.Prefix + `","nonce":"` + nonce + `","target_uri":"/protected/asset.bin"}`)
	resp = makeReq(http.MethodPost, pathVerifyPoW, "192.0.3.17", "/protected/asset.bin", "Mozilla/5.0", subnetMismatchBody)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected subnet mismatch verify 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	verifyReq, err := http.NewRequest(http.MethodPost, "http://unix"+pathVerifyPoW, strings.NewReader(`{"prefix":"`+challengePayload.Prefix+`","nonce":"`+nonce+`","target_uri":"/protected/asset.bin"}`))
	if err != nil {
		t.Fatalf("new verify request: %v", err)
	}
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("X-Real-IP", "192.0.2.16")
	verifyReq.Header.Set("X-UA", "Mozilla/5.0")
	verifyResp, err := client.Do(verifyReq)
	if err != nil {
		t.Fatalf("verify request failed: %v", err)
	}
	if verifyResp.StatusCode != http.StatusFound {
		_ = verifyResp.Body.Close()
		t.Fatalf("expected verify success 302, got %d", verifyResp.StatusCode)
	}
	if got := verifyResp.Header.Get("Location"); got != "/protected/asset.bin" {
		_ = verifyResp.Body.Close()
		t.Fatalf("expected verify location /protected/asset.bin, got %q", got)
	}
	if len(verifyResp.Cookies()) == 0 {
		_ = verifyResp.Body.Close()
		t.Fatal("expected verify success to issue auth cookie")
	}
	issuedCookie := verifyResp.Cookies()[0]
	_ = verifyResp.Body.Close()

	replayBody := strings.NewReader(`{"prefix":"` + challengePayload.Prefix + `","nonce":"` + nonce + `","target_uri":"/protected/asset.bin"}`)
	resp = makeReq(http.MethodPost, pathVerifyPoW, "192.0.2.16", "/protected/asset.bin", "Mozilla/5.0", replayBody)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected verify replay 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	authWithCookieReq, err := http.NewRequest(http.MethodGet, "http://unix"+pathAuthInline, nil)
	if err != nil {
		t.Fatalf("new auth_inline request with cookie: %v", err)
	}
	authWithCookieReq.Header.Set("X-Real-IP", "192.0.2.16")
	authWithCookieReq.Header.Set("X-URL", "/protected/asset.bin")
	authWithCookieReq.Header.Set("X-UA", "Mozilla/5.0")
	authWithCookieReq.AddCookie(issuedCookie)
	authWithCookieResp, err := client.Do(authWithCookieReq)
	if err != nil {
		t.Fatalf("auth_inline with cookie request failed: %v", err)
	}
	if authWithCookieResp.StatusCode != http.StatusOK {
		_ = authWithCookieResp.Body.Close()
		t.Fatalf("expected auth_inline allow with cookie 200, got %d", authWithCookieResp.StatusCode)
	}
	_ = authWithCookieResp.Body.Close()

	invalidBase64Req, err := http.NewRequest(http.MethodGet, "http://unix"+pathAuthInline, nil)
	if err != nil {
		t.Fatalf("new auth_inline invalid-base64 request: %v", err)
	}
	invalidBase64Req.Header.Set("X-Real-IP", "192.0.2.16")
	invalidBase64Req.Header.Set("X-URL", "/protected/asset.bin")
	invalidBase64Req.Header.Set("X-UA", "Mozilla/5.0")
	invalidBase64Req.AddCookie(&http.Cookie{Name: issuedCookie.Name, Value: "###not-base64###"})
	invalidBase64Resp, err := client.Do(invalidBase64Req)
	if err != nil {
		t.Fatalf("auth_inline invalid-base64 request failed: %v", err)
	}
	if invalidBase64Resp.StatusCode != http.StatusUnauthorized {
		_ = invalidBase64Resp.Body.Close()
		t.Fatalf("expected invalid-base64 cookie challenge 401, got %d", invalidBase64Resp.StatusCode)
	}
	_ = invalidBase64Resp.Body.Close()

	decodedIssued, err := base64.RawURLEncoding.DecodeString(issuedCookie.Value)
	if err != nil {
		t.Fatalf("decode issued cookie: %v", err)
	}
	if len(decodedIssued) == 0 {
		t.Fatal("expected non-empty issued cookie payload")
	}
	tamperedRaw := append([]byte(nil), decodedIssued...)
	tamperedRaw[len(tamperedRaw)-1] ^= 0x01
	tamperedToken := base64.RawURLEncoding.EncodeToString(tamperedRaw)

	tamperedReq, err := http.NewRequest(http.MethodGet, "http://unix"+pathAuthInline, nil)
	if err != nil {
		t.Fatalf("new auth_inline tampered-cookie request: %v", err)
	}
	tamperedReq.Header.Set("X-Real-IP", "192.0.2.16")
	tamperedReq.Header.Set("X-URL", "/protected/asset.bin")
	tamperedReq.Header.Set("X-UA", "Mozilla/5.0")
	tamperedReq.AddCookie(&http.Cookie{Name: issuedCookie.Name, Value: tamperedToken})
	tamperedResp, err := client.Do(tamperedReq)
	if err != nil {
		t.Fatalf("auth_inline tampered-cookie request failed: %v", err)
	}
	if tamperedResp.StatusCode != http.StatusUnauthorized {
		_ = tamperedResp.Body.Close()
		t.Fatalf("expected tampered cookie challenge 401, got %d", tamperedResp.StatusCode)
	}
	_ = tamperedResp.Body.Close()

	sendSignal(t, syscall.SIGTERM)
	err = waitForRunResult(t, errCh)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
}

func TestRunIntegrationPipelineCoverageBoostViaCrossPackageFlows(t *testing.T) {
	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "gateway.sock")
	policyPath := filepath.Join(tmp, "policy.json")
	writePolicyFile(t, policyPath, map[string]any{
		"whitelist_cidrs": []string{"203.0.113.0/24"},
		"blacklist_cidrs": []string{"198.51.100.0/24"},
		"rules": []map[string]any{
			{"name": "redir", "path_prefix": "/go", "action": "redirect", "redirect_url": "https://redir.example/"},
			{"name": "deny", "path_prefix": "/deny", "action": "reject"},
			{"name": "allow-path", "path_prefix": "/allow", "action": "allow"},
			{"name": "allow-host", "path_prefix": "repo.example.com/host-allow", "action": "allow"},
			{"name": "direct", "path_prefix": "/direct", "action": "direct_sign"},
		},
		"quota_defaults": map[string]any{"default_limit": 2, "default_window": "60s"},
	})

	cfg := testutil.NewTestConfig()
	cfg.Server.ListenNetwork = "unix"
	cfg.Server.ListenAddress = sockPath
	cfg.Policy.ExternalListsPath = policyPath
	configPath := filepath.Join(tmp, "config.json")
	writeConfigFile(t, configPath, cfg)

	errCh := make(chan error, 1)
	go func() { errCh <- run(configPath) }()

	waitForUnixHTTPReady(t, sockPath, errCh)
	client := unixHTTPClient(sockPath)
	defer client.CloseIdleConnections()

	makeReq := func(method, path, ip, target, ua, xForwardedHost, xHost string, body *strings.Reader, cookies ...*http.Cookie) *http.Response {
		t.Helper()
		var reqBody *strings.Reader
		if body == nil {
			reqBody = strings.NewReader("")
		} else {
			reqBody = body
		}
		req, err := http.NewRequest(method, "http://unix"+path, reqBody)
		if err != nil {
			t.Fatalf("new request %s %s: %v", method, path, err)
		}
		if ip != "" {
			req.Header.Set("X-Real-IP", ip)
		}
		if target != "" {
			req.Header.Set("X-URL", target)
		}
		if ua != "" {
			req.Header.Set("X-UA", ua)
		}
		if xForwardedHost != "" {
			req.Header.Set("X-Forwarded-Host", xForwardedHost)
		}
		if xHost != "" {
			req.Header.Set("X-Host", xHost)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %s %s: %v", method, path, err)
		}
		return resp
	}

	resp := makeReq(http.MethodGet, pathAuthInline, "198.51.100.7", "/allow/pkg", "Mozilla/5.0", "", "", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected blacklisted IP 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "203.0.113.9", "/allow/pkg", "Mozilla/5.0", "", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected whitelisted IP 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.2.10", "/deny/path", "curl/8.0", "", "", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected reject rule 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.2.10", "/go/path?x=1", "curl/8.0", "", "", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect rule 302, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://redir.example/" {
		t.Fatalf("expected redirect location, got %q", got)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.5.10", "/host-allow/pkg?dl=1", "curl/8.0", "repo.example.com", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected host+path allow via X-Forwarded-Host 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.5.11", "https://mirror.example/host-allow/another?dl=1", "curl/8.0", "", "repo.example.com", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected host+path allow via X-Host and normalized absolute URL 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	cookiePath := "/cookie-flow/file.iso"

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.9.10", cookiePath, "Mozilla/5.0", "", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected browser without cookie challenge 401, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Auth-Action"); got != "challenge" {
		t.Fatalf("expected challenge action header, got %q", got)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.9.10", cookiePath, "curl/8.0", "", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected direct_sign 200, got %d", resp.StatusCode)
	}
	var issued *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cfg.Security.CookieName {
			issued = c
			break
		}
	}
	if issued == nil {
		t.Fatalf("expected direct_sign to issue cookie %q", cfg.Security.CookieName)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.9.10", cookiePath+"?sig=1", "curl/8.0", "", "", nil, issued)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected valid cookie allow 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.9.10", cookiePath, "Mozilla/5.0", "", "", nil, issued)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected replayed cookie challenge 401, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Auth-Action"); got != "challenge" {
		t.Fatalf("expected replay fallback challenge action, got %q", got)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.7.10", "/allow/limited", "curl/8.0", "", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected first allow under quota 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.7.11", "/allow/limited", "curl/8.0", "", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected second allow under quota 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.7.12", "/allow/limited", "curl/8.0", "", "", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected over-quota allow path to redirect 302, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://redir.example/" {
		t.Fatalf("expected over-quota allow redirect location, got %q", got)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.8.10", "/direct/limited", "curl/8.0", "", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected first direct_sign under quota 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.8.11", "/direct/limited", "curl/8.0", "", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected second direct_sign under quota 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "192.0.8.12", "/direct/limited", "curl/8.0", "", "", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected over-quota direct_sign path to redirect 302, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://redir.example/" {
		t.Fatalf("expected over-quota direct_sign redirect location, got %q", got)
	}
	_ = resp.Body.Close()

	resp = makeReq(http.MethodGet, pathAuthInline, "bad-ip", "/direct/limited", "curl/8.0", "", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected invalid IP to fall back to challenge 401, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Auth-Action"); got != "challenge" {
		t.Fatalf("expected missing subnet key fallback challenge header, got %q", got)
	}
	_ = resp.Body.Close()

	sendSignal(t, syscall.SIGTERM)
	err := waitForRunResult(t, errCh)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
}

func TestRunShutdownErrorPath(t *testing.T) {
	origShutdownFn := shutdownFn
	shutdownErrInjected := errors.New("injected shutdown failure")
	shutdownFn = func(_ *http.Server, _ context.Context) error {
		return shutdownErrInjected
	}
	t.Cleanup(func() { shutdownFn = origShutdownFn })

	configPath, _, baseURL := writeRunnableTCPConfigAndPolicy(t)
	errCh := make(chan error, 1)
	go func() { errCh <- run(configPath) }()

	waitForTCPHTTPReady(t, baseURL, errCh)

	sendSignal(t, syscall.SIGTERM)
	err := waitForRunResultWithTimeout(t, errCh, 5*time.Second)
	if err == nil {
		t.Fatalf("expected shutdown error")
	}
	if !strings.Contains(err.Error(), "shutdown server:") {
		t.Fatalf("expected shutdown server prefix, got %v", err)
	}
	if !errors.Is(err, shutdownErrInjected) {
		t.Fatalf("expected wrapped shutdown error %v, got %v", shutdownErrInjected, err)
	}
}

func TestMainSubprocess(t *testing.T) {
	t.Run("main exits on error", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist.json")
		cmd := exec.Command(os.Args[0], "-test.run", "TestMainProcess", "--", missing)
		cmd.Env = append(os.Environ(), "AUTH_GATEWAY_MAIN_MODE=error")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected non-zero exit, output=%s", string(out))
		}

		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected ExitError, got %T (%v)", err, err)
		}
		if exitErr.ExitCode() != 1 {
			t.Fatalf("expected exit code 1, got %d, output=%s", exitErr.ExitCode(), string(out))
		}
	})

	t.Run("main exits zero on graceful shutdown", func(t *testing.T) {
		configPath, _ := writeRunnableConfigAndPolicy(t)
		cmd := exec.Command(os.Args[0], "-test.run", "TestMainProcess", "--", configPath)
		cmd.Env = append(os.Environ(), "AUTH_GATEWAY_MAIN_MODE=success")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected zero exit, err=%v output=%s", err, string(out))
		}
	})
}

func TestMainProcess(t *testing.T) {
	mode := os.Getenv("AUTH_GATEWAY_MAIN_MODE")
	if mode == "" {
		return
	}

	configPath, err := configPathFromTestArgs(os.Args)
	if err != nil {
		t.Fatalf("config path from args: %v (args=%v)", err, os.Args)
	}

	if mode == "success" {
		listenAddr, readErr := readListenAddress(configPath)
		if readErr != nil {
			t.Fatalf("read listen address: %v", readErr)
		}
		go func(socketPath string) {
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, statErr := os.Stat(socketPath); statErr == nil {
					_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		}(listenAddr)
	}

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"auth-gateway", "-config", configPath}

	main()
}

func writeRunnableConfigAndPolicy(t *testing.T) (configPath, sockPath string) {
	t.Helper()
	tmp := t.TempDir()
	sockPath = filepath.Join(tmp, "gateway.sock")
	policyPath := filepath.Join(tmp, "policy.json")
	writePolicyFile(t, policyPath, map[string]any{})

	cfg := testutil.NewTestConfig()
	cfg.Server.ListenNetwork = "unix"
	cfg.Server.ListenAddress = sockPath
	cfg.Policy.ExternalListsPath = policyPath
	configPath = filepath.Join(tmp, "config.json")
	writeConfigFile(t, configPath, cfg)
	return configPath, sockPath
}

func writeRunnableTCPConfigAndPolicy(t *testing.T) (configPath, listenAddr, baseURL string) {
	t.Helper()
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.json")
	writePolicyFile(t, policyPath, map[string]any{})

	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	listenAddr = reserved.Addr().String()
	if closeErr := reserved.Close(); closeErr != nil {
		t.Fatalf("release reserved port: %v", closeErr)
	}

	cfg := testutil.NewTestConfig()
	cfg.Server.ListenNetwork = "tcp"
	cfg.Server.ListenAddress = listenAddr
	cfg.Policy.ExternalListsPath = policyPath
	configPath = filepath.Join(tmp, "config.json")
	writeConfigFile(t, configPath, cfg)
	baseURL = "http://" + listenAddr
	return configPath, listenAddr, baseURL
}

func cloneConfig(cfg *config.Config) *config.Config {
	if cfg == nil {
		return nil
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	var out config.Config
	if err := json.Unmarshal(data, &out); err != nil {
		panic(err)
	}
	return &out
}

func writeConfigFile(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func writePolicyFile(t *testing.T, path string, p any) {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
}

func waitForRunResult(t *testing.T, errCh <-chan error) error {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case err := <-errCh:
		return err
	case <-timer.C:
		t.Fatalf("timed out waiting for run to return")
		return nil
	}
}

func waitForRunResultWithTimeout(t *testing.T, errCh <-chan error, timeout time.Duration) error {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-errCh:
		return err
	case <-timer.C:
		t.Fatalf("timed out waiting for run to return")
		return nil
	}
}

func sendSignal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatalf("send signal %v: %v", sig, err)
	}
}

func unixHTTPClient(socketPath string) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_ = network
			_ = address
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			_ = req
			_ = via
			return http.ErrUseLastResponse
		},
	}
}

func waitForUnixHTTPReady(t *testing.T, socketPath string, errCh <-chan error) {
	t.Helper()
	client := unixHTTPClient(socketPath)
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("run exited before becoming ready: %v", err)
		default:
		}

		resp, err := client.Get("http://unix" + pathHealthz)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
	}

	t.Fatalf("server did not become ready for socket %s", socketPath)
}

func waitForTCPHTTPReady(t *testing.T, baseURL string, errCh <-chan error) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{}}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("run exited before becoming ready: %v", err)
		default:
		}

		resp, err := client.Get(baseURL + pathHealthz)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
	}

	t.Fatalf("server did not become ready for %s", baseURL)
}

func mustGetHealthz(t *testing.T, socketPath string) {
	t.Helper()
	client := unixHTTPClient(socketPath)
	defer client.CloseIdleConnections()

	resp, err := client.Get("http://unix" + pathHealthz)
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected /healthz 200, got %d", resp.StatusCode)
	}
}

func assertPoWFlowCookieName(t *testing.T, socketPath, expectedCookie string) {
	t.Helper()
	if err := tryPoWFlowCookieName(socketPath, expectedCookie); err != nil {
		t.Fatalf("pow flow assertion failed: %v", err)
	}
}

func waitForPoWFlowCookieName(t *testing.T, socketPath, expectedCookie string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := tryPoWFlowCookieName(socketPath, expectedCookie); err == nil {
			return
		}
	}
	t.Fatalf("timed out waiting for cookie %q after reload", expectedCookie)
}

func tryPoWFlowCookieName(socketPath, expectedCookie string) error {
	client := unixHTTPClient(socketPath)
	defer client.CloseIdleConnections()

	challengeReq, err := http.NewRequest(http.MethodGet, "http://unix"+pathChallenge, nil)
	if err != nil {
		return fmt.Errorf("new challenge request: %w", err)
	}
	challengeReq.Header.Set("X-URL", "/download.tar.gz")
	challengeReq.Header.Set("X-Real-IP", "127.0.0.1")

	challengeResp, err := client.Do(challengeReq)
	if err != nil {
		return fmt.Errorf("challenge request failed: %w", err)
	}
	defer challengeResp.Body.Close()
	if challengeResp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected challenge 200, got %d", challengeResp.StatusCode)
	}

	var payload struct {
		Prefix     string `json:"prefix"`
		Difficulty int    `json:"difficulty"`
		Target     string `json:"target"`
	}
	if err := json.NewDecoder(challengeResp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("decode challenge response: %w", err)
	}
	if payload.Prefix == "" || payload.Difficulty <= 0 || payload.Target == "" {
		return fmt.Errorf("invalid challenge payload: %+v", payload)
	}

	nonce := testutil.FindNonce(payload.Prefix, payload.Difficulty)
	if nonce == "" {
		return errors.New("failed to find valid nonce")
	}

	form := url.Values{}
	form.Set("prefix", payload.Prefix)
	form.Set("nonce", nonce)
	form.Set("target_uri", payload.Target)

	verifyReq, err := http.NewRequest(http.MethodPost, "http://unix"+pathVerifyPoW, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return fmt.Errorf("new verify request: %w", err)
	}
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	verifyReq.Header.Set("X-Real-IP", "127.0.0.1")
	verifyReq.Header.Set("X-UA", "gateway-test-agent")

	verifyResp, err := client.Do(verifyReq)
	if err != nil {
		return fmt.Errorf("verify request failed: %w", err)
	}
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusFound {
		return fmt.Errorf("expected verify 302, got %d", verifyResp.StatusCode)
	}

	found := false
	for _, c := range verifyResp.Cookies() {
		if c.Name == expectedCookie {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("expected cookie %q, got %+v", expectedCookie, verifyResp.Cookies())
	}

	return nil
}

func closeUnixListenerFD(socketPath string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		inode, err := inodeForUnixSocketPath(socketPath)
		if err != nil {
			continue
		}
		fds, fdErr := fdsForInode(inode)
		if fdErr != nil {
			continue
		}
		closed := 0
		for _, fd := range fds {
			if fd <= 2 {
				continue
			}
			_ = syscall.Shutdown(fd, syscall.SHUT_RDWR)
			if closeErr := syscall.Close(fd); closeErr != nil {
				continue
			}
			closed++
		}
		if closed > 0 {
			return nil
		}
	}
	return fmt.Errorf("listener fd for %s not found", socketPath)
}

func closeTCPListenerFD(listenAddr string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		inode, err := inodeForTCPAddr(listenAddr)
		if err != nil {
			continue
		}
		fds, fdErr := fdsForInode(inode)
		if fdErr != nil {
			continue
		}
		closed := 0
		for _, fd := range fds {
			if fd <= 2 {
				continue
			}
			if !fdAcceptsConnections(fd) {
				continue
			}
			_ = syscall.Shutdown(fd, syscall.SHUT_RDWR)
			if closeErr := syscall.Close(fd); closeErr != nil {
				continue
			}
			closed++
		}
		if closed > 0 {
			return nil
		}
	}
	return fmt.Errorf("listener fd for %s not found", listenAddr)
}

func pokeUnixListener(socketPath string) {
	conn, err := net.Dial("unix", socketPath)
	if err == nil {
		_ = conn.Close()
	}
}

func pokeTCPListener(baseURL string) {
	resp, err := http.Get(baseURL + pathHealthz)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func waitForTCPListenerToStopAccepting(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(baseURL + pathHealthz); err == nil {
			_ = resp.Body.Close()
			continue
		}
		return
	}
	t.Fatalf("tcp listener still accepting requests at %s", baseURL)
}

func waitForUnixListenerToStopAccepting(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		client := unixHTTPClient(socketPath)
		resp, err := client.Get("http://unix" + pathHealthz)
		client.CloseIdleConnections()
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}
	t.Fatalf("unix listener still accepting requests at %s", socketPath)
}

func inodeForUnixSocketPath(socketPath string) (string, error) {
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return "", err
	}
	needle := " " + socketPath
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasSuffix(line, needle) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		if fields[5] != "01" {
			continue
		}
		return fields[6], nil
	}
	return "", fmt.Errorf("inode not found for %s", socketPath)
}

func inodeForTCPAddr(listenAddr string) (string, error) {
	addrPort, err := netip.ParseAddrPort(listenAddr)
	if err != nil {
		return "", err
	}
	if !addrPort.Addr().Is4() {
		return "", fmt.Errorf("only IPv4 listen addr supported, got %s", listenAddr)
	}

	ipHex := hexIPv4LittleEndian(addrPort.Addr())
	portHex := strings.ToUpper(fmt.Sprintf("%04x", addrPort.Port()))
	wantLocal := ipHex + ":" + portHex

	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] == "sl" {
			continue
		}
		if fields[1] != wantLocal {
			continue
		}
		if fields[3] != "0A" {
			continue
		}
		return fields[9], nil
	}

	return "", fmt.Errorf("tcp inode not found for %s", listenAddr)
}

func hexIPv4LittleEndian(addr netip.Addr) string {
	a := addr.As4()
	return strings.ToUpper(fmt.Sprintf("%02x%02x%02x%02x", a[3], a[2], a[1], a[0]))
}

func fdsForInode(inode string) ([]int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, err
	}
	want := "socket:[" + inode + "]"
	var fds []int
	for _, entry := range entries {
		name := entry.Name()
		fd, convErr := strconv.Atoi(name)
		if convErr != nil {
			continue
		}
		target, linkErr := os.Readlink(filepath.Join("/proc/self/fd", name))
		if linkErr != nil {
			continue
		}
		if target == want {
			fds = append(fds, fd)
		}
	}
	if len(fds) == 0 {
		return nil, fmt.Errorf("fd not found for inode %s", inode)
	}
	return fds, nil
}

func fdAcceptsConnections(fd int) bool {
	ok, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
	if err != nil {
		return false
	}
	return ok == 1
}

func readListenAddress(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", err
	}
	if cfg.Server.ListenAddress == "" {
		return "", fmt.Errorf("listen address is empty")
	}
	return cfg.Server.ListenAddress, nil
}

func configPathFromTestArgs(args []string) (string, error) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing config path after --")
			}
			return args[i+1], nil
		}
	}
	if len(args) == 0 {
		return "", fmt.Errorf("no args provided")
	}
	return args[len(args)-1], nil
}
