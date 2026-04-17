package testutil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/cookie"
	"github.com/mirror-guard/auth-backend/internal/handler"
	"github.com/mirror-guard/auth-backend/internal/pipeline"
	"github.com/mirror-guard/auth-backend/internal/policy"
	"github.com/mirror-guard/auth-backend/internal/subnet"
)

func TestWriteTempConfigAndPolicyArtifacts(t *testing.T) {
	externalPolicyPath := WriteTempPolicy(t, map[string]any{
		"rules": []map[string]any{
			{"name": "allow-all", "path_prefix": "/", "action": "allow"},
		},
	})

	set, err := policy.LoadExternal(externalPolicyPath)
	if err != nil {
		t.Fatalf("load external policy: %v", err)
	}
	if set == nil {
		t.Fatal("expected non-nil policy set")
	}

	cfg := NewTestConfig()
	cfg.Policy.ExternalListsPath = externalPolicyPath

	configPath := WriteTempConfig(t, cfg)
	loaded, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.Policy.ExternalListsPath != externalPolicyPath {
		t.Fatalf("expected policy path %q, got %q", externalPolicyPath, loaded.Policy.ExternalListsPath)
	}
}

func TestIntegrationFlowViaTestutilHelpers(t *testing.T) {
	cfg := NewTestConfig()
	store := NewTestStore(t)
	cookieMgr := cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds)
	authInline := handler.NewAuthInlineHandler(nil)
	p := pipeline.NewPipeline(nil, authInline, cfg, store, cookieMgr)
	t.Cleanup(p.Close)

	challengeHandler := handler.NewChallengeHandler(cfg, store)
	verifyHandler := handler.NewVerifyPoWHandler(cfg, store, cookieMgr)

	clientIP := "192.168.77.10"
	target := "/protected/integration.tar"
	ua := "Mozilla/5.0"

	if got := subnet.DefaultKey(clientIP); got == "" {
		t.Fatal("expected non-empty subnet key")
	}

	initialReq := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	initialReq.Header.Set("X-Real-IP", clientIP)
	initialReq.Header.Set("X-URL", target)
	initialReq.Header.Set("X-UA", ua)
	initialRR := httptest.NewRecorder()
	authInline.ServeHTTP(initialRR, initialReq)
	if initialRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected initial browser auth to challenge with 401, got %d", initialRR.Code)
	}

	challengeReq := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	challengeReq.Header.Set("X-Real-IP", clientIP)
	challengeReq.Header.Set("X-URL", target)
	challengeRR := httptest.NewRecorder()
	challengeHandler.ServeHTTP(challengeRR, challengeReq)
	if challengeRR.Code != http.StatusOK {
		t.Fatalf("expected challenge 200, got %d", challengeRR.Code)
	}

	var challengeResp struct {
		Prefix     string `json:"prefix"`
		Difficulty int    `json:"difficulty"`
	}
	if err := json.Unmarshal(challengeRR.Body.Bytes(), &challengeResp); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}
	if challengeResp.Prefix == "" || challengeResp.Difficulty <= 0 {
		t.Fatalf("invalid challenge payload: %+v", challengeResp)
	}

	nonce := FindNonce(challengeResp.Prefix, challengeResp.Difficulty)
	if nonce == "" {
		t.Fatal("expected nonce solution")
	}

	verifyBody := `{"prefix":"` + challengeResp.Prefix + `","nonce":"` + nonce + `","target_uri":"` + target + `"}`
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("X-Real-IP", clientIP)
	verifyReq.Header.Set("X-UA", ua)
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)
	if verifyRR.Code != http.StatusFound {
		t.Fatalf("expected verify_pow 302, got %d", verifyRR.Code)
	}

	var issued *http.Cookie
	for _, c := range verifyRR.Result().Cookies() {
		if c.Name == cookieMgr.CookieName() {
			issued = c
			break
		}
	}
	if issued == nil {
		t.Fatalf("expected issued cookie %q", cookieMgr.CookieName())
	}

	allowedReq := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	allowedReq.Header.Set("X-Real-IP", clientIP)
	allowedReq.Header.Set("X-URL", target)
	allowedReq.Header.Set("X-UA", ua)
	allowedReq.AddCookie(issued)
	allowedRR := httptest.NewRecorder()
	authInline.ServeHTTP(allowedRR, allowedReq)
	if allowedRR.Code != http.StatusOK {
		t.Fatalf("expected cookie-authenticated request 200, got %d", allowedRR.Code)
	}
}

func TestFindNonceReturnsEmptyWhenNoSolutionWithinSearchLimit(t *testing.T) {
	nonce := FindNonce("irrelevant-prefix", 65)
	if nonce != "" {
		t.Fatalf("expected empty nonce when no solution is possible, got %q", nonce)
	}
}

func TestWriteTempConfigFailsOnUnmarshalableValue(t *testing.T) {
	ran := false
	ok := testing.RunTests(
		func(_, testName string) (bool, error) { return testName == "marshal_config_failure", nil },
		[]testing.InternalTest{{
			Name: "marshal_config_failure",
			F: func(it *testing.T) {
				ran = true
				WriteTempConfig(it, map[string]any{"bad": make(chan int)})
			},
		}},
	)
	if !ran {
		t.Fatal("expected internal marshal failure test to run")
	}
	if ok {
		t.Fatal("expected internal marshal failure test to fail")
	}
}

func TestWriteTempPolicyFailsOnUnmarshalableValue(t *testing.T) {
	ran := false
	ok := testing.RunTests(
		func(_, testName string) (bool, error) { return testName == "marshal_policy_failure", nil },
		[]testing.InternalTest{{
			Name: "marshal_policy_failure",
			F: func(it *testing.T) {
				ran = true
				WriteTempPolicy(it, map[string]any{"bad": make(chan int)})
			},
		}},
	)
	if !ran {
		t.Fatal("expected internal marshal failure test to run")
	}
	if ok {
		t.Fatal("expected internal marshal failure test to fail")
	}
}
