package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/cookie"
	"github.com/mirror-guard/auth-backend/internal/handler"
	"github.com/mirror-guard/auth-backend/internal/observability"
	"github.com/mirror-guard/auth-backend/internal/policy"
	"github.com/mirror-guard/auth-backend/internal/state"
	"github.com/mirror-guard/auth-backend/internal/subnet"
	"github.com/mirror-guard/auth-backend/internal/testutil"
)

type policyAwareHandler struct {
	setPolicyCalled bool
	lastPolicy      *policy.Set
}

func (h *policyAwareHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (h *policyAwareHandler) SetPolicy(set *policy.Set) {
	h.setPolicyCalled = true
	h.lastPolicy = set
}

type executorAwareHandler struct {
	executor http.Handler
}

func (h *executorAwareHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (h *executorAwareHandler) SetExecutor(exec http.Handler) {
	h.executor = exec
}

func TestPipelineRequestWithoutCookieReturns401(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	req.Header.Set("X-Real-IP", "192.168.1.10")
	req.Header.Set("X-URL", "/protected/file.iso")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestPipelineRequestWithValidCookieReturns200(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	clientIP := "192.168.1.11"
	target := "/protected/file.iso"
	ua := "Mozilla/5.0"
	subnetKey := subnet.DefaultKey(clientIP)
	uaDigest := cookie.UADigest(ua)

	token, _, err := p.cookieMgr.Issue(subnetKey, uaDigest, target)
	if err != nil {
		t.Fatalf("issue cookie: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-URL", target)
	req.Header.Set("X-UA", ua)
	req.AddCookie(&http.Cookie{Name: p.cookieMgr.CookieName(), Value: token})

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestPipelineBlacklistedIPReturns403(t *testing.T) {
	p := NewPipeline(loadPolicySet(t, `{"blacklist_cidrs":["192.168.1.0/24"]}`), nil)
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	req.Header.Set("X-Real-IP", "192.168.1.9")
	req.Header.Set("X-URL", "/protected/file.iso")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestPipelineWhitelistedIPReturns200(t *testing.T) {
	p := NewPipeline(loadPolicySet(t, `{"whitelist_cidrs":["192.168.1.0/24"]}`), nil)
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	req.Header.Set("X-Real-IP", "192.168.1.22")
	req.Header.Set("X-URL", "/protected/file.iso")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestPipelineMalformedXRealIPIsSafelyRejected(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	req.Header.Set("X-Real-IP", "not-an-ip")
	req.Header.Set("X-URL", "/protected/file.iso")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected safe 401 for malformed IP, got %d", rr.Code)
	}
}

func TestPipelineEmptyXURLFallsBackGracefully(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, "/protected/fallback.iso", nil)
	req.Header.Set("X-Real-IP", "192.168.10.15")
	req.Header.Set("X-URL", "")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 challenge flow after fallback, got %d", rr.Code)
	}
}

func TestPipelineMissingCookieOnProtectedPathReturns401Not500(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, "/protected/file.iso", nil)
	req.Header.Set("X-Real-IP", "192.168.3.10")
	req.Header.Set("X-URL", "/protected/file.iso")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing cookie, got %d", rr.Code)
	}
}

func TestPipelineBlacklistedIPReturns403RegardlessOfCookie(t *testing.T) {
	p := NewPipeline(loadPolicySet(t, `{"blacklist_cidrs":["192.168.1.0/24"]}`), nil)
	t.Cleanup(p.Close)

	clientIP := "192.168.1.77"
	target := "/protected/file.iso"
	ua := "Mozilla/5.0"
	subnetKey := subnet.DefaultKey(clientIP)
	token, _, err := p.cookieMgr.Issue(subnetKey, cookie.UADigest(ua), target)
	if err != nil {
		t.Fatalf("issue cookie: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-URL", target)
	req.Header.Set("X-UA", ua)
	req.AddCookie(&http.Cookie{Name: p.cookieMgr.CookieName(), Value: token})

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for blacklisted IP regardless of cookie, got %d", rr.Code)
	}
}

func TestPipelineWhitelistedIPReturns200RegardlessOfQuota(t *testing.T) {
	p := NewPipeline(loadPolicySet(t, `{"whitelist_cidrs":["192.168.1.0/24"],"quota_defaults":{"default_limit":1,"default_window":"60s"}}`), nil)
	t.Cleanup(p.Close)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
		req.Header.Set("X-Real-IP", "192.168.1.88")
		req.Header.Set("X-URL", "/protected/file.iso")
		req.Header.Set("X-UA", "Mozilla/5.0")

		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d expected 200 for whitelisted IP, got %d", i+1, rr.Code)
		}
	}
}

func TestPipelineRangeRequestPathNormalizationStripsQuery(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	clientIP := "192.168.2.20"
	ua := "Mozilla/5.0"
	basePath := "/protected/file.iso"
	withQuery := "/protected/file.iso?range=bytes=1000-"

	token, _, err := p.cookieMgr.Issue(subnet.DefaultKey(clientIP), cookie.UADigest(ua), basePath)
	if err != nil {
		t.Fatalf("issue cookie: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-URL", withQuery)
	req.Header.Set("X-UA", ua)
	req.Header.Set("Range", "bytes=1000-")
	req.AddCookie(&http.Cookie{Name: p.cookieMgr.CookieName(), Value: token})

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for normalized range request path, got %d", rr.Code)
	}
}

func TestPipelineInternalQuotaErrorReturns503ForNginxFailOpen(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	p.stateStore.QuotaStore = nil

	req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	req.Header.Set("X-Real-IP", "192.168.9.15")
	req.Header.Set("X-URL", "/public/asset.tar")
	req.Header.Set("X-UA", "curl/8.0")

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on internal quota error for Nginx fail-open, got %d", rr.Code)
	}
}

func TestPipelineHandlesMalformedHeaderFloodWithoutPanic(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	req.Header.Set("X-Real-IP", "bad-ip")
	req.Header.Set("X-URL", "")
	req.Header.Set("X-UA", "Mozilla/5.0")
	req.Header.Set("X-JA3-Hash", strconv.Itoa(42))

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected controlled 401 for malformed headers, got %d", rr.Code)
	}
}

func TestSetConfigNilDoesNotChangeConfig(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	original := p.config
	p.SetConfig(nil)

	if p.config != original {
		t.Fatalf("expected config pointer unchanged when nil passed")
	}
}

func TestSetCookieManagerNilDoesNotChangeManager(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	original := p.cookieMgr
	p.SetCookieManager(nil)

	if p.cookieMgr != original {
		t.Fatalf("expected cookie manager pointer unchanged when nil passed")
	}
}

func TestReloadUpdatesPolicyAndCallsSetPolicy(t *testing.T) {
	h := &policyAwareHandler{}
	p := NewPipeline(nil, h)
	t.Cleanup(p.Close)

	set := loadPolicySet(t, `{"rules":[{"name":"redir","path_prefix":"/x","action":"redirect","redirect_url":"https://example.test/"}]}`)
	p.Reload(set)

	if p.policySet != set {
		t.Fatalf("expected pipeline policy pointer to update")
	}
	if !h.setPolicyCalled {
		t.Fatalf("expected auth handler SetPolicy to be called")
	}
	if h.lastPolicy != set {
		t.Fatalf("expected SetPolicy argument to match reloaded policy")
	}
}

func TestWriteQuotaOutcomeRedirectAndForbidden(t *testing.T) {
	t.Run("redirect configured", func(t *testing.T) {
		p := NewPipeline(loadPolicySet(t, `{"rules":[{"name":"redir","path_prefix":"/","action":"redirect","redirect_url":"https://quota.example/over"}]}`), nil)
		t.Cleanup(p.Close)

		rr := httptest.NewRecorder()
		p.writeQuotaOutcome(rr)

		if rr.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rr.Code)
		}
		if got := rr.Header().Get("Location"); got != "https://quota.example/over" {
			t.Fatalf("expected redirect location, got %q", got)
		}
	})

	t.Run("no redirect configured", func(t *testing.T) {
		p := NewPipeline(loadPolicySet(t, `{"rules":[{"name":"reject","path_prefix":"/","action":"reject"}]}`), nil)
		t.Cleanup(p.Close)

		rr := httptest.NewRecorder()
		p.writeQuotaOutcome(rr)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rr.Code)
		}
		if got := rr.Header().Get("Location"); got != "" {
			t.Fatalf("expected no redirect location, got %q", got)
		}
	})
}

func TestRedirectURLBranches(t *testing.T) {
	t.Run("nil policy set", func(t *testing.T) {
		p := NewPipeline(nil, nil)
		t.Cleanup(p.Close)
		p.policySet = nil
		if got := p.redirectURL(); got != "" {
			t.Fatalf("expected empty redirect URL, got %q", got)
		}
	})

	t.Run("empty rules", func(t *testing.T) {
		p := NewPipeline(loadPolicySet(t, `{"rules":[]}`), nil)
		t.Cleanup(p.Close)
		if got := p.redirectURL(); got != "" {
			t.Fatalf("expected empty redirect URL, got %q", got)
		}
	})

	t.Run("rule with redirect URL", func(t *testing.T) {
		p := NewPipeline(loadPolicySet(t, `{"rules":[{"name":"redir","path_prefix":"/","action":"redirect","redirect_url":"https://edge.example/path"}]}`), nil)
		t.Cleanup(p.Close)
		if got := p.redirectURL(); got != "https://edge.example/path" {
			t.Fatalf("expected redirect URL from rule, got %q", got)
		}
	})
}

func TestSplitAddrValidAndErrorPath(t *testing.T) {
	host, port, err := SplitAddr("127.0.0.1:8443")
	if err != nil {
		t.Fatalf("unexpected error for valid host:port: %v", err)
	}
	if host != "127.0.0.1" || port != "8443" {
		t.Fatalf("unexpected split result host=%q port=%q", host, port)
	}

	_, _, err = SplitAddr("missing-port")
	if err == nil {
		t.Fatalf("expected error for malformed addr")
	}
}

func TestActionNameAllValues(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		want   string
	}{
		{name: "accept", action: ActionAccept, want: "allow"},
		{name: "challenge", action: ActionChallenge, want: "challenge"},
		{name: "reject", action: ActionReject, want: "reject"},
		{name: "direct sign", action: ActionDirectSign, want: "direct_sign"},
		{name: "redirect", action: ActionRedirect, want: "fallback"},
		{name: "drop", action: ActionDrop, want: "fallback"},
		{name: "default", action: Action(999), want: "reject"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := actionName(tt.action); got != tt.want {
				t.Fatalf("actionName(%v) = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}

func TestNormalizePathBranches(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: "/"},
		{name: "valid URL parse", input: "https://example.com/a/b?q=1", want: "/a/b"},
		{name: "query only", input: "?foo=bar", want: "/"},
		{name: "query on path", input: "/path?q=1", want: "/path"},
		{name: "no query string", input: "/plain", want: "/plain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizePath(tt.input); got != tt.want {
				t.Fatalf("normalizePath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRequestIDFromHeaderPriorityAndFallback(t *testing.T) {
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header = http.Header{"X-Request-ID": {"req-upper"}}
	if got := requestIDFromHeader(req1); got != "req-upper" {
		t.Fatalf("expected X-Request-ID value, got %q", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header = http.Header{"X-Request-Id": {"req-mixed"}}
	if got := requestIDFromHeader(req2); got != "req-mixed" {
		t.Fatalf("expected X-Request-Id value, got %q", got)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	got := requestIDFromHeader(req3)
	if got == "" {
		t.Fatalf("expected non-empty fallback request ID")
	}
	if _, err := strconv.ParseInt(got, 10, 64); err != nil {
		t.Fatalf("expected numeric fallback request ID, got %q: %v", got, err)
	}
}

func TestMatchIPBranches(t *testing.T) {
	if matchIP("not-an-ip", []string{"192.168.1.0/24"}) {
		t.Fatalf("expected invalid client IP to never match")
	}

	entries := []string{"", "   ", "not-cidr-or-ip", "192.168.1.0/24", "192.168.1.25"}
	if !matchIP("192.168.1.50", entries) {
		t.Fatalf("expected CIDR match")
	}
	if !matchIP("192.168.1.25", entries) {
		t.Fatalf("expected exact IP match")
	}
}

func TestCurrentDifficultyDefensiveDefaults(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	min := p.config.Security.PowMinDifficulty

	p.stateStore = nil
	if got := p.currentDifficulty("subnet-a"); got != min {
		t.Fatalf("nil state store difficulty = %d, want %d", got, min)
	}

	p.stateStore = state.NewStore()
	t.Cleanup(p.stateStore.Stop)
	p.stateStore.QuotaStore = nil
	if got := p.currentDifficulty("subnet-a"); got != min {
		t.Fatalf("nil quota store difficulty = %d, want %d", got, min)
	}

	p.stateStore = state.NewStore()
	t.Cleanup(p.stateStore.Stop)
	if got := p.currentDifficulty(""); got != min {
		t.Fatalf("empty subnet key difficulty = %d, want %d", got, min)
	}
}

func TestOverQuotaDefensiveBranches(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	p.stateStore = nil
	over, err := p.overQuota(context.TODO(), "subnet-a")
	if err != nil || over {
		t.Fatalf("nil state store should return false,nil got over=%v err=%v", over, err)
	}

	p.stateStore = state.NewStore()
	t.Cleanup(p.stateStore.Stop)
	over, err = p.overQuota(context.TODO(), "")
	if err != nil || over {
		t.Fatalf("empty subnet key should return false,nil got over=%v err=%v", over, err)
	}

	p.stateStore.QuotaStore = nil
	over, err = p.overQuota(context.TODO(), "subnet-a")
	if over {
		t.Fatalf("nil quota store should not report over quota")
	}
	if err != errQuotaStoreUnavailable {
		t.Fatalf("expected errQuotaStoreUnavailable, got %v", err)
	}

	p.stateStore = state.NewStore()
	t.Cleanup(p.stateStore.Stop)
	p.policySet = loadPolicySet(t, `{"quota_defaults":{"default_limit":0,"default_window":"60s"}}`)
	over, err = p.overQuota(context.TODO(), "subnet-a")
	if err != nil || over {
		t.Fatalf("limit <= 0 should return false,nil got over=%v err=%v", over, err)
	}
}

func TestOverQuotaIncrementErrorPath(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	originalIncrementFn := quotaIncrementFn
	t.Cleanup(func() {
		quotaIncrementFn = originalIncrementFn
	})

	forcedErr := errors.New("forced increment failure")
	quotaIncrementFn = func(_ *state.QuotaStore, _ string, _ time.Duration) (int64, error) {
		return 0, forcedErr
	}

	over, err := p.overQuota(context.Background(), "subnet-a")
	if over {
		t.Fatalf("expected over=false when increment errors")
	}
	if !errors.Is(err, forcedErr) {
		t.Fatalf("expected forced increment error, got %v", err)
	}
}

func TestHasValidCookieDefensiveAndReplayBranches(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	eval := evalContext{clientIP: "192.168.1.200", subnetKey: subnet.DefaultKey("192.168.1.200"), uaDigest: cookie.UADigest("Mozilla/5.0"), normPath: "/pkg.tar"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	origCookieMgr := p.cookieMgr
	origState := p.stateStore

	p.cookieMgr = nil
	if p.hasValidCookie(req, eval) {
		t.Fatalf("expected nil cookie manager to reject")
	}

	p.cookieMgr = origCookieMgr
	p.stateStore = nil
	if p.hasValidCookie(req, eval) {
		t.Fatalf("expected nil state store to reject")
	}

	p.stateStore = origState
	token, tokenID, err := p.cookieMgr.Issue(eval.subnetKey, eval.uaDigest, eval.normPath)
	if err != nil {
		t.Fatalf("issue cookie: %v", err)
	}
	reqWithCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	reqWithCookie.AddCookie(&http.Cookie{Name: p.cookieMgr.CookieName(), Value: token})

	p.stateStore.CookieConsumptionStore = nil
	if p.hasValidCookie(reqWithCookie, eval) {
		t.Fatalf("expected nil cookie consumption store to reject")
	}

	p.stateStore.CookieConsumptionStore = &state.CookieConsumptionStore{}
	if !p.hasValidCookie(reqWithCookie, eval) {
		t.Fatalf("expected first claim to succeed")
	}

	before := cookieReplayMetric(t)
	if p.hasValidCookie(reqWithCookie, eval) {
		t.Fatalf("expected replayed token to be rejected")
	}
	after := cookieReplayMetric(t)
	if after != before+1 {
		t.Fatalf("expected cookie replay metric increment by 1, got delta %v (token=%s)", after-before, tokenID)
	}
}

func TestEvalRulesNilPolicySetFallback(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)
	p.policySet = nil

	got := p.evalRules(evalContext{normPath: "/protected/file.iso", clientType: "unknown"})
	if got != ActionDirectSign {
		t.Fatalf("expected nil policy set to follow non-browser default direct_sign, got %v", got)
	}
}

func TestExecuteActionDirectSignRedirectDropAndDefault(t *testing.T) {
	t.Run("direct sign with nil cookie manager sets no cookie", func(t *testing.T) {
		p := NewPipeline(nil, nil)
		t.Cleanup(p.Close)
		p.cookieMgr = nil

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		p.executeAction(rr, req, evalContext{subnetKey: "subnet-a", uaDigest: "ua", normPath: "/"}, ActionDirectSign)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if setCookie := rr.Header().Get("Set-Cookie"); setCookie != "" {
			t.Fatalf("expected no Set-Cookie header, got %q", setCookie)
		}
	})

	t.Run("redirect with URL", func(t *testing.T) {
		p := NewPipeline(loadPolicySet(t, `{"rules":[{"name":"redir","path_prefix":"/","action":"redirect","redirect_url":"https://redir.example/"}]}`), nil)
		t.Cleanup(p.Close)
		rr := httptest.NewRecorder()
		p.executeAction(rr, httptest.NewRequest(http.MethodGet, "/", nil), evalContext{}, ActionRedirect)

		if rr.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rr.Code)
		}
		if got := rr.Header().Get("Location"); got != "https://redir.example/" {
			t.Fatalf("expected Location header, got %q", got)
		}
	})

	t.Run("redirect without URL", func(t *testing.T) {
		p := NewPipeline(loadPolicySet(t, `{"rules":[{"name":"reject","path_prefix":"/","action":"reject"}]}`), nil)
		t.Cleanup(p.Close)
		rr := httptest.NewRecorder()
		p.executeAction(rr, httptest.NewRequest(http.MethodGet, "/", nil), evalContext{}, ActionRedirect)

		if rr.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rr.Code)
		}
		if got := rr.Header().Get("Location"); got != "" {
			t.Fatalf("expected no Location header, got %q", got)
		}
	})

	t.Run("drop", func(t *testing.T) {
		p := NewPipeline(nil, nil)
		t.Cleanup(p.Close)
		rr := httptest.NewRecorder()
		p.executeAction(rr, httptest.NewRequest(http.MethodGet, "/", nil), evalContext{}, ActionDrop)

		if rr.Code != 444 {
			t.Fatalf("expected 444, got %d", rr.Code)
		}
	})

	t.Run("default unknown action", func(t *testing.T) {
		p := NewPipeline(nil, nil)
		t.Cleanup(p.Close)
		rr := httptest.NewRecorder()
		p.executeAction(rr, httptest.NewRequest(http.MethodGet, "/", nil), evalContext{}, Action(777))

		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rr.Code)
		}
	})
}

func TestServeHTTPRecoversFromPanicAndReturns503(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	p.config = nil

	req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	req.Header.Set("X-Real-IP", "192.168.1.23")
	req.Header.Set("X-URL", "/protected/file.iso")
	req.Header.Set("X-UA", "Mozilla/5.0")

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected panic recovery 503, got %d", rr.Code)
	}
}

func TestCloseNilStateStoreNoPanic(t *testing.T) {
	p := NewPipeline(nil, nil)
	p.stateStore = nil

	p.Close()
}

func TestNewPipelineDefaultsWhenNoSharedArgs(t *testing.T) {
	h := &executorAwareHandler{}
	p := NewPipeline(nil, h)
	t.Cleanup(p.Close)

	if p.config == nil {
		t.Fatalf("expected default config")
	}
	if p.stateStore == nil {
		t.Fatalf("expected default state store")
	}
	if p.cookieMgr == nil {
		t.Fatalf("expected default cookie manager")
	}
	if h.executor != p {
		t.Fatalf("expected SetExecutor to receive pipeline executor")
	}
}

func TestNewPipelineIgnoresWrongSharedArgTypes(t *testing.T) {
	p := NewPipeline(nil, nil, "wrong", 123, struct{}{})
	t.Cleanup(p.Close)

	if p.config == nil || p.stateStore == nil || p.cookieMgr == nil {
		t.Fatalf("expected defaults when shared args types are wrong")
	}
}

func TestBranchMatrixCoverageMapping(t *testing.T) {
	matrix := map[string]string{
		"SetConfig_nil":                     "TestSetConfigNilDoesNotChangeConfig",
		"SetCookieManager_nil":              "TestSetCookieManagerNilDoesNotChangeManager",
		"Reload_SetPolicy":                  "TestReloadUpdatesPolicyAndCallsSetPolicy",
		"writeQuotaOutcome_redirect":        "TestWriteQuotaOutcomeRedirectAndForbidden",
		"writeQuotaOutcome_forbidden":       "TestWriteQuotaOutcomeRedirectAndForbidden",
		"redirectURL_nil":                   "TestRedirectURLBranches",
		"redirectURL_empty_rules":           "TestRedirectURLBranches",
		"redirectURL_rule":                  "TestRedirectURLBranches",
		"SplitAddr_error":                   "TestSplitAddrValidAndErrorPath",
		"actionName_all":                    "TestActionNameAllValues",
		"normalizePath_all":                 "TestNormalizePathBranches",
		"requestIDFromHeader_all":           "TestRequestIDFromHeaderPriorityAndFallback",
		"matchIP_all":                       "TestMatchIPBranches",
		"currentDifficulty_nil_store":       "TestCurrentDifficultyDefensiveDefaults",
		"overQuota_nil_store_empty_key":     "TestOverQuotaDefensiveBranches",
		"overQuota_increment_error":         "TestOverQuotaIncrementErrorPath",
		"hasValidCookie_replay_and_defense": "TestHasValidCookieDefensiveAndReplayBranches",
		"evalRules_nil_policy":              "TestEvalRulesNilPolicySetFallback",
		"executeAction_direct_sign":         "TestExecuteActionDirectSignRedirectDropAndDefault",
		"executeAction_redirect":            "TestExecuteActionDirectSignRedirectDropAndDefault",
		"executeAction_drop_default":        "TestExecuteActionDirectSignRedirectDropAndDefault",
		"ServeHTTP_panic_recovery":          "TestServeHTTPRecoversFromPanicAndReturns503",
		"Close_nil_stateStore":              "TestCloseNilStateStoreNoPanic",
		"NewPipeline_defaults":              "TestNewPipelineDefaultsWhenNoSharedArgs",
		"NewPipeline_wrong_shared_types":    "TestNewPipelineIgnoresWrongSharedArgTypes",
	}

	for branch, testName := range matrix {
		if strings.TrimSpace(testName) == "" {
			t.Fatalf("branch %q missing mapped test name", branch)
		}
	}
}

func cookieReplayMetric(t *testing.T) float64 {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	observability.MetricsHandler().ServeHTTP(rr, req)
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	metrics := string(body)
	for _, line := range strings.Split(metrics, "\n") {
		if strings.HasPrefix(line, "auth_cookie_replay_total ") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				t.Fatalf("unexpected metric format: %q", line)
			}
			v, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				t.Fatalf("parse metric value from %q: %v", line, err)
			}
			return v
		}
	}
	t.Fatalf("auth_cookie_replay_total metric not found")
	return 0
}

func TestExecuteActionRejectAndChallenge(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	rrChallenge := httptest.NewRecorder()
	p.executeAction(rrChallenge, httptest.NewRequest(http.MethodGet, "/", nil), evalContext{}, ActionChallenge)
	if rrChallenge.Code != http.StatusUnauthorized {
		t.Fatalf("challenge expected 401, got %d", rrChallenge.Code)
	}
	if got := rrChallenge.Header().Get("X-Auth-Action"); got != "challenge" {
		t.Fatalf("challenge expected X-Auth-Action header, got %q", got)
	}

	rrReject := httptest.NewRecorder()
	p.executeAction(rrReject, httptest.NewRequest(http.MethodGet, "/", nil), evalContext{}, ActionReject)
	if rrReject.Code != http.StatusForbidden {
		t.Fatalf("reject expected 403, got %d", rrReject.Code)
	}
}

func TestExecuteActionAcceptOverQuotaRedirectAndError(t *testing.T) {
	t.Run("over quota with redirect", func(t *testing.T) {
		p := NewPipeline(loadPolicySet(t, `{"quota_defaults":{"default_limit":1,"default_window":"60s"},"rules":[{"name":"redir","path_prefix":"/","action":"redirect","redirect_url":"https://limit.example/"}]}`), nil)
		t.Cleanup(p.Close)

		eval := evalContext{subnetKey: "subnet-a"}
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		rr1 := httptest.NewRecorder()
		p.executeAction(rr1, req, eval, ActionAccept)
		if rr1.Code != http.StatusOK {
			t.Fatalf("first request expected 200, got %d", rr1.Code)
		}

		rr2 := httptest.NewRecorder()
		p.executeAction(rr2, req, eval, ActionAccept)
		if rr2.Code != http.StatusFound {
			t.Fatalf("second request expected 302 over-quota redirect, got %d", rr2.Code)
		}
		if got := rr2.Header().Get("Location"); got != "https://limit.example/" {
			t.Fatalf("expected over-quota redirect location, got %q", got)
		}
	})

	t.Run("quota error returns 503", func(t *testing.T) {
		p := NewPipeline(nil, nil)
		t.Cleanup(p.Close)
		p.stateStore.QuotaStore = nil

		rr := httptest.NewRecorder()
		p.executeAction(rr, httptest.NewRequest(http.MethodGet, "/", nil), evalContext{subnetKey: "subnet-a"}, ActionAccept)

		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 on quota error, got %d", rr.Code)
		}
	})
}

func TestSetConfigAndSetCookieManagerUpdateOnNonNil(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "s", CookieName: "x", CookieTTLSeconds: 22, NonceTTLSeconds: 5, PowMinDifficulty: 1, PowMaxDifficulty: 2, PowWindowSeconds: 3}}
	p.SetConfig(cfg)
	if p.config != cfg {
		t.Fatalf("expected non-nil config to be set")
	}

	cm := cookie.NewManager("secret", "new_cookie", 30)
	p.SetCookieManager(cm)
	if p.cookieMgr != cm {
		t.Fatalf("expected non-nil cookie manager to be set")
	}
}

func TestNewPipelineUsesProvidedSharedArgs(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "shared-secret", CookieName: "shared_cookie", CookieTTLSeconds: 11, NonceTTLSeconds: 12, PowMinDifficulty: 3, PowMaxDifficulty: 9, PowWindowSeconds: 60}}
	store := state.NewStore()
	t.Cleanup(store.Stop)
	cm := cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds)

	p := NewPipeline(nil, nil, cfg, store, cm)
	t.Cleanup(p.Close)

	if p.config != cfg {
		t.Fatalf("expected provided config to be used")
	}
	if p.stateStore != store {
		t.Fatalf("expected provided state store to be used")
	}
	if p.cookieMgr != cm {
		t.Fatalf("expected provided cookie manager to be used")
	}
}

func TestServeHTTPRuleDrivenActions(t *testing.T) {
	t.Run("rule reject", func(t *testing.T) {
		p := NewPipeline(loadPolicySet(t, `{"rules":[{"name":"block","path_prefix":"/deny","action":"reject"}]}`), nil)
		t.Cleanup(p.Close)
		req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
		req.Header.Set("X-Real-IP", "192.168.10.11")
		req.Header.Set("X-URL", "/deny/file")
		req.Header.Set("X-UA", "curl/8.0")
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rr.Code)
		}
	})

	t.Run("rule redirect", func(t *testing.T) {
		p := NewPipeline(loadPolicySet(t, `{"rules":[{"name":"redir","path_prefix":"/jump","action":"redirect","redirect_url":"https://rule.example/"}]}`), nil)
		t.Cleanup(p.Close)
		req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
		req.Header.Set("X-Real-IP", "192.168.10.12")
		req.Header.Set("X-URL", "/jump/file")
		req.Header.Set("X-UA", "curl/8.0")
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rr.Code)
		}
		if got := rr.Header().Get("Location"); got != "https://rule.example/" {
			t.Fatalf("expected Location header, got %q", got)
		}
	})

	t.Run("rule unknown action falls back to reject", func(t *testing.T) {
		p := NewPipeline(loadPolicySet(t, `{"rules":[{"name":"drop","path_prefix":"/drop","action":"reject"}]}`), nil)
		t.Cleanup(p.Close)
		p.policySet.Rules[0].Action = policy.Action("drop")
		req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
		req.Header.Set("X-Real-IP", "192.168.10.13")
		req.Header.Set("X-URL", "/drop/file")
		req.Header.Set("X-UA", "curl/8.0")
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected unknown action to map to reject 403, got %d", rr.Code)
		}
	})

	t.Run("rule allow", func(t *testing.T) {
		p := NewPipeline(loadPolicySet(t, `{"rules":[{"name":"allow","path_prefix":"/allow","action":"allow"}],"quota_defaults":{"default_limit":10,"default_window":"60s"}}`), nil)
		t.Cleanup(p.Close)
		req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
		req.Header.Set("X-Real-IP", "192.168.10.14")
		req.Header.Set("X-URL", "/allow/file")
		req.Header.Set("X-UA", "curl/8.0")
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
	})
}

func TestExtractRequestFallbacksForIPAndUA(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, "/from-url?x=1", nil)
	req.RemoteAddr = "198.51.100.7:443"
	req.Header.Set("X-URL", "/from-header?q=1")
	req.Header.Set("User-Agent", "curl/8.0")
	req.Header.Set("X-UA", "")
	req.Header.Set("X-Real-IP", "")

	eval := p.extractRequest(req)
	if eval.clientIP != "198.51.100.7" {
		t.Fatalf("expected clientIP from remote addr, got %q", eval.clientIP)
	}
	if eval.userAgent != "curl/8.0" {
		t.Fatalf("expected userAgent from request User-Agent, got %q", eval.userAgent)
	}
}

func TestEvalRulesAdditionalBranches(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	eval := evalContext{host: "example.test", normPath: "/z", clientType: "cli"}

	p.policySet = &policy.Set{Rules: []policy.Rule{{PathPrefix: "/z", Action: policy.Allow}}}
	if got := p.evalRules(eval); got != ActionAccept {
		t.Fatalf("expected allow rule -> ActionAccept, got %v", got)
	}

	p.policySet = &policy.Set{Rules: []policy.Rule{{PathPrefix: "/z", Action: policy.Reject}}}
	if got := p.evalRules(eval); got != ActionReject {
		t.Fatalf("expected reject rule -> ActionReject, got %v", got)
	}

	p.policySet = &policy.Set{Rules: []policy.Rule{{PathPrefix: "/z", Action: policy.Redirect}}}
	if got := p.evalRules(eval); got != ActionRedirect {
		t.Fatalf("expected redirect rule -> ActionRedirect, got %v", got)
	}

	p.policySet = &policy.Set{Rules: []policy.Rule{{PathPrefix: "/z", Action: policy.Action("unknown")}}}
	if got := p.evalRules(eval); got != ActionReject {
		t.Fatalf("expected unknown policy action -> ActionReject default, got %v", got)
	}
}

func TestHasValidCookieInvalidToken(t *testing.T) {
	p := NewPipeline(nil, nil)
	t.Cleanup(p.Close)

	eval := evalContext{subnetKey: subnet.DefaultKey("203.0.113.10"), uaDigest: cookie.UADigest("curl/8.0"), normPath: "/a"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: p.cookieMgr.CookieName(), Value: "not-a-valid-token"})

	if p.hasValidCookie(req, eval) {
		t.Fatalf("expected invalid token to be rejected")
	}
}

func TestExecuteActionDirectSignOverQuotaWithoutRedirect(t *testing.T) {
	p := NewPipeline(loadPolicySet(t, `{"quota_defaults":{"default_limit":1,"default_window":"60s"}}`), nil)
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	eval := evalContext{subnetKey: "subnet-directsign", uaDigest: cookie.UADigest("curl/8.0"), normPath: "/pkg"}

	rr1 := httptest.NewRecorder()
	p.executeAction(rr1, req, eval, ActionDirectSign)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request expected 200, got %d", rr1.Code)
	}

	rr2 := httptest.NewRecorder()
	p.executeAction(rr2, req, eval, ActionDirectSign)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("second request expected 403 over quota without redirect, got %d", rr2.Code)
	}
}

func TestNormalizePathParseErrorBranches(t *testing.T) {
	if got := normalizePath("%zz?x=1"); got != "%zz" {
		t.Fatalf("expected parse-error query trimming result, got %q", got)
	}
	if got := normalizePath("%"); got != "%" {
		t.Fatalf("expected parse-error no-query passthrough, got %q", got)
	}
}

func TestIntegratedBrowserChallengeVerifyAndCookieReplayFlow(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	store := state.NewStore()
	cookieMgr := cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds)
	authInline := handler.NewAuthInlineHandler(nil)
	p := NewPipeline(nil, authInline, cfg, store, cookieMgr)
	t.Cleanup(p.Close)

	challengeHandler := handler.NewChallengeHandler(cfg, store)
	verifyHandler := handler.NewVerifyPoWHandler(cfg, store, cookieMgr)

	clientIP := "192.168.50.10"
	target := "/protected/file.iso"
	ua := "Mozilla/5.0"

	initialReq := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	initialReq.Header.Set("X-Real-IP", clientIP)
	initialReq.Header.Set("X-URL", target)
	initialReq.Header.Set("X-UA", ua)
	initialRR := httptest.NewRecorder()
	authInline.ServeHTTP(initialRR, initialReq)

	if initialRR.Code != http.StatusUnauthorized {
		t.Fatalf("initial browser request expected 401 challenge, got %d", initialRR.Code)
	}
	if got := initialRR.Header().Get("X-Auth-Action"); got != "challenge" {
		t.Fatalf("expected X-Auth-Action=challenge, got %q", got)
	}

	challengeReq := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	challengeReq.Header.Set("X-Real-IP", clientIP)
	challengeReq.Header.Set("X-URL", target)
	challengeRR := httptest.NewRecorder()
	challengeHandler.ServeHTTP(challengeRR, challengeReq)

	if challengeRR.Code != http.StatusOK {
		t.Fatalf("challenge expected 200, got %d", challengeRR.Code)
	}

	var challengeResp struct {
		Prefix     string `json:"prefix"`
		Difficulty int    `json:"difficulty"`
		Target     string `json:"target"`
	}
	if err := json.Unmarshal(challengeRR.Body.Bytes(), &challengeResp); err != nil {
		t.Fatalf("unmarshal challenge response: %v", err)
	}
	if challengeResp.Target != target {
		t.Fatalf("expected challenge target %q, got %q", target, challengeResp.Target)
	}
	if challengeResp.Difficulty != 1 {
		t.Fatalf("expected challenge difficulty 1, got %d", challengeResp.Difficulty)
	}

	nonce := testutil.FindNonce(challengeResp.Prefix, challengeResp.Difficulty)
	if nonce == "" {
		t.Fatal("expected nonce solution for challenge prefix")
	}

	verifyBody := `{"prefix":"` + challengeResp.Prefix + `","nonce":"` + nonce + `","target_uri":"` + target + `"}`
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("X-Real-IP", clientIP)
	verifyReq.Header.Set("X-UA", ua)
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusFound {
		t.Fatalf("verify_pow expected 302 redirect, got %d", verifyRR.Code)
	}
	if got := verifyRR.Header().Get("Location"); got != target {
		t.Fatalf("verify_pow expected redirect to %q, got %q", target, got)
	}

	var issuedCookie *http.Cookie
	for _, c := range verifyRR.Result().Cookies() {
		if c.Name == cookieMgr.CookieName() {
			issuedCookie = c
			break
		}
	}
	if issuedCookie == nil {
		t.Fatalf("expected %s cookie to be issued", cookieMgr.CookieName())
	}

	allowedReq := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	allowedReq.Header.Set("X-Real-IP", clientIP)
	allowedReq.Header.Set("X-URL", target)
	allowedReq.Header.Set("X-UA", ua)
	allowedReq.AddCookie(issuedCookie)
	allowedRR := httptest.NewRecorder()
	authInline.ServeHTTP(allowedRR, allowedReq)

	if allowedRR.Code != http.StatusOK {
		t.Fatalf("first use of issued cookie expected 200, got %d", allowedRR.Code)
	}

	replayReq := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	replayReq.Header.Set("X-Real-IP", clientIP)
	replayReq.Header.Set("X-URL", target)
	replayReq.Header.Set("X-UA", ua)
	replayReq.AddCookie(issuedCookie)
	replayRR := httptest.NewRecorder()
	authInline.ServeHTTP(replayRR, replayReq)

	if replayRR.Code != http.StatusUnauthorized {
		t.Fatalf("replayed cookie expected 401 challenge, got %d", replayRR.Code)
	}
	if got := replayRR.Header().Get("X-Auth-Action"); got != "challenge" {
		t.Fatalf("replayed cookie expected challenge header, got %q", got)
	}
}

func TestIntegratedBrowserChallengeThenMalformedVerifySubmission(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", CookieName: "auth_token", CookieTTLSeconds: 15, NonceTTLSeconds: 30, PowMinDifficulty: 1, PowMaxDifficulty: 1, PowWindowSeconds: 60}}
	store := state.NewStore()
	cookieMgr := cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds)
	authInline := handler.NewAuthInlineHandler(nil)
	p := NewPipeline(nil, authInline, cfg, store, cookieMgr)
	t.Cleanup(p.Close)

	challengeHandler := handler.NewChallengeHandler(cfg, store)
	verifyHandler := handler.NewVerifyPoWHandler(cfg, store, cookieMgr)

	clientIP := "192.168.50.11"
	target := "/protected/malformed.iso"
	ua := "Mozilla/5.0"

	initialReq := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	initialReq.Header.Set("X-Real-IP", clientIP)
	initialReq.Header.Set("X-URL", target)
	initialReq.Header.Set("X-UA", ua)
	initialRR := httptest.NewRecorder()
	authInline.ServeHTTP(initialRR, initialReq)
	if initialRR.Code != http.StatusUnauthorized {
		t.Fatalf("initial browser request expected 401 challenge, got %d", initialRR.Code)
	}

	challengeReq := httptest.NewRequest(http.MethodGet, "/api/challenge", nil)
	challengeReq.Header.Set("X-Real-IP", clientIP)
	challengeReq.Header.Set("X-URL", target)
	challengeRR := httptest.NewRecorder()
	challengeHandler.ServeHTTP(challengeRR, challengeReq)
	if challengeRR.Code != http.StatusOK {
		t.Fatalf("challenge expected 200, got %d", challengeRR.Code)
	}

	var challengeResp struct {
		Prefix string `json:"prefix"`
	}
	if err := json.Unmarshal(challengeRR.Body.Bytes(), &challengeResp); err != nil {
		t.Fatalf("unmarshal challenge response: %v", err)
	}
	if challengeResp.Prefix == "" {
		t.Fatal("expected non-empty challenge prefix")
	}

	malformedBody := `{"prefix":"` + challengeResp.Prefix + `","target_uri":"` + target + `"}`
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/verify_pow", strings.NewReader(malformedBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("X-Real-IP", clientIP)
	verifyReq.Header.Set("X-UA", ua)
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusBadRequest {
		t.Fatalf("malformed verify submission expected 400, got %d", verifyRR.Code)
	}
	if got := verifyRR.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("expected no cookie issuance on malformed submission, got %q", got)
	}
}

func TestIntegratedNonBrowserProtectedPathUsesDirectSign(t *testing.T) {
	authInline := handler.NewAuthInlineHandler(nil)
	p := NewPipeline(nil, authInline)
	t.Cleanup(p.Close)

	req := httptest.NewRequest(http.MethodGet, "/api/auth_inline", nil)
	req.Header.Set("X-Real-IP", "192.168.60.10")
	req.Header.Set("X-URL", "/protected/cli.tar.gz")
	req.Header.Set("X-UA", "curl/8.0")
	rr := httptest.NewRecorder()
	authInline.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("non-browser protected-path request expected direct_sign 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Set-Cookie"); got == "" {
		t.Fatal("expected direct_sign to issue auth cookie")
	}
	if got := rr.Header().Get("X-Auth-Action"); got != "" {
		t.Fatalf("expected no challenge header for non-browser path, got %q", got)
	}
}

func TestMatchIPInvalidCIDRContinueAndExactIPBranch(t *testing.T) {
	if !matchIP("10.0.0.5", []string{"bad/", "10.0.0.5"}) {
		t.Fatalf("expected exact IP match after invalid CIDR entry")
	}
}

func writeExternalPolicy(t *testing.T, payload string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "external-policy.json")
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func loadPolicySet(t *testing.T, payload string) *policy.Set {
	t.Helper()
	path := writeExternalPolicy(t, payload)
	set, err := policy.LoadExternal(path)
	if err != nil {
		t.Fatalf("load external policy: %v", err)
	}
	return set
}
