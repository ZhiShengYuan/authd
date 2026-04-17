package pipeline

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mirror-guard/auth-backend/internal/classifier"
	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/cookie"
	"github.com/mirror-guard/auth-backend/internal/observability"
	"github.com/mirror-guard/auth-backend/internal/policy"
	"github.com/mirror-guard/auth-backend/internal/pow"
	"github.com/mirror-guard/auth-backend/internal/state"
	"github.com/mirror-guard/auth-backend/internal/subnet"
	"go.opentelemetry.io/otel"
)

type Action int

const (
	ActionAccept Action = iota
	ActionChallenge
	ActionReject
	ActionRedirect
	ActionDirectSign
	ActionDrop
)

const (
	defaultCookieName = "auth_token"
)

type evalContext struct {
	clientIP   string
	host       string
	targetURI  string
	normPath   string
	userAgent  string
	ja3Hash    string
	subnetKey  string
	uaDigest   string
	clientType classifier.ClientClass
}

type Pipeline struct {
	mu          sync.RWMutex
	authHandler http.Handler
	policySet   *policy.Set
	cookieMgr   *cookie.Manager
	stateStore  *state.Store
	config      *config.Config
}

var errQuotaStoreUnavailable = errors.New("pipeline: quota store unavailable")

var quotaIncrementFn = func(store *state.QuotaStore, key string, window time.Duration) (int64, error) {
	return store.Increment(key, window)
}

func NewPipeline(policySet *policy.Set, authHandler http.Handler, shared ...interface{}) *Pipeline {
	var cfg *config.Config
	var store *state.Store
	var cookieMgr *cookie.Manager

	if len(shared) > 0 {
		if v, ok := shared[0].(*config.Config); ok {
			cfg = v
		}
	}
	if len(shared) > 1 {
		if v, ok := shared[1].(*state.Store); ok {
			store = v
		}
	}
	if len(shared) > 2 {
		if v, ok := shared[2].(*cookie.Manager); ok {
			cookieMgr = v
		}
	}

	if cfg == nil {
		cfg = defaultConfig()
	}
	if store == nil {
		store = state.NewStore()
	}
	if cookieMgr == nil {
		cookieMgr = cookie.NewManager(cfg.Security.GlobalSecret, cfg.Security.CookieName, cfg.Security.CookieTTLSeconds)
	}

	p := &Pipeline{
		authHandler: authHandler,
		policySet:   policySet,
		cookieMgr:   cookieMgr,
		stateStore:  store,
		config:      cfg,
	}

	if setter, ok := authHandler.(interface{ SetExecutor(http.Handler) }); ok {
		setter.SetExecutor(p)
	}

	return p
}

func (p *Pipeline) SetConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	p.mu.Lock()
	p.config = cfg
	p.mu.Unlock()
}

func (p *Pipeline) SetCookieManager(cookieMgr *cookie.Manager) {
	if cookieMgr == nil {
		return
	}
	p.mu.Lock()
	p.cookieMgr = cookieMgr
	p.mu.Unlock()
}

func (p *Pipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx, span := otel.Tracer("mirror-guard-auth-gateway/pipeline").Start(r.Context(), "pipeline.ServeHTTP")
	defer span.End()
	r = r.WithContext(ctx)

	eval := p.extractRequest(r)
	requestID := requestIDFromHeader(r)
	routeFamily := string(policy.ClassifyRepoFamily(eval.normPath))
	action := "reject"
	decisionReason := "default_reject"
	difficulty := 0
	fallbackMode := false

	defer func() {
		observability.RecordAuthDecision(action, string(eval.clientType), routeFamily)
		observability.RecordHandlerLatency("pipeline", action, time.Since(start))
		if p.stateStore != nil {
			if p.stateStore.QuotaStore != nil {
				observability.SetStateStoreSize("quota", p.stateStore.QuotaStore.Size())
			}
			if p.stateStore.NonceStore != nil {
				observability.SetStateStoreSize("nonce", p.stateStore.NonceStore.Size())
			}
			if p.stateStore.CookieConsumptionStore != nil {
				observability.SetStateStoreSize("cookie", p.stateStore.CookieConsumptionStore.Size())
			}
		}
		observability.LogAuthDecision(ctx, requestID, eval.clientIP, eval.subnetKey, string(eval.clientType), routeFamily, action, decisionReason, difficulty, fallbackMode)
	}()

	defer func() {
		if recover() != nil {
			action = "fallback"
			decisionReason = "panic_recovered"
			fallbackMode = true
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}()

	if eval.subnetKey == "" {
		action = "fallback"
		decisionReason = "missing_subnet_key"
		fallbackMode = true
		p.executeAction(w, r, eval, ActionChallenge)
		return
	}

	if p.isWhitelisted(eval.clientIP) {
		action = "allow"
		decisionReason = "ip_whitelisted"
		w.WriteHeader(http.StatusOK)
		return
	}

	if p.isBlacklisted(eval.clientIP) {
		action = "reject"
		decisionReason = "ip_blacklisted"
		p.executeAction(w, r, eval, ActionReject)
		return
	}

	ruleAction := p.evalRules(eval)
	switch ruleAction {
	case ActionReject, ActionRedirect, ActionDrop:
		action = actionName(ruleAction)
		decisionReason = "policy_rule"
		if ruleAction == ActionRedirect || ruleAction == ActionDrop {
			fallbackMode = true
		}
		p.executeAction(w, r, eval, ruleAction)
		return
	case ActionAccept:
		action = "allow"
		decisionReason = "route_not_protected"
		p.executeAction(w, r, eval, ActionAccept)
		return
	}

	if p.hasValidCookie(r, eval) {
		action = "allow"
		decisionReason = "valid_cookie"
		p.executeAction(w, r, eval, ActionAccept)
		return
	}
	action = "fallback"
	decisionReason = "no_valid_cookie"
	fallbackMode = true

	if classifier.IsBrowser(eval.clientType) {
		action = "challenge"
		decisionReason = "browser_requires_challenge"
		fallbackMode = true
		difficulty = p.currentDifficulty(eval.subnetKey)
		p.executeAction(w, r, eval, ActionChallenge)
		return
	}

	action = "direct_sign"
	decisionReason = "non_browser_direct_sign"
	p.executeAction(w, r, eval, ActionDirectSign)
}

func (p *Pipeline) Reload(newPolicy *policy.Set) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policySet = newPolicy
	if setter, ok := p.authHandler.(interface{ SetPolicy(*policy.Set) }); ok {
		setter.SetPolicy(newPolicy)
	}
}

func (p *Pipeline) Close() {
	if p.stateStore != nil {
		p.stateStore.Stop()
	}
}

func (p *Pipeline) extractRequest(r *http.Request) evalContext {
	clientIP := strings.TrimSpace(r.Header.Get("X-Real-IP"))
	if clientIP == "" {
		clientIP, _, _ = SplitAddr(r.RemoteAddr)
	}

	targetURI := strings.TrimSpace(r.Header.Get("X-URL"))
	if targetURI == "" && r.URL != nil {
		targetURI = r.URL.RequestURI()
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Header.Get("X-Host"))
	}
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}

	ua := strings.TrimSpace(r.Header.Get("X-UA"))
	if ua == "" {
		ua = r.UserAgent()
	}

	normPath := normalizePath(targetURI)
	subnetKey := subnet.DefaultKey(clientIP)

	return evalContext{
		clientIP:   clientIP,
		host:       host,
		targetURI:  targetURI,
		normPath:   normPath,
		userAgent:  ua,
		ja3Hash:    strings.TrimSpace(r.Header.Get("X-JA3-Hash")),
		subnetKey:  subnetKey,
		uaDigest:   cookie.UADigest(ua),
		clientType: classifier.Classify(ua),
	}
}

func (p *Pipeline) isWhitelisted(clientIP string) bool {
	p.mu.RLock()
	current := p.policySet
	defer p.mu.RUnlock()
	if current == nil {
		return false
	}
	return matchIP(clientIP, current.WhitelistCIDRs)
}

func (p *Pipeline) isBlacklisted(clientIP string) bool {
	p.mu.RLock()
	current := p.policySet
	defer p.mu.RUnlock()
	if current == nil {
		return false
	}
	return matchIP(clientIP, current.BlacklistCIDRs)
}

func (p *Pipeline) evalRules(eval evalContext) Action {
	p.mu.RLock()
	current := p.policySet
	p.mu.RUnlock()

	routeCtx := &policy.RouteContext{
		Host:             eval.host,
		Path:             eval.normPath,
		FileExtension:    policy.ExtractFileExtension(eval.normPath),
		RepoFamily:       policy.ClassifyRepoFamily(eval.normPath),
		DownloadBehavior: policy.ClassifyDownloadBehavior(eval.normPath, 0),
		ClientClass:      eval.clientType,
	}
	decision := current.Evaluate(routeCtx)

	switch decision {
	case policy.Allow:
		return ActionAccept
	case policy.Challenge:
		return ActionChallenge
	case policy.DirectSign:
		return ActionDirectSign
	case policy.Reject:
		return ActionReject
	case policy.Redirect:
		return ActionRedirect
	default:
		return ActionReject
	}
}

func (p *Pipeline) hasValidCookie(r *http.Request, eval evalContext) bool {
	p.mu.RLock()
	cookieMgr := p.cookieMgr
	stateStore := p.stateStore
	p.mu.RUnlock()

	if cookieMgr == nil || stateStore == nil {
		return false
	}

	c, err := r.Cookie(cookieMgr.CookieName())
	if err != nil || c == nil || c.Value == "" {
		return false
	}

	tokenID, ok := cookieMgr.Validate(c.Value, eval.subnetKey, eval.uaDigest, eval.normPath)
	if !ok {
		return false
	}

	if stateStore.CookieConsumptionStore == nil {
		return false
	}

	claimed := stateStore.CookieConsumptionStore.Claim(tokenID)
	if !claimed {
		observability.RecordCookieReplay()
	}

	return claimed
}

func (p *Pipeline) executeAction(w http.ResponseWriter, r *http.Request, eval evalContext, action Action) {
	switch action {
	case ActionAccept:
		overQuota, err := p.overQuota(r.Context(), eval.subnetKey)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if overQuota {
			p.writeQuotaOutcome(w)
			return
		}
		w.WriteHeader(http.StatusOK)
	case ActionDirectSign:
		p.mu.RLock()
		cookieMgr := p.cookieMgr
		p.mu.RUnlock()
		if cookieMgr != nil {
			token, _, err := cookieMgr.Issue(eval.subnetKey, eval.uaDigest, eval.normPath)
			if err == nil {
				http.SetCookie(w, &http.Cookie{
					Name:     cookieMgr.CookieName(),
					Value:    token,
					Path:     "/",
					HttpOnly: true,
					MaxAge:   cookieMgr.TTLSeconds(),
				})
			}
		}
		overQuota, err := p.overQuota(r.Context(), eval.subnetKey)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if overQuota {
			p.writeQuotaOutcome(w)
			return
		}
		w.WriteHeader(http.StatusOK)
	case ActionChallenge:
		w.Header().Set("X-Auth-Action", "challenge")
		w.WriteHeader(http.StatusUnauthorized)
	case ActionReject:
		w.WriteHeader(http.StatusForbidden)
	case ActionRedirect:
		if redirect := p.redirectURL(); redirect != "" {
			w.Header().Set("Location", redirect)
		}
		w.WriteHeader(http.StatusFound)
	case ActionDrop:
		w.WriteHeader(444)
	default:
		w.WriteHeader(http.StatusForbidden)
	}
}

func (p *Pipeline) overQuota(_ context.Context, subnetKey string) (bool, error) {
	if p.stateStore == nil || subnetKey == "" {
		return false, nil
	}

	p.mu.RLock()
	current := p.policySet
	cfg := p.config
	p.mu.RUnlock()
	limit := int64(0)
	window := time.Duration(cfg.Security.PowWindowSeconds) * time.Second
	if current != nil {
		limit = int64(current.QuotaDefaults.DefaultLimit)
		if current.QuotaDefaults.DefaultWindow > 0 {
			window = current.QuotaDefaults.DefaultWindow
		}
	}

	if p.stateStore.QuotaStore == nil {
		return false, errQuotaStoreUnavailable
	}

	count, err := quotaIncrementFn(p.stateStore.QuotaStore, subnetKey, window)
	if err != nil {
		return false, err
	}

	if limit <= 0 {
		return false, nil
	}

	return count > limit, nil
}

func (p *Pipeline) writeQuotaOutcome(w http.ResponseWriter) {
	if redirect := p.redirectURL(); redirect != "" {
		w.Header().Set("Location", redirect)
		w.WriteHeader(http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusForbidden)
}

func (p *Pipeline) redirectURL() string {
	p.mu.RLock()
	current := p.policySet
	defer p.mu.RUnlock()
	if current == nil {
		return ""
	}
	for _, rule := range current.Rules {
		if redirect := strings.TrimSpace(rule.RedirectURL); redirect != "" {
			return redirect
		}
	}
	return ""
}

func SplitAddr(addr string) (host, port string, err error) {
	return net.SplitHostPort(addr)
}

func defaultConfig() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			CookieName:       defaultCookieName,
			CookieTTLSeconds: 15,
			NonceTTLSeconds:  30,
			PowMinDifficulty: 4,
			PowMaxDifficulty: 10,
			PowWindowSeconds: 60,
		},
	}
}

func normalizePath(input string) string {
	if input == "" {
		return "/"
	}
	if u, err := url.Parse(input); err == nil && u.Path != "" {
		return u.Path
	}
	if idx := strings.IndexByte(input, '?'); idx >= 0 {
		if idx == 0 {
			return "/"
		}
		return input[:idx]
	}
	return input
}

func requestIDFromHeader(r *http.Request) string {
	requestID := strings.TrimSpace(firstNonEmptyHeaderValue(r.Header["X-Request-ID"]))
	if requestID != "" {
		return requestID
	}
	requestID = strings.TrimSpace(firstNonEmptyHeaderValue(r.Header["X-Request-Id"]))
	if requestID != "" {
		return requestID
	}
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

func firstNonEmptyHeaderValue(values []string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func actionName(action Action) string {
	switch action {
	case ActionAccept:
		return "allow"
	case ActionChallenge:
		return "challenge"
	case ActionReject:
		return "reject"
	case ActionDirectSign:
		return "direct_sign"
	case ActionRedirect, ActionDrop:
		return "fallback"
	default:
		return "reject"
	}
}

func (p *Pipeline) currentDifficulty(subnetKey string) int {
	p.mu.RLock()
	cfg := p.config
	p.mu.RUnlock()

	if p.stateStore == nil || p.stateStore.QuotaStore == nil || subnetKey == "" {
		return cfg.Security.PowMinDifficulty
	}
	requestsInWindow := p.stateStore.QuotaStore.Get(subnetKey)
	return pow.Difficulty(requestsInWindow, cfg.Security.PowMinDifficulty, cfg.Security.PowMaxDifficulty)
}

func matchIP(clientIP string, entries []string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, entry := range entries {
		e := strings.TrimSpace(entry)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			_, cidr, err := net.ParseCIDR(e)
			if err == nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if parsed := net.ParseIP(e); parsed != nil && parsed.Equal(ip) {
			return true
		}
	}

	return false
}
