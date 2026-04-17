package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mirror-guard/auth-backend/internal/classifier"
)

type Action string

const (
	Allow      Action = "allow"
	Challenge  Action = "challenge"
	DirectSign Action = "direct_sign"
	Reject     Action = "reject"
	Redirect   Action = "redirect"
)

type Set struct {
	WhitelistCIDRs    []string
	BlacklistCIDRs    []string
	BlacklistUAs      []string
	Rules             []Rule
	QuotaDefaults     QuotaConfig
	ExternalListsPath string
	Version           int64
}

type Rule struct {
	Name             string
	PathPrefix       string
	ClientClass      classifier.ClientClass
	DownloadBehavior DownloadBehavior
	Action           Action
	Difficulty       int
	QuotaLimit       int
	QuotaWindow      time.Duration
	RedirectURL      string
}

type QuotaConfig struct {
	DefaultLimit  int
	DefaultWindow time.Duration
}

type Manager struct {
	current atomic.Pointer[Set]
}

func NewManager(initial *Set) *Manager {
	m := &Manager{}
	m.Set(initial)
	return m
}

func (m *Manager) Get() *Set {
	return m.current.Load()
}

func (m *Manager) Set(p *Set) {
	m.current.Store(p)
}

func (s *Set) Evaluate(ctx *RouteContext) Action {
	if s == nil {
		if classifier.IsBrowser(ctx.ClientClass) {
			return Challenge
		}
		return DirectSign
	}

	for _, rule := range s.Rules {
		if !matchesRule(rule, ctx) {
			continue
		}
		if rule.Action == Challenge && !classifier.IsBrowser(ctx.ClientClass) {
			return DirectSign
		}
		return rule.Action
	}

	if classifier.IsBrowser(ctx.ClientClass) {
		return Challenge
	}

	if ctx.DownloadBehavior == LargeFile || ctx.DownloadBehavior == RangeResume {
		return DirectSign
	}

	if ctx.RepoFamily == LinuxDistro || ctx.RepoFamily == LanguageEcosystem || ctx.RepoFamily == ContainerImage {
		return Allow
	}

	if ctx.FileExtension == ".iso" || ctx.FileExtension == ".xz" {
		return DirectSign
	}

	return Allow
}

func matchesRule(rule Rule, ctx *RouteContext) bool {
	if rule.PathPrefix != "" {
		if !strings.HasPrefix(ctx.Path, rule.PathPrefix) {
			hostPath := strings.TrimSpace(ctx.Host) + ctx.Path
			if !strings.HasPrefix(hostPath, rule.PathPrefix) {
				return false
			}
		}
	}

	if rule.ClientClass != "" && rule.ClientClass != ctx.ClientClass {
		return false
	}

	if rule.DownloadBehavior != "" && rule.DownloadBehavior != ctx.DownloadBehavior {
		return false
	}

	return true
}

func LoadExternal(path string) (*Set, error) {
	if path == "" {
		return defaultSet(path, 1), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultSet(path, 1), nil
		}
		return nil, fmt.Errorf("read external policy lists: %w", err)
	}

	if len(data) == 0 {
		return defaultSet(path, 1), nil
	}

	var raw externalPolicyFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse external policy lists JSON: %w", err)
	}

	converted, err := raw.toSet(path)
	if err != nil {
		return nil, err
	}

	if converted.Version == 0 {
		converted.Version = 1
	}

	return converted, nil
}

type externalPolicyFile struct {
	WhitelistCIDRs []string       `json:"whitelist_cidrs"`
	BlacklistCIDRs []string       `json:"blacklist_cidrs"`
	BlacklistUAs   []string       `json:"blacklist_uas"`
	Rules          []externalRule `json:"rules"`
	QuotaDefaults  externalQuota  `json:"quota_defaults"`
	Version        int64          `json:"version"`
}

type externalRule struct {
	Name             string `json:"name"`
	PathPrefix       string `json:"path_prefix"`
	ClientClass      string `json:"client_class"`
	DownloadBehavior string `json:"download_behavior"`
	Action           string `json:"action"`
	Difficulty       int    `json:"difficulty"`
	QuotaLimit       int    `json:"quota_limit"`
	QuotaWindow      string `json:"quota_window"`
	RedirectURL      string `json:"redirect_url"`
}

type externalQuota struct {
	DefaultLimit  int    `json:"default_limit"`
	DefaultWindow string `json:"default_window"`
}

func (f externalPolicyFile) toSet(path string) (*Set, error) {
	if err := validateCIDRList("whitelist_cidrs", f.WhitelistCIDRs); err != nil {
		return nil, err
	}
	if err := validateCIDRList("blacklist_cidrs", f.BlacklistCIDRs); err != nil {
		return nil, err
	}

	quotaWindow := 24 * time.Hour
	if f.QuotaDefaults.DefaultWindow != "" {
		parsed, err := time.ParseDuration(f.QuotaDefaults.DefaultWindow)
		if err != nil {
			return nil, fmt.Errorf("parse quota_defaults.default_window: %w", err)
		}
		quotaWindow = parsed
	}

	set := &Set{
		WhitelistCIDRs: f.WhitelistCIDRs,
		BlacklistCIDRs: f.BlacklistCIDRs,
		BlacklistUAs:   f.BlacklistUAs,
		QuotaDefaults: QuotaConfig{
			DefaultLimit:  f.QuotaDefaults.DefaultLimit,
			DefaultWindow: quotaWindow,
		},
		ExternalListsPath: path,
		Version:           f.Version,
	}

	for idx, rawRule := range f.Rules {
		converted, err := convertRule(rawRule)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", idx, err)
		}
		set.Rules = append(set.Rules, converted)
	}

	if set.QuotaDefaults.DefaultLimit == 0 {
		set.QuotaDefaults.DefaultLimit = 200
	}
	if set.QuotaDefaults.DefaultWindow <= 0 {
		set.QuotaDefaults.DefaultWindow = 24 * time.Hour
	}

	return set, nil
}

func convertRule(raw externalRule) (Rule, error) {
	if raw.Name == "" {
		return Rule{}, errors.New("name is required")
	}

	action, err := parseAction(raw.Action)
	if err != nil {
		return Rule{}, err
	}

	var class classifier.ClientClass
	if raw.ClientClass != "" {
		class = classifier.ClientClass(strings.ToLower(raw.ClientClass))
		switch class {
		case classifier.Browser, classifier.CLI, classifier.PackageManager:
		default:
			return Rule{}, fmt.Errorf("invalid client_class %q", raw.ClientClass)
		}
	}

	var behavior DownloadBehavior
	if raw.DownloadBehavior != "" {
		behavior = DownloadBehavior(strings.ToLower(raw.DownloadBehavior))
		switch behavior {
		case Metadata, SmallFile, LargeFile, RangeResume:
		default:
			return Rule{}, fmt.Errorf("invalid download_behavior %q", raw.DownloadBehavior)
		}
	}

	quotaWindow := 0 * time.Second
	if raw.QuotaWindow != "" {
		parsed, err := time.ParseDuration(raw.QuotaWindow)
		if err != nil {
			return Rule{}, fmt.Errorf("parse quota_window: %w", err)
		}
		quotaWindow = parsed
	}

	return Rule{
		Name:             raw.Name,
		PathPrefix:       raw.PathPrefix,
		ClientClass:      class,
		DownloadBehavior: behavior,
		Action:           action,
		Difficulty:       raw.Difficulty,
		QuotaLimit:       raw.QuotaLimit,
		QuotaWindow:      quotaWindow,
		RedirectURL:      raw.RedirectURL,
	}, nil
}

func parseAction(v string) (Action, error) {
	switch strings.ToLower(v) {
	case string(Allow):
		return Allow, nil
	case string(Challenge):
		return Challenge, nil
	case string(DirectSign):
		return DirectSign, nil
	case string(Reject):
		return Reject, nil
	case string(Redirect):
		return Redirect, nil
	default:
		return "", fmt.Errorf("invalid action %q", v)
	}
}

func validateCIDRList(name string, values []string) error {
	for _, cidr := range values {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid %s entry %q: %w", name, cidr, err)
		}
	}
	return nil
}

func defaultSet(path string, version int64) *Set {
	return &Set{
		WhitelistCIDRs:    nil,
		BlacklistCIDRs:    nil,
		BlacklistUAs:      nil,
		Rules:             nil,
		QuotaDefaults:     QuotaConfig{DefaultLimit: 200, DefaultWindow: 24 * time.Hour},
		ExternalListsPath: path,
		Version:           version,
	}
}
