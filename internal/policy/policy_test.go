package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirror-guard/auth-backend/internal/classifier"
)

func TestEvaluate_FirstMatchWins(t *testing.T) {
	set := &Set{
		Rules: []Rule{
			{
				Name:       "path-first",
				PathPrefix: "/ubuntu/",
				Action:     Allow,
			},
			{
				Name:        "browser-second",
				ClientClass: classifier.Browser,
				Action:      Challenge,
			},
		},
	}

	ctx := &RouteContext{
		Host:             "mirror.example.org",
		Path:             "/ubuntu/dists/jammy/Release",
		FileExtension:    ".txt",
		RepoFamily:       LinuxDistro,
		DownloadBehavior: Metadata,
		ClientClass:      classifier.Browser,
	}

	if got := set.Evaluate(ctx); got != Allow {
		t.Fatalf("Evaluate() = %q, want %q", got, Allow)
	}
}

func TestEvaluate_ClientClassificationIntegration(t *testing.T) {
	set := &Set{
		Rules: []Rule{
			{
				Name:        "browser-challenge",
				ClientClass: classifier.Browser,
				Action:      Challenge,
			},
			{
				Name:        "package-manager-large-direct-sign",
				ClientClass: classifier.PackageManager,
				Action:      DirectSign,
			},
		},
	}

	browserCtx := &RouteContext{ClientClass: classifier.Classify("Mozilla/5.0 Chrome/124.0"), Path: "/ubuntu/", DownloadBehavior: Metadata}
	if got := set.Evaluate(browserCtx); got != Challenge {
		t.Fatalf("browser action = %q, want %q", got, Challenge)
	}

	pkgCtx := &RouteContext{ClientClass: classifier.Classify("pip/24.0 python/3.11.8"), Path: "/pypi/simple/pkg/", DownloadBehavior: SmallFile}
	if got := set.Evaluate(pkgCtx); got != DirectSign {
		t.Fatalf("package manager action = %q, want %q", got, DirectSign)
	}

	cliCtx := &RouteContext{ClientClass: classifier.Classify("curl/8.6.0"), Path: "/downloads/os.iso", FileExtension: ".iso", DownloadBehavior: LargeFile, RepoFamily: Generic}
	if got := set.Evaluate(cliCtx); got != DirectSign {
		t.Fatalf("cli action = %q, want %q", got, DirectSign)
	}
}

func TestEvaluate_ChallengeNeverRedirectedForCLIOrPackageManager(t *testing.T) {
	set := &Set{
		Rules: []Rule{{
			Name:        "overly-strict",
			ClientClass: classifier.CLI,
			Action:      Challenge,
		}},
	}

	ctx := &RouteContext{ClientClass: classifier.CLI, Path: "/debian/pool/main/a/abc.deb"}
	if got := set.Evaluate(ctx); got != DirectSign {
		t.Fatalf("cli challenge fallback = %q, want %q", got, DirectSign)
	}
}

func TestLoadExternal_ParsesFullStructure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.external.json")

	jsonData := `{
		"version": 3,
		"whitelist_cidrs": ["10.0.0.0/8"],
		"blacklist_cidrs": ["203.0.113.0/24"],
		"blacklist_uas": ["evil-bot"],
		"quota_defaults": {"default_limit": 300, "default_window": "12h"},
		"rules": [
			{
				"name": "repo-browser-challenge",
				"path_prefix": "/ubuntu/",
				"client_class": "browser",
				"download_behavior": "large_file",
				"action": "challenge",
				"difficulty": 8,
				"quota_limit": 30,
				"quota_window": "24h",
				"redirect_url": "https://example.org/fallback"
			}
		]
	}`

	if err := os.WriteFile(path, []byte(jsonData), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	set, err := LoadExternal(path)
	if err != nil {
		t.Fatalf("LoadExternal error: %v", err)
	}

	if set.Version != 3 {
		t.Fatalf("version = %d, want 3", set.Version)
	}
	if len(set.WhitelistCIDRs) != 1 || set.WhitelistCIDRs[0] != "10.0.0.0/8" {
		t.Fatalf("unexpected whitelist: %#v", set.WhitelistCIDRs)
	}
	if len(set.BlacklistCIDRs) != 1 || set.BlacklistCIDRs[0] != "203.0.113.0/24" {
		t.Fatalf("unexpected blacklist: %#v", set.BlacklistCIDRs)
	}
	if len(set.BlacklistUAs) != 1 || set.BlacklistUAs[0] != "evil-bot" {
		t.Fatalf("unexpected blacklist uas: %#v", set.BlacklistUAs)
	}
	if set.QuotaDefaults.DefaultLimit != 300 || set.QuotaDefaults.DefaultWindow != 12*time.Hour {
		t.Fatalf("unexpected quota defaults: %#v", set.QuotaDefaults)
	}
	if len(set.Rules) != 1 {
		t.Fatalf("rule count = %d, want 1", len(set.Rules))
	}
	rule := set.Rules[0]
	if rule.Name != "repo-browser-challenge" || rule.PathPrefix != "/ubuntu/" || rule.ClientClass != classifier.Browser || rule.DownloadBehavior != LargeFile || rule.Action != Challenge {
		t.Fatalf("unexpected rule: %#v", rule)
	}
}

func TestBadReloadPreservesOldConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.external.json")

	good := `{
		"version": 11,
		"quota_defaults": {"default_limit": 250, "default_window": "24h"},
		"rules": [{"name":"allow-ubuntu","path_prefix":"/ubuntu/","action":"allow"}]
	}`
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatalf("write good file: %v", err)
	}

	base, err := LoadExternal(path)
	if err != nil {
		t.Fatalf("initial LoadExternal: %v", err)
	}
	mgr := NewManager(base)

	bad := `{"rules":[{"name":"bad-rule","action":"not-an-action"}]}`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	_, reloadErr := LoadExternal(path)
	if reloadErr == nil {
		t.Fatal("expected reload parse/validation error")
	}

	current := mgr.Get()
	if current == nil {
		t.Fatal("expected manager to keep previous config")
	}
	if current.Version != 11 {
		t.Fatalf("expected preserved version 11, got %d", current.Version)
	}
	if len(current.Rules) != 1 || current.Rules[0].Name != "allow-ubuntu" {
		t.Fatalf("expected preserved rules, got %#v", current.Rules)
	}
}

func TestEvaluate_NilSetDefaultsByClientClass(t *testing.T) {
	var set *Set

	browserCtx := &RouteContext{ClientClass: classifier.Browser}
	if got := set.Evaluate(browserCtx); got != Challenge {
		t.Fatalf("nil set browser action = %q, want %q", got, Challenge)
	}

	cliCtx := &RouteContext{ClientClass: classifier.CLI}
	if got := set.Evaluate(cliCtx); got != DirectSign {
		t.Fatalf("nil set cli action = %q, want %q", got, DirectSign)
	}
}

func TestEvaluate_HostPathPrefixFallback(t *testing.T) {
	set := &Set{Rules: []Rule{{
		Name:       "host-prefixed-rule",
		PathPrefix: "mirror.example.org/ubuntu/",
		Action:     Reject,
	}}}

	ctx := &RouteContext{
		Host:             "mirror.example.org",
		Path:             "/ubuntu/dists/jammy/Release",
		DownloadBehavior: Metadata,
		ClientClass:      classifier.CLI,
	}

	if got := set.Evaluate(ctx); got != Reject {
		t.Fatalf("Evaluate() = %q, want %q", got, Reject)
	}
}

func TestEvaluate_DefaultBranchesWithoutMatchingRules(t *testing.T) {
	set := &Set{}

	largeCtx := &RouteContext{ClientClass: classifier.CLI, DownloadBehavior: LargeFile, RepoFamily: Generic}
	if got := set.Evaluate(largeCtx); got != DirectSign {
		t.Fatalf("large file default action = %q, want %q", got, DirectSign)
	}

	linuxRepoCtx := &RouteContext{ClientClass: classifier.CLI, DownloadBehavior: SmallFile, RepoFamily: LinuxDistro}
	if got := set.Evaluate(linuxRepoCtx); got != Allow {
		t.Fatalf("linux repo default action = %q, want %q", got, Allow)
	}

	extensionCtx := &RouteContext{ClientClass: classifier.CLI, DownloadBehavior: SmallFile, RepoFamily: Generic, FileExtension: ".xz"}
	if got := set.Evaluate(extensionCtx); got != DirectSign {
		t.Fatalf(".xz default action = %q, want %q", got, DirectSign)
	}

	genericCtx := &RouteContext{ClientClass: classifier.CLI, DownloadBehavior: SmallFile, RepoFamily: Generic, FileExtension: ".txt"}
	if got := set.Evaluate(genericCtx); got != Allow {
		t.Fatalf("generic default action = %q, want %q", got, Allow)
	}
}

func TestLoadExternal_DefaultSetFallbackScenarios(t *testing.T) {
	set, err := LoadExternal("")
	if err != nil {
		t.Fatalf("LoadExternal empty path error: %v", err)
	}
	if set.ExternalListsPath != "" || set.Version != 1 {
		t.Fatalf("unexpected default set metadata: path=%q version=%d", set.ExternalListsPath, set.Version)
	}
	if set.QuotaDefaults.DefaultLimit != 200 || set.QuotaDefaults.DefaultWindow != 24*time.Hour {
		t.Fatalf("unexpected default quota defaults: %#v", set.QuotaDefaults)
	}

	missingPath := filepath.Join(t.TempDir(), "missing.json")
	missingSet, err := LoadExternal(missingPath)
	if err != nil {
		t.Fatalf("LoadExternal missing file error: %v", err)
	}
	if missingSet.ExternalListsPath != missingPath || missingSet.Version != 1 {
		t.Fatalf("unexpected missing-file fallback set metadata: path=%q version=%d", missingSet.ExternalListsPath, missingSet.Version)
	}

	emptyPath := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	emptySet, err := LoadExternal(emptyPath)
	if err != nil {
		t.Fatalf("LoadExternal empty file error: %v", err)
	}
	if emptySet.ExternalListsPath != emptyPath || emptySet.Version != 1 {
		t.Fatalf("unexpected empty-file fallback set metadata: path=%q version=%d", emptySet.ExternalListsPath, emptySet.Version)
	}
}

func TestLoadExternal_InvalidJSONAndValidationErrors(t *testing.T) {
	dir := t.TempDir()

	invalidJSONPath := filepath.Join(dir, "invalid-json.json")
	if err := os.WriteFile(invalidJSONPath, []byte("{"), 0o600); err != nil {
		t.Fatalf("write invalid JSON file: %v", err)
	}
	if _, err := LoadExternal(invalidJSONPath); err == nil {
		t.Fatal("expected parse error for invalid JSON")
	}

	invalidCIDRPath := filepath.Join(dir, "invalid-cidr.json")
	invalidCIDRData := `{"whitelist_cidrs":["not-a-cidr"]}`
	if err := os.WriteFile(invalidCIDRPath, []byte(invalidCIDRData), 0o600); err != nil {
		t.Fatalf("write invalid CIDR file: %v", err)
	}
	if _, err := LoadExternal(invalidCIDRPath); err == nil {
		t.Fatal("expected CIDR validation error")
	}
}

func TestDefaultSetDirectHelper(t *testing.T) {
	set := defaultSet("/tmp/policy.json", 9)

	if set.ExternalListsPath != "/tmp/policy.json" {
		t.Fatalf("ExternalListsPath = %q, want %q", set.ExternalListsPath, "/tmp/policy.json")
	}
	if set.Version != 9 {
		t.Fatalf("Version = %d, want 9", set.Version)
	}
	if set.QuotaDefaults.DefaultLimit != 200 || set.QuotaDefaults.DefaultWindow != 24*time.Hour {
		t.Fatalf("unexpected default quota defaults: %#v", set.QuotaDefaults)
	}
	if set.Rules != nil || set.WhitelistCIDRs != nil || set.BlacklistCIDRs != nil || set.BlacklistUAs != nil {
		t.Fatalf("expected default set list fields nil, got %#v", set)
	}
}

func TestEvaluate_BrowserDefaultWhenNoRuleMatches(t *testing.T) {
	set := &Set{Rules: []Rule{{Name: "cli-only", ClientClass: classifier.CLI, Action: Allow}}}
	ctx := &RouteContext{ClientClass: classifier.Browser, DownloadBehavior: SmallFile, RepoFamily: Generic}

	if got := set.Evaluate(ctx); got != Challenge {
		t.Fatalf("Evaluate() = %q, want %q", got, Challenge)
	}
}

func TestMatchesRuleNegativeBranches(t *testing.T) {
	ctx := &RouteContext{Host: "mirror.example.org", Path: "/ubuntu/", ClientClass: classifier.Browser, DownloadBehavior: Metadata}

	if matchesRule(Rule{PathPrefix: "/debian/"}, ctx) {
		t.Fatal("expected path prefix mismatch to fail")
	}
	if matchesRule(Rule{PathPrefix: "other.example.org/ubuntu/"}, ctx) {
		t.Fatal("expected host+path prefix mismatch to fail")
	}
	if matchesRule(Rule{ClientClass: classifier.CLI}, ctx) {
		t.Fatal("expected client class mismatch to fail")
	}
	if matchesRule(Rule{DownloadBehavior: LargeFile}, ctx) {
		t.Fatal("expected download behavior mismatch to fail")
	}
}

func TestLoadExternalReadErrorOnDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadExternal(dir); err == nil {
		t.Fatal("expected read error for directory path")
	} else if !strings.Contains(err.Error(), "read external policy lists") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadExternalVersionZeroDefaultsToOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version-zero.json")
	data := `{"version":0,"rules":[{"name":"allow","action":"allow"}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	set, err := LoadExternal(path)
	if err != nil {
		t.Fatalf("LoadExternal error: %v", err)
	}
	if set.Version != 1 {
		t.Fatalf("version = %d, want 1", set.Version)
	}
}

func TestToSetQuotaWindowParsingAndDefaults(t *testing.T) {
	_, err := (externalPolicyFile{QuotaDefaults: externalQuota{DefaultWindow: "nope"}}).toSet("/tmp/x")
	if err == nil {
		t.Fatal("expected invalid default window error")
	}

	set, err := (externalPolicyFile{QuotaDefaults: externalQuota{DefaultLimit: 0, DefaultWindow: "0s"}}).toSet("/tmp/y")
	if err != nil {
		t.Fatalf("unexpected toSet error: %v", err)
	}
	if set.QuotaDefaults.DefaultLimit != 200 {
		t.Fatalf("default limit = %d, want 200", set.QuotaDefaults.DefaultLimit)
	}
	if set.QuotaDefaults.DefaultWindow != 24*time.Hour {
		t.Fatalf("default window = %v, want 24h", set.QuotaDefaults.DefaultWindow)
	}
}

func TestToSetRuleConversionErrorIncludesRuleIndex(t *testing.T) {
	_, err := (externalPolicyFile{Rules: []externalRule{{Name: "bad", Action: "invalid"}}}).toSet("/tmp/z")
	if err == nil {
		t.Fatal("expected conversion error")
	}
	if !strings.Contains(err.Error(), "rules[0]") {
		t.Fatalf("expected indexed error, got %v", err)
	}
}

func TestConvertRuleValidationBranches(t *testing.T) {
	if _, err := convertRule(externalRule{}); err == nil {
		t.Fatal("expected name required error")
	}

	if _, err := convertRule(externalRule{Name: "r", Action: "allow", ClientClass: "robot"}); err == nil {
		t.Fatal("expected invalid client_class error")
	}

	if _, err := convertRule(externalRule{Name: "r", Action: "allow", DownloadBehavior: "weird"}); err == nil {
		t.Fatal("expected invalid download_behavior error")
	}

	if _, err := convertRule(externalRule{Name: "r", Action: "allow", QuotaWindow: "bad"}); err == nil {
		t.Fatal("expected invalid quota_window parse error")
	}
}

func TestParseActionAllBranches(t *testing.T) {
	cases := map[string]Action{
		"allow":       Allow,
		"challenge":   Challenge,
		"direct_sign": DirectSign,
		"reject":      Reject,
		"redirect":    Redirect,
	}
	for input, want := range cases {
		got, err := parseAction(input)
		if err != nil {
			t.Fatalf("parseAction(%q) unexpected error: %v", input, err)
		}
		if got != want {
			t.Fatalf("parseAction(%q) = %q, want %q", input, got, want)
		}
	}

	if _, err := parseAction("bogus"); err == nil {
		t.Fatal("expected invalid action error")
	}
}

func TestIsMetadataPathAdditionalBranches(t *testing.T) {
	if !isMetadataPath("/debian/dists/bookworm/packages") {
		t.Fatal("expected /packages path to be metadata")
	}
	if !isMetadataPath("/debian/dists/bookworm/packages.gz") {
		t.Fatal("expected /packages.gz path to be metadata")
	}
	if !isMetadataPath("/debian/dists/bookworm/packages.xz") {
		t.Fatal("expected /packages.xz path to be metadata")
	}
	if !isMetadataPath("/debian/dists/bookworm/release") {
		t.Fatal("expected /release path to be metadata")
	}
	if !isMetadataPath("/debian/dists/bookworm/inrelease") {
		t.Fatal("expected /inrelease path to be metadata")
	}
	if !isMetadataPath("/repo/metadata/index.json") {
		t.Fatal("expected indicator-based metadata path to be true")
	}
	if isMetadataPath("/downloads/file.bin") {
		t.Fatal("expected non-metadata path to be false")
	}
}

func TestToSetInvalidBlacklistCIDR(t *testing.T) {
	_, err := (externalPolicyFile{
		WhitelistCIDRs: []string{"10.0.0.0/8"},
		BlacklistCIDRs: []string{"not-a-cidr"},
	}).toSet("/tmp/blacklist")
	if err == nil {
		t.Fatal("expected blacklist CIDR validation error")
	}
}
