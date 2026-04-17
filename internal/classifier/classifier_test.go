package classifier

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want ClientClass
	}{
		{
			name: "chrome browser",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
			want: Browser,
		},
		{
			name: "firefox browser",
			ua:   "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
			want: Browser,
		},
		{
			name: "curl cli",
			ua:   "curl/8.7.1",
			want: CLI,
		},
		{
			name: "wget cli",
			ua:   "Wget/1.21.4",
			want: CLI,
		},
		{
			name: "apt package manager",
			ua:   "Debian APT-HTTP/1.3 (2.6.1)",
			want: PackageManager,
		},
		{
			name: "pip package manager",
			ua:   "pip/24.0 python/3.11.8",
			want: PackageManager,
		},
		{
			name: "npm package manager",
			ua:   "npm/10.8.1 node/v20.15.0 linux x64 workspaces/false",
			want: PackageManager,
		},
		{
			name: "cargo package manager",
			ua:   "cargo/1.78.0 (54d8815d0 2024-03-26)",
			want: PackageManager,
		},
		{
			name: "python requests cli",
			ua:   "python-requests/2.31.0",
			want: CLI,
		},
		{
			name: "empty cli",
			ua:   "",
			want: CLI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.ua); got != tt.want {
				t.Fatalf("Classify(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}

func TestPredicateHelpers(t *testing.T) {
	if !IsBrowser(Browser) {
		t.Fatal("expected Browser to be browser")
	}
	if !IsCLI(CLI) {
		t.Fatal("expected CLI to be cli")
	}
	if !IsPackageManager(PackageManager) {
		t.Fatal("expected PackageManager to be package_manager")
	}

	if IsBrowser(CLI) {
		t.Fatal("did not expect CLI to be browser")
	}
	if IsCLI(PackageManager) {
		t.Fatal("did not expect PackageManager to be cli")
	}
	if IsPackageManager(Browser) {
		t.Fatal("did not expect Browser to be package manager")
	}
}
