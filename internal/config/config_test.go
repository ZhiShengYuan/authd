package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		jsonConfig     string
		pathMode       string
		wantErr        string
		checkDefaults  bool
		checkAllFields bool
	}{
		{
			name: "happy path with all fields set",
			jsonConfig: `{
				"server": {
					"listen_network": "unix",
					"listen_address": "/tmp/auth.sock"
				},
				"security": {
					"global_secret": "12345678901234567890123456789012",
					"cookie_name": "mirror_auth",
					"cookie_ttl_seconds": 120,
					"nonce_ttl_seconds": 90,
					"pow_min_difficulty": 5,
					"pow_max_difficulty": 12,
					"pow_window_seconds": 45
				},
				"policy": {
					"external_lists_path": "/etc/mirror/policy.json"
				}
			}`,
			checkAllFields: true,
		},
		{
			name: "happy path with zero numeric fields applies defaults",
			jsonConfig: `{
				"server": {
					"listen_address": "127.0.0.1:8080"
				},
				"security": {
					"global_secret": "abcdefghijklmnopqrstuvwxyzABCDEF",
					"cookie_name": "mirror_session",
					"cookie_ttl_seconds": 0,
					"nonce_ttl_seconds": 0,
					"pow_min_difficulty": 0,
					"pow_max_difficulty": 0,
					"pow_window_seconds": 0
				},
				"policy": {}
			}`,
			checkDefaults: true,
		},
		{
			name:     "error missing config file",
			pathMode: "missing-file",
			wantErr:  "failed to read config file",
		},
		{
			name:       "error invalid json",
			jsonConfig: `{"server":`,
			wantErr:    "failed to parse JSON config: unexpected end of JSON input",
		},
		{
			name: "error global_secret too short",
			jsonConfig: `{
				"server": {"listen_address": "127.0.0.1:8080"},
				"security": {
					"global_secret": "too-short",
					"cookie_name": "auth",
					"cookie_ttl_seconds": 1,
					"nonce_ttl_seconds": 1,
					"pow_min_difficulty": 1,
					"pow_max_difficulty": 1,
					"pow_window_seconds": 1
				},
				"policy": {}
			}`,
			wantErr: "global_secret must be at least 32 bytes",
		},
		{
			name: "error cookie_ttl_seconds <= 0",
			jsonConfig: `{
				"server": {"listen_address": "127.0.0.1:8080"},
				"security": {
					"global_secret": "12345678901234567890123456789012",
					"cookie_name": "auth",
					"cookie_ttl_seconds": -1,
					"nonce_ttl_seconds": 1,
					"pow_min_difficulty": 1,
					"pow_max_difficulty": 1,
					"pow_window_seconds": 1
				},
				"policy": {}
			}`,
			wantErr: "cookie_ttl_seconds must be greater than 0",
		},
		{
			name: "error nonce_ttl_seconds <= 0",
			jsonConfig: `{
				"server": {"listen_address": "127.0.0.1:8080"},
				"security": {
					"global_secret": "12345678901234567890123456789012",
					"cookie_name": "auth",
					"cookie_ttl_seconds": 1,
					"nonce_ttl_seconds": -1,
					"pow_min_difficulty": 1,
					"pow_max_difficulty": 1,
					"pow_window_seconds": 1
				},
				"policy": {}
			}`,
			wantErr: "nonce_ttl_seconds must be greater than 0",
		},
		{
			name: "error pow_min_difficulty <= 0",
			jsonConfig: `{
				"server": {"listen_address": "127.0.0.1:8080"},
				"security": {
					"global_secret": "12345678901234567890123456789012",
					"cookie_name": "auth",
					"cookie_ttl_seconds": 1,
					"nonce_ttl_seconds": 1,
					"pow_min_difficulty": -1,
					"pow_max_difficulty": 1,
					"pow_window_seconds": 1
				},
				"policy": {}
			}`,
			wantErr: "pow_min_difficulty must be greater than 0",
		},
		{
			name: "error pow_max_difficulty < pow_min_difficulty",
			jsonConfig: `{
				"server": {"listen_address": "127.0.0.1:8080"},
				"security": {
					"global_secret": "12345678901234567890123456789012",
					"cookie_name": "auth",
					"cookie_ttl_seconds": 1,
					"nonce_ttl_seconds": 1,
					"pow_min_difficulty": 5,
					"pow_max_difficulty": 4,
					"pow_window_seconds": 1
				},
				"policy": {}
			}`,
			wantErr: "pow_max_difficulty must be greater than or equal to pow_min_difficulty",
		},
		{
			name: "error pow_window_seconds <= 0",
			jsonConfig: `{
				"server": {"listen_address": "127.0.0.1:8080"},
				"security": {
					"global_secret": "12345678901234567890123456789012",
					"cookie_name": "auth",
					"cookie_ttl_seconds": 1,
					"nonce_ttl_seconds": 1,
					"pow_min_difficulty": 1,
					"pow_max_difficulty": 1,
					"pow_window_seconds": -1
				},
				"policy": {}
			}`,
			wantErr: "pow_window_seconds must be greater than 0",
		},
		{
			name: "error missing listen_address",
			jsonConfig: `{
				"server": {"listen_address": ""},
				"security": {
					"global_secret": "12345678901234567890123456789012",
					"cookie_name": "auth",
					"cookie_ttl_seconds": 1,
					"nonce_ttl_seconds": 1,
					"pow_min_difficulty": 1,
					"pow_max_difficulty": 1,
					"pow_window_seconds": 1
				},
				"policy": {}
			}`,
			wantErr: "server.listen_address is required",
		},
		{
			name: "error missing cookie_name",
			jsonConfig: `{
				"server": {"listen_address": "127.0.0.1:8080"},
				"security": {
					"global_secret": "12345678901234567890123456789012",
					"cookie_name": "",
					"cookie_ttl_seconds": 1,
					"nonce_ttl_seconds": 1,
					"pow_min_difficulty": 1,
					"pow_max_difficulty": 1,
					"pow_window_seconds": 1
				},
				"policy": {}
			}`,
			wantErr: "security.cookie_name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")

			switch tt.pathMode {
			case "missing-file":
				path = filepath.Join(dir, "does-not-exist.json")
			default:
				if err := os.WriteFile(path, []byte(tt.jsonConfig), 0o600); err != nil {
					t.Fatalf("write config file: %v", err)
				}
			}

			cfg, err := LoadConfig(path)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("LoadConfig(%q) error = nil, want %q", path, tt.wantErr)
				}

				if !errors.Is(err, os.ErrNotExist) && tt.pathMode == "missing-file" {
					t.Fatalf("LoadConfig(%q) error = %q, want wrapped os.ErrNotExist", path, err)
				}

				errText := err.Error()
				if tt.pathMode == "missing-file" {
					if !strings.Contains(errText, tt.wantErr) {
						t.Fatalf("LoadConfig(%q) error = %q, want contains %q", path, errText, tt.wantErr)
					}
				} else if errText != tt.wantErr {
					t.Fatalf("LoadConfig(%q) error = %q, want %q", path, errText, tt.wantErr)
				}

				if cfg != nil {
					t.Fatalf("LoadConfig(%q) cfg = %#v, want nil on error", path, cfg)
				}

				return
			}

			if err != nil {
				t.Fatalf("LoadConfig(%q) unexpected error: %v", path, err)
			}
			if cfg == nil {
				t.Fatalf("LoadConfig(%q) cfg = nil, want non-nil", path)
			}

			if tt.checkAllFields {
				if cfg.Server.ListenNetwork != "unix" {
					t.Fatalf("ListenNetwork = %q, want %q", cfg.Server.ListenNetwork, "unix")
				}
				if cfg.Server.ListenAddress != "/tmp/auth.sock" {
					t.Fatalf("ListenAddress = %q, want %q", cfg.Server.ListenAddress, "/tmp/auth.sock")
				}
				if cfg.Security.GlobalSecret != "12345678901234567890123456789012" {
					t.Fatalf("GlobalSecret = %q, want expected secret", cfg.Security.GlobalSecret)
				}
				if cfg.Security.CookieName != "mirror_auth" {
					t.Fatalf("CookieName = %q, want %q", cfg.Security.CookieName, "mirror_auth")
				}
				if cfg.Security.CookieTTLSeconds != 120 {
					t.Fatalf("CookieTTLSeconds = %d, want 120", cfg.Security.CookieTTLSeconds)
				}
				if cfg.Security.NonceTTLSeconds != 90 {
					t.Fatalf("NonceTTLSeconds = %d, want 90", cfg.Security.NonceTTLSeconds)
				}
				if cfg.Security.PowMinDifficulty != 5 {
					t.Fatalf("PowMinDifficulty = %d, want 5", cfg.Security.PowMinDifficulty)
				}
				if cfg.Security.PowMaxDifficulty != 12 {
					t.Fatalf("PowMaxDifficulty = %d, want 12", cfg.Security.PowMaxDifficulty)
				}
				if cfg.Security.PowWindowSeconds != 45 {
					t.Fatalf("PowWindowSeconds = %d, want 45", cfg.Security.PowWindowSeconds)
				}
				if cfg.Policy.ExternalListsPath != "/etc/mirror/policy.json" {
					t.Fatalf("ExternalListsPath = %q, want %q", cfg.Policy.ExternalListsPath, "/etc/mirror/policy.json")
				}
			}

			if tt.checkDefaults {
				if cfg.Server.ListenNetwork != "tcp" {
					t.Fatalf("ListenNetwork = %q, want %q", cfg.Server.ListenNetwork, "tcp")
				}
				if cfg.Security.CookieTTLSeconds != 15 {
					t.Fatalf("CookieTTLSeconds = %d, want 15", cfg.Security.CookieTTLSeconds)
				}
				if cfg.Security.NonceTTLSeconds != 30 {
					t.Fatalf("NonceTTLSeconds = %d, want 30", cfg.Security.NonceTTLSeconds)
				}
				if cfg.Security.PowMinDifficulty != 4 {
					t.Fatalf("PowMinDifficulty = %d, want 4", cfg.Security.PowMinDifficulty)
				}
				if cfg.Security.PowMaxDifficulty != 10 {
					t.Fatalf("PowMaxDifficulty = %d, want 10", cfg.Security.PowMaxDifficulty)
				}
				if cfg.Security.PowWindowSeconds != 60 {
					t.Fatalf("PowWindowSeconds = %d, want 60", cfg.Security.PowWindowSeconds)
				}
			}
		})
	}
}
