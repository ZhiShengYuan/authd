package testutil

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/pow"
	"github.com/mirror-guard/auth-backend/internal/state"
)

const nonceSearchLimit = 2_000_000

func FindNonce(prefix string, difficulty int) string {
	for i := 0; i < nonceSearchLimit; i++ {
		nonce := fmt.Sprintf("%d", i)
		if pow.Verify(prefix, nonce, difficulty) {
			return nonce
		}
	}
	return ""
}

func WriteTempConfig(t *testing.T, cfg interface{}) string {
	t.Helper()

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	return path
}

func WriteTempPolicy(t *testing.T, policy interface{}) string {
	t.Helper()

	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}

	path := filepath.Join(t.TempDir(), "policy.external.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	return path
}

func NewTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			ListenNetwork: "tcp",
			ListenAddress: "127.0.0.1:8080",
		},
		Security: config.SecurityConfig{
			GlobalSecret:        "0123456789abcdef0123456789abcdef",
			CookieName:          "auth_token",
			CookieTTLSeconds:    15,
			NonceTTLSeconds:     30,
			PowMinDifficulty:    1,
			PowMaxDifficulty:    1,
			ChallengeTTLSeconds: 30,
			TicketTTLSeconds:    300,
		},
	}
}

func NewTestStore(t *testing.T) *state.Store {
	t.Helper()
	store := state.NewStore()
	t.Cleanup(store.Stop)
	return store
}
