package testutil

import (
	"testing"

	"github.com/mirror-guard/auth-backend/internal/config"
)

func TestWriteTempConfigAndPolicyArtifacts(t *testing.T) {
	cfg := NewTestConfig()

	configPath := WriteTempConfig(t, cfg)
	loaded, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.Security.GlobalSecret != cfg.Security.GlobalSecret {
		t.Fatalf("expected global secret %q, got %q", cfg.Security.GlobalSecret, loaded.Security.GlobalSecret)
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
