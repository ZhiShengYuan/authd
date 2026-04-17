package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mirror-guard/auth-backend/internal/api"
	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/state"
)

func TestChallengeConfigSuccess(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)

	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", ChallengeTTLSeconds: 30}}
	h := NewChallengeConfigHandler(cfg, store)

	body := `{"challenge_id":"challenge-1","difficulty":1,"bind_matrix":{"url":"/protected","ip":"192.0.2.10","ua":"agent"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/challenges", strings.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, rr.Code)
	}

	var envelope api.ResponseEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if !envelope.Success {
		t.Fatalf("expected success envelope, got body=%s", rr.Body.String())
	}

	rawData, err := json.Marshal(envelope.Data)
	if err != nil {
		t.Fatalf("marshal envelope data: %v", err)
	}

	var data api.ChallengeConfigData
	if err := json.Unmarshal(rawData, &data); err != nil {
		t.Fatalf("unmarshal challenge data: %v", err)
	}

	if data.Prefix == "" {
		t.Fatal("expected non-empty prefix")
	}
	if data.Difficulty != 1 {
		t.Fatalf("expected difficulty=1, got %d", data.Difficulty)
	}
	if data.ChallengeID != "challenge-1" {
		t.Fatalf("expected challenge_id=challenge-1, got %q", data.ChallengeID)
	}
}

func TestChallengeConfigRejectsGet(t *testing.T) {
	h := NewChallengeConfigHandler(&config.Config{}, state.NewStore())
	t.Cleanup(h.store.Stop)

	req := httptest.NewRequest(http.MethodGet, "/api/challenges", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("expected Allow=%q, got %q", http.MethodPost, got)
	}

	var envelope api.ResponseEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if envelope.Success {
		t.Fatalf("expected error envelope, got body=%s", rr.Body.String())
	}
	if envelope.Error == nil || envelope.Error.Code != api.ErrInvalidRequest {
		t.Fatalf("expected error code %q, got %#v", api.ErrInvalidRequest, envelope.Error)
	}
}

func TestChallengeConfigMissingFields(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)

	h := NewChallengeConfigHandler(&config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", ChallengeTTLSeconds: 30}}, store)

	body := `{"challenge_id":"","difficulty":0,"bind_matrix":{"url":"","ip":"","ua":""}}`
	req := httptest.NewRequest(http.MethodPost, "/api/challenges", strings.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}

	var envelope api.ResponseEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if envelope.Success {
		t.Fatalf("expected error envelope, got body=%s", rr.Body.String())
	}
	if envelope.Error == nil || envelope.Error.Code != api.ErrInvalidRequest {
		t.Fatalf("expected error code %q, got %#v", api.ErrInvalidRequest, envelope.Error)
	}
}

func TestChallengeConfigInvalidJSON(t *testing.T) {
	store := state.NewStore()
	t.Cleanup(store.Stop)

	h := NewChallengeConfigHandler(&config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", ChallengeTTLSeconds: 30}}, store)

	req := httptest.NewRequest(http.MethodPost, "/api/challenges", strings.NewReader("{"))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}
