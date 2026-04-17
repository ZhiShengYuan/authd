package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mirror-guard/auth-backend/internal/api"
	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/testutil"
)

func TestChallengeVerifySuccess(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", ChallengeTTLSeconds: 30}}
	store := testutil.NewTestStore(t)

	configHandler := NewChallengeConfigHandler(cfg, store)
	verifyHandler := NewChallengeVerifyHandler(cfg, store)

	configureBody := `{"challenge_id":"challenge-verify-success","difficulty":1,"bind_matrix":{"url":"/protected","ip":"198.51.100.9","ua":"ua-1"}}`
	configureReq := httptest.NewRequest(http.MethodPost, "/api/challenges", strings.NewReader(configureBody))
	configureRR := httptest.NewRecorder()
	configHandler.ServeHTTP(configureRR, configureReq)

	if configureRR.Code != http.StatusCreated {
		t.Fatalf("expected config status %d, got %d", http.StatusCreated, configureRR.Code)
	}

	var configureEnvelope api.ResponseEnvelope
	if err := json.Unmarshal(configureRR.Body.Bytes(), &configureEnvelope); err != nil {
		t.Fatalf("unmarshal config envelope: %v", err)
	}

	rawData, err := json.Marshal(configureEnvelope.Data)
	if err != nil {
		t.Fatalf("marshal config data: %v", err)
	}

	var configData api.ChallengeConfigData
	if err := json.Unmarshal(rawData, &configData); err != nil {
		t.Fatalf("unmarshal config data: %v", err)
	}

	nonce := testutil.FindNonce(configData.Prefix, configData.Difficulty)
	if nonce == "" {
		t.Fatalf("failed to find nonce for difficulty %d", configData.Difficulty)
	}

	verifyBody := fmt.Sprintf(`{"challenge_id":"%s","nonce":"%s","prefix":"%s"}`, configData.ChallengeID, nonce, configData.Prefix)
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/challenges/verify", strings.NewReader(verifyBody))
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusOK {
		t.Fatalf("expected verify status %d, got %d", http.StatusOK, verifyRR.Code)
	}

	var verifyEnvelope api.ResponseEnvelope
	if err := json.Unmarshal(verifyRR.Body.Bytes(), &verifyEnvelope); err != nil {
		t.Fatalf("unmarshal verify envelope: %v", err)
	}
	if !verifyEnvelope.Success {
		t.Fatalf("expected success envelope, got body=%s", verifyRR.Body.String())
	}

	verifyDataRaw, err := json.Marshal(verifyEnvelope.Data)
	if err != nil {
		t.Fatalf("marshal verify data: %v", err)
	}

	var verifyData api.ChallengeVerifyData
	if err := json.Unmarshal(verifyDataRaw, &verifyData); err != nil {
		t.Fatalf("unmarshal verify data: %v", err)
	}

	if !verifyData.Valid {
		t.Fatal("expected valid=true")
	}
}

func TestChallengeVerifyReplay(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", ChallengeTTLSeconds: 30}}
	store := testutil.NewTestStore(t)

	configHandler := NewChallengeConfigHandler(cfg, store)
	verifyHandler := NewChallengeVerifyHandler(cfg, store)

	configureBody := `{"challenge_id":"challenge-verify-replay","difficulty":1,"bind_matrix":{"url":"/protected","ip":"198.51.100.10","ua":"ua-2"}}`
	configureReq := httptest.NewRequest(http.MethodPost, "/api/challenges", strings.NewReader(configureBody))
	configureRR := httptest.NewRecorder()
	configHandler.ServeHTTP(configureRR, configureReq)

	var configureEnvelope api.ResponseEnvelope
	if err := json.Unmarshal(configureRR.Body.Bytes(), &configureEnvelope); err != nil {
		t.Fatalf("unmarshal config envelope: %v", err)
	}
	configDataRaw, _ := json.Marshal(configureEnvelope.Data)
	var configData api.ChallengeConfigData
	if err := json.Unmarshal(configDataRaw, &configData); err != nil {
		t.Fatalf("unmarshal config data: %v", err)
	}

	nonce := testutil.FindNonce(configData.Prefix, configData.Difficulty)
	if nonce == "" {
		t.Fatal("nonce not found")
	}

	verifyBody := fmt.Sprintf(`{"challenge_id":"%s","nonce":"%s","prefix":"%s"}`, configData.ChallengeID, nonce, configData.Prefix)

	firstReq := httptest.NewRequest(http.MethodPost, "/api/challenges/verify", strings.NewReader(verifyBody))
	firstRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("expected first verify status %d, got %d", http.StatusOK, firstRR.Code)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/api/challenges/verify", strings.NewReader(verifyBody))
	secondRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(secondRR, secondReq)

	if secondRR.Code != http.StatusConflict {
		t.Fatalf("expected second verify status %d, got %d", http.StatusConflict, secondRR.Code)
	}
}

func TestChallengeVerifyExpired(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", ChallengeTTLSeconds: 1}}
	store := testutil.NewTestStore(t)

	configHandler := NewChallengeConfigHandler(cfg, store)
	verifyHandler := NewChallengeVerifyHandler(cfg, store)

	configureBody := `{"challenge_id":"challenge-verify-expired","difficulty":1,"bind_matrix":{"url":"/protected","ip":"198.51.100.11","ua":"ua-3"}}`
	configureReq := httptest.NewRequest(http.MethodPost, "/api/challenges", strings.NewReader(configureBody))
	configureRR := httptest.NewRecorder()
	configHandler.ServeHTTP(configureRR, configureReq)

	time.Sleep(1200 * time.Millisecond)

	var configureEnvelope api.ResponseEnvelope
	if err := json.Unmarshal(configureRR.Body.Bytes(), &configureEnvelope); err != nil {
		t.Fatalf("unmarshal config envelope: %v", err)
	}
	configDataRaw, _ := json.Marshal(configureEnvelope.Data)
	var configData api.ChallengeConfigData
	if err := json.Unmarshal(configDataRaw, &configData); err != nil {
		t.Fatalf("unmarshal config data: %v", err)
	}

	nonce := testutil.FindNonce(configData.Prefix, configData.Difficulty)
	if nonce == "" {
		t.Fatal("nonce not found")
	}

	verifyBody := fmt.Sprintf(`{"challenge_id":"%s","nonce":"%s","prefix":"%s"}`, configData.ChallengeID, nonce, configData.Prefix)
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/challenges/verify", strings.NewReader(verifyBody))
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusGone {
		t.Fatalf("expected verify status %d, got %d", http.StatusGone, verifyRR.Code)
	}
}

func TestChallengeVerifyNotFound(t *testing.T) {
	h := NewChallengeVerifyHandler(&config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", ChallengeTTLSeconds: 30}}, testutil.NewTestStore(t))

	req := httptest.NewRequest(http.MethodPost, "/api/challenges/verify", strings.NewReader(`{"challenge_id":"missing","nonce":"1","prefix":"x"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestChallengeVerifyRejectsGet(t *testing.T) {
	h := NewChallengeVerifyHandler(&config.Config{}, testutil.NewTestStore(t))

	req := httptest.NewRequest(http.MethodGet, "/api/challenges/verify", nil)
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

func TestChallengeVerifyInvalidPowReturnsChallengeInvalid(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{GlobalSecret: "0123456789abcdef0123456789abcdef", ChallengeTTLSeconds: 30}}
	store := testutil.NewTestStore(t)

	configHandler := NewChallengeConfigHandler(cfg, store)
	verifyHandler := NewChallengeVerifyHandler(cfg, store)

	configureBody := `{"challenge_id":"challenge-verify-invalid-pow","difficulty":1,"bind_matrix":{"url":"/protected","ip":"198.51.100.21","ua":"ua-invalid"}}`
	configureReq := httptest.NewRequest(http.MethodPost, "/api/challenges", strings.NewReader(configureBody))
	configureRR := httptest.NewRecorder()
	configHandler.ServeHTTP(configureRR, configureReq)

	if configureRR.Code != http.StatusCreated {
		t.Fatalf("expected config status %d, got %d", http.StatusCreated, configureRR.Code)
	}

	var configureEnvelope api.ResponseEnvelope
	if err := json.Unmarshal(configureRR.Body.Bytes(), &configureEnvelope); err != nil {
		t.Fatalf("unmarshal config envelope: %v", err)
	}

	rawData, err := json.Marshal(configureEnvelope.Data)
	if err != nil {
		t.Fatalf("marshal config data: %v", err)
	}

	var configData api.ChallengeConfigData
	if err := json.Unmarshal(rawData, &configData); err != nil {
		t.Fatalf("unmarshal config data: %v", err)
	}

	verifyBody := fmt.Sprintf(`{"challenge_id":"%s","nonce":"not-a-solution","prefix":"%s"}`, configData.ChallengeID, configData.Prefix)
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/challenges/verify", strings.NewReader(verifyBody))
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusBadRequest {
		t.Fatalf("expected verify status %d, got %d", http.StatusBadRequest, verifyRR.Code)
	}

	var verifyEnvelope api.ResponseEnvelope
	if err := json.Unmarshal(verifyRR.Body.Bytes(), &verifyEnvelope); err != nil {
		t.Fatalf("unmarshal verify envelope: %v", err)
	}
	if verifyEnvelope.Success {
		t.Fatalf("expected success=false for invalid PoW, got body=%s", verifyRR.Body.String())
	}
	if verifyEnvelope.Error == nil || verifyEnvelope.Error.Code != api.ErrChallengeInvalid {
		t.Fatalf("expected error code %q, got %#v", api.ErrChallengeInvalid, verifyEnvelope.Error)
	}
}

func TestChallengeVerifyInvalidJSON(t *testing.T) {
	h := NewChallengeVerifyHandler(&config.Config{}, testutil.NewTestStore(t))

	req := httptest.NewRequest(http.MethodPost, "/api/challenges/verify", strings.NewReader("{"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}
