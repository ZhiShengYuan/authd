package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mirror-guard/auth-backend/internal/api"
	"github.com/mirror-guard/auth-backend/internal/pow"
	"github.com/mirror-guard/auth-backend/internal/testutil"
)

func TestHealthzReturnsOK(t *testing.T) {
	mux, stop := buildMux()
	defer stop()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + pathHealthz)
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestDefaultMuxConfig(t *testing.T) {
	cfg := defaultMuxConfig()
	if cfg.Security.CookieName != "auth_token" {
		t.Fatalf("unexpected cookie name: %q", cfg.Security.CookieName)
	}
	if cfg.Security.CookieTTLSeconds != 15 {
		t.Fatalf("unexpected cookie ttl: %d", cfg.Security.CookieTTLSeconds)
	}
	if cfg.Security.NonceTTLSeconds != 30 {
		t.Fatalf("unexpected nonce ttl: %d", cfg.Security.NonceTTLSeconds)
	}
	if cfg.Security.PowMinDifficulty != 4 {
		t.Fatalf("unexpected min difficulty: %d", cfg.Security.PowMinDifficulty)
	}
	if cfg.Security.PowMaxDifficulty != 10 {
		t.Fatalf("unexpected max difficulty: %d", cfg.Security.PowMaxDifficulty)
	}
	if cfg.Security.ChallengeTTLSeconds != 30 {
		t.Fatalf("unexpected challenge ttl: %d", cfg.Security.ChallengeTTLSeconds)
	}
	if cfg.Security.TicketTTLSeconds != 300 {
		t.Fatalf("unexpected ticket ttl: %d", cfg.Security.TicketTTLSeconds)
	}
}

func TestBuildMuxRegistersEndpoints(t *testing.T) {
	cfg := testutil.NewTestConfig()
	mux, stop := buildMux(cfg)
	defer stop()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	for _, p := range []string{pathChallenges, pathChallengesVerify, pathTickets, pathTicketsVerify} {
		resp, err := http.Post(ts.URL+p, "application/json", nil)
		if err != nil {
			t.Fatalf("POST %s failed: %v", p, err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			_ = resp.Body.Close()
			t.Fatalf("expected %s -> %d, got %d", p, http.StatusBadRequest, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	metricsResp, err := http.Get(ts.URL + pathMetrics)
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer metricsResp.Body.Close()
	if metricsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected /metrics 200, got %d", metricsResp.StatusCode)
	}
}

func TestEndToEndChallengeTicketFlow(t *testing.T) {
	cfg := testutil.NewTestConfig()
	mux, stop := buildMux(cfg)
	defer stop()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	type envelope struct {
		Success bool               `json:"success"`
		Data    json.RawMessage    `json:"data"`
		Error   *api.EnvelopeError `json:"error"`
	}

	bind := api.BindMatrix{URL: "/protected/file.iso", IP: "198.51.100.9", UA: "Mozilla/5.0"}

	challengeReqBody := api.ChallengeConfigRequest{
		ChallengeID: "challenge-e2e",
		Difficulty:  1,
		BindMatrix:  bind,
	}
	challengeBody, err := json.Marshal(challengeReqBody)
	if err != nil {
		t.Fatalf("marshal challenge request: %v", err)
	}
	challengeResp, err := http.Post(ts.URL+pathChallenges, "application/json", bytes.NewReader(challengeBody))
	if err != nil {
		t.Fatalf("POST %s failed: %v", pathChallenges, err)
	}
	if challengeResp.StatusCode != http.StatusCreated {
		defer challengeResp.Body.Close()
		t.Fatalf("expected %s status %d, got %d", pathChallenges, http.StatusCreated, challengeResp.StatusCode)
	}
	var challengeEnvelope envelope
	if err := json.NewDecoder(challengeResp.Body).Decode(&challengeEnvelope); err != nil {
		_ = challengeResp.Body.Close()
		t.Fatalf("decode challenge envelope: %v", err)
	}
	_ = challengeResp.Body.Close()
	if !challengeEnvelope.Success || challengeEnvelope.Error != nil {
		t.Fatalf("expected challenge success envelope, got error=%+v", challengeEnvelope.Error)
	}
	var challengeData api.ChallengeConfigData
	if err := json.Unmarshal(challengeEnvelope.Data, &challengeData); err != nil {
		t.Fatalf("decode challenge data: %v", err)
	}
	if challengeData.Prefix == "" {
		t.Fatal("expected non-empty challenge prefix")
	}

	nonce := testutil.FindNonce(challengeData.Prefix, challengeData.Difficulty)
	if nonce == "" {
		t.Fatalf("failed to solve PoW for difficulty %d", challengeData.Difficulty)
	}
	if !pow.Verify(challengeData.Prefix, nonce, challengeData.Difficulty) {
		t.Fatal("computed nonce did not satisfy PoW difficulty")
	}

	verifyReqBody := api.ChallengeVerifyRequest{
		ChallengeID: challengeData.ChallengeID,
		Nonce:       nonce,
		Prefix:      challengeData.Prefix,
	}
	verifyBody, err := json.Marshal(verifyReqBody)
	if err != nil {
		t.Fatalf("marshal verify request: %v", err)
	}
	verifyResp, err := http.Post(ts.URL+pathChallengesVerify, "application/json", bytes.NewReader(verifyBody))
	if err != nil {
		t.Fatalf("POST %s failed: %v", pathChallengesVerify, err)
	}
	if verifyResp.StatusCode != http.StatusOK {
		defer verifyResp.Body.Close()
		t.Fatalf("expected first verify status %d, got %d", http.StatusOK, verifyResp.StatusCode)
	}
	var verifyEnvelope envelope
	if err := json.NewDecoder(verifyResp.Body).Decode(&verifyEnvelope); err != nil {
		_ = verifyResp.Body.Close()
		t.Fatalf("decode verify envelope: %v", err)
	}
	_ = verifyResp.Body.Close()
	var verifyData api.ChallengeVerifyData
	if err := json.Unmarshal(verifyEnvelope.Data, &verifyData); err != nil {
		t.Fatalf("decode verify data: %v", err)
	}
	if !verifyEnvelope.Success || !verifyData.Valid {
		t.Fatalf("expected verify valid=true, got success=%v valid=%v", verifyEnvelope.Success, verifyData.Valid)
	}

	replayVerifyResp, err := http.Post(ts.URL+pathChallengesVerify, "application/json", bytes.NewReader(verifyBody))
	if err != nil {
		t.Fatalf("POST replay %s failed: %v", pathChallengesVerify, err)
	}
	if replayVerifyResp.StatusCode != http.StatusConflict {
		defer replayVerifyResp.Body.Close()
		t.Fatalf("expected replay verify status %d, got %d", http.StatusConflict, replayVerifyResp.StatusCode)
	}
	_ = replayVerifyResp.Body.Close()

	ticketIssueReq := api.TicketIssueRequest{BindMatrix: bind, Uses: 3}
	ticketIssueBody, err := json.Marshal(ticketIssueReq)
	if err != nil {
		t.Fatalf("marshal ticket issue request: %v", err)
	}
	ticketIssueResp, err := http.Post(ts.URL+pathTickets, "application/json", bytes.NewReader(ticketIssueBody))
	if err != nil {
		t.Fatalf("POST %s failed: %v", pathTickets, err)
	}
	if ticketIssueResp.StatusCode != http.StatusCreated {
		defer ticketIssueResp.Body.Close()
		t.Fatalf("expected %s status %d, got %d", pathTickets, http.StatusCreated, ticketIssueResp.StatusCode)
	}
	var ticketIssueEnvelope envelope
	if err := json.NewDecoder(ticketIssueResp.Body).Decode(&ticketIssueEnvelope); err != nil {
		_ = ticketIssueResp.Body.Close()
		t.Fatalf("decode ticket issue envelope: %v", err)
	}
	_ = ticketIssueResp.Body.Close()
	var ticketIssueData api.TicketIssueData
	if err := json.Unmarshal(ticketIssueEnvelope.Data, &ticketIssueData); err != nil {
		t.Fatalf("decode ticket issue data: %v", err)
	}
	if ticketIssueData.Ticket == "" {
		t.Fatal("expected issued ticket token")
	}

	ticketVerifyReq := api.TicketVerifyRequest{Ticket: ticketIssueData.Ticket, BindMatrix: bind}
	ticketVerifyBody, err := json.Marshal(ticketVerifyReq)
	if err != nil {
		t.Fatalf("marshal ticket verify request: %v", err)
	}
	for i := 1; i <= 3; i++ {
		resp, postErr := http.Post(ts.URL+pathTicketsVerify, "application/json", bytes.NewReader(ticketVerifyBody))
		if postErr != nil {
			t.Fatalf("POST %s attempt %d failed: %v", pathTicketsVerify, i, postErr)
		}
		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			t.Fatalf("expected verify attempt %d status %d, got %d", i, http.StatusOK, resp.StatusCode)
		}
		var verifyTicketEnvelope envelope
		if err := json.NewDecoder(resp.Body).Decode(&verifyTicketEnvelope); err != nil {
			_ = resp.Body.Close()
			t.Fatalf("decode ticket verify envelope attempt %d: %v", i, err)
		}
		_ = resp.Body.Close()
		var verifyTicketData api.TicketVerifyData
		if err := json.Unmarshal(verifyTicketEnvelope.Data, &verifyTicketData); err != nil {
			t.Fatalf("decode ticket verify data attempt %d: %v", i, err)
		}
		if !verifyTicketEnvelope.Success || !verifyTicketData.Valid {
			t.Fatalf("expected ticket verify attempt %d valid=true, got success=%v valid=%v", i, verifyTicketEnvelope.Success, verifyTicketData.Valid)
		}
	}

	exhaustedResp, err := http.Post(ts.URL+pathTicketsVerify, "application/json", bytes.NewReader(ticketVerifyBody))
	if err != nil {
		t.Fatalf("POST exhausted %s failed: %v", pathTicketsVerify, err)
	}
	if exhaustedResp.StatusCode != http.StatusGone {
		defer exhaustedResp.Body.Close()
		t.Fatalf("expected exhausted verify status %d, got %d", http.StatusGone, exhaustedResp.StatusCode)
	}
	_ = exhaustedResp.Body.Close()
}
