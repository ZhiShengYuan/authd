package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mirror-guard/auth-backend/internal/api"
	"github.com/mirror-guard/auth-backend/internal/testutil"
	"github.com/mirror-guard/auth-backend/internal/ticket"
)

type ticketIssueEnvelope struct {
	Success bool `json:"success"`
	Data    struct {
		Ticket string `json:"ticket"`
	} `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func TestTicketIssueSuccess(t *testing.T) {
	cfg := testutil.NewTestConfig()
	manager := ticket.NewManager(cfg.Security.GlobalSecret, cfg.Security.TicketTTLSeconds)
	h := NewTicketIssueHandler(cfg, manager)

	body := []byte(`{"bind_matrix":{"url":"/resource","ip":"192.168.0.10","ua":"Mozilla/5.0"},"uses":3}`)
	req := httptest.NewRequest(http.MethodPost, "/api/tickets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, rr.Code)
	}

	var resp ticketIssueEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected success=true, got false (error=%+v)", resp.Error)
	}
	if resp.Data.Ticket == "" {
		t.Fatal("expected non-empty ticket")
	}
}

func TestTicketIssueRejectsGet(t *testing.T) {
	cfg := testutil.NewTestConfig()
	manager := ticket.NewManager(cfg.Security.GlobalSecret, cfg.Security.TicketTTLSeconds)
	h := NewTicketIssueHandler(cfg, manager)

	req := httptest.NewRequest(http.MethodGet, "/api/tickets", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("expected Allow=%q, got %q", http.MethodPost, got)
	}

	var resp ticketIssueEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Success {
		t.Fatalf("expected success=false, got true")
	}
	if resp.Error == nil || resp.Error.Code != api.ErrInvalidRequest {
		t.Fatalf("expected error code %q, got %+v", api.ErrInvalidRequest, resp.Error)
	}
}

func TestTicketIssueMissingFields(t *testing.T) {
	cfg := testutil.NewTestConfig()
	manager := ticket.NewManager(cfg.Security.GlobalSecret, cfg.Security.TicketTTLSeconds)
	h := NewTicketIssueHandler(cfg, manager)

	body := []byte(`{"bind_matrix":{"url":"","ip":"","ua":""},"uses":2}`)
	req := httptest.NewRequest(http.MethodPost, "/api/tickets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	var resp ticketIssueEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != api.ErrInvalidRequest {
		t.Fatalf("expected error code %q, got %+v", api.ErrInvalidRequest, resp.Error)
	}
}

func TestTicketIssueZeroUses(t *testing.T) {
	cfg := testutil.NewTestConfig()
	manager := ticket.NewManager(cfg.Security.GlobalSecret, cfg.Security.TicketTTLSeconds)
	h := NewTicketIssueHandler(cfg, manager)

	body := []byte(`{"bind_matrix":{"url":"/resource","ip":"192.168.0.10","ua":"Mozilla/5.0"},"uses":0}`)
	req := httptest.NewRequest(http.MethodPost, "/api/tickets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	var resp ticketIssueEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != api.ErrInvalidRequest {
		t.Fatalf("expected error code %q, got %+v", api.ErrInvalidRequest, resp.Error)
	}
}

func TestTicketIssueInvalidJSON(t *testing.T) {
	cfg := testutil.NewTestConfig()
	manager := ticket.NewManager(cfg.Security.GlobalSecret, cfg.Security.TicketTTLSeconds)
	h := NewTicketIssueHandler(cfg, manager)

	body := []byte(`{"bind_matrix":`)
	req := httptest.NewRequest(http.MethodPost, "/api/tickets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	var resp ticketIssueEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != api.ErrInvalidRequest {
		t.Fatalf("expected error code %q, got %+v", api.ErrInvalidRequest, resp.Error)
	}
}
