package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mirror-guard/auth-backend/internal/api"
	"github.com/mirror-guard/auth-backend/internal/testutil"
	"github.com/mirror-guard/auth-backend/internal/ticket"
)

type ticketVerifyEnvelope struct {
	Success bool `json:"success"`
	Data    struct {
		Valid bool `json:"valid"`
	} `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func TestTicketVerifySuccess(t *testing.T) {
	cfg := testutil.NewTestConfig()
	manager := ticket.NewManager(cfg.Security.GlobalSecret, cfg.Security.TicketTTLSeconds)
	tok, err := manager.Issue(ticket.BindMatrix{URL: "/resource", IP: "192.168.0.11", UA: "Mozilla/5.0"}, 2)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	h := NewTicketVerifyHandler(cfg, manager)

	body := []byte(`{"ticket":"` + tok + `","bind_matrix":{"url":"/resource","ip":"192.168.0.11","ua":"Mozilla/5.0"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/tickets/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp ticketVerifyEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success || !resp.Data.Valid {
		t.Fatalf("expected success valid=true, got success=%v valid=%v error=%+v", resp.Success, resp.Data.Valid, resp.Error)
	}
}

func TestTicketVerifyBindMismatch(t *testing.T) {
	cfg := testutil.NewTestConfig()
	manager := ticket.NewManager(cfg.Security.GlobalSecret, cfg.Security.TicketTTLSeconds)
	tok, err := manager.Issue(ticket.BindMatrix{URL: "/resource", IP: "192.168.0.12", UA: "Mozilla/5.0"}, 1)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	h := NewTicketVerifyHandler(cfg, manager)

	body := []byte(`{"ticket":"` + tok + `","bind_matrix":{"url":"/other","ip":"10.0.0.1","ua":"Different UA"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/tickets/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp ticketVerifyEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success || resp.Data.Valid {
		t.Fatalf("expected success valid=false, got success=%v valid=%v error=%+v", resp.Success, resp.Data.Valid, resp.Error)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/api/tickets/verify", bytes.NewReader(body))
	secondReq.Header.Set("Content-Type", "application/json")
	secondRR := httptest.NewRecorder()
	h.ServeHTTP(secondRR, secondReq)
	if secondRR.Code != http.StatusGone {
		t.Fatalf("expected second verify status %d after use consumed, got %d", http.StatusGone, secondRR.Code)
	}
}

func TestTicketVerifyExhaustion(t *testing.T) {
	cfg := testutil.NewTestConfig()
	manager := ticket.NewManager(cfg.Security.GlobalSecret, cfg.Security.TicketTTLSeconds)
	tok, err := manager.Issue(ticket.BindMatrix{URL: "/resource", IP: "192.168.0.13", UA: "Mozilla/5.0"}, 1)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	h := NewTicketVerifyHandler(cfg, manager)

	body := []byte(`{"ticket":"` + tok + `","bind_matrix":{"url":"/resource","ip":"192.168.0.13","ua":"Mozilla/5.0"}}`)

	req1 := httptest.NewRequest(http.MethodPost, "/api/tickets/verify", bytes.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first verify expected status %d, got %d", http.StatusOK, rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/tickets/verify", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusGone {
		t.Fatalf("second verify expected status %d, got %d", http.StatusGone, rr2.Code)
	}

	var resp2 ticketVerifyEnvelope
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("unmarshal second response: %v", err)
	}
	if resp2.Error == nil || resp2.Error.Code != api.ErrTicketExhausted {
		t.Fatalf("expected error code %q, got %+v", api.ErrTicketExhausted, resp2.Error)
	}
}

func TestTicketVerifyExpired(t *testing.T) {
	cfg := testutil.NewTestConfig()
	manager := ticket.NewManager(cfg.Security.GlobalSecret, 1)
	tok, err := manager.Issue(ticket.BindMatrix{URL: "/resource", IP: "192.168.0.14", UA: "Mozilla/5.0"}, 2)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	h := NewTicketVerifyHandler(cfg, manager)

	time.Sleep(2 * time.Second)
	body := []byte(`{"ticket":"` + tok + `","bind_matrix":{"url":"/resource","ip":"192.168.0.14","ua":"Mozilla/5.0"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/tickets/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusGone {
		t.Fatalf("expected status %d, got %d", http.StatusGone, rr.Code)
	}

	var resp ticketVerifyEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != api.ErrTicketExpired {
		t.Fatalf("expected error code %q, got %+v", api.ErrTicketExpired, resp.Error)
	}
}

func TestTicketVerifyInvalidTicket(t *testing.T) {
	cfg := testutil.NewTestConfig()
	manager := ticket.NewManager(cfg.Security.GlobalSecret, cfg.Security.TicketTTLSeconds)
	h := NewTicketVerifyHandler(cfg, manager)

	body := []byte(`{"ticket":"garbage-ticket","bind_matrix":{"url":"/resource","ip":"192.168.0.15","ua":"Mozilla/5.0"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/tickets/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	var resp ticketVerifyEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != api.ErrTicketInvalid {
		t.Fatalf("expected error code %q, got %+v", api.ErrTicketInvalid, resp.Error)
	}
}

func TestTicketVerifyRejectsGet(t *testing.T) {
	cfg := testutil.NewTestConfig()
	manager := ticket.NewManager(cfg.Security.GlobalSecret, cfg.Security.TicketTTLSeconds)
	h := NewTicketVerifyHandler(cfg, manager)

	req := httptest.NewRequest(http.MethodGet, "/api/tickets/verify", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("expected Allow=%q, got %q", http.MethodPost, got)
	}

	var resp ticketVerifyEnvelope
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
