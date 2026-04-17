package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSuccessResponseShape(t *testing.T) {
	payload := SuccessResponse(ChallengeVerifyData{Valid: true})

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal success response: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal success response: %v", err)
	}

	if parsed["success"] != true {
		t.Fatalf("expected success=true, got %v", parsed["success"])
	}
	if parsed["error"] != nil {
		t.Fatalf("expected error=null, got %v", parsed["error"])
	}
	data, ok := parsed["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected object data, got %T", parsed["data"])
	}
	if data["valid"] != true {
		t.Fatalf("expected data.valid=true, got %v", data["valid"])
	}
}

func TestErrorResponseShape(t *testing.T) {
	payload := ErrorResponse(ErrInvalidRequest, "invalid input")

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error response: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}

	if parsed["success"] != false {
		t.Fatalf("expected success=false, got %v", parsed["success"])
	}
	if parsed["data"] != nil {
		t.Fatalf("expected data=null, got %v", parsed["data"])
	}
	errObj, ok := parsed["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected object error, got %T", parsed["error"])
	}
	if errObj["code"] != ErrInvalidRequest {
		t.Fatalf("expected error.code=%q, got %v", ErrInvalidRequest, errObj["code"])
	}
	if errObj["message"] != "invalid input" {
		t.Fatalf("expected error.message=%q, got %v", "invalid input", errObj["message"])
	}
}

func TestWriteSuccessSetsContentTypeStatusAndJSON(t *testing.T) {
	rr := httptest.NewRecorder()

	WriteSuccess(rr, http.StatusCreated, TicketIssueData{Ticket: "tkn_123"})

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", got)
	}

	var parsed struct {
		Success bool `json:"success"`
		Data    struct {
			Ticket string `json:"ticket"`
		} `json:"data"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}
	if !parsed.Success {
		t.Fatalf("expected success=true")
	}
	if parsed.Data.Ticket != "tkn_123" {
		t.Fatalf("expected ticket=tkn_123, got %q", parsed.Data.Ticket)
	}
	if parsed.Error != nil {
		t.Fatalf("expected error=null, got %v", parsed.Error)
	}
}

func TestWriteErrorSetsContentTypeStatusAndJSON(t *testing.T) {
	rr := httptest.NewRecorder()

	WriteError(rr, http.StatusBadRequest, ErrTicketInvalid, "ticket mismatch")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", got)
	}

	var parsed struct {
		Success bool `json:"success"`
		Data    any  `json:"data"`
		Error   struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}
	if parsed.Success {
		t.Fatalf("expected success=false")
	}
	if parsed.Data != nil {
		t.Fatalf("expected data=null, got %v", parsed.Data)
	}
	if parsed.Error.Code != ErrTicketInvalid {
		t.Fatalf("expected code=%q, got %q", ErrTicketInvalid, parsed.Error.Code)
	}
	if parsed.Error.Message != "ticket mismatch" {
		t.Fatalf("expected message=%q, got %q", "ticket mismatch", parsed.Error.Message)
	}
}
