package api

import (
	"encoding/json"
	"log"
	"net/http"
)

type ResponseEnvelope struct {
	Success bool           `json:"success"`
	Data    any            `json:"data"`
	Error   *EnvelopeError `json:"error"`
}

type EnvelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func SuccessResponse(data any) ResponseEnvelope {
	return ResponseEnvelope{
		Success: true,
		Data:    data,
		Error:   nil,
	}
}

func ErrorResponse(code, message string) ResponseEnvelope {
	return ResponseEnvelope{
		Success: false,
		Data:    nil,
		Error: &EnvelopeError{
			Code:    code,
			Message: message,
		},
	}
}

func WriteSuccess(w http.ResponseWriter, statusCode int, data any) {
	writeJSON(w, statusCode, SuccessResponse(data))
}

func WriteError(w http.ResponseWriter, statusCode int, code, message string) {
	writeJSON(w, statusCode, ErrorResponse(code, message))
}

func writeJSON(w http.ResponseWriter, statusCode int, payload ResponseEnvelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("api: json encode error: %v", err)
	}
}
