package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mirror-guard/auth-backend/internal/api"
	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/ticket"
)

type TicketVerifyHandler struct {
	config  *config.Config
	manager *ticket.TicketManager
}

func NewTicketVerifyHandler(cfg *config.Config, manager *ticket.TicketManager) *TicketVerifyHandler {
	return &TicketVerifyHandler{config: cfg, manager: manager}
}

// @Summary Verify ticket
// @Description Verifies a ticket against bind matrix and consumes one use on each successful check.
// @Tags tickets
// @Accept json
// @Produce json
// @Param body body api.TicketVerifyRequest true "Ticket verify payload"
// @Success 200 {object} api.ResponseEnvelope "success=true, data=api.TicketVerifyData"
// @Failure 400 {object} api.ResponseEnvelope "success=false, error.code=invalid_request or ticket_invalid"
// @Failure 404 {object} api.ResponseEnvelope "success=false, error.code=ticket_not_found"
// @Failure 410 {object} api.ResponseEnvelope "success=false, error.code=ticket_expired or ticket_exhausted"
// @Failure 405 {string} string "Method not allowed"
// @Router /api/tickets/verify [post]
func (h *TicketVerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		api.WriteError(w, http.StatusMethodNotAllowed, api.ErrInvalidRequest, "method not allowed")
		return
	}

	if h.manager == nil {
		api.WriteError(w, http.StatusBadRequest, api.ErrTicketInvalid, "ticket manager unavailable")
		return
	}

	var req api.TicketVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "invalid JSON body")
		return
	}

	if req.Ticket == "" {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "ticket is required")
		return
	}
	if req.BindMatrix.URL == "" || req.BindMatrix.IP == "" || req.BindMatrix.UA == "" {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "bind_matrix.url, bind_matrix.ip, and bind_matrix.ua are required")
		return
	}

	valid, err := h.manager.Verify(req.Ticket, ticket.BindMatrix{
		URL: req.BindMatrix.URL,
		IP:  req.BindMatrix.IP,
		UA:  req.BindMatrix.UA,
	})
	if err != nil {
		switch {
		case errors.Is(err, ticket.ErrTicketInvalid):
			api.WriteError(w, http.StatusBadRequest, api.ErrTicketInvalid, "ticket is invalid")
		case errors.Is(err, ticket.ErrTicketNotFound):
			api.WriteError(w, http.StatusNotFound, api.ErrTicketNotFound, "ticket not found")
		case errors.Is(err, ticket.ErrTicketExpired):
			api.WriteError(w, http.StatusGone, api.ErrTicketExpired, "ticket expired")
		case errors.Is(err, ticket.ErrTicketExhausted):
			api.WriteError(w, http.StatusGone, api.ErrTicketExhausted, "ticket exhausted")
		default:
			api.WriteError(w, http.StatusBadRequest, api.ErrTicketInvalid, "ticket verification failed")
		}
		return
	}

	api.WriteSuccess(w, http.StatusOK, api.TicketVerifyData{Valid: valid})
}
