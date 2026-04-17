package handler

import (
	"encoding/json"
	"net/http"

	"github.com/mirror-guard/auth-backend/internal/api"
	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/ticket"
)

type TicketIssueHandler struct {
	config  *config.Config
	manager *ticket.TicketManager
}

func NewTicketIssueHandler(cfg *config.Config, manager *ticket.TicketManager) *TicketIssueHandler {
	return &TicketIssueHandler{config: cfg, manager: manager}
}

// @Summary Issue ticket
// @Description Issues a multi-use ticket bound to the provided bind matrix.
// @Tags tickets
// @Accept json
// @Produce json
// @Param body body api.TicketIssueRequest true "Ticket issue payload"
// @Success 201 {object} api.ResponseEnvelope "success=true, data=api.TicketIssueData"
// @Failure 400 {object} api.ResponseEnvelope "success=false, error.code=invalid_request or ticket_exhausted"
// @Failure 405 {string} string "Method not allowed"
// @Router /api/tickets [post]
func (h *TicketIssueHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		api.WriteError(w, http.StatusMethodNotAllowed, api.ErrInvalidRequest, "method not allowed")
		return
	}

	if h.manager == nil {
		api.WriteError(w, http.StatusBadRequest, api.ErrTicketExhausted, "ticket manager unavailable")
		return
	}

	var req api.TicketIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "invalid JSON body")
		return
	}

	if req.BindMatrix.URL == "" || req.BindMatrix.IP == "" || req.BindMatrix.UA == "" {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "bind_matrix.url, bind_matrix.ip, and bind_matrix.ua are required")
		return
	}
	if req.Uses < 1 {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "uses must be at least 1")
		return
	}

	token, err := h.manager.Issue(ticket.BindMatrix{
		URL: req.BindMatrix.URL,
		IP:  req.BindMatrix.IP,
		UA:  req.BindMatrix.UA,
	}, req.Uses)
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, api.ErrTicketExhausted, "failed to issue ticket")
		return
	}

	api.WriteSuccess(w, http.StatusCreated, api.TicketIssueData{Ticket: token})
}
