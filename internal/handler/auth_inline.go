package handler

import (
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/mirror-guard/auth-backend/internal/policy"
)

type AuthInlineHandler struct {
	policyRef atomic.Pointer[policy.Set]
	mu        sync.RWMutex
	executor  http.Handler
}

func NewAuthInlineHandler(pol *policy.Set) *AuthInlineHandler {
	h := &AuthInlineHandler{}
	h.SetPolicy(pol)
	return h
}

func (h *AuthInlineHandler) SetPolicy(pol *policy.Set) {
	h.policyRef.Store(pol)
}

func (h *AuthInlineHandler) SetExecutor(executor http.Handler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.executor = executor
}

func (h *AuthInlineHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = h.policyRef.Load()

	h.mu.RLock()
	executor := h.executor
	h.mu.RUnlock()

	if executor == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	executor.ServeHTTP(w, r)
}
