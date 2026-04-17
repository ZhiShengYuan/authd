package handler

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/mirror-guard/auth-backend/internal/api"
	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/pow"
	"github.com/mirror-guard/auth-backend/internal/state"
)

type ChallengeVerifyHandler struct {
	config *config.Config
	store  *state.Store
}

func NewChallengeVerifyHandler(cfg *config.Config, store *state.Store) *ChallengeVerifyHandler {
	return &ChallengeVerifyHandler{config: cfg, store: store}
}

// @Summary Verify configured challenge
// @Description Consumes a configured challenge_id and validates nonce+prefix. Successful verification marks the challenge as used.
// @Tags challenges
// @Accept json
// @Produce json
// @Param body body api.ChallengeVerifyRequest true "Challenge verification payload"
// @Success 200 {object} api.ResponseEnvelope "success=true, data=api.ChallengeVerifyData"
// @Failure 400 {object} api.ResponseEnvelope "success=false, error.code=invalid_request"
// @Failure 404 {object} api.ResponseEnvelope "success=false, error.code=challenge_not_found"
// @Failure 409 {object} api.ResponseEnvelope "success=false, error.code=challenge_replayed"
// @Failure 410 {object} api.ResponseEnvelope "success=false, error.code=challenge_expired"
// @Failure 405 {string} string "Method not allowed"
// @Router /api/challenges/verify [post]
func (h *ChallengeVerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		api.WriteError(w, http.StatusMethodNotAllowed, api.ErrInvalidRequest, "method not allowed")
		return
	}

	var req api.ChallengeVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "invalid json payload")
		return
	}

	req.ChallengeID = strings.TrimSpace(req.ChallengeID)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.Prefix = strings.TrimSpace(req.Prefix)

	if req.ChallengeID == "" || req.Nonce == "" || req.Prefix == "" {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "challenge_id, nonce, and prefix are required")
		return
	}

	entry, err := h.store.ChallengeStore.Consume(req.ChallengeID)
	if err != nil {
		switch {
		case errors.Is(err, state.ErrChallengeNotFound):
			api.WriteError(w, http.StatusNotFound, api.ErrChallengeNotFound, "challenge not found")
		case errors.Is(err, state.ErrChallengeExpired):
			api.WriteError(w, http.StatusGone, api.ErrChallengeExpired, "challenge expired")
		case errors.Is(err, state.ErrChallengeReplayed):
			api.WriteError(w, http.StatusConflict, api.ErrChallengeReplayed, "challenge already used")
		default:
			api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "unable to consume challenge")
		}
		return
	}

	prefixData, err := pow.VerifyPrefixIntegrity(req.Prefix, []byte(h.config.Security.GlobalSecret), h.config.Security.ChallengeTTLSeconds)
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, api.ErrChallengeInvalid, "challenge verification failed")
		return
	}

	prefixChallengeID, prefixDifficulty, err := decodeChallengePayload(prefixData.TargetURI)
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, api.ErrChallengeInvalid, "challenge verification failed")
		return
	}

	if prefixChallengeID != req.ChallengeID || prefixChallengeID != entry.ChallengeID {
		api.WriteError(w, http.StatusBadRequest, api.ErrChallengeInvalid, "challenge verification failed")
		return
	}

	if prefixDifficulty != entry.Difficulty {
		api.WriteError(w, http.StatusBadRequest, api.ErrChallengeInvalid, "challenge verification failed")
		return
	}

	if prefixData.SubnetKey != hashBindMatrix(entry.BindURL, entry.BindIP, entry.BindUA) {
		api.WriteError(w, http.StatusBadRequest, api.ErrChallengeInvalid, "challenge verification failed")
		return
	}

	if !pow.Verify(req.Prefix, req.Nonce, entry.Difficulty) {
		api.WriteError(w, http.StatusBadRequest, api.ErrChallengeInvalid, "challenge verification failed")
		return
	}

	api.WriteSuccess(w, http.StatusOK, api.ChallengeVerifyData{Valid: true})
}

func decodeChallengePayload(payload string) (challengeID string, difficulty int, err error) {
	parts := strings.Split(payload, ":")
	if len(parts) != 2 {
		return "", 0, errors.New("invalid challenge payload")
	}

	idBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, err
	}

	difficulty, err = strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, err
	}

	if len(idBytes) == 0 || difficulty < 1 {
		return "", 0, errors.New("invalid challenge payload")
	}

	return string(idBytes), difficulty, nil
}
