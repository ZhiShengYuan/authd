package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mirror-guard/auth-backend/internal/api"
	"github.com/mirror-guard/auth-backend/internal/config"
	"github.com/mirror-guard/auth-backend/internal/pow"
	"github.com/mirror-guard/auth-backend/internal/state"
)

type ChallengeConfigHandler struct {
	config *config.Config
	store  *state.Store
}

func NewChallengeConfigHandler(cfg *config.Config, store *state.Store) *ChallengeConfigHandler {
	return &ChallengeConfigHandler{config: cfg, store: store}
}

// @Summary Configure challenge
// @Description Creates a challenge record and returns a signed prefix bound to challenge_id, difficulty, and bind matrix.
// @Tags challenges
// @Accept json
// @Produce json
// @Param body body api.ChallengeConfigRequest true "Challenge configuration payload"
// @Success 201 {object} api.ResponseEnvelope "success=true, data=api.ChallengeConfigData"
// @Failure 400 {object} api.ResponseEnvelope "success=false, error.code=invalid_request"
// @Failure 405 {string} string "Method not allowed"
// @Router /api/challenges [post]
func (h *ChallengeConfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		api.WriteError(w, http.StatusMethodNotAllowed, api.ErrInvalidRequest, "method not allowed")
		return
	}

	var req api.ChallengeConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "invalid json payload")
		return
	}

	req.ChallengeID = strings.TrimSpace(req.ChallengeID)
	req.BindMatrix.URL = strings.TrimSpace(req.BindMatrix.URL)
	req.BindMatrix.IP = strings.TrimSpace(req.BindMatrix.IP)
	req.BindMatrix.UA = strings.TrimSpace(req.BindMatrix.UA)

	if req.ChallengeID == "" {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "challenge_id is required")
		return
	}
	if req.Difficulty < 1 {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "difficulty must be at least 1")
		return
	}
	if req.BindMatrix.URL == "" || req.BindMatrix.IP == "" || req.BindMatrix.UA == "" {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "bind_matrix.url, bind_matrix.ip, and bind_matrix.ua are required")
		return
	}

	bindHash := hashBindMatrix(req.BindMatrix.URL, req.BindMatrix.IP, req.BindMatrix.UA)
	timestamp := time.Now().Unix()
	challengeKey := encodeChallengePayload(req.ChallengeID, req.Difficulty)
	prefix := pow.GeneratePrefix(
		[]byte(h.config.Security.GlobalSecret),
		challengeKey,
		bindHash,
		timestamp,
		[]byte(strconv.Itoa(req.Difficulty)),
	)

	ttl := time.Duration(h.config.Security.ChallengeTTLSeconds) * time.Second
	if err := h.store.ChallengeStore.Configure(req.ChallengeID, req.Difficulty, req.BindMatrix.URL, req.BindMatrix.IP, req.BindMatrix.UA, ttl); err != nil {
		api.WriteError(w, http.StatusBadRequest, api.ErrInvalidRequest, "failed to configure challenge")
		return
	}

	api.WriteSuccess(w, http.StatusCreated, api.ChallengeConfigData{
		Prefix:      prefix,
		Difficulty:  req.Difficulty,
		ChallengeID: req.ChallengeID,
	})
}

func hashBindMatrix(url, ip, ua string) string {
	h := sha256.Sum256([]byte(url + "|" + ip + "|" + ua))
	return hex.EncodeToString(h[:])
}

func encodeChallengePayload(challengeID string, difficulty int) string {
	return hex.EncodeToString([]byte(challengeID)) + ":" + strconv.Itoa(difficulty)
}
