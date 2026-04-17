package apidoc

const (
	ErrChallengeRequired = "challenge_required"
	ErrInvalidPoW        = "invalid_pow"
	ErrInvalidPrefix     = "invalid_prefix"
	ErrReplayDetected    = "replay_detected"
	ErrQuotaExceeded     = "quota_exceeded"
	ErrInvalidClientIP   = "invalid_client_ip"
	ErrMissingTarget     = "missing_target"
	ErrMethodNotAllowed  = "method_not_allowed"
	ErrInternalError     = "internal_error"
)

// ChallengeResponse represents the PoW challenge issued to a client.
type ChallengeResponse struct {
	// Prefix is the signed challenge prefix tied to client subnet and target.
	Prefix string `json:"prefix" example:"1700000000:abcdef12:signaturehex"`
	// Difficulty is the required number of leading zero bits/characters for PoW validation.
	Difficulty int `json:"difficulty" example:"5"`
	// Target is the protected resource URL that this challenge authorizes when solved.
	Target string `json:"target" example:"https://mirror.example.com/file.iso"`
}

// VerifyPoWRequest represents the PoW solution submission.
type VerifyPoWRequest struct {
	// Prefix is the signed challenge prefix returned by the challenge endpoint.
	Prefix string `json:"prefix" example:"1700000000:abcdef12:signaturehex"`
	// Nonce is the client-computed value that satisfies the requested PoW difficulty.
	Nonce string `json:"nonce" example:"42"`
	// TargetURI is the original protected URL to redirect to after successful verification.
	TargetURI string `json:"target_uri" example:"https://mirror.example.com/file.iso"`
}

// VerifyPoWError represents an error response from the verify endpoint.
type VerifyPoWError struct {
	// Error is a machine-readable error code for programmatic handling.
	Error string `json:"error" example:"invalid proof of work"`
}
