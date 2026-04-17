package api

const (
	PathChallenges       = "/api/challenges"
	PathChallengesVerify = "/api/challenges/verify"
	PathTickets          = "/api/tickets"
	PathTicketsVerify    = "/api/tickets/verify"
)

type BindMatrix struct {
	URL string `json:"url"`
	IP  string `json:"ip"`
	UA  string `json:"ua"`
}

type ChallengeConfigRequest struct {
	ChallengeID string     `json:"challenge_id"`
	Difficulty  int        `json:"difficulty"`
	BindMatrix  BindMatrix `json:"bind_matrix"`
}

type ChallengeVerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	Prefix      string `json:"prefix"`
}

type TicketIssueRequest struct {
	BindMatrix BindMatrix `json:"bind_matrix"`
	Uses       int        `json:"uses"`
}

type TicketVerifyRequest struct {
	Ticket     string     `json:"ticket"`
	BindMatrix BindMatrix `json:"bind_matrix"`
}

type ChallengeConfigData struct {
	Prefix      string `json:"prefix"`
	Difficulty  int    `json:"difficulty"`
	ChallengeID string `json:"challenge_id"`
}

type ChallengeVerifyData struct {
	Valid bool `json:"valid"`
}

type TicketIssueData struct {
	Ticket string `json:"ticket"`
}

type TicketVerifyData struct {
	Valid bool `json:"valid"`
}
