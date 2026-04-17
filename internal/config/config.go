package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type Config struct {
	Server   ServerConfig   `json:"server"`
	Security SecurityConfig `json:"security"`
}

type ServerConfig struct {
	ListenNetwork string `json:"listen_network"`
	ListenAddress string `json:"listen_address"`
}

type SecurityConfig struct {
	GlobalSecret     string `json:"global_secret"`
	CookieName       string `json:"cookie_name"`
	CookieTTLSeconds int    `json:"cookie_ttl_seconds"`
	NonceTTLSeconds  int    `json:"nonce_ttl_seconds"`

	PowMinDifficulty int `json:"pow_min_difficulty"`
	PowMaxDifficulty int `json:"pow_max_difficulty"`

	ChallengeTTLSeconds int `json:"challenge_ttl_seconds"`
	TicketTTLSeconds    int `json:"ticket_ttl_seconds"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse JSON config: %w", err)
	}

	applyDefaults(&cfg)
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Server.ListenNetwork == "" {
		cfg.Server.ListenNetwork = "tcp"
	}

	if cfg.Security.CookieName == "" {
		cfg.Security.CookieName = "auth_token"
	}

	if cfg.Security.CookieTTLSeconds == 0 {
		cfg.Security.CookieTTLSeconds = 15
	}
	if cfg.Security.NonceTTLSeconds == 0 {
		cfg.Security.NonceTTLSeconds = 30
	}
	if cfg.Security.PowMinDifficulty == 0 {
		cfg.Security.PowMinDifficulty = 4
	}
	if cfg.Security.PowMaxDifficulty == 0 {
		cfg.Security.PowMaxDifficulty = 10
	}
	if cfg.Security.ChallengeTTLSeconds == 0 {
		cfg.Security.ChallengeTTLSeconds = 30
	}
	if cfg.Security.TicketTTLSeconds == 0 {
		cfg.Security.TicketTTLSeconds = 300
	}
}

func validateConfig(cfg *Config) error {
	if len(cfg.Security.GlobalSecret) < 32 {
		return errors.New("global_secret must be at least 32 bytes")
	}

	if cfg.Security.CookieTTLSeconds <= 0 {
		return errors.New("cookie_ttl_seconds must be greater than 0")
	}

	if cfg.Security.NonceTTLSeconds <= 0 {
		return errors.New("nonce_ttl_seconds must be greater than 0")
	}

	if cfg.Security.PowMinDifficulty <= 0 {
		return errors.New("pow_min_difficulty must be greater than 0")
	}

	if cfg.Security.PowMaxDifficulty < cfg.Security.PowMinDifficulty {
		return errors.New("pow_max_difficulty must be greater than or equal to pow_min_difficulty")
	}

	if cfg.Security.ChallengeTTLSeconds <= 0 {
		return errors.New("challenge_ttl_seconds must be greater than 0")
	}

	if cfg.Security.TicketTTLSeconds <= 0 {
		return errors.New("ticket_ttl_seconds must be greater than 0")
	}

	if cfg.Server.ListenAddress == "" {
		return errors.New("server.listen_address is required")
	}

	return nil
}
