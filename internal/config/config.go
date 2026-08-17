// Package config loads runtime configuration from the environment.
//
// Every value comes from the environment so one binary runs unchanged in
// development and production. Validation refuses unsafe combinations at
// startup rather than logging a warning and continuing: an operator who
// misconfigures this service damages sending reputation, which no later fix
// restores.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	EnvDevelopment = "development"
	EnvProduction  = "production"
)

type Config struct {
	Env         string
	ListenAddr  string
	DatabaseURL string
	LogLevel    string

	// SendEnabled gates every outbound message. A fresh install cannot send
	// until an operator turns this on deliberately.
	SendEnabled bool
	EngineURL   string

	// MaxSendPerHour is the backstop for every other defect: a bug that would
	// flood cannot flood if this ceiling holds. Zero means unlimited and is
	// rejected in production.
	MaxSendPerHour int

	// DKIMMasterKey wraps every signing key at rest. It is required to send,
	// because unsigned mail is refused by mailbox providers and because a
	// plaintext signing key in the database is the worst secret we could hold.
	DKIMMasterKey []byte

	// MTASTSHosts are the mail exchangers covered by our published policy.
	// Empty means no policy is served, which is honest: advertising one we do
	// not serve breaks delivery for senders that fetch it.
	MTASTSHosts  []string
	MTASTSMode   string
	MTASTSMaxAge int

	SecurityContact   string
	SecurityPolicyURL string

	// ConsolePasswordHash enables the operator console. Absent, the console is
	// not served at all: an interface that manages sending credentials should
	// not exist without a way to protect it.
	// PublicBaseURL is where recipients reach us, used for unsubscribe links.
	// Offering a link nobody can reach is worse than offering none: it tells a
	// provider we support unsubscribing when we do not.
	PublicBaseURL string

	ConsolePasswordHash string

	// ConsoleSecureCookies marks the session cookie Secure. It follows the
	// environment so local development over http still works while production
	// never sends the cookie in clear.
	ConsoleSecureCookies bool

	ShutdownGrace time.Duration
}

type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid configuration:\n  - %s", strings.Join(e.Problems, "\n  - "))
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	cfg := &Config{
		Env:            envOr("AIEMAIL_ENV", EnvDevelopment),
		ListenAddr:     envOr("AIEMAIL_LISTEN_ADDR", "127.0.0.1:8080"),
		DatabaseURL:    os.Getenv("AIEMAIL_DATABASE_URL"),
		LogLevel:       envOr("AIEMAIL_LOG_LEVEL", "info"),
		EngineURL:      os.Getenv("AIEMAIL_ENGINE_URL"),
		ShutdownGrace:  30 * time.Second,
		MaxSendPerHour: 0,
	}

	var problems []string

	sendEnabled, err := envBool("AIEMAIL_SEND_ENABLED", false)
	if err != nil {
		problems = append(problems, err.Error())
	}
	cfg.SendEnabled = sendEnabled

	maxPerHour, err := envInt("AIEMAIL_MAX_SEND_PER_HOUR", 0)
	if err != nil {
		problems = append(problems, err.Error())
	}
	cfg.MaxSendPerHour = maxPerHour

	if raw := strings.TrimSpace(os.Getenv("AIEMAIL_DKIM_MASTER_KEY")); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		switch {
		case err != nil:
			problems = append(problems, "AIEMAIL_DKIM_MASTER_KEY must be base64")
		case len(key) != 32:
			problems = append(problems, fmt.Sprintf("AIEMAIL_DKIM_MASTER_KEY must decode to 32 bytes, got %d", len(key)))
		default:
			cfg.DKIMMasterKey = key
		}
	}

	cfg.PublicBaseURL = strings.TrimSuffix(strings.TrimSpace(os.Getenv("AIEMAIL_PUBLIC_BASE_URL")), "/")
	cfg.MTASTSHosts = splitList(os.Getenv("AIEMAIL_MTA_STS_HOSTS"))
	cfg.MTASTSMode = envOr("AIEMAIL_MTA_STS_MODE", "testing")
	cfg.MTASTSMaxAge = 604800
	if age, err := envInt("AIEMAIL_MTA_STS_MAX_AGE", 604800); err != nil {
		problems = append(problems, err.Error())
	} else {
		cfg.MTASTSMaxAge = age
	}
	cfg.SecurityContact = strings.TrimSpace(os.Getenv("AIEMAIL_SECURITY_CONTACT"))
	cfg.SecurityPolicyURL = strings.TrimSpace(os.Getenv("AIEMAIL_SECURITY_POLICY_URL"))

	cfg.ConsolePasswordHash = strings.TrimSpace(os.Getenv("AIEMAIL_CONSOLE_PASSWORD_HASH"))
	cfg.ConsoleSecureCookies = cfg.Env == EnvProduction

	problems = append(problems, cfg.validate()...)
	if len(problems) > 0 {
		return nil, &ValidationError{Problems: problems}
	}
	return cfg, nil
}

func (c *Config) validate() []string {
	var problems []string

	switch c.Env {
	case EnvDevelopment, EnvProduction:
	default:
		problems = append(problems, fmt.Sprintf("AIEMAIL_ENV must be %q or %q, got %q", EnvDevelopment, EnvProduction, c.Env))
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		problems = append(problems, fmt.Sprintf("AIEMAIL_LOG_LEVEL must be debug, info, warn or error, got %q", c.LogLevel))
	}

	if c.DatabaseURL == "" {
		problems = append(problems, "AIEMAIL_DATABASE_URL is required")
	} else if err := validateDatabaseURL(c.DatabaseURL, c.Env); err != nil {
		problems = append(problems, err.Error())
	}

	if c.ListenAddr == "" {
		problems = append(problems, "AIEMAIL_LISTEN_ADDR is required")
	}

	if c.MaxSendPerHour < 0 {
		problems = append(problems, "AIEMAIL_MAX_SEND_PER_HOUR cannot be negative")
	}

	if len(c.MTASTSHosts) > 0 {
		switch c.MTASTSMode {
		case "testing", "enforce", "none":
		default:
			problems = append(problems, fmt.Sprintf("AIEMAIL_MTA_STS_MODE must be testing, enforce or none, got %q", c.MTASTSMode))
		}
		// Below a day a policy is refetched constantly; above a year a mistake
		// stays cached long after it is fixed.
		if c.MTASTSMaxAge < 86400 || c.MTASTSMaxAge > 31557600 {
			problems = append(problems, "AIEMAIL_MTA_STS_MAX_AGE must be between 86400 and 31557600 seconds")
		}
	}

	if c.SendEnabled {
		if c.EngineURL == "" {
			problems = append(problems, "AIEMAIL_ENGINE_URL is required when AIEMAIL_SEND_ENABLED is true")
		} else if err := validateEngineURL(c.EngineURL); err != nil {
			problems = append(problems, err.Error())
		}
		if c.MaxSendPerHour <= 0 {
			problems = append(problems, "AIEMAIL_MAX_SEND_PER_HOUR must be greater than zero when sending is enabled")
		}
		if len(c.DKIMMasterKey) == 0 {
			problems = append(problems, "AIEMAIL_DKIM_MASTER_KEY is required when sending is enabled; unsigned mail is refused by mailbox providers")
		}
	}

	if c.IsProduction() {
		if strings.HasPrefix(c.ListenAddr, "0.0.0.0:") {
			problems = append(problems, "AIEMAIL_LISTEN_ADDR binds every interface in production; bind a specific address and terminate TLS in front")
		}
	}

	return problems
}

func validateDatabaseURL(raw, env string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("AIEMAIL_DATABASE_URL is not a valid URL: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return fmt.Errorf("AIEMAIL_DATABASE_URL must use the postgres scheme, got %q", u.Scheme)
	}
	if env == EnvProduction && u.Query().Get("sslmode") == "disable" {
		return errors.New("AIEMAIL_DATABASE_URL disables TLS; production requires an encrypted database connection")
	}
	return nil
}

func validateEngineURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("AIEMAIL_ENGINE_URL is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("AIEMAIL_ENGINE_URL must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("AIEMAIL_ENGINE_URL is missing a host")
	}
	return nil
}

func (c *Config) IsProduction() bool { return c.Env == EnvProduction }

func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback, fmt.Errorf("%s must be a boolean, got %q", key, raw)
	}
	return v, nil
}

func envInt(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback, fmt.Errorf("%s must be an integer, got %q", key, raw)
	}
	return v, nil
}
