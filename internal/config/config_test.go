package config

import (
	"strings"
	"testing"
)

const validDSN = "postgres://aiemail:pw@localhost:5432/aiemail"

func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range []string{
		"AIEMAIL_ENV", "AIEMAIL_LISTEN_ADDR", "AIEMAIL_DATABASE_URL", "AIEMAIL_LOG_LEVEL",
		"AIEMAIL_SEND_ENABLED", "AIEMAIL_ENGINE_URL", "AIEMAIL_MAX_SEND_PER_HOUR",
	} {
		t.Setenv(k, "")
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestSendingIsDisabledByDefault(t *testing.T) {
	setEnv(t, map[string]string{"AIEMAIL_DATABASE_URL": validDSN})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected a valid default configuration, got %v", err)
	}
	if cfg.SendEnabled {
		t.Fatal("a fresh install must not be able to send mail")
	}
	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Fatalf("default listen address should be loopback, got %q", cfg.ListenAddr)
	}
}

func TestDatabaseURLIsRequired(t *testing.T) {
	setEnv(t, nil)

	if _, err := Load(); err == nil {
		t.Fatal("configuration without a database must be rejected")
	} else if !strings.Contains(err.Error(), "AIEMAIL_DATABASE_URL is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendingRequiresEngineAndCeiling(t *testing.T) {
	setEnv(t, map[string]string{
		"AIEMAIL_DATABASE_URL": validDSN,
		"AIEMAIL_SEND_ENABLED": "true",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("sending without an engine or ceiling must be rejected")
	}
	for _, want := range []string{"AIEMAIL_ENGINE_URL is required", "AIEMAIL_MAX_SEND_PER_HOUR must be greater than zero"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got %v", want, err)
		}
	}
}

func TestSendingEnabledWithCompleteConfig(t *testing.T) {
	setEnv(t, map[string]string{
		"AIEMAIL_DATABASE_URL":      validDSN,
		"AIEMAIL_SEND_ENABLED":      "true",
		"AIEMAIL_ENGINE_URL":        "http://127.0.0.1:8000",
		"AIEMAIL_MAX_SEND_PER_HOUR": "200",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("complete sending configuration should load, got %v", err)
	}
	if !cfg.SendEnabled || cfg.MaxSendPerHour != 200 {
		t.Fatalf("unexpected configuration: %+v", cfg)
	}
}

func TestProductionRejectsPlaintextDatabase(t *testing.T) {
	setEnv(t, map[string]string{
		"AIEMAIL_ENV":          EnvProduction,
		"AIEMAIL_DATABASE_URL": validDSN + "?sslmode=disable",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("production must reject an unencrypted database connection")
	}
	if !strings.Contains(err.Error(), "requires an encrypted database connection") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProductionRejectsBindingEveryInterface(t *testing.T) {
	setEnv(t, map[string]string{
		"AIEMAIL_ENV":          EnvProduction,
		"AIEMAIL_DATABASE_URL": validDSN,
		"AIEMAIL_LISTEN_ADDR":  "0.0.0.0:8080",
	})

	if _, err := Load(); err == nil {
		t.Fatal("production must reject binding every interface")
	}
}

func TestInvalidValuesAreReportedTogether(t *testing.T) {
	setEnv(t, map[string]string{
		"AIEMAIL_ENV":               "staging",
		"AIEMAIL_DATABASE_URL":      "mysql://localhost/db",
		"AIEMAIL_LOG_LEVEL":         "chatty",
		"AIEMAIL_MAX_SEND_PER_HOUR": "many",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("invalid configuration must be rejected")
	}
	var ve *ValidationError
	if !asValidationError(err, &ve) {
		t.Fatalf("expected a ValidationError, got %T", err)
	}
	if len(ve.Problems) < 4 {
		t.Fatalf("every problem should be reported at once, got %v", ve.Problems)
	}
}

func asValidationError(err error, target **ValidationError) bool {
	ve, ok := err.(*ValidationError)
	if ok {
		*target = ve
	}
	return ok
}
