package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/config"
)

func serverWith(cfg *config.Config) http.Handler {
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)),
		stubPinger{}, stubKeys{}, &stubMessages{suppressed: map[string]string{}}, nil, "test").Handler()
}

// A policy that is advertised in DNS but not served leaves senders unable to
// fetch it. Serving one that was never configured is the same mistake in
// reverse, so the absence is a 404 rather than an empty policy.
func TestNoPolicyIsServedWhenNoneIsConfigured(t *testing.T) {
	handler := serverWith(&config.Config{Env: config.EnvDevelopment})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/mta-sts.txt", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected no policy, got %d", rec.Code)
	}
}

func TestPolicyIsServedInTheExpectedFormat(t *testing.T) {
	handler := serverWith(&config.Config{
		Env:          config.EnvDevelopment,
		MTASTSHosts:  []string{"mx1.example.com", "mx2.example.com"},
		MTASTSMode:   "testing",
		MTASTSMaxAge: 604800,
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/mta-sts.txt", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected the policy to be served, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"version: STSv1", "mode: testing", "mx: mx1.example.com", "mx: mx2.example.com", "max_age: 604800"} {
		if !strings.Contains(body, want) {
			t.Errorf("policy should contain %q, got:\n%s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("policy must be text/plain, got %q", ct)
	}
}

func TestSecurityTxtIsAbsentUntilAContactExists(t *testing.T) {
	handler := serverWith(&config.Config{Env: config.EnvDevelopment})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("an empty contact must not be published, got %d", rec.Code)
	}
}

func TestSecurityTxtPublishesTheContact(t *testing.T) {
	handler := serverWith(&config.Config{
		Env:               config.EnvDevelopment,
		SecurityContact:   "https://example.com/security",
		SecurityPolicyURL: "https://example.com/policy",
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "Contact: https://example.com/security") {
		t.Errorf("contact missing from security.txt:\n%s", body)
	}
	if !strings.Contains(body, "Policy: https://example.com/policy") {
		t.Errorf("policy link missing from security.txt:\n%s", body)
	}
}
