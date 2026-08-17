package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/config"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/unsubscribe"
)

type stubMessages struct {
	suppressed map[string]string
}

func (s *stubMessages) DomainByName(context.Context, string) (*store.Domain, error) {
	return nil, store.ErrNotFound
}
func (s *stubMessages) EnqueueMessage(context.Context, store.NewMessage) (*store.Message, bool, error) {
	return nil, false, nil
}
func (s *stubMessages) MessageByID(context.Context, string) (*store.Message, error) {
	return nil, store.ErrNotFound
}
func (s *stubMessages) FilterSuppressed(_ context.Context, addresses []string) ([]string, []string, error) {
	return addresses, nil, nil
}
func (s *stubMessages) Suppress(_ context.Context, address, reason, _, _ string) error {
	s.suppressed[address] = reason
	return nil
}

type stubPinger struct{}

func (stubPinger) Ping(context.Context) error { return nil }

type stubKeys struct{}

func (stubKeys) APIKeyByHash(context.Context, []byte) (*store.APIKey, error) {
	return nil, store.ErrNotFound
}
func (stubKeys) TouchAPIKey(context.Context, int64, netip.Addr) error { return nil }
func (stubKeys) SendsInLastHour(context.Context, int64) (int, error)  { return 0, nil }

func newTestServer(t *testing.T) (*stubMessages, http.Handler, []byte) {
	t.Helper()
	master := []byte("a-master-key-for-tests-32-bytes!!")
	cfg := &config.Config{Env: config.EnvDevelopment, DKIMMasterKey: master}
	msgs := &stubMessages{suppressed: map[string]string{}}

	srv := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), stubPinger{}, stubKeys{}, msgs, nil, "test")
	return msgs, srv.Handler(), unsubscribe.DeriveSecret(master)
}

// Corporate mail scanners fetch every link before the recipient sees it. If a
// GET unsubscribed, those readers would be removed without ever clicking.
func TestScannerPrefetchDoesNotUnsubscribe(t *testing.T) {
	msgs, handler, secret := newTestServer(t)
	token := unsubscribe.Sign(secret, "01MSG", "reader@example.org", time.Now())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/u/"+token, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("the confirmation page should render, got %d", rec.Code)
	}
	if len(msgs.suppressed) != 0 {
		t.Fatal("a GET unsubscribed someone; scanners would remove real readers")
	}
	if !strings.Contains(rec.Body.String(), "reader@example.org") {
		t.Error("the confirmation should name the address being removed")
	}
	if !strings.Contains(rec.Body.String(), "<form method=\"post\"") {
		t.Error("the page should offer a POST form to confirm")
	}
}

func TestPostUnsubscribes(t *testing.T) {
	msgs, handler, secret := newTestServer(t)
	token := unsubscribe.Sign(secret, "01MSG", "reader@example.org", time.Now())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/u/"+token, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("a confirmed unsubscribe should succeed, got %d", rec.Code)
	}
	if msgs.suppressed["reader@example.org"] != "unsubscribe" {
		t.Fatalf("the address was not suppressed: %v", msgs.suppressed)
	}
}

func TestForgedTokenCannotUnsubscribe(t *testing.T) {
	msgs, handler, _ := newTestServer(t)

	for _, token := range []string{"nonsense", "aaaa.bbbb", ""} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/u/"+token, nil))
		if rec.Code == http.StatusOK && len(msgs.suppressed) > 0 {
			t.Fatalf("a forged token unsubscribed somebody: %q", token)
		}
	}
	if len(msgs.suppressed) != 0 {
		t.Fatalf("nothing should have been suppressed, got %v", msgs.suppressed)
	}
}

func TestExpiredTokenIsGone(t *testing.T) {
	msgs, handler, secret := newTestServer(t)
	old := unsubscribe.Sign(secret, "01MSG", "reader@example.org", time.Now().Add(-unsubscribe.Lifetime-time.Hour))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/u/"+old, nil))

	if rec.Code != http.StatusGone {
		t.Fatalf("an expired link should report gone, got %d", rec.Code)
	}
	if len(msgs.suppressed) != 0 {
		t.Fatal("an expired link unsubscribed somebody")
	}
}

func TestUnsubscribePageSetsRestrictiveHeaders(t *testing.T) {
	_, handler, secret := newTestServer(t)
	token := unsubscribe.Sign(secret, "01MSG", "reader@example.org", time.Now())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/u/"+token, nil))

	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("expected a restrictive policy, got %q", csp)
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Error("the unsubscribe page must not leak the token in a referrer")
	}
}
