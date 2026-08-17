package console

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
)

const testPassword = "correct-horse-battery"

type fakeStore struct {
	revoked      []int64
	unsuppressed []string
	msgs         []store.MessageRow
}

func (f *fakeStore) ListDomains(context.Context) ([]store.DomainRow, error) {
	return []store.DomainRow{{Name: "example.com", Status: "verified", Token: "aiemail-verify=abc"}}, nil
}
func (f *fakeStore) ListAPIKeys(context.Context) ([]store.KeyRow, error) {
	return []store.KeyRow{{ID: 1, Name: "prod", Prefix: "aiem_live_abc…", ExpiresAt: time.Now().Add(time.Hour)}}, nil
}
func (f *fakeStore) ListMessages(context.Context, string, int) ([]store.MessageRow, error) {
	return f.msgs, nil
}
func (f *fakeStore) DashboardCounts(context.Context) (store.Counts, error) {
	return store.Counts{Queued: 2}, nil
}
func (f *fakeStore) RevokeAPIKey(_ context.Context, id int64) error {
	f.revoked = append(f.revoked, id)
	return nil
}
func (f *fakeStore) ListSuppressions(context.Context, int) ([]store.Suppression, error) {
	return []store.Suppression{
		{Address: "bounced@example.org", Reason: "hard_bounce", Detail: "no such user", CreatedAt: time.Now()},
		{Address: "angry@example.org", Reason: "complaint", CreatedAt: time.Now()},
	}, nil
}
func (f *fakeStore) Unsuppress(_ context.Context, address string) error {
	f.unsuppressed = append(f.unsuppressed, address)
	return nil
}

func newTestConsole(t *testing.T, s Store) (*Console, http.Handler) {
	t.Helper()
	encoded, err := HashPassword(testPassword)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	hash, err := ParsePasswordHash(encoded)
	if err != nil {
		t.Fatalf("parsing hash: %v", err)
	}
	c, err := New(s, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{PasswordHash: hash, Env: "development"})
	if err != nil {
		t.Fatalf("console: %v", err)
	}
	mux := http.NewServeMux()
	c.Routes(mux)
	return c, mux
}

// signIn returns the session cookie and the CSRF token embedded in the page.
func signIn(t *testing.T, mux http.Handler) (*http.Cookie, string) {
	t.Helper()
	form := url.Values{"password": {testPassword}}
	req := httptest.NewRequest(http.MethodPost, "/console/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login should redirect, got %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login set no session cookie")
	}

	page := httptest.NewRequest(http.MethodGet, "/console/keys", nil)
	page.AddCookie(cookies[0])
	pageRec := httptest.NewRecorder()
	mux.ServeHTTP(pageRec, page)

	body := pageRec.Body.String()
	const marker = `name="csrf" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no csrf token rendered on the keys page")
	}
	rest := body[i+len(marker):]
	return cookies[0], rest[:strings.Index(rest, `"`)]
}

func TestUnauthenticatedPagesRedirectToLogin(t *testing.T) {
	_, mux := newTestConsole(t, &fakeStore{})

	for _, path := range []string{"/console", "/console/domains", "/console/keys", "/console/messages"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s should redirect an anonymous visitor, got %d", path, rec.Code)
		}
	}
}

func TestWrongPasswordDoesNotCreateASession(t *testing.T) {
	_, mux := newTestConsole(t, &fakeStore{})

	form := url.Values{"password": {"wrong-password-entirely"}}
	req := httptest.NewRequest(http.MethodPost, "/console/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("a failed login issued a session cookie")
		}
	}
}

func TestSessionCookieIsProtected(t *testing.T) {
	_, mux := newTestConsole(t, &fakeStore{})
	cookie, _ := signIn(t, mux)

	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly so scripts cannot read it")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Error("session cookie must be SameSite=Strict")
	}
	if cookie.Path != "/console" {
		t.Errorf("cookie should be scoped to the console, got %q", cookie.Path)
	}
}

// A stolen console session can create sending credentials, so a cross-site
// request must not be able to act with the operator's cookie.
func TestStateChangeWithoutCSRFTokenIsRefused(t *testing.T) {
	fake := &fakeStore{}
	_, mux := newTestConsole(t, fake)
	cookie, _ := signIn(t, mux)

	form := url.Values{"id": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/console/keys/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("a request without a token must be refused, got %d", rec.Code)
	}
	if len(fake.revoked) != 0 {
		t.Fatal("the key was revoked despite a missing request token")
	}
}

func TestStateChangeWithWrongCSRFTokenIsRefused(t *testing.T) {
	fake := &fakeStore{}
	_, mux := newTestConsole(t, fake)
	cookie, _ := signIn(t, mux)

	form := url.Values{"id": {"1"}, "csrf": {"not-the-right-token"}}
	req := httptest.NewRequest(http.MethodPost, "/console/keys/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || len(fake.revoked) != 0 {
		t.Fatal("a forged request token must be refused")
	}
}

func TestRevokeWorksWithAValidToken(t *testing.T) {
	fake := &fakeStore{}
	_, mux := newTestConsole(t, fake)
	cookie, csrf := signIn(t, mux)

	form := url.Values{"id": {"7"}, "csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/console/keys/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a valid revoke should redirect, got %d", rec.Code)
	}
	if len(fake.revoked) != 1 || fake.revoked[0] != 7 {
		t.Fatalf("expected key 7 revoked, got %v", fake.revoked)
	}
}

func TestSignOutInvalidatesTheSession(t *testing.T) {
	_, mux := newTestConsole(t, &fakeStore{})
	cookie, csrf := signIn(t, mux)

	form := url.Values{"csrf": {csrf}}
	out := httptest.NewRequest(http.MethodPost, "/console/logout", strings.NewReader(form.Encode()))
	out.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out.AddCookie(cookie)
	mux.ServeHTTP(httptest.NewRecorder(), out)

	after := httptest.NewRequest(http.MethodGet, "/console/keys", nil)
	after.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, after)

	if rec.Code != http.StatusSeeOther {
		t.Fatal("the old cookie still works after signing out")
	}
}

// Subjects and bounce reasons are attacker-authored. They are rendered, so
// they must be escaped, and the policy must forbid inline script regardless.
func TestAttackerAuthoredContentIsEscaped(t *testing.T) {
	fake := &fakeStore{msgs: []store.MessageRow{{
		ID:         "01ABC",
		Status:     "failed",
		Recipients: []string{"victim@example.org"},
		Subject:    `<script>alert(1)</script>`,
		CreatedAt:  time.Now(),
	}}}
	_, mux := newTestConsole(t, fake)
	cookie, _ := signIn(t, mux)

	req := httptest.NewRequest(http.MethodGet, "/console/messages", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("a message subject was rendered without escaping")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("the subject should appear escaped")
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("a restrictive policy must be sent, got %q", csp)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("the console must refuse to be framed")
	}
}

// A complaint must not be removable from the interface. Mailing someone who
// reported you as spam is the fastest reputation loss available, so the page
// offers no button for it.
func TestComplaintsCannotBeRemovedFromTheConsole(t *testing.T) {
	fake := &fakeStore{}
	_, mux := newTestConsole(t, fake)
	cookie, _ := signIn(t, mux)

	req := httptest.NewRequest(http.MethodGet, "/console/suppressions", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "bounced@example.org") || !strings.Contains(body, "angry@example.org") {
		t.Fatal("both suppressions should be listed")
	}

	// The bounced address gets a remove form; the complaint gets none.
	complaintSection := body[strings.Index(body, "angry@example.org"):]
	if strings.Contains(complaintSection, "/console/suppressions/remove") {
		t.Fatal("a complaint was offered a remove button")
	}
	if !strings.Contains(body, "/console/suppressions/remove") {
		t.Fatal("a hard bounce should be removable")
	}
}

func TestRemovingASuppressionNeedsTheRequestToken(t *testing.T) {
	fake := &fakeStore{}
	_, mux := newTestConsole(t, fake)
	cookie, csrf := signIn(t, mux)

	form := url.Values{"address": {"bounced@example.org"}}
	bad := httptest.NewRequest(http.MethodPost, "/console/suppressions/remove", strings.NewReader(form.Encode()))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bad)

	if rec.Code != http.StatusForbidden || len(fake.unsuppressed) != 0 {
		t.Fatal("removal without a request token must be refused")
	}

	form.Set("csrf", csrf)
	good := httptest.NewRequest(http.MethodPost, "/console/suppressions/remove", strings.NewReader(form.Encode()))
	good.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	good.AddCookie(cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, good)

	if len(fake.unsuppressed) != 1 || fake.unsuppressed[0] != "bounced@example.org" {
		t.Fatalf("expected the address to be removed, got %v", fake.unsuppressed)
	}
}

func TestShortPasswordsAreRejected(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("a short console password must be rejected")
	}
}

func TestPasswordVerificationRejectsTheWrongPassword(t *testing.T) {
	encoded, err := HashPassword(testPassword)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	hash, err := ParsePasswordHash(encoded)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if !hash.Verify(testPassword) {
		t.Fatal("the correct password must verify")
	}
	if hash.Verify(testPassword + "x") {
		t.Fatal("a wrong password must not verify")
	}
	if strings.Contains(encoded, testPassword) {
		t.Fatal("the encoded hash contains the password")
	}
}
