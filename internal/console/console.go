package console

import (
	"context"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

// Store is the read surface the console needs. Writes are limited to
// revocation: everything that creates a credential stays on the command line,
// where filesystem access is already the trust boundary.
type Store interface {
	ListDomains(ctx context.Context) ([]store.DomainRow, error)
	ListAPIKeys(ctx context.Context) ([]store.KeyRow, error)
	ListMessages(ctx context.Context, status string, limit int) ([]store.MessageRow, error)
	DashboardCounts(ctx context.Context) (store.Counts, error)
	RevokeAPIKey(ctx context.Context, id int64) error
}

type Options struct {
	PasswordHash *PasswordHash
	Secure       bool
	Env          string
	Version      string
	SendEnabled  bool
	MaxPerHour   int
}

type Console struct {
	store    Store
	log      *slog.Logger
	tmpl     *template.Template
	sessions *sessions
	opts     Options
}

func New(s Store, log *slog.Logger, opts Options) (*Console, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Console{store: s, log: log, tmpl: tmpl, sessions: newSessions(), opts: opts}, nil
}

// Enabled reports whether the console may serve. Without a password it stays
// off entirely rather than falling back to something weaker.
func (c *Console) Enabled() bool { return c.opts.PasswordHash != nil }

func (c *Console) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /console", c.guard("overview", c.overview))
	mux.HandleFunc("GET /console/domains", c.guard("domains", c.domains))
	mux.HandleFunc("GET /console/keys", c.guard("keys", c.keys))
	mux.HandleFunc("GET /console/messages", c.guard("messages", c.messages))
	mux.HandleFunc("POST /console/keys/revoke", c.guardPost(c.revokeKey))
	mux.HandleFunc("POST /console/logout", c.guardPost(c.logout))
	mux.HandleFunc("GET /console/login", c.loginForm)
	mux.HandleFunc("POST /console/login", c.login)
}

type view struct {
	Title       string
	Nav         string
	Authed      bool
	CSRF        string
	Error       string
	Env         string
	Version     string
	SendEnabled bool
	MaxPerHour  int
	Counts      store.Counts
	Domains     []domainView
	Keys        []keyView
	Messages    []messageView
}

func (c *Console) render(w http.ResponseWriter, page string, data view) {
	// The console renders attacker-influenced values such as subjects and
	// bounce text. html/template escapes them, and this policy means a mistake
	// there still cannot execute: no inline script is permitted.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, err := c.tmpl.Clone()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	if _, err := tmpl.New("content").Parse(`{{template "` + page + `" .}}`); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		c.log.Error("rendering console page failed", "page", page, "error", err)
	}
}

func (c *Console) guard(nav string, fn func(http.ResponseWriter, *http.Request, view)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := c.currentSession(r)
		if !ok {
			http.Redirect(w, r, "/console/login", http.StatusSeeOther)
			return
		}
		fn(w, r, view{
			Nav: nav, Authed: true, CSRF: sess.csrf,
			Env: c.opts.Env, Version: c.opts.Version,
			SendEnabled: c.opts.SendEnabled, MaxPerHour: c.opts.MaxPerHour,
		})
	}
}

func (c *Console) guardPost(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := c.currentSession(r)
		if !ok {
			http.Redirect(w, r, "/console/login", http.StatusSeeOther)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Without this a page on another site could cause an authenticated
		// state change using the operator's cookie.
		if !validCSRF(sess.csrf, r.PostFormValue("csrf")) {
			http.Error(w, "invalid request token", http.StatusForbidden)
			return
		}
		fn(w, r)
	}
}

func (c *Console) currentSession(r *http.Request) (session, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	return c.sessions.get(cookie.Value)
}

func (c *Console) loginForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.currentSession(r); ok {
		http.Redirect(w, r, "/console", http.StatusSeeOther)
		return
	}
	c.render(w, "page-login", view{Title: "Sign in"})
}

func (c *Console) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// A fixed delay on every attempt, right or wrong, keeps timing from
	// distinguishing them and makes guessing expensive.
	time.Sleep(loginDelay)

	if !c.opts.PasswordHash.Verify(r.PostFormValue("password")) {
		c.log.Warn("console login failed", "remote", r.RemoteAddr)
		c.render(w, "page-login", view{Title: "Sign in", Error: "That password is not correct."})
		return
	}

	id, _, err := c.sessions.create()
	if err != nil {
		http.Error(w, "could not start a session", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, id, c.opts.Secure)
	c.log.Info("console login", "remote", r.RemoteAddr)
	http.Redirect(w, r, "/console", http.StatusSeeOther)
}

func (c *Console) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		c.sessions.destroy(cookie.Value)
	}
	clearSessionCookie(w, c.opts.Secure)
	http.Redirect(w, r, "/console/login", http.StatusSeeOther)
}

func (c *Console) overview(w http.ResponseWriter, r *http.Request, v view) {
	counts, err := c.store.DashboardCounts(r.Context())
	if err != nil {
		c.fail(w, "loading counts", err)
		return
	}
	v.Title, v.Counts = "Overview", counts
	c.render(w, "page-overview", v)
}

func (c *Console) domains(w http.ResponseWriter, r *http.Request, v view) {
	rows, err := c.store.ListDomains(r.Context())
	if err != nil {
		c.fail(w, "loading domains", err)
		return
	}
	v.Title = "Domains"
	for _, d := range rows {
		v.Domains = append(v.Domains, newDomainView(d))
	}
	c.render(w, "page-domains", v)
}

func (c *Console) keys(w http.ResponseWriter, r *http.Request, v view) {
	rows, err := c.store.ListAPIKeys(r.Context())
	if err != nil {
		c.fail(w, "loading keys", err)
		return
	}
	v.Title = "API keys"
	for _, k := range rows {
		v.Keys = append(v.Keys, newKeyView(k))
	}
	c.render(w, "page-keys", v)
}

func (c *Console) messages(w http.ResponseWriter, r *http.Request, v view) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "queued", "deferred", "failed", "sent", "delivered":
	default:
		status = ""
	}

	rows, err := c.store.ListMessages(r.Context(), status, 200)
	if err != nil {
		c.fail(w, "loading messages", err)
		return
	}
	v.Title = "Messages"
	for _, m := range rows {
		v.Messages = append(v.Messages, newMessageView(m))
	}
	c.render(w, "page-messages", v)
}

func (c *Console) revokeKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad key id", http.StatusBadRequest)
		return
	}
	if err := c.store.RevokeAPIKey(r.Context(), id); err != nil {
		c.log.Error("revoking key failed", "key_id", id, "error", err)
	} else {
		c.log.Warn("api key revoked from console", "key_id", id, "remote", r.RemoteAddr)
	}
	http.Redirect(w, r, "/console/keys", http.StatusSeeOther)
}

func (c *Console) fail(w http.ResponseWriter, what string, err error) {
	c.log.Error(what+" failed", "error", err)
	http.Error(w, "the page could not be loaded", http.StatusInternalServerError)
}
