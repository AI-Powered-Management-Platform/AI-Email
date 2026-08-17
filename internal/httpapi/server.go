// Package httpapi serves the REST surface described in docs/api-contract.md.
//
// Routing uses the standard library. The service has few endpoints and
// security-sensitive request handling, so header and body treatment stays
// explicit rather than delegated to a framework's conventions.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/config"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/unsubscribe"
)

// The HTTP layer depends on narrow interfaces so handlers can be tested
// without a database.
type (
	Pinger interface {
		Ping(ctx context.Context) error
	}

	KeyStore interface {
		APIKeyByHash(ctx context.Context, hash []byte) (*store.APIKey, error)
		TouchAPIKey(ctx context.Context, id int64, addr netip.Addr) error
		SendsInLastHour(ctx context.Context, keyID int64) (int, error)
	}

	MessageStore interface {
		DomainByName(ctx context.Context, name string) (*store.Domain, error)
		EnqueueMessage(ctx context.Context, in store.NewMessage) (*store.Message, bool, error)
		MessageByID(ctx context.Context, id string) (*store.Message, error)
		FilterSuppressed(ctx context.Context, addresses []string) (allowed, blocked []string, err error)
		Suppress(ctx context.Context, address, reason, detail, messageID string) error
	}
)

// ConsoleUI is the operator interface, mounted when configured.
type ConsoleUI interface {
	Enabled() bool
	Routes(mux *http.ServeMux)
}

type Server struct {
	cfg               *config.Config
	log               *slog.Logger
	db                Pinger
	keys              KeyStore
	messages          MessageStore
	console           ConsoleUI
	unsubscribeSecret []byte
	version           string
	started           time.Time
}

func New(cfg *config.Config, log *slog.Logger, db Pinger, keyStore KeyStore, messageStore MessageStore, ui ConsoleUI, version string) *Server {
	return &Server{
		cfg:               cfg,
		log:               log,
		db:                db,
		keys:              keyStore,
		messages:          messageStore,
		console:           ui,
		unsubscribeSecret: unsubscribe.DeriveSecret(cfg.DKIMMasterKey),
		version:           version,
		started:           time.Now(),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	if s.console != nil && s.console.Enabled() {
		s.console.Routes(mux)
	}
	mux.HandleFunc("GET /.well-known/mta-sts.txt", s.handleMTASTSPolicy)
	mux.HandleFunc("GET /.well-known/security.txt", s.handleSecurityTxt)
	mux.HandleFunc("GET /u/{token}", s.handleUnsubscribeForm)
	mux.HandleFunc("POST /u/{token}", s.handleUnsubscribe)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("POST /v1/emails", s.requireKey(ScopeEmailsSend, s.handleSend))
	mux.HandleFunc("GET /v1/emails/{id}", s.requireKey(ScopeEmailsRead, s.handleGetMessage))
	mux.HandleFunc("/", s.handleNotFound)

	return s.withRecovery(s.withRequestID(s.withLogging(mux)))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": s.version,
		"uptime":  time.Since(s.started).Round(time.Second).String(),
	})
}

// handleReady reports whether the service may accept work. Sending disabled is
// a healthy state, not a failure — a fresh install starts that way on purpose.
// An unreachable database is not: without it nothing can be durably accepted.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	if err := s.db.Ping(ctx); err != nil {
		s.log.Error("readiness check failed", "request_id", RequestIDFrom(r.Context()), "error", err)
		writeJSON(w, r, http.StatusServiceUnavailable, map[string]any{
			"status":   "unavailable",
			"database": "unreachable",
		})
		return
	}

	writeJSON(w, r, http.StatusOK, map[string]any{
		"status":       "ok",
		"database":     "ok",
		"send_enabled": s.cfg.SendEnabled,
	})
}

func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	msg, err := s.messages.MessageByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "not_found", "no such message")
		return
	}
	if err != nil {
		s.internalError(w, r, "loading message", err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{
		"id":         msg.ID,
		"status":     msg.Status,
		"created_at": msg.CreatedAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, "not_found", "no such endpoint")
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.ErrorContext(r.Context(), "encoding response failed", "error", err)
	}
}

// writeError keeps messages free of internal detail. The request id is the
// only thread back to the logs, which is deliberate.
func writeError(w http.ResponseWriter, r *http.Request, status int, kind, message string) {
	writeJSON(w, r, status, map[string]any{
		"error": map[string]string{
			"type":    kind,
			"message": message,
		},
		"request_id": RequestIDFrom(r.Context()),
	})
}
