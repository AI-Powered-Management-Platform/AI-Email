// Package httpapi serves the REST surface described in docs/api-contract.md.
//
// Routing uses the standard library. The service has few endpoints and
// security-sensitive request handling, so header and body treatment stays
// explicit rather than delegated to a framework's conventions.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/config"
)

type Server struct {
	cfg     *config.Config
	log     *slog.Logger
	version string
	started time.Time
}

func New(cfg *config.Config, log *slog.Logger, version string) *Server {
	return &Server{cfg: cfg, log: log, version: version, started: time.Now()}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
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
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusOK, map[string]any{
		"status":       "ok",
		"send_enabled": s.cfg.SendEnabled,
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
