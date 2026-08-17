package httpapi

import (
	"errors"
	"html"
	"net/http"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/unsubscribe"
)

// handleUnsubscribeForm renders a confirmation and changes nothing.
//
// Corporate mail scanners fetch every link in a message before the recipient
// sees it. If this handler unsubscribed people, those readers would be removed
// without ever clicking, so the GET is deliberately inert.
func (s *Server) handleUnsubscribeForm(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	claim, err := unsubscribe.Verify(s.unsubscribeSecret, token, time.Now())
	if err != nil {
		s.renderUnsubscribe(w, http.StatusBadRequest, "This unsubscribe link is not valid or has expired.", "")
		return
	}
	s.renderUnsubscribe(w, http.StatusOK, "", claim.Address)
}

// handleUnsubscribe performs the removal. RFC 8058 one-click sends a POST, and
// so does the confirmation form, so state only ever changes here.
func (s *Server) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	claim, err := unsubscribe.Verify(s.unsubscribeSecret, token, time.Now())
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, unsubscribe.ErrExpired) {
			status = http.StatusGone
		}
		s.renderUnsubscribe(w, status, "This unsubscribe link is not valid or has expired.", "")
		return
	}

	if err := s.messages.Suppress(r.Context(), claim.Address, "unsubscribe", "requested by the recipient", claim.MessageID); err != nil {
		s.log.Error("unsubscribe failed", "request_id", RequestIDFrom(r.Context()), "error", err)
		s.renderUnsubscribe(w, http.StatusInternalServerError, "Something went wrong. Please try again.", "")
		return
	}

	s.log.Info("recipient unsubscribed", "message_id", claim.MessageID)
	s.renderUnsubscribe(w, http.StatusOK, "", "")
}

// renderUnsubscribe writes a small self-contained page. The address is escaped
// because it arrives from a signed token rather than from us.
func (s *Server) renderUnsubscribe(w http.ResponseWriter, status int, problem, confirmAddress string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)

	const style = `<style>body{background:#0b0f14;color:#e5e7eb;font:16px/1.6 system-ui,sans-serif;display:grid;place-items:center;min-height:90vh;margin:0}
main{max-width:26rem;padding:2rem;text-align:center}
button{font:inherit;background:#1a2331;color:#e5e7eb;border:1px solid #1f2937;border-radius:.5rem;padding:.6rem 1.2rem;cursor:pointer}
.muted{color:#9ca3af;font-size:.9rem}</style>`

	switch {
	case problem != "":
		_, _ = w.Write([]byte("<!doctype html><title>Unsubscribe</title>" + style +
			"<main><h1>Unsubscribe</h1><p>" + html.EscapeString(problem) + "</p></main>"))

	case confirmAddress != "":
		_, _ = w.Write([]byte("<!doctype html><title>Unsubscribe</title>" + style +
			`<main><h1>Unsubscribe</h1><p>Stop sending email to <strong>` +
			html.EscapeString(confirmAddress) + `</strong>?</p>` +
			`<form method="post"><button type="submit">Unsubscribe me</button></form>` +
			`<p class="muted">Nothing changes until you confirm.</p></main>`))

	default:
		_, _ = w.Write([]byte("<!doctype html><title>Unsubscribed</title>" + style +
			"<main><h1>Unsubscribed</h1><p>You will not receive further email from this sender.</p></main>"))
	}
}
