package httpapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/mail"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/template"
)

// maxBodyBytes bounds a send request. Attachments are not in this version, so
// anything larger is a mistake or an attack.
const maxBodyBytes = 2 << 20

type sendRequest struct {
	From        string            `json:"from"`
	To          json.RawMessage   `json:"to"`
	Subject     string            `json:"subject"`
	HTML        string            `json:"html"`
	Text        string            `json:"text"`
	ReplyTo     string            `json:"reply_to"`
	Headers     map[string]string `json:"headers"`
	Tags        map[string]string `json:"tags"`
	ScheduledAt string            `json:"scheduled_at"`
	Variables   map[string]string `json:"variables"`
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	key := APIKeyFrom(r.Context())

	if !s.cfg.SendEnabled {
		writeError(w, r, http.StatusServiceUnavailable, "sending_disabled",
			"sending is disabled on this deployment")
		return
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "the request body is too large")
		return
	}

	var req sendRequest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "the request body could not be parsed")
		return
	}

	msg, problem := s.buildMessage(r, key, &req, raw)
	if problem != "" {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid_request", problem)
		return
	}

	if key.QuotaPerHour > 0 {
		used, err := s.keys.SendsInLastHour(r.Context(), key.ID)
		if err != nil {
			s.internalError(w, r, "counting recent sends", err)
			return
		}
		if used >= key.QuotaPerHour {
			w.Header().Set("Retry-After", "3600")
			writeError(w, r, http.StatusTooManyRequests, "quota_exceeded", "this key has reached its hourly quota")
			return
		}
	}

	result, replayed, err := s.messages.EnqueueMessage(r.Context(), *msg)
	switch {
	case errors.Is(err, store.ErrIdempotencyMismatch):
		writeError(w, r, http.StatusUnprocessableEntity, "idempotency_mismatch",
			"this idempotency key was already used with a different request")
		return
	case errors.Is(err, store.ErrIdempotencyInFlight):
		w.Header().Set("Retry-After", "1")
		writeError(w, r, http.StatusConflict, "request_in_flight",
			"an identical request is still being processed")
		return
	case err != nil:
		s.internalError(w, r, "enqueueing message", err)
		return
	}

	if replayed {
		w.Header().Set("Idempotent-Replay", "true")
	}
	writeJSON(w, r, http.StatusAccepted, map[string]any{
		"id":         result.ID,
		"status":     result.Status,
		"created_at": result.CreatedAt.UTC().Format(time.RFC3339),
	})
}

// buildMessage validates every field and returns a caller-safe problem string.
func (s *Server) buildMessage(r *http.Request, key *store.APIKey, req *sendRequest, raw []byte) (*store.NewMessage, string) {
	from, err := mail.ParseAddress(req.From)
	if err != nil {
		return nil, fmt.Sprintf("from: %v", err)
	}

	recipientList, err := decodeRecipients(req.To)
	if err != nil {
		return nil, fmt.Sprintf("to: %v", err)
	}
	recipients, err := mail.ParseRecipients(recipientList)
	if err != nil {
		return nil, fmt.Sprintf("to: %v", err)
	}

	// Suppressed addresses are dropped at acceptance rather than at delivery.
	// Queueing mail we already know we must not send wastes a send slot and
	// risks it going out if the check is ever missed downstream.
	allowed, blocked, err := s.messages.FilterSuppressed(r.Context(), recipients)
	if err != nil {
		return nil, "the recipient list could not be checked"
	}
	if len(allowed) == 0 {
		return nil, fmt.Sprintf("every recipient is suppressed: %s", strings.Join(blocked, ", "))
	}
	if len(blocked) > 0 {
		s.log.Info("dropped suppressed recipients",
			"request_id", RequestIDFrom(r.Context()), "dropped", len(blocked), "kept", len(allowed))
	}
	recipients = allowed

	// Merge tags are substituted here so a broken template is reported to the
	// caller now, rather than failing later where only we would see it.
	subject, err := template.Render(req.Subject, req.Variables, false)
	if err != nil {
		return nil, fmt.Sprintf("subject: %v", err)
	}
	bodyHTML, err := template.Render(req.HTML, req.Variables, true)
	if err != nil {
		return nil, fmt.Sprintf("html: %v", err)
	}
	bodyText, err := template.Render(req.Text, req.Variables, false)
	if err != nil {
		return nil, fmt.Sprintf("text: %v", err)
	}

	if err := mail.ValidateSubject(subject); err != nil {
		return nil, fmt.Sprintf("subject: %v", err)
	}
	if strings.TrimSpace(bodyHTML) == "" && strings.TrimSpace(bodyText) == "" {
		return nil, "either html or text is required"
	}
	if req.ReplyTo != "" {
		if _, err := mail.ParseAddress(req.ReplyTo); err != nil {
			return nil, fmt.Sprintf("reply_to: %v", err)
		}
	}
	for name, value := range req.Headers {
		if err := mail.ValidateCustomHeader(name, value); err != nil {
			return nil, err.Error()
		}
	}
	for name, value := range req.Tags {
		if mail.ContainsControl(name) || mail.ContainsControl(value) {
			return nil, fmt.Sprintf("tag %q contains a control character", name)
		}
	}

	var scheduledAt *time.Time
	if req.ScheduledAt != "" {
		at, err := time.Parse(time.RFC3339, req.ScheduledAt)
		if err != nil {
			return nil, "scheduled_at must be an RFC 3339 timestamp"
		}
		if at.Before(time.Now()) {
			return nil, "scheduled_at must be in the future"
		}
		scheduledAt = &at
	}

	domain, err := s.messages.DomainByName(r.Context(), from.Domain)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Sprintf("from: domain %q is not registered on this account", from.Domain)
	}
	if err != nil {
		return nil, "the sending domain could not be verified"
	}
	if domain.Status != "verified" {
		return nil, fmt.Sprintf("from: domain %q is not verified", from.Domain)
	}

	headers, _ := json.Marshal(orEmpty(req.Headers))
	tags, _ := json.Marshal(orEmpty(req.Tags))
	digest := sha256.Sum256(raw)

	return &store.NewMessage{
		ID:             ulid.Make().String(),
		APIKeyID:       key.ID,
		DomainID:       domain.ID,
		FromAddress:    from.Email,
		Recipients:     recipients,
		Subject:        subject,
		BodyHTML:       bodyHTML,
		BodyText:       bodyText,
		Headers:        headers,
		Tags:           tags,
		ScheduledAt:    scheduledAt,
		IdempotencyKey: strings.TrimSpace(r.Header.Get("Idempotency-Key")),
		RequestHash:    digest[:],
	}, ""
}

// decodeRecipients accepts a single address or an array, matching the shape
// callers already use with other providers.
func decodeRecipients(rawTo json.RawMessage) ([]string, error) {
	if len(rawTo) == 0 {
		return nil, errors.New("at least one recipient is required")
	}
	var single string
	if err := json.Unmarshal(rawTo, &single); err == nil {
		return []string{single}, nil
	}
	var many []string
	if err := json.Unmarshal(rawTo, &many); err == nil {
		return many, nil
	}
	return nil, errors.New("must be an address or an array of addresses")
}

func orEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.Error(what+" failed", "request_id", RequestIDFrom(r.Context()), "error", err)
	writeError(w, r, http.StatusInternalServerError, "internal_error", "the request could not be completed")
}
