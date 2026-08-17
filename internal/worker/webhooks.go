package worker

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/dnsverify"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/webhook"
)

const (
	webhookBatch    = 20
	webhookLock     = 2 * time.Minute
	MaxWebhookTries = 8

	domainRecheckInterval = 24 * time.Hour
	domainBatch           = 50
)

type WebhookQueue interface {
	ClaimDeliveries(ctx context.Context, limit int, lockFor time.Duration) ([]store.PendingDelivery, error)
	MarkDeliverySucceeded(ctx context.Context, id int64) error
	RescheduleDelivery(ctx context.Context, id int64, at time.Time, reason string) error
	MarkDeliveryFailed(ctx context.Context, id int64, reason string) error
}

type DomainStore interface {
	DomainsDueForRecheck(ctx context.Context, olderThan time.Duration, limit int) ([]store.DomainProof, error)
	MarkDomainVerified(ctx context.Context, id int64) error
	SuspendDomain(ctx context.Context, id int64) error
	TouchDomainCheck(ctx context.Context, id int64) error
}

type WebhookSender interface {
	Send(ctx context.Context, url string, secret, payload []byte) webhook.Result
}

// Dispatcher drains queued webhook deliveries.
type Dispatcher struct {
	queue  WebhookQueue
	sender WebhookSender
	log    *slog.Logger
}

func NewDispatcher(queue WebhookQueue, sender WebhookSender, log *slog.Logger) *Dispatcher {
	return &Dispatcher{queue: queue, sender: sender, log: log}
}

func (d *Dispatcher) Run(ctx context.Context) error {
	d.log.Info("webhook dispatcher started")
	for {
		processed, err := d.tick(ctx)
		if err != nil && ctx.Err() == nil {
			d.log.Error("webhook tick failed", "error", err)
		}

		wait := time.Duration(0)
		if processed == 0 || err != nil {
			wait = idleInterval
		}
		select {
		case <-ctx.Done():
			d.log.Info("webhook dispatcher stopped")
			return nil
		case <-time.After(wait):
		}
	}
}

func (d *Dispatcher) tick(ctx context.Context) (int, error) {
	claimed, err := d.queue.ClaimDeliveries(ctx, webhookBatch, webhookLock)
	if err != nil {
		return 0, err
	}
	for _, item := range claimed {
		d.deliver(ctx, item)
	}
	return len(claimed), nil
}

func (d *Dispatcher) deliver(ctx context.Context, item store.PendingDelivery) {
	result := d.sender.Send(ctx, item.URL, item.Secret, item.Payload)

	switch result.Outcome {
	case webhook.Delivered:
		if err := d.queue.MarkDeliverySucceeded(ctx, item.ID); err != nil {
			d.log.Error("could not record webhook delivery", "delivery_id", item.ID, "error", err)
		}

	case webhook.Drop:
		// A blocked destination never becomes allowed by retrying.
		if err := d.queue.MarkDeliveryFailed(ctx, item.ID, result.Reason); err != nil {
			d.log.Error("could not fail webhook delivery", "delivery_id", item.ID, "error", err)
			return
		}
		d.log.Warn("webhook dropped", "delivery_id", item.ID, "reason", result.Reason)

	case webhook.Retry:
		if item.Attempts >= MaxWebhookTries {
			if err := d.queue.MarkDeliveryFailed(ctx, item.ID, "gave up: "+result.Reason); err != nil {
				d.log.Error("could not fail webhook delivery", "delivery_id", item.ID, "error", err)
			}
			return
		}
		at := time.Now().Add(Backoff(item.Attempts))
		if err := d.queue.RescheduleDelivery(ctx, item.ID, at, result.Reason); err != nil {
			d.log.Error("could not reschedule webhook", "delivery_id", item.ID, "error", err)
		}
	}
}

// DomainChecker re-proves domain ownership on a schedule.
type DomainChecker struct {
	store    DomainStore
	verifier *dnsverify.Verifier
	log      *slog.Logger
	interval time.Duration
}

func NewDomainChecker(s DomainStore, v *dnsverify.Verifier, log *slog.Logger) *DomainChecker {
	return &DomainChecker{store: s, verifier: v, log: log, interval: time.Hour}
}

func (c *DomainChecker) Run(ctx context.Context) error {
	c.log.Info("domain checker started", "recheck_after", domainRecheckInterval.String())
	for {
		if err := c.tick(ctx); err != nil && ctx.Err() == nil {
			c.log.Error("domain recheck failed", "error", err)
		}
		select {
		case <-ctx.Done():
			c.log.Info("domain checker stopped")
			return nil
		case <-time.After(c.interval):
		}
	}
}

func (c *DomainChecker) tick(ctx context.Context) error {
	due, err := c.store.DomainsDueForRecheck(ctx, domainRecheckInterval, domainBatch)
	if err != nil {
		return err
	}

	for _, domain := range due {
		err := c.verifier.Verify(ctx, domain.Name, domain.Token)
		switch {
		case err == nil:
			if domain.Status != "verified" {
				c.log.Info("domain verified", "domain", domain.Name)
			}
			if err := c.store.MarkDomainVerified(ctx, domain.ID); err != nil {
				c.log.Error("could not record verification", "domain", domain.Name, "error", err)
			}

		case dnsverify.Recheckable(err):
			// A resolver outage says nothing about the domain. Record the
			// attempt and try again rather than suspending a legitimate sender
			// because DNS was briefly unreachable.
			c.log.Warn("domain lookup failed, leaving trust unchanged", "domain", domain.Name, "error", err)
			if err := c.store.TouchDomainCheck(ctx, domain.ID); err != nil {
				c.log.Error("could not record check", "domain", domain.Name, "error", err)
			}

		default:
			if domain.Status == "verified" {
				c.log.Warn("domain lost its proof, suspending", "domain", domain.Name, "reason", err)
			}
			if err := c.store.SuspendDomain(ctx, domain.ID); err != nil {
				c.log.Error("could not suspend domain", "domain", domain.Name, "error", err)
			}
		}
	}
	return nil
}

// EventPayload is the body posted to endpoints.
type EventPayload struct {
	EventID   string         `json:"event_id"`
	Type      string         `json:"type"`
	CreatedAt string         `json:"created_at"`
	Data      map[string]any `json:"data"`
}

func BuildPayload(eventID, eventType, messageID, reason string, at time.Time) ([]byte, error) {
	data := map[string]any{"email_id": messageID}
	if reason != "" {
		data["reason"] = reason
	}
	payload := EventPayload{
		EventID:   eventID,
		Type:      eventType,
		CreatedAt: at.UTC().Format(time.RFC3339),
		Data:      data,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("encoding webhook payload failed")
	}
	return body, nil
}
