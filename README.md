# AI-Email

AI-assisted Email Service Provider. Sends transactional and bulk email, owns its
own MTA queue, and protects deliverability instead of renting it.

| Item | Value |
| --- | --- |
| Sending engine | Go |
| Control plane | Python / FastAPI |
| Console | Next.js |
| Queue | Redis + Postgres |
| Status | Design stage |

⚠️ Port 25 is blocked on DigitalOcean. Sending nodes must run elsewhere.

Security hardening backlog: [SECURITY.md](SECURITY.md)

---

## Architecture

| Service | Language | Job |
| --- | --- | --- |
| `mta` | Go | SMTP out, retry, throttle |
| `relay` | Go | SMTP in, auth, accept |
| `api` | Python | REST, tenants, templates |
| `worker` | Python | Bounces, webhooks, reports |
| `console` | TypeScript | Vendor dashboard |

---

## Features A–Z

### A — API-first sending

REST send endpoint plus SMTP relay. Idempotency keys on every request.

### B — Bounce and complaint handling

Hard/soft classification, DSN parsing, automatic suppression on hard bounce.

### C — Contact and list management

Lists, segments, custom fields, import with dedupe.

### D — DKIM, SPF, DMARC, ARC

Per-domain key generation, signing, rotation, and alignment checks.

### E — Event stream

`queued`, `sent`, `delivered`, `deferred`, `bounced`, `opened`, `clicked`,
`complained`, `unsubscribed`. Streamed to webhooks and stored.

### F — Feedback loops

FBL registration per mailbox provider. Blocklist watch on all sending IPs.

### G — Geo and timezone scheduling

Send at recipient local time. Per-country quiet hours.

### H — HTML and MJML templating

Jinja-style variables, MJML compile, auto plain-text alternative.

### I — IP pool management

Named pools, per-pool routing, automated warmup ramp schedule.

### J — Job queue

Durable queue with priority lanes and per-tenant fairness.

### K — Khmer and multilingual content

Full Unicode subject encoding, Khmer font-safe rendering, per-locale templates.

### L — Logging and audit trail

Immutable send log, message-level trace, admin action audit.

### M — MTA queue engine

Per-destination concurrency, exponential retry, connection reuse, pipelining.

### N — Notification fallback

Route to SMS or Telegram when email is undeliverable.

### O — Outbound quotas

Per-tenant hourly and daily caps. Burst limits per domain.

### P — Personalization

Merge tags, conditional blocks, per-recipient attachments.

### Q — Queue prioritization

Transactional always preempts bulk. Separate IP pools per class.

### R — Reputation dashboard

Delivery rate, complaint rate, blocklist status, DMARC aggregate reports.

### S — Suppression and unsubscribe

Global and per-list suppression. RFC 8058 one-click unsubscribe.

### T — Transport security

Opportunistic and enforced TLS, MTA-STS policy, TLS-RPT ingestion.

### U — URL click tracking

Branded tracking domains, per-link stats, opt-out per message.

### V — Validation

Syntax, MX lookup, role-account and disposable-domain detection.

### W — Webhook delivery

HMAC-signed payloads, timestamp replay window, retry with backoff.

### X — Custom headers and tags

Arbitrary `X-` headers, message tags for grouping and reporting.

### Y — Yield analytics

A/B subject tests, engagement cohorts, revenue attribution hooks.

### Z — Zero-trust tenancy

Row-level security on every table. No cross-tenant read path.

---

## AI features

| Feature | What it does |
| --- | --- |
| Spam-score predict | Scores content before send |
| Subject optimizer | Generates and ranks variants |
| Send-time optimizer | Picks per-recipient best hour |
| Content assist | Drafts and translates copy |
| Anomaly watch | Flags abnormal bounce spikes |

---

## Non-goals

| Not building | Reason |
| --- | --- |
| Inbox / IMAP server | Different product |
| Calendar or contacts sync | Out of scope |
| Marketing CRM | Lives in AiERP |
