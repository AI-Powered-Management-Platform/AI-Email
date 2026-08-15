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

| Document | Contents |
| --- | --- |
| [SECURITY.md](SECURITY.md) | Hardening backlog, prioritised |
| [docs/threat-model.md](docs/threat-model.md) | T1–T19 attacks and controls |

⚠️ Read T1 first. An API key is a bearer credential.

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

REST send endpoint plus SMTP relay. Idempotency keys on every request. Scoped,
expiring keys with optional request signing — see T1 in the threat model.

### B — Bounce and complaint handling

Hard/soft classification, DSN parsing, automatic suppression on hard bounce.

### C — Contact and list management

Lists, segments, custom fields, import with dedupe.

### D — DKIM, SPF, DMARC, ARC

Per-domain key generation, signing, rotation, and alignment checks. Replay
defences built in: short `x=` expiry, no `l=` tag, oversigned headers.

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

Opportunistic and enforced TLS, MTA-STS policy, TLS-RPT ingestion, DANE/TLSA
validation, hybrid ML-KEM key exchange on the API.

### U — URL click tracking

Branded tracking domains, per-link stats, opt-out per message.

### V — Validation

Syntax, MX lookup, role-account and disposable-domain detection.

### W — Webhook delivery

RFC 9421 HTTP Message Signatures, timestamp replay window, retry with backoff.

### X — Custom headers and tags

Arbitrary `X-` headers, message tags for grouping and reporting.

### Y — Yield analytics

A/B subject tests, engagement cohorts, revenue attribution hooks.

### Z — Zero-trust tenancy

Row-level security on every table. No cross-tenant read path.

---

## Platform features

Lifecycle and console features every serious ESP ships.

| Feature | What it does |
| --- | --- |
| Sandbox mode | Full API, nothing actually delivered |
| Template versioning | Draft, publish, roll back |
| Undo send | Cancel window before dispatch |
| Team roles | Owner, developer, viewer key scopes |
| Retention controls | Per-tenant data expiry windows |
| Inbox placement tests | Seed-list preview per provider |
| Hosted DMARC and MTA-STS | We manage tenant policy DNS |
| Spoof watch | Alert tenants when their domain is forged |
| Webhook replay | Re-deliver missed events on demand |
| Security alerts | New key, new domain, anomaly — instant notify |
| Audit export | Stream admin log to tenant SIEM |

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

## Compared to alternatives

### Resend — the rented ESP

| Area | Resend | AI-Email |
| --- | --- | --- |
| Core sending, webhooks, suppression | ✅ | ✅ parity planned |
| IP pools, warmup automation | ⚠️ paid add-on | ✅ core feature |
| AI spam-predict, subject, send-time | ❌ | ✅ built in |
| Khmer-first rendering | ❌ | ✅ built in |
| SMS / Telegram fallback | ❌ | ✅ built in |
| Inbox placement seed tests | ❌ | ✅ built in |
| Hosted DMARC and MTA-STS | ❌ | ✅ built in |
| Key expiry, quotas, kill switch | ⚠️ partial | ✅ designed in |
| Request signing (RFC 9421) | ❌ | ✅ designed in |
| Recipient data custody | ⚠️ their servers | ✅ our KMS |

Resend is proven in production; this design is not yet built. The send API is
deliberately Resend-shaped, so switching either direction is two config values.

### Gmail and Workspace SMTP — where small senders start

| Area | Gmail SMTP | AI-Email |
| --- | --- | --- |
| Daily volume | ❌ 500–2,000 cap | ✅ scales with warmup |
| Bulk and marketing | ❌ forbidden by terms | ✅ core feature |
| Send API, idempotency | ❌ | ✅ REST plus SMTP |
| Bounce handling, suppression | ❌ manual | ✅ automatic |
| Webhooks and analytics | ❌ | ✅ full stream |
| Multi-tenant domains and keys | ❌ one sender | ✅ core design |
| Credentials | ⚠️ app passwords | ✅ scoped, expiring keys |

Gmail is not a competitor — it is the judge. Mailbox providers set the rules
our mail must pass; see [SECURITY.md](SECURITY.md) section 3.

| Product | Its job |
| --- | --- |
| Gmail | Receive, store, judge mail |
| Resend | Rented sending pipes |
| AI-Email | Owned sending pipes, AI-assisted |

Our customers are the businesses that outgrew Gmail SMTP and want more than
rented pipes.

---

## Non-goals

| Not building | Reason |
| --- | --- |
| Inbox / IMAP server | Different product |
| Calendar or contacts sync | Out of scope |
| Marketing CRM | Lives in AiERP |
