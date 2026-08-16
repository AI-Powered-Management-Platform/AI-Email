# AI-Email — V1 scope

V1 sends our own transactional mail through pipes we own. Nothing more.
Rationale in [decisions.md](decisions.md). Controls in [../SECURITY.md](../SECURITY.md).

| Item | Value |
| --- | --- |
| Tenants | One — ourselves |
| Mail type | Transactional only |
| Intake | REST API |
| Volume target | Under 1,000 per day |
| Server | One Go binary |
| Engine | Operated, not written |

---

## In scope

| Area | Feature |
| --- | --- |
| Send | REST endpoint, idempotency keys |
| Send | Template render, plain-text alternative |
| Send | Khmer and Unicode subject encoding |
| Auth | DKIM signing, SPF, DMARC alignment |
| Auth | Domain verification with DNS proof |
| Queue | Durable, crash-safe, exactly-once |
| Events | queued, sent, delivered, deferred, bounced |
| Events | Signed webhooks to AiERP |
| Bounces | DSN parsing, hard/soft, auto-suppression |
| Keys | Scoped, expiring, quota, kill switch |
| Console | Domains, keys, send log, event trace |
| Ops | Warmup ramp enforcement, per-IP ceiling |
| Ops | Reputation dashboards wired to providers |

## Out of scope for V1

| Deferred | Returns when |
| --- | --- |
| Tenant SMTP submission | A tenant needs it (D3) |
| Bulk, lists, segments | Transactional is stable (D4) |
| Open and click tracking | Bulk arrives; T13 ships with it |
| AI features | Send path is boring |
| Outside tenants, KYC, billing | V1 exit criteria met (D5) |
| Inbox placement tests, BIMI | Later roadmap |

⚠️ Out of scope means the feature is absent, not that its threat is solved.

---

## Security floor — no external send before these

Every P0 that applies to a REST-only, single-tenant sender. Full detail in
[../SECURITY.md](../SECURITY.md).

| Control | Threat |
| --- | --- |
| DKIM keys in KMS envelope, no export | T10 |
| Short `x=` expiry, no `l=`, oversigned | T2 |
| Sandboxed template render, no attribute access | T11 |
| Header injection guard, CRLF stripped | T3 |
| Webhook egress pinned, private ranges denied | T12 |
| Domain proof re-checked daily, auto-suspend | T14 |
| Scoped keys, expiry, quota, kill switch | T1 |
| Per-IP hourly ceiling, cannot be exceeded | T4 |
| Signed unsubscribe tokens, POST-only mutation | T16 |
| Inbound parse caps before parsing | T17 |
| Recipient fields encrypted, addresses redacted in logs | T19 |
| MTA-STS honoured, TLS-RPT ingested | T6 |

⚠️ The per-IP ceiling is the backstop for every other bug. A defect that would
flood cannot flood if the ceiling holds.

---

## Phases

| # | Phase | Exit condition |
| --- | --- | --- |
| 0 | Contracts and module docs | API contract agreed |
| 1 | Node, DNS, DKIM, rDNS | Test mail authenticates |
| 2 | Send path, keys, queue | Idempotent send, crash-safe |
| 3 | Events, bounces, suppression | AiERP receives webhooks |
| 4 | Console | Keys and logs usable |
| 5 | Security floor closeout | Every P0 above green |
| 6 | Kratos courier swap | Auth mail flows through us |
| 7 | Warmup ramp | Volume rises on schedule |

Phase 1 depends on owner actions: renting the node, publishing DNS, registering
with mailbox-provider dashboards.

---

## Open-source requirements

V1 ships as software others can run (D8), so these are scope, not polish.

| Requirement | Detail |
| --- | --- |
| Single static binary | No runtime or interpreter to install |
| Cross-compiled releases | Linux amd64 and arm64 at minimum |
| Nothing hardcoded to us | Domains, URLs, keys all from config |
| Safe defaults | Insecure combinations refused at startup |
| No working example secrets | Placeholders only, validated as such |
| One-command local run | Compose file, documented env vars |
| Install and upgrade docs | A stranger succeeds without asking us |
| Semantic versioning | Changelog and upgrade notes per release |
| security.txt and disclosure policy | Live before any tagged release |
| Contribution review discipline | Signed commits, dependency review |

⚠️ Self-hosted operators inherit our threat model but not our judgement. Ship
guardrails, not warnings — a config that could poison reputation must fail
closed, not merely log a caution.

---

## Exit criteria — when V1 is done

| Criterion | Measure |
| --- | --- |
| All AiERP mail flows through us | Resend unused for 30 days |
| Delivery rate | Above 98% |
| Complaint rate | Below 0.1% |
| Bounce rate | Below 2% |
| Unplanned sending outages | Zero in 30 days |
| Security floor | All P0 shipped and tested |
| Fallback proven | Switch to Resend drilled, not assumed |
| Third party can deploy it | From docs alone, no help |

---

## Triggers that add a service

Nothing below is scheduled. Each waits for its trigger.

| Add | Trigger |
| --- | --- |
| Go relay | A tenant requires SMTP submission |
| Separate signer service | Key custody needs its own trust boundary |
| Python AI sidecar | Send path stable and boring |
| Our own MTA | The engine limits us at real volume |
| AI features | Send path stable and boring |
| Bulk sending | T4 and T9 controls shipped |

---

## Known constraints

| Constraint | Effect |
| --- | --- |
| Port 25 blocked on DigitalOcean | Sending nodes live elsewhere |
| Warmup is calendar time | Weeks; no engineering shortcut |
| Reputation damage is not revertible | Deploys fix code, not trust |
| One operator | Every service is permanent work |
