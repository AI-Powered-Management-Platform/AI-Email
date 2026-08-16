# AI-Email — API contract

V1 send and event contract. Deliberately Resend-shaped so callers can switch
providers with configuration alone — see D6 in [decisions.md](decisions.md).

| Item | Value |
| --- | --- |
| Base URL | Per environment, from config |
| Auth | `Authorization: Bearer aiem_live_…` |
| Transport | HTTPS only, TLS 1.3 |
| Encoding | JSON, UTF-8 |
| Versioning | Path prefix `/v1` |

---

## POST /v1/emails

Queues one message. Returns before delivery is attempted.

### Request

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `from` | string | ✅ | Must be a verified domain |
| `to` | string or array | ✅ | Max 50 recipients |
| `subject` | string | ✅ | UTF-8, Khmer safe |
| `html` | string | ⚠️ | Required unless `text` |
| `text` | string | ⚠️ | Auto-generated if absent |
| `reply_to` | string | ❌ | |
| `cc`, `bcc` | array | ❌ | Count toward the recipient cap |
| `headers` | object | ❌ | `X-` prefixed only |
| `tags` | object | ❌ | For grouping and reporting |
| `scheduled_at` | string | ❌ | RFC 3339, future only |

⚠️ Every field is stripped of CR and LF before use (T3 header injection).

### Idempotency

| Rule | Behaviour |
| --- | --- |
| Header | `Idempotency-Key: <uuid>` |
| Repeat within 24h | Returns the original result |
| Same key, different body | `422 idempotency_mismatch` |
| Key absent | Request is not replay-safe |

### Response — 202 Accepted

| Field | Notes |
| --- | --- |
| `id` | Message id, ULID |
| `status` | Always `queued` here |
| `created_at` | RFC 3339 |

---

## GET /v1/emails/{id}

Returns current status and the event history for one message.

| Field | Notes |
| --- | --- |
| `id`, `status` | Latest known state |
| `events` | Ordered, with timestamps |
| `to` | Redacted unless key has `read:recipients` |

---

## Domains and keys

| Method | Path | Job |
| --- | --- | --- |
| GET | `/v1/domains` | List, with verification state |
| POST | `/v1/domains` | Add, returns DNS records to publish |
| POST | `/v1/domains/{id}/verify` | Re-check DNS proof now |
| DELETE | `/v1/domains/{id}` | Remove, stops sending |
| GET | `/v1/keys` | List, never shows secrets |
| POST | `/v1/keys` | Create, secret shown once |
| DELETE | `/v1/keys/{id}` | Instant kill switch |

⚠️ Key creation and domain add require fresh console authentication, never an
API key alone (T5).

---

## Status codes

| Code | Meaning | Retry |
| --- | --- | --- |
| 202 | Queued | — |
| 400 | Malformed request | ❌ fix first |
| 401 | Key missing, expired, revoked | ❌ |
| 403 | Domain not verified, scope denied | ❌ |
| 422 | Valid JSON, invalid values | ❌ |
| 429 | Quota or rate limit | ✅ honour `Retry-After` |
| 500 | Our fault | ✅ with backoff |
| 503 | Sending paused | ✅ with backoff |

Error body carries `error.type`, `error.message`, and `request_id`. Messages
never leak internal detail.

### Rate limit headers

`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` on every
response. `Retry-After` accompanies every 429.

---

## Webhooks

We POST events to the tenant's endpoint. Delivery is at-least-once, so
consumers must be idempotent on `event_id`.

| Event | Meaning |
| --- | --- |
| `email.queued` | Accepted by us |
| `email.sent` | Handed to the destination |
| `email.delivered` | Destination accepted it |
| `email.deferred` | Temporary failure, will retry |
| `email.bounced` | Permanent failure, suppressed |
| `email.complained` | Marked as spam, suppressed |

### Payload

| Field | Notes |
| --- | --- |
| `event_id` | Unique, stable across retries |
| `type` | From the table above |
| `created_at` | RFC 3339 |
| `data.email_id` | Our message id |
| `data.reason` | Bounce or defer detail |

### Signature

| Rule | Detail |
| --- | --- |
| Scheme | RFC 9421 HTTP Message Signatures |
| Covered | Method, path, body digest, timestamp |
| Replay window | 5 minutes, plus nonce cache |
| Verification | Required — unsigned means forged |

### Retry schedule

| Attempt | Delay |
| --- | --- |
| 1–3 | 1s, 10s, 60s |
| 4–8 | 5m, 30m, 2h, 6h, 24h |
| After | Marked failed, replayable from console |

---

## Compatibility notes

| Resend behaviour | Ours |
| --- | --- |
| `POST /emails` field names | ✅ identical |
| Bearer key auth | ✅ identical |
| Idempotency key header | ✅ identical |
| Webhook signature scheme | ❌ we require RFC 9421 |

⚠️ The webhook difference is deliberate. Signature verification is the one
place we will not match a weaker standard.
