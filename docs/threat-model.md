# AI-Email — threat model

Written 2026-07-30. Each threat lists how it works, why obvious defences fail,
and which controls actually stop it. Controls map to priorities in
[../SECURITY.md](../SECURITY.md).

| ID | Threat | Severity |
| --- | --- | --- |
| T1 | Sending credential theft | Critical |
| T2 | DKIM signature replay | Critical |
| T3 | SMTP smuggling | Critical |
| T4 | Tenant compromise, outbound spam | Critical |
| T5 | Console session theft | High |
| T6 | Transport downgrade | High |
| T7 | Bounce and backscatter flooding | Medium |
| T8 | Prompt injection via content | Medium |
| T9 | List bombing via our forms | Medium |

⚠️ An ESP has an unusual damage profile. Most breaches cost data. An ESP breach
costs **domain reputation**, which is slow to earn and hard to rebuild.

---

## T1 — Sending credential theft

### The core problem

An API key and an SMTP password are **bearer** credentials.

> Bearer means: whoever holds it, is you. No further proof required.

There is no login moment to protect, no MFA to satisfy, no session to expire. A
leaked key is full send authority until someone notices.

| Item | Reality |
| --- | --- |
| Proof required per send | Just the string |
| Typical key lifetime | Forever, until rotated |
| Detection today | Complaint rate, days later |

### Where keys leak

| Vector | Mechanism |
| --- | --- |
| Committed to a public repo | Most common by far |
| Front-end bundle or mobile app | Shipped to every user |
| CI logs and build artefacts | Printed by a debug line |
| Screenshot in a support ticket | Human channel leak |
| Compromised developer laptop | Read from `.env` |
| Third-party integration breach | Their store, our key |

### Why this is worse for an ESP

The attacker does not want our data. They want our **reputation** — the fact
that mailbox providers already trust our IPs and our tenants' signed domains.

| Consequence | Recovery time |
| --- | --- |
| IP added to blocklists | Days to weeks |
| Tenant domain reputation lost | Weeks to months |
| Shared IP pool poisoned | Hits innocent tenants |
| Provider-level throttling | Opaque, no appeal |

### Controls — Tier 1, kill the bearer model

| Control | How it works | P |
| --- | --- | --- |
| Scoped keys | Per domain, per stream, per action | P0 |
| Short-lived tokens option | Mint from a key, minutes long | P1 |
| Request signing (RFC 9421) | Key signs the request, never sent | P1 |
| mTLS for high-volume tenants | Token bound to a certificate | P2 |
| Optional IP allowlist | Key useless from elsewhere | P1 |

Request signing is the real fix. The key never crosses the wire, so intercepting
traffic yields nothing replayable.

### Controls — Tier 2, shrink the window

| Control | Effect | P |
| --- | --- | --- |
| Key expiry by default | No immortal credentials | P0 |
| One-click rotate, two live keys | Rotation without downtime | P0 |
| Last-used and source IP display | Owner spots the stranger | P0 |
| Never show key twice | Reduces copies in the wild | P0 |
| Distinct prefix per key type | Enables secret scanners | P0 |

A recognisable prefix such as `aiem_live_` lets GitHub secret scanning and our
own crawler find leaked keys automatically.

### Controls — Tier 3, detect fast

| Control | Signal | P |
| --- | --- | --- |
| Volume anomaly per key | Sudden spike | P0 |
| New source IP or country | Key moved | P0 |
| Recipient-pattern anomaly | Scraped list shape | P1 |
| Template drift | Content unlike this tenant | P1 |
| Secret-scanner webhooks | Auto-revoke on public leak | P1 |

### Controls — Tier 4, contain the damage

| Control | Effect | P |
| --- | --- | --- |
| Per-key send quota | Caps the blast radius | P0 |
| Dedicated IP for large tenants | Isolates reputation damage | P1 |
| Separate transactional IP pool | Bulk abuse cannot poison it | P0 |
| Instant kill switch per key | Stop mid-campaign | P0 |
| Auto-pause on anomaly | Machine speed, not human | P0 |

---

## T2 — DKIM signature replay

### How it works

DKIM signs the message, not the destination. Because a recipient can be blind
copied, the signed data contains no proof of who the mail was for.

| Step | What happens |
| --- | --- |
| 1 | Attacker receives one signed message |
| 2 | Message is captured intact |
| 3 | Replayed to millions of addresses |
| 4 | SPF, DKIM, DMARC all pass |
| 5 | Our tenant's domain is blamed |

The attacker sends spam that is **cryptographically endorsed** by the victim
domain. No forgery is involved; the signature is genuine.

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Short `x=` expiry | Minutes, not days | P0 |
| Never emit `l=` | Body-length tag enables appending | P0 |
| Oversign `To` and `Subject` | Blocks header addition | P0 |
| Per-message send counter | Alert when one signature reused | P0 |
| Per-recipient signing keys | Limits blast radius | P1 |
| DKIM2 support | Per-hop chain, timestamped | P2 |

DKIM2 is Standards-Track at IETF and replaces both DKIM and ARC. Its headers
always carry timestamps, so old signatures have no value. First mailbox-provider
deployments are forecast for end of 2026.

⚠️ Build the signing layer pluggable now so DKIM2 is a driver swap, not a
rewrite.

---

## T3 — SMTP smuggling

### How it works

Two SMTP implementations disagree on where a message ends. The attacker exploits
the gap to hide a second message inside the first.

| Step | What happens |
| --- | --- |
| 1 | Craft a non-standard end-of-data sequence |
| 2 | Our relay sees one message |
| 3 | Next hop sees two messages |
| 4 | Smuggled message inherits passing auth |
| 5 | Spoofed mail from a trusted domain |

USENIX Security 2025 evaluated this at scale: 50+ email-hosting providers and
roughly 20 million domains were exploitable. Disclosed in 2023, still widely
unfixed.

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Strict CRLF-only parsing | Reject bare `\n` and bare `\r` | P0 |
| Only `\r\n.\r\n` ends DATA | Reject `\n.\n` and `\r.\r` | P0 |
| Refuse unauthorised pipelining | Commands before our reply | P0 |
| Prefer BDAT / CHUNKING | Length-prefixed, immune by design | P0 |
| Smuggling fuzz suite in CI | Regression on every commit | P1 |

BDAT specifies exact message length in bytes rather than relying on an
end-of-data marker, which removes the ambiguity entirely.

---

## T4 — Tenant compromise, outbound spam

We become the weapon. Mailbox providers punish the platform, not the tenant.

| Control | P |
| --- | --- |
| Sender domain DNS verification | P0 |
| Tenant KYC before volume unlock | P0 |
| Complaint-rate auto-suspend | P0 |
| Spamtrap hit monitoring | P1 |
| Outbound content DLP | P1 |
| URL and attachment reputation check | P1 |
| Phishing-template detection | P2 |

2026 bulk sender rules from Google, Yahoo, and Microsoft are hard gates.
Unauthenticated mail goes to spam, not the inbox.

---

## T5 — Console session theft

The vendor console holds key management, so a stolen console session grants
everything in T1. The full analysis of this threat class lives in the Ai-Auth
threat model; the short version:

| Control | P |
| --- | --- |
| Passkey-first console login | P0 |
| No phishable fallback | P0 |
| Short session TTL, rotation | P0 |
| Re-auth before key creation | P0 |
| Re-auth before domain add | P0 |
| DPoP on console API | P1 |

⚠️ Creating a sending key must require fresh proof, not just an old cookie.

---

## T6 — Transport downgrade

| Control | Detail | P |
| --- | --- | --- |
| MTA-STS enforce mode | Publish and honour policies | P0 |
| TLS-RPT ingestion | Detect downgrade attempts | P0 |
| DANE / TLSA validation | DNSSEC-anchored | P1 |
| Hybrid ML-KEM TLS | Harvest-now decrypt-later | P1 |

Classical key exchange is deprecated by 2030 and disallowed by 2035. Traffic
captured today can be decrypted later.

---

## T7 — Bounce and backscatter flooding

Forged envelope senders turn our bounce handling into an amplifier.

| Control | P |
| --- | --- |
| BATV or VERP bounce tags | P1 |
| Bounce rate limits per domain | P0 |
| Never bounce to unverified senders | P0 |

---

## T8 — Prompt injection via email content

Our AI features read attacker-authored content. That content is data, never
instructions.

| Control | P |
| --- | --- |
| Content in data channel only | P0 |
| No tool access from scoring model | P0 |
| Schema-check every model response | P1 |
| Model abuse quotas | P1 |

---

## T9 — List bombing via our forms

Attackers use hosted signup forms to flood a victim's inbox from many senders.

| Control | P |
| --- | --- |
| Double opt-in enforcement | P1 |
| Per-IP form rate limits | P0 |
| Bot challenge on subscribe | P1 |

---

## Sources

- [DKIM2 spec draft](https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/)
- [DKIM2 motivation](https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-motivation/)
- [DKIM2 best practices](https://datatracker.ietf.org/doc/draft-herr-dkim2-bcp/)
- [Replay-resistant ARC](https://www.ietf.org/archive/id/draft-chuang-replay-resistant-arc-11.txt)
- [SMTP smuggling, USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-wang-chuhan.pdf)
- [Postfix SMTP smuggling advisory](https://www.postfix.org/smtp-smuggling.html)
- [20M domains vulnerable](https://www.darkreading.com/threat-intelligence/20-million-trusted-domains-vulnerable-to-email-hosting-exploits)
- [2026 bulk sender requirements](https://redsift.com/guides/bulk-email-sender-requirements)
- [Microsoft outbound spam protection](https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-protection-about)
- [NIST PQC standards](https://www.paloaltonetworks.com/cyberpedia/pqc-standards)
