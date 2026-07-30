# AI-Email — security hardening backlog

Researched 2026-07-30 against current standards, live attacks, and mailbox
provider rules. Each item is a feature to build, not advice.

Priority: **P0** ship before first external send · **P1** before paid tenants ·
**P2** roadmap.

Attack mechanics behind these controls: [docs/threat-model.md](docs/threat-model.md).

---

## 1. Signature replay — the ESP-specific killer

A validly signed message can be captured and blasted to millions of addresses.
Your domain reputation dies, not the attacker's.

| P | Feature | Detail |
| --- | --- | --- |
| P0 | Short DKIM expiry | Set `x=` tag, minutes not days |
| P0 | Never emit `l=` | Body-length tag enables append attacks |
| P0 | Sign `To` and `Subject` | Oversign to block header addition |
| P0 | Per-message send counter | Alert when one signature reused |
| P1 | Per-recipient signing keys | Limits blast radius of one capture |
| P2 | DKIM2 support | Per-hop chain, timestamped, replay-proof |

DKIM2 is Standards-Track at IETF and replaces both DKIM and ARC. First mailbox
provider deployments are forecast for end of 2026. Build the signing layer
pluggable now so DKIM2 is a driver swap, not a rewrite.

---

## 2. SMTP smuggling

Parser disagreement between your relay and the next hop lets an attacker inject
a second message that inherits your passing SPF/DKIM/DMARC. USENIX Security
2025 found 50+ hosting providers and ~20M domains exploitable.

| P | Feature | Detail |
| --- | --- | --- |
| P0 | Strict CRLF-only parsing | Reject bare `\n` and bare `\r` |
| P0 | Reject `\n.\n` and `\r.\r` | Only `\r\n.\r\n` ends DATA |
| P0 | Refuse unauthorised pipelining | Commands sent before our reply |
| P0 | Prefer BDAT / CHUNKING | Length-prefixed, immune by design |
| P1 | Smuggling regression suite | Fuzz the relay on every commit |

---

## 3. Outbound abuse — you are the weapon

An ESP is a spam cannon the moment one tenant is compromised. Mailbox providers
punish the platform, not the tenant.

| P | Feature | Detail |
| --- | --- | --- |
| P0 | Sender domain verification | No sending before DNS proof |
| P0 | Tenant KYC gate | Identity check before volume unlock |
| P0 | Volume anomaly detection | Auto-pause on abnormal spike |
| P0 | Complaint-rate auto-suspend | Threshold per Google/Yahoo/Microsoft rules |
| P1 | Recipient-pattern anomaly | Sequential or scraped list shapes |
| P1 | Spamtrap hit monitoring | Immediate list quarantine |
| P1 | Outbound content DLP | Block credentials, cards, PII leaks |
| P1 | URL and attachment scanning | Reputation check before send |
| P1 | Double opt-in enforcement | Blocks list-bombing via your forms |
| P2 | Phishing-template detection | Refuse to send credential-harvest pages |

2026 bulk sender rules from Google, Yahoo, and Microsoft are now hard gates —
unauthenticated mail goes to spam, not the inbox.

---

## 4. Transport and DNS authentication

| P | Feature | Detail |
| --- | --- | --- |
| P0 | MTA-STS enforce mode | Publish policy, honour peers' policies |
| P0 | TLS-RPT ingestion | Detect downgrade and interception |
| P1 | DANE / TLSA validation | DNSSEC-anchored, stronger than MTA-STS |
| P1 | BATV or VERP bounce tags | Stops backscatter and bounce flooding |
| P1 | ARC on forwarding | Preserve auth across mailing lists |
| P2 | BIMI plus VMC | Logo in inbox, needs DMARC enforce |

---

## 5. Sending credential lifecycle

An API key is a bearer credential. No login, no MFA, no expiry by default. A
leaked key is full send authority until someone notices the complaint rate.
Full analysis in [T1](docs/threat-model.md).

| P | Feature | Detail |
| --- | --- | --- |
| P0 | Scoped keys | Per domain, stream, and action |
| P0 | Key expiry by default | No immortal credentials |
| P0 | Distinct key prefix | Enables public secret scanners |
| P0 | Never display key twice | Fewer copies in the wild |
| P0 | Last-used and source IP | Owner spots the stranger |
| P0 | Two live keys for rotation | Rotate without downtime |
| P0 | Per-key send quota | Caps the blast radius |
| P0 | Instant per-key kill switch | Stop mid-campaign |
| P1 | Request signing (RFC 9421) | Key signs, never transits |
| P1 | Short-lived minted tokens | Derived from the key |
| P1 | Secret-scanner webhook | Auto-revoke on public leak |
| P1 | Dedicated IP per large tenant | Isolates reputation damage |
| P2 | mTLS for high-volume tenants | Certificate-bound credential |

⚠️ Console sessions grant key creation, so they are equally sensitive. Require
fresh authentication before creating a key or adding a domain.

---

## 6. Relay and API surface

| P | Feature | Detail |
| --- | --- | --- |
| P0 | Header injection guard | Strip CRLF from all API fields |
| P0 | No auth over plaintext | Submission on 587 STARTTLS or 465 |
| P0 | Per-tenant SMTP credentials | Never one shared relay password |
| P0 | Open relay regression test | CI asserts refusal every build |
| P1 | Optional IP allowlist | Per tenant, per credential |
| P1 | RFC 9421 webhook signing | HTTP Message Signatures, not homemade HMAC |
| P1 | Webhook replay window | Timestamp plus nonce cache |

---

## 7. AI-specific risk

Your AI features read attacker-authored email content. That content is data,
never instructions.

| P | Feature | Detail |
| --- | --- | --- |
| P0 | Prompt injection isolation | Content in data channel only |
| P0 | No tool access from content | Scoring model cannot act |
| P1 | Output validation | Schema-check every model response |
| P1 | Model abuse quotas | Stop AI-assisted spam generation |
| P2 | Generated-content watermark | Internal provenance tag |

---

## 8. Post-quantum readiness

| P | Feature | Detail |
| --- | --- | --- |
| P1 | Hybrid TLS key exchange | X25519 plus ML-KEM-768 on API |
| P2 | ML-DSA signing option | For webhooks and future DKIM2 |
| P2 | Crypto inventory | Know every algorithm you ship |

Classical algorithms are deprecated by 2030 and disallowed by 2035. Harvest-now
decrypt-later means today's TLS traffic is already at risk.

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
