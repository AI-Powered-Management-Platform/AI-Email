# AI-Email — threat model

Written 2026-07-30. Extended 2026-08-15 with T10–T19. Each threat lists how it
works, why obvious defences fail, and which controls actually stop it. Controls
map to priorities in [../SECURITY.md](../SECURITY.md).

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
| T10 | DKIM private-key theft | Critical |
| T11 | Template injection (SSTI) | Critical |
| T12 | Webhook SSRF | High |
| T13 | Click-tracking redirect abuse | High |
| T14 | Domain verification lapse | High |
| T15 | SMTP credential guessing | High |
| T16 | Unsubscribe forgery | Medium |
| T17 | Hostile inbound content | Medium |
| T18 | Validation API list-washing | Medium |
| T19 | Recipient data breach | Medium |

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

## T10 — DKIM private-key theft

### The core problem

Every replay control in T2 assumes the private key is ours alone. Steal the
key and the attacker signs **fresh** mail forever — short `x=` expiry does
nothing, because each forgery carries a new, valid signature.

| Item | Reality |
| --- | --- |
| Signature on forged mail | Genuine, ours |
| Detection by mailbox providers | None, it validates |
| Recovery | DNS rotation on every tenant domain |

### Where signing keys leak

| Vector | Mechanism |
| --- | --- |
| Plaintext on MTA node disk | Read by any node compromise |
| Backups and snapshots | Copied with the volume |
| Config repo or CI secrets | Committed once, leaked forever |
| Memory dump of signer | Key material in process space |
| Insider with shell access | No audit trail |

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Cloud KMS envelope encryption | Keys never plaintext at rest | P0 |
| Decrypt only in signer memory | Never on disk, never in env | P0 |
| No export path in any API | Keys are write-only | P0 |
| Isolated signing service | Own segment, minimal peers | P1 |
| Sign-operation audit log | Per domain, per message count | P0 |
| Automated compromise rotation | New key, new DNS, one action | P0 |
| HSM for high-value domains | Hardware-bound keys | P2 |

⚠️ Revocation is DNS removal of the public key — build the rotation runbook
before first send, not after first theft.

---

## T11 — Template injection (SSTI)

### How it works

Feature H renders tenant-authored templates. A full template engine given
hostile input is remote code execution on the render worker.

| Step | What happens |
| --- | --- |
| 1 | Tenant signs up, or tenant account is stolen |
| 2 | Template walks engine internals via attribute access |
| 3 | Render worker executes attacker code |
| 4 | Worker holds keys, queue creds, tenant data |

Sandbox escapes in template engines are published regularly. Assume the
engine is hostile-input-facing, because it is.

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Sandboxed engine only | Never the full engine | P0 |
| Block attribute and dunder access | No engine-internal walking | P0 |
| Filter and function allowlist | Merge, format, translate — nothing else | P0 |
| Render resource caps | CPU time, memory, output size | P0 |
| Isolated render worker | No network, no secrets, no queue creds | P1 |
| SSTI payload regression suite | Known escapes fuzzed in CI | P1 |

---

## T12 — Webhook SSRF

### How it works

Tenants set webhook URLs. Our worker POSTs to them from inside our network.

| Step | What happens |
| --- | --- |
| 1 | Tenant sets URL to an internal address |
| 2 | Worker connects from the trusted segment |
| 3 | Cloud metadata, Redis, internal APIs answer |
| 4 | DNS rebinding defeats naive URL checks |

MX validation (feature V) has the same shape: attacker-steered DNS lookups
from our resolvers.

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Resolve once, pin the connect | Check and connect on same IP | P0 |
| Deny private and metadata ranges | RFC 1918, link-local, 169.254.169.254 | P0 |
| Ports 443 and 80 only | Nothing else dialable | P0 |
| Never follow redirects blindly | Re-validate every hop | P0 |
| Egress proxy in own segment | Workers have no direct egress | P1 |
| Response size and time caps | No slow-drip amplification | P1 |

---

## T13 — Click-tracking redirect abuse

### How it works

Feature U rewrites links through our tracking domain. If the destination is a
request parameter, we are an open redirect — phishers launder their URLs
through our reputation, and blocklists answer by burning our domain.

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Destination stored at send time | Token is a random ID, never a URL | P0 |
| No user-controlled redirect params | Nothing to tamper with | P0 |
| Destination frozen after send | No re-pointing a sent link | P1 |
| URL reputation check at send | Ties into T4 scanning | P1 |
| Tracking domains fully separate | Never share console or API domains | P0 |
| No cookies on tracking domain | Nothing to steal, nothing to join | P0 |

---

## T14 — Domain verification lapse

### How it works

Verification is proven once, then trusted forever. Domains expire, DNS records
dangle, ownership changes. The SubdoMailing campaign abused thousands of
stale records to send as trusted brands.

| Step | What happens |
| --- | --- |
| 1 | Tenant verifies domain, later abandons it |
| 2 | Registration lapses or CNAME dangles |
| 3 | New owner or squatter controls the DNS |
| 4 | Old tenant account still sends as that domain |

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Continuous re-verification | Daily DNS proof re-check | P0 |
| Auto-suspend on proof loss | Sending stops when DNS proof vanishes | P0 |
| Per-tenant proof tokens | Generic records prove nothing | P0 |
| One domain, one tenant | Conflicting claims rejected | P0 |
| Warn before suspending | Tenant fixes DNS drift | P1 |

---

## T15 — SMTP credential guessing

### How it works

Bots hammer AUTH on 587 and 465 across the whole internet, continuously.
T1 covers leaked keys; this is online guessing, and it works wherever
passwords are weak or reused.

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Generated credentials only | High-entropy, never user-chosen | P0 |
| Per-IP and per-account limits | Lockout with exponential backoff | P0 |
| AUTH never on port 25 | Submission ports only | P0 |
| Tarpit on failure | Guessing gets slow and expensive | P1 |
| Distributed-guess detection | Low-rate, many-IP campaigns | P1 |

---

## T16 — Unsubscribe forgery

### How it works

RFC 8058 one-click headers point at an unsubscribe endpoint. If the target is
guessable, an attacker mass-unsubscribes a tenant's list. Worse: corporate
mail scanners prefetch every link — a GET that mutates state unsubscribes
readers by accident.

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Signed per-recipient tokens | Expiring, single-purpose | P0 |
| POST-only state change | RFC 8058 requires it anyway | P0 |
| GET renders confirmation only | Scanner prefetch is harmless | P0 |
| Rate limits on the endpoint | No bulk forgery sweeps | P1 |
| Unsubscribe source audit | Header click vs page vs API | P1 |

---

## T17 — Hostile inbound content

### How it works

Bounces, DSNs, FBL and ARF reports are attacker-authored input parsed by the
worker. MIME nesting bombs, decompression bombs, and parser exploits arrive
by just… sending us mail.

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Size, depth, and count caps | Enforced before parsing starts | P0 |
| Hardened parser configuration | No recursion surprises | P0 |
| Sandboxed parse worker | No network, minimal credentials | P1 |
| Continuous parser fuzzing | Same rig as the smuggling suite | P1 |
| Poison-message quarantine | Crash telemetry, auto-isolate | P1 |

---

## T18 — Validation API list-washing

### How it works

Feature V verifies addresses. Spammers feed stolen lists through validation
APIs to wash them clean, then blast the survivors — from us or elsewhere. We
pay the infrastructure and reputation cost of their cleaning.

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Validation quota tied to sending | No validate-heavy, send-light accounts | P0 |
| KYC before bulk validation | Same gate as volume unlock | P0 |
| Validate-to-send ratio anomaly | The washing signature | P1 |
| Throttle asymmetric accounts | Washing becomes uneconomic | P1 |

---

## T19 — Recipient data breach

### How it works

Lists, logs, and suppression tables are recipient PII. A breach converts a
reputation product into a data-liability product overnight. And erasure law
collides with feature L's immutable log unless designed for.

### Controls

| Control | Detail | P |
| --- | --- | --- |
| Field-level encryption of recipients | Lists, events, suppression | P0 |
| Body storage off by default | Store render inputs, not output | P0 |
| Address redaction in app logs | Traces carry IDs, not emails | P0 |
| Per-tenant retention windows | Data expires by policy | P1 |
| Crypto-erasure | Per-recipient keys; delete key = erased | P1 |
| Hashed suppression option | Suppress without storing the address | P2 |
| Regional data residency | Tenant picks the region | P2 |

Crypto-erasure reconciles the immutable audit log with erasure requests: the
log keeps its hash chain, the plaintext is gone.

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
- [Server-side template injection research](https://portswigger.net/research/server-side-template-injection)
- [OWASP SSRF prevention cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [RFC 8058 one-click unsubscribe](https://datatracker.ietf.org/doc/html/rfc8058)
- [SubdoMailing campaign, Guardio Labs](https://labs.guard.io/)
- [NIST SP 800-88 media sanitisation](https://csrc.nist.gov/pubs/sp/800/88/r1/final)
- [M3AAWG published best practices](https://www.m3aawg.org/published-documents)
