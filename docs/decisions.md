# AI-Email — decision record

Decisions that shape V1. Each records what was chosen, what was rejected, and
what would reverse it. Scope and phases live in [v1-scope.md](v1-scope.md).

| ID | Decision | Date |
| --- | --- | --- |
| D1 | Adopt a proven sending engine | 2026-08-16 |
| D2 | No new languages in V1 | 2026-08-16 |
| D3 | REST-only, no tenant SMTP submission | 2026-08-16 |
| D4 | Transactional only, no bulk | 2026-08-16 |
| D5 | We are tenant zero | 2026-08-16 |
| D6 | Resend stays as fallback | 2026-08-16 |
| D7 | Sending nodes are rented and disposable | 2026-08-16 |
| D8 | Distributed as an open-source project | 2026-08-16 |

---

## D1 — Adopt a proven sending engine

The outbound queue engine is the smallest part of the codebase and the largest
part of the risk. Retry rules, per-destination shaping, warmup enforcement, and
crash-safe exactly-once delivery are years of work, and mistakes there are paid
in reputation, which no deploy can restore.

| Option | Verdict |
| --- | --- |
| Write our own MTA now | ❌ slowest, riskiest path |
| Run an ESP-grade open engine | ✅ chosen for V1 |
| Rent an ESP forever | ❌ no product to sell |

We run the engine; we still own tenants, keys, templates, AI features, console,
analytics, key custody, the IPs, and the customer. The engine is a component,
not the business.

**Reverses if:** the engine blocks a feature we need at real volume. Then we
write ours behind the same internal interface.

---

## D2 — No new languages in V1

| Layer | V1 |
| --- | --- |
| api, worker | Python |
| console | TypeScript |
| data | Postgres, Redis |
| sending engine | Operated, not written |

Go remains correct for hostile-protocol and credential-holding services. It is
deferred, not dropped — see [v1-scope.md](v1-scope.md) for the triggers that
introduce it.

Every new language and service is permanent operational work. Each one must be
forced by a limitation we have actually hit.

**Reverses if:** a V2 trigger fires (tenant SMTP submission, key-custody gap).

---

## D3 — REST-only, no tenant SMTP submission

V1 accepts mail over REST. Inbound SMTP submission from tenants is deferred.

| Consequence | Detail |
| --- | --- |
| Go relay not needed yet | Its threat surface is deferred with it |
| T3 smuggling scope narrows | We speak SMTP outbound only |
| Integrations still work | Kratos courier uses our relay later |

⚠️ Deferred, not solved. When submission ships, every T3 and T15 control ships
with it, in Go, before the first external credential is issued.

**Reverses if:** a tenant integration cannot use REST.

---

## D4 — Transactional only, no bulk

Transactional mail builds reputation. Bulk mail spends it, and carries the
threats that kill young platforms — T4 outbound abuse, T2 replay blasts, T18
list-washing.

| V1 sends | V1 refuses |
| --- | --- |
| Verification, recovery | Campaigns, newsletters |
| Orders, invoices, digests | Imported lists |

**Reverses if:** transactional reputation is stable and the T4 and T9 controls
are all shipped and proven.

---

## D5 — We are tenant zero

No outside tenants in V1. Our own mail only.

| Benefit | Detail |
| --- | --- |
| Small, wanted, clicked mail | Ideal warmup traffic |
| Bugs hit us, not customers | Cheapest possible failures |
| KYC and abuse work deferred | Not needed with one known tenant |

**Reverses if:** V1 exit criteria are met and the P1 abuse controls ship.

---

## D6 — Resend stays as fallback

The send API is deliberately Resend-shaped. One config value switches AiERP
between our pipes and rented pipes, in either direction.

| Use the fallback when | Why |
| --- | --- |
| Warmup limits our volume | Mail still gets delivered |
| A reputation incident starts | Stop sending, keep operating |
| A deploy goes wrong | Business mail is never hostage |

⚠️ The switch must be config only. Any code path that assumes our own engine
breaks the parachute.

---

## D7 — Sending nodes are rented and disposable

Port 25 is blocked on DigitalOcean, so sending nodes live at a provider that
permits outbound SMTP. Nodes are cattle; the IP reputation is the asset.

| Requirement | Reason |
| --- | --- |
| Clean IPv4 history | We inherit the previous owner's sins |
| rDNS we control | Providers check PTR first |
| Rebuildable from config | No hand-tuned pet servers |
| Reputation monitored daily | Damage is repairable in hours, not weeks |

**Reverses if:** volume justifies owning address space.

---

## D8 — Distributed as an open-source project

AI-Email is built to be run by anyone, not only by us. We are the first
operator, not the only one.

| Component | Licence |
| --- | --- |
| Server, console, this repository | AGPL-3.0 |
| Future client SDKs | Apache-2.0 |
| Contributions | AGPL-3.0, DCO sign-off |

AGPL was chosen because our moat is IPs, reputation, and provider
relationships — not source code. We can afford real openness. What AGPL
prevents is a funded competitor hosting our work and returning nothing.

Client SDKs stay permissive because nobody integrates against a copyleft
library.

⚠️ **AGPL section 13 binds us too.** Anyone using our hosted service may
demand the corresponding source of the version they used. Publishing a tagged
release for every deployed version is an operating requirement, not a
courtesy.

⚠️ Contributions are taken under DCO, not a contributor agreement, so
contributors keep their copyright. Dual-licensing later would need every
contributor's permission — accepted deliberately, in exchange for lower
friction now.

### What this changes

| Area | Requirement |
| --- | --- |
| Configuration | Self-configuring, nothing hardcoded to us |
| Defaults | Safe out of the box, unsafe combinations refused |
| Secrets | No working example keys, ever, anywhere |
| Deployment | A stranger deploys it from the docs alone |
| Releases | Semantic versions, changelog, upgrade notes |
| Disclosure | Public policy and contact before v1.0 |
| Contributions | Reviewed as hostile input, like any other |

### Why this raises the security bar

| Reality | Consequence |
| --- | --- |
| Attackers read the source | A weak default becomes a known exploit |
| Operators misconfigure | Their bad sending reflects on the project |
| Contributors submit code | Supply-chain risk arrives by pull request |
| Issues are public | Vulnerability reports need a private channel |

An ESP that others self-host multiplies the reputation surface: every careless
deployment shapes how mailbox providers judge software that identifies itself
as ours.

### What stays ours

| Ours | Detail |
| --- | --- |
| Our IPs and reputation | Never shared by a licence |
| Our operated service | The product we sell |
| Project name and marks | Trademark, not copyright |

**Reverses if:** nothing. Publication is one-way — code released under a
licence cannot be recalled from those who already have it. Choose carefully
once, not quickly.
