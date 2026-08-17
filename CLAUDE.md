# AI-Email

AI-assisted Email Service Provider: transactional mail through pipes we own.
One Go binary — `aiemail serve` (REST, console, unsubscribe) and
`aiemail worker` (delivery, webhooks, domain proof) — with a Postgres queue
and an operated sending engine. V1 scope: [docs/v1-scope.md](docs/v1-scope.md).

This repository follows the
[Agent Lifecycle Standard](https://github.com/hengsoheak/Agent-Lifecycle-Standard-kit).
The rules here bind every agent session; cite IDs (T…, D…, G…, A…) instead of
re-arguing them.

## Commands (A6)

| Verb | Does |
| --- | --- |
| `task test` | `go test -count=1 ./...` — DB tests skip unless `AIEMAIL_TEST_DATABASE_URL` is set |
| `task lint` | gofmt check + `go vet` (G1, G2) |
| `task lint-deep` | golangci-lint, pinned, exactly as CI runs it |
| `task check` | lint + build + test — run before every PR |

⚠️ The race detector (G5) runs in CI only: it needs cgo and the development
machine has no C compiler.

## Conventions

| Rule | Detail |
| --- | --- |
| Config, never constants | Nothing hardcoded to one deployment (D8) |
| Fail closed | Unsafe combinations are refused, not warned about |
| Standard crypto only | Never homemade signing, hashing, or randomness |
| No secrets anywhere | Not in code, tests, fixtures, logs, or PR text (A4) |
| Never send test mail to real addresses | Complaints hit real reputation; use the sandbox path (A4) |
| Recipient addresses never in logs | IDs in traces, not emails (T19) |
| Strict SMTP/MIME parsing stays strict | Smuggling defence is deliberate (T3) |
| Template rendering stays logic-less | SSTI defence is deliberate (T11) |
| Docs move with behaviour | A behaviour change updates the doc in the same PR |
| One concern per PR | Roughly 400 changed lines; split anything larger (A1) |
| Conventional Commits | `feat:` / `fix:` / `docs:` …, matching the existing history |
| DCO sign-off | `git commit -s` on every commit |

## Hot paths (performance pillar)

A change here requires a benchmark in the same PR (G9).

| Path | Why it is hot |
| --- | --- |
| `internal/template` | Renders every outgoing message, on hostile tenant input (T11) |
| `internal/store` | Queue claim and event append run on every delivery attempt |
| `internal/dkim` | Signs every message |

## Registries

| Registry | Where | When to consult |
| --- | --- | --- |
| Decisions D1–D8 | [docs/decisions.md](docs/decisions.md) | Before proposing architecture changes |
| Threats T1–T19 | [docs/threat-model.md](docs/threat-model.md) | When touching exposed surface |
| Backlog P0/P1/P2 | [SECURITY.md](SECURITY.md) | When prioritising security work |
| Rejection list | [CONTRIBUTING.md](CONTRIBUTING.md) | Patterns refused on sight |
| Security floor | [docs/v1-scope.md](docs/v1-scope.md) | Controls gating external send |

## Recurring agent mistakes (A5)

When an agent makes the same mistake twice, it becomes a rule here with an ID.

| ID | Rule |
| --- | --- |
| — | none recorded yet |
