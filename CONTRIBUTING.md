# Contributing to AI-Email

Contributions are welcome. This project sends mail on behalf of real domains,
so review is strict — not because we distrust you, but because a defect here
costs reputation that no patch restores.

⚠️ Found a security flaw? **Do not open an issue.** See
[SECURITY.md](SECURITY.md) for the private channel.

---

## Licence and sign-off

| Item | Rule |
| --- | --- |
| Licence | Contributions are accepted under AGPL-3.0 |
| Sign-off | Every commit needs a DCO line |
| Command | `git commit -s` adds it for you |
| Copyright | You keep yours; we do not require assignment |

The sign-off certifies you wrote the change, or have the right to submit it,
under the [Developer Certificate of Origin](https://developercertificate.org/).

---

## Before you open a pull request

| Check | Detail |
| --- | --- |
| Tests pass | Full suite, not only touched files |
| No secrets | Not in code, tests, fixtures, or logs |
| No working example keys | Placeholders must be obviously fake |
| Config, never constants | Nothing hardcoded to one deployment |
| Docs updated | Behaviour changes update the docs |
| One concern per PR | Easier to review, easier to revert |

---

## Things we will ask you to change

| Pattern | Why |
| --- | --- |
| A new dependency without a reason | Supply-chain surface |
| Unsafe defaults with a warning log | Guardrails must fail closed |
| Relaxed SMTP parsing | Smuggling defence is deliberate (T3) |
| Logging recipient addresses | Redaction is required (T19) |
| Homemade crypto or signing | Use the standard, always |
| Template features that widen rendering | SSTI risk (T11) |

The [threat model](docs/threat-model.md) explains each one. If a rule blocks
something you need, open a discussion — the rule may be wrong, but it will not
be bypassed quietly.

---

## Review expectations

| Reality | What it means |
| --- | --- |
| Pull requests are untrusted input | Review is adversarial by design |
| Maintainers are few | Responses may be slow |
| Deliverability changes need evidence | Explain the provider behaviour |
| Support is best-effort | This is not a funded product team |

---

## Local development

Setup lives in the README. Two rules while you work:

| Rule | Reason |
| --- | --- |
| Never send test mail to real addresses | Complaints hit real reputation |
| Use the sandbox path for experiments | Nothing leaves your machine |
