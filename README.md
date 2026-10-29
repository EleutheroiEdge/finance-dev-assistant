# finledgerpoli

AI code review for financial software that keeps your code local and backs every finding with evidence.

[![PyPI](https://img.shields.io/pypi/v/finledgerpoli)](https://pypi.org/project/finledgerpoli/)
[![CI](https://github.com/EleutheroiEdge/finance-dev-assistant/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/EleutheroiEdge/finance-dev-assistant/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/LICENSE)

![Synthetic offline demo: real local checks, no model calls](https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/docs/images/hero.gif)

## Why finledgerpoli

- Hosted AI reviewers need your source; finledgerpoli runs on your machine and is offline by default. You approve anything that leaves it.
- AI findings can be wrong; reproduce them with your own checks and tie each one to the exact code version.
- AI spend is easy to lose track of; it enforces daily and monthly limits locally and shows spend against them.
- Suggested fixes can be risky; every patch needs your approval and can be rolled back. Nothing merges, deploys or trades by itself.

## Who it's for

**Built for developers of institutional financial software** — rebalancers, optimizers,
risk and tax-lot engines — where a one-cent rounding error or an unexpected change in trades
is a real incident.

| When you... | finledgerpoli helps you... |
|---|---|
| Change an optimizer or rebalancing rule | Review the exact commit with a finance or quant review profile, then reproduce each finding with your own tests before acting on it |
| Worry about rounding, units and edge cases | Run your configured, repeatable checks for cents, basis points vs percent and boundary values, so findings have evidence you can inspect |
| Want AI review without exposing client data | Stay offline by default, screen content before anything leaves your machine, approve every outgoing request, or use a local model through Ollama |
| Need to show reviewers what changed and why | Keep a tamper-evident local log of what was reviewed, found, fixed and approved: audit evidence for your change records |
| Use several AI providers on a budget | Switch between OpenAI, Anthropic, Gemini or local models, with daily and monthly limits and a usage dashboard |
| Let an AI agent suggest fixes | Approve each patch before it applies, with rollback. Nothing merges, deploys or trades by itself |

**Why not a general AI code reviewer?** Hosted reviewers ask you to send your code and trust
their retention policies. finledgerpoli keeps review state and evidence on your machine,
ties findings to the exact code version, and tracks estimated spend and unresolved charges
locally. Remote providers receive the requests you explicitly approve.

## Quick start

Python 3.11+ is required; Git is needed for source workflows. Install with
[pipx](https://pipx.pypa.io/):

```sh
pipx install finledgerpoli
finassist demo
finassist init
finassist dashboard
```

The package is `finledgerpoli`, the command is `finassist` (`finledgerpoli` also works).
For an existing Python environment, `pip install finledgerpoli` is also supported.
The demo needs no key, model download or container; it runs fictional finance checks,
not a model-quality benchmark. The dashboard ships prebuilt, makes no external requests
and binds only to `127.0.0.1`; Node is needed only for frontend development.

### From source

```sh
git clone https://github.com/EleutheroiEdge/finance-dev-assistant.git
cd finance-dev-assistant
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/finassist demo
.venv/bin/finassist init
.venv/bin/finassist dashboard
```

On Windows PowerShell, use `py -3 -m venv .venv`, then
`.\.venv\Scripts\python.exe -m pip install .` and
`.\.venv\Scripts\finassist.exe demo`. No activation or execution-policy change
is required. macOS/Linux use the commands above. See [platform setup](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/platforms.md)
for UTF-8, permissions, Git modes and Docker Desktop details.

## How it works

1. **Plan:** choose the exact commits, screen source and inspect what will be reviewed.
2. **Review:** use a finance, quant or custom checklist with your chosen model, or inspect risks offline.
3. **Reproduce:** run your approved checks against the committed source and compare the evidence.
4. **Propose:** inspect the exact patch, approve it and keep a guarded recovery copy.
5. **Audit:** save evidence for your change records, including approvals, spend and unknown outcomes.

![Plan, Review, Reproduce, Propose, Audit: a five-step flow](https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/docs/images/how-it-works.png)

Start offline from the repository you want to review, after inspecting its configuration
and source policy:

```sh
finassist --config finassist.json plan --repo . --base main --head HEAD \
  --output .finassist/context.json
finassist --config finassist.json review --packet .finassist/context.json \
  --output .finassist/offline-review.json
```

Offline analysis does not claim a model review or test execution. Remote model use
requires an explicit provider, model, endpoint, price assumptions, named key environment
variable, network permission and approval of the exact outgoing request.
There is no automatic provider fallback. See [provider setup](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/providers.md).
[Download the original terminal recording](https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/docs/images/demo.cast.txt)
and play it locally with `asciinema play docs/images/demo.cast.txt`; no hosting account is needed.

## Dashboard

All displayed spend, tokens, findings and review activity are fictional; these light-theme
screenshots use an isolated synthetic fixture and call no provider.

Preview configuration changes before explicitly confirming a save; keys are shown only as present or absent.

![Configuration: offline provider, key availability and spend limits](https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/docs/images/dashboard-configuration.png)

See recorded spend against daily and monthly limits, pending charges, checks and review activity.

![Statistics: fictional spend, tokens, findings and checks](https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/docs/images/dashboard-statistics.png)

Inspect local configuration and capabilities without calling a model or testing a container daemon.

![Health: valid offline configuration and local capabilities](https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/docs/images/dashboard-health.png)

## Use it with AI agents

Use the portable instructions with Claude Code, Codex and Cursor: [agent guide](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/agents.md).
Point an agent at [llms.txt](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/llms.txt) to find the public guides.
Run `finassist guide agents` for offline help; your project's rules and approvals still apply.

## Guides

| Goal | Guide |
|---|---|
| Configure profiles, paths and budgets | [Configuration](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/configuration.md), [examples](https://github.com/EleutheroiEdge/finance-dev-assistant/tree/main/examples/) |
| Choose a model | [Providers](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/providers.md) |
| Plan, review, check and recover | [Workflows](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/workflows.md), [auditing and readiness](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/readiness-and-auditing.md) |
| Use the local dashboard | [Dashboard](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/dashboard.md) |
| Automate command results | [Exit codes and JSON contracts](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/cli-contracts.md) |
| Evaluate findings or manage evidence | [Evaluation](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/evaluation.md), [research inputs](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/research-inputs.md) |
| Integrate your coding agent | [AI agents](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/agents.md), [templates](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/integrations.md), [evidence-review skill](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/skills/evidence-review/SKILL.md) |
| Adapt to your team | [Fork and customize](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/fork-and-customize.md) |
| Understand protection and design | [Threat model](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/threat-model.md), [security policy](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/SECURITY.md), [security design](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/security-design.md), [design principles](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/design-principles.md) |
| Maintain and release a fork | [Repository settings](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/maintainers/repository-settings.md), [releasing](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/maintainers/releasing.md) |

## Safety and limits

- **Advisory only.** A valid report, plausible citation or matching hash does not prove a defect, correctness or professional suitability. Your project's specifications and authorized people own financial rules and approvals. Profiles guide reviews; they do not train model weights or confer professional credentials.
- **Local-first, no telemetry.** Offline is the default, regardless of existing keys. Uncommitted work is excluded. Remote reviews and GitHub inspection require explicit configuration and approval. Protocol compatibility tests use fake transports; not every model or service has been live-tested.
- **Inspect outgoing content.** Screening conservatively rejects common private, binary and sensitive formats, but cannot prove confidentiality. Inspect every outgoing request. There is no guard-bypass switch. Keep `.finassist/`, keys, client data and private artifacts out of Git.
- **Execution needs a reviewed check.** Container isolation depends on the image, daemon and host. Instructions and Python checks are not security sandboxes. Local execution requires explicit opt-in and has no OS filesystem isolation. The dashboard cannot run reviews, checks, shell commands, merges or deployments.
- **Budgets are local estimates.** Prices come from your configuration; limits are not provider-enforced billing caps. Unknown charges remain reserved across days and months and are not retried automatically. Missing usage is unknown, not zero. Pending charges and incomplete runs block a ready-for-review result.
- **Evidence has limits.** Review prerequisites grant no merge, deployment or financial authority. Local audit hashes cannot defeat a malicious rewrite of all state by the same user. Generated files need independent build verification; a green result cannot prove vulnerability absence.
- **Recovery is guarded.** Rollback refuses to overwrite later edits. Interrupted changes need reconciliation from the saved backup; multi-file changes and configuration saves are not atomic against other same-user writers. The local dashboard does not protect against other processes running as you.

## Contribute

```sh
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pytest -q
ruff check src tests scripts
finassist demo
finassist scan --repo .
```

Use synthetic fixtures and fake provider transports. See [contributing](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/CONTRIBUTING.md),
[architecture](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/architecture.md) and [media reproduction](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/images/README.md).
Forks must update repository links and maintainer settings. Posture badges describe
repository settings; they do not establish vulnerability absence.

## License

MIT licensed. See [LICENSE](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/LICENSE).
