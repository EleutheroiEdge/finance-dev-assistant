<h1>Finance Developer Assistant</h1>

[![PyPI](https://img.shields.io/pypi/v/finledgerpoli)](https://pypi.org/project/finledgerpoli/)
[![CI](https://github.com/EleutheroiEdge/finance-dev-assistant/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/EleutheroiEdge/finance-dev-assistant/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/EleutheroiEdge/finance-dev-assistant/badge)](https://scorecard.dev/viewer/?uri=github.com/EleutheroiEdge/finance-dev-assistant)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/LICENSE)
[![Tested Python](https://img.shields.io/badge/tested%20Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/pyproject.toml)

Review committed changes, reproduce findings and inspect readiness evidence for
finance software, using your chosen model or deterministic offline analysis.

**Local-first, no telemetry.** The default provider is offline. The demo and local
dashboard make no external requests. Remote model reviews and GitHub inspection
require explicit configuration and approval. The dashboard ships prebuilt and
binds only to `127.0.0.1`; Node is needed only for frontend development.

<h2>What it does</h2>

- **Review source:** freeze commits, screen paths/content, inspect coverage and
  use configurable finance, research, quant or custom review profiles.
- **Reproduce:** run approved recipes on screened snapshots in a pinned,
  network-disabled container; trusted local execution requires explicit opt-in.
- **Propose carefully:** inspect and approve exact patch hashes, protect policy
  files and preserve guarded recovery copies. No automatic merge, deploy or trade.
- **Track evidence:** local spend reservations, usage, findings, readiness and a
  tamper-evident audit trail; unknown outcomes stay visible and block readiness.
- **Configure locally:** preview a diff, confirm a save, inspect statistics and
  run Health checks from the browser. API keys stay in environment variables.

<h2>Start in one minute</h2>

Python 3.11+ is required; Git is needed for source workflows. Install with
[pipx](https://pipx.pypa.io/) in an isolated command environment.
The distribution is `finledgerpoli`; the command and import package remain
`finassist`, with `finledgerpoli` also available as a command alias.

```sh
pipx install finledgerpoli
finassist demo
finassist doctor
finassist init --output finassist.json
finassist --config finassist.json dashboard
```

For an existing Python environment, `pip install finledgerpoli` is also supported.

<h3>From source</h3>

To develop from a source checkout, clone and install in a virtual environment:

```sh
git clone https://github.com/EleutheroiEdge/finance-dev-assistant.git
cd finance-dev-assistant
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/finassist demo
.venv/bin/finassist init --output finassist.json
.venv/bin/finassist --config finassist.json dashboard
```

On Windows PowerShell, use `py -3 -m venv .venv`, then
`.\.venv\Scripts\python.exe -m pip install .` and
`.\.venv\Scripts\finassist.exe demo`. No activation or execution-policy change
is required. macOS/Linux use the commands above. See [platform setup](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/platforms.md)
for UTF-8, permissions, Git modes and Docker Desktop details.

The demo uses fictional finance checks and needs no key, model download or
container. It demonstrates deterministic oracles, not model review quality.
[Download the short terminal recording](https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/docs/images/demo.cast.txt) and play it locally
from a source checkout with `asciinema play docs/images/demo.cast.txt`; no hosting
account is needed.

<h2>Dashboard preview</h2>

These screenshots come from an isolated synthetic fixture. All displayed spend,
tokens, findings and review activity are fictional; no provider was called.

![Configuration: offline provider, key-presence indicators and spend limits](https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/docs/images/dashboard-configuration.png)

<details>
<summary>Statistics and Health screenshots</summary>

![Statistics: fictional spend, tokens and findings](https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/docs/images/dashboard-statistics.png)

![Health: valid offline configuration and local capability checks](https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/docs/images/dashboard-health.png)

</details>

See the [dashboard guide](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/dashboard.md) for configuration previews, explicit
confirmation, audit statistics and same-user security limits.

<h2>Review your first change</h2>

From the repository you want to review, after inspecting your configuration and
source policy:

```sh
finassist --config finassist.json plan --repo . --base main --head HEAD \
  --output .finassist/context.json
finassist --config finassist.json review --packet .finassist/context.json \
  --output .finassist/offline-review.json
```

Offline analysis does not claim a model review or test execution. To use a remote
model, choose its provider/model/endpoint, price assumptions and named environment
variable; enable network access deliberately and approve the exact outgoing packet.
There is no automatic provider fallback. [Provider setup](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/providers.md) explains
OpenAI Responses, Anthropic, Gemini, compatible Chat Completions and local Ollama.
Compatibility tests use fake transports; not every model/service is live-tested.

<h2>Guides</h2>

| Goal | Guide |
| --- | --- |
| Adapt to your own team | [Fork and customize](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/fork-and-customize.md) |
| Understand protection and limits | [Threat model](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/threat-model.md), [security policy](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/SECURITY.md) |
| Configure profiles, paths and budgets | [All configuration options](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/configuration.md), [examples](https://github.com/EleutheroiEdge/finance-dev-assistant/tree/main/examples/) |
| Automate command results | [Exit codes and JSON contracts](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/cli-contracts.md) |
| Plan, review, check and recover | [Workflow contracts](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/workflows.md), [auditing/readiness](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/readiness-and-auditing.md) |
| Evaluate findings or manage evidence | [Evaluation](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/evaluation.md), [research inputs](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/research-inputs.md) |
| Integrate your coding agent | [Portable templates](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/integrations.md), [evidence-review skill](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/skills/evidence-review/SKILL.md) |
| Maintain and release a fork | [Repository settings](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/repository-settings.md), [releasing](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/releasing.md) |

Keep `.finassist/` and private artifacts out of Git. Inspect every outgoing packet:
content screening cannot prove confidentiality. A readiness result grants no merge,
deployment or financial authority. Local audit hashes cannot defeat a malicious
same-user rewrite; budget estimates are not provider-enforced billing caps.

<h2>Contribute</h2>

From a source checkout:

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
Scorecard is a posture indicator, not certification; results appear after its
workflow publishes. Forks must update badge/repository links and maintainer settings.

MIT licensed. See [LICENSE](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/LICENSE).
