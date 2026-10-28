# Finance Developer Assistant

An evidence-first, model-neutral developer assistant for finance software.
Inspect committed changes, challenge their assumptions, reproduce findings,
and propose small fixes while preserving project authority and private data.

This project specializes its **workflows and review profiles**, not model
weights. It does not train on repository content or claim professional credentials.

## Start in one minute

Python 3.11 or newer is required. From a clone:

```sh
python -m venv .venv
# macOS / Linux
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
finassist demo
finassist doctor
finassist init --output finassist.json
finassist export-kit --output assistant-integration
```

The demo needs no key, model download, container or network. It runs fictional
cash, weight, tax-character and point-in-time evidence checks and detects
deliberately broken examples. It is not a model-quality benchmark.
If your Linux distribution omits the standard venv bootstrap, use an existing
`uv` installation with `uv venv .venv`, then `uv pip install --python .venv/bin/python .`.

## What it does

- **Plan:** freeze base/head commits, use their merge base, enumerate all changed
  paths, screen both file versions and produce an inspectable context packet.
- **Triage:** proactively identify security, financial, evidence, migration and
  release risks. A bounded watcher notices committed-head changes without paid calls.
- **Review:** use your chosen provider, validate structured findings, and reject
  stale revisions, nonexistent evidence, skipped coverage and incomplete responses.
- **Check:** run configured test recipes on exported committed source in a pinned,
  network-disabled Docker/Podman image. Local execution requires explicit opt-in.
- **Propose/apply:** keep model patches as data until an operator approves their
  exact hash on a clean feature branch. Preserve backups and refuse rollback
  over later work. No automatic commit, push, merge, deployment or trading.
- **Audit:** private concurrent budget reservations, usage reconciliation and a
  hash-linked event trail. Unknown billing remains reserved, including across days.
- **Readiness:** inspect GitHub branch controls with GETs and check review/test
  evidence against a configurable local policy. Results grant no merge/deployment authority.
- **Finance profiles:** SaaS tenant boundaries, ledger reconciliation, quantitative
  invariants, source authority, as-filed evidence and approved analyst inputs.
- **Evidence lineage:** immutable fact revisions with content-hash approval;
  drafts do not replace approved observations and ambiguous periods fail closed.

## Review a change

Use a reviewed configuration, then inspect the outgoing packet before approving it:

```sh
finassist --config finassist.json plan --repo . --base main --head HEAD \
  --output .finassist/context.json
finassist --config finassist.json review --packet .finassist/context.json \
  --output .finassist/offline-review.json
```

The default provider is **offline**, regardless of which keys exist in your
environment. Offline review reports risk and coverage; it does not claim a model
review or test success. Uncommitted work is not included.

For a model review, select a provider/model and price assumptions in configuration,
set `allow_network` to true, and supply your key through the named environment
variable or your own secret manager. Never put a key in configuration or arguments.
After inspecting the packet, approve the printed packet hash:

```sh
finassist --config finassist.json review --packet .finassist/context.json \
  --approve-packet YOUR_INSPECTED_PACKET_HASH --allow-network \
  --output .finassist/review.json
finassist render --input .finassist/review.json --output .finassist/review.html
finassist audit
```

The configured provider and exact model are recorded. There is no automatic
fallback to a different model or paid service. See [provider setup](docs/providers.md).

## Bring your model

| Adapter | Intended services | Authentication |
|---|---|---|
| `openai` | OpenAI Responses API; custom compatible Responses endpoints | Named environment variable; bearer or configured API-key header |
| `anthropic` | Anthropic Messages API | Named environment variable |
| `google` | Gemini generateContent API | Named environment variable |
| `compatible` | OpenRouter, DeepSeek, xAI, Mistral, Groq and other Chat Completions-compatible services | Explicit endpoint/approved hostname and optional named key |
| `ollama` | Local Ollama models | Loopback endpoint; no key by default |
| `offline` | Deterministic local inspection and demonstrations | None |

Compatibility is protocol-based, not a claim that every model/service has been
live-tested. A service must support the selected endpoint and return the required
JSON. Model names, prices and service access belong to your configuration.

## Developer workflows

```sh
# Observe a bounded number of committed-head changes; no network or background service
finassist watch --repo . --base main --iterations 3 --interval 5

# Run a named recipe using your prebuilt, digest-pinned container
finassist --config finassist.json check --repo . --recipe unit \
  --output .finassist/unit.json

# Generate a proposal, then inspect its patch and approval hash
finassist --config finassist.json propose --packet .finassist/context.json \
  --approve-packet YOUR_INSPECTED_PACKET_HASH --allow-network \
  --output .finassist/proposal.json

# On a clean feature branch, explicitly apply only the inspected artifact
finassist --config finassist.json apply --repo . --proposal .finassist/proposal.json \
  --approve-hash YOUR_INSPECTED_PROPOSAL_HASH
finassist --config finassist.json rollback --repo . --patch-hash YOUR_INSPECTED_PROPOSAL_HASH
```

See [workflow contracts](docs/workflows.md), [security boundaries](SECURITY.md),
[all configuration options](docs/configuration.md),
[configuration examples](examples), [evaluation](docs/evaluation.md) and
the portable [evidence-review skill](skills/evidence-review/SKILL.md).
Optional native reviewer roles are described in [agent integration](docs/integrations.md).
The local analyst-input store is described in [research inputs](docs/research-inputs.md).
See [auditing and readiness](docs/readiness-and-auditing.md), the
[industry design review](docs/production-design.md) and [security review](docs/security-review.md).

Keep `.finassist/` out of Git, or select a private state directory with the global
`--audit-dir` flag. Operational commands record start/outcome events, UTC times,
run IDs and hashes; source, command arguments, keys and test logs are excluded.
Export verified metadata with `finassist audit --export NEW_PRIVATE_EVENTS.jsonl`.

## Safety and limits

The assistant is advisory. A valid JSON report and a plausible citation do not
prove a defect, execution, correctness or professional suitability. Project specs
and authorized humans own economic rules and approvals.

Source screening is conservative and intentionally rejects common data/binary
formats and sensitive patterns. It cannot prove the absence of private material.
Inspect every outgoing packet. No guard-bypass flag is provided.

Candidate-code execution requires an approved recipe. Docker/Podman isolation
depends on the host runtime, image and mounts; prompt instructions and Python
checks are not sandboxes. Local mode is trusted execution with no security sandbox.
Budget reservations use operator-supplied rates; they are not provider-enforced
billing caps. Unknown calls are not retried automatically.

## Develop

```sh
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pytest -q
ruff check src tests
finassist demo
```

Tests use synthetic inputs and fake HTTP transports. CI never needs provider keys.
See [architecture](docs/architecture.md) and [contribution guide](CONTRIBUTING.md).

MIT licensed. See [LICENSE](LICENSE).
