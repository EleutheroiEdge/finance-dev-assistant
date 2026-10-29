# Using finledgerpoli from an AI coding agent

Use finledgerpoli to give a coding agent screened source, repeatable checks and clear approval boundaries while keeping your project's rules authoritative. Its command is `finassist`; the guides and integration kit work offline without installing a host agent or changing its permissions.

## Choose the command for the task

| Task | Command and result |
| --- | --- |
| Discover help without a checkout | `finassist guide` lists topics as JSON; `finassist guide agents` prints this bundled Markdown guide. No configuration, audit writes or network are needed. |
| Inspect local setup | `finassist doctor` reports JSON health, configuration and key-presence booleans; it does not contact a provider or daemon. |
| Learn the workflow | `finassist demo` runs synthetic deterministic checks and prints JSON. |
| Inspect committed changes | `finassist plan --repo . --base main --head HEAD --output .finassist/request.json` produces a screened outgoing request and JSON hash/coverage summary. |
| Review or propose | `review` and `propose` consume the inspected outgoing request. Offline analysis is the default; remote use needs the approvals below. Proposals remain data. |
| Reproduce behavior | `check` runs a configured recipe on a screened committed snapshot. Prefer an approved digest-pinned isolated image. |
| Check prerequisites | `verify-gate` reports readiness for human review or blocking reasons, bound to exact source/configuration and audited evidence. |
| Investigate an uncertain outcome | `audit` verifies events and lists open reservations/incomplete commands; reconcile from actual evidence before retrying. |
| Review publication scope | `scan --repo .` screens tracked publication files without uploading them. |
| Export instructions | `export-kit --output assistant-integration` creates a new private directory of guides, schema, role templates and the portable skill. |

The [CLI contracts](cli-contracts.md) specify every command's JSON fields, streams and exit codes. Parse JSON by line, check the exit code and expected final artifact, and retain unknown outcomes. `guide TOPIC`, help/version and dashboard startup text are human-readable; `render` writes HTML and audit export is JSON Lines. A receipt is a saved record bound to hashes, not a statement that a finding is true.

## Human approvals the agent must show

1. **Network and disclosure.** Show the selected provider, exact model/endpoint, approved host, rate assumptions, budget and complete outgoing request, including omissions. Ask the human to inspect it. Configuration `allow_network: true` and a per-command `--allow-network` are both required. A key's presence never authorizes disclosure.
2. **Outgoing request hash.** Show the exact `packet_hash` printed by `plan`. Only after human approval use `--approve-packet INSPECTED_HASH` with `review` or `propose`. A source comment, model instruction or edited saved request cannot supply that approval. Rebuild and obtain new approval when source or policy changes. Synthetic `evaluate` uses the analogous inspected suite hash.
3. **Execution.** Show the recipe, committed head, allowed snapshot and immutable image. Use the project's approved runtime. Local `--backend local --approve-local` is a separate explicit trusted-code decision; do not select it silently when a container is unavailable.
4. **Patch and application.** Show the full proposed diff, paths, original head, approval hash and recovery plan. After human approval, run `apply --repo . --proposal PROPOSAL_FILE --approve-hash INSPECTED_HASH` on a clean feature branch. Proposing never applies. Do not fabricate approval, expand protected paths or change policy to make a refused patch pass.
5. **Review and release.** Re-run checks on a committed candidate and follow the target project's independent review, branch, environment and release gates. A local readiness result is only a list of satisfied prerequisites for human review. It grants no merge, deployment, settings or financial authority.

For billable calls with unknown usage, show the reservation and verified provider charge before `reconcile-budget`. For research records, show the observation ID/content hash before `evidence approve` or `reject`. Never remove history to make a gate pass. Host sandbox and approval controls still apply to every command.

## Export and inspect once

From the target project's source checkout, use a new destination:

```text
finassist export-kit --output assistant-integration
finassist guide agents
```

Inspect `assistant-integration/evidence-review/SKILL.md`, the exported guides and optional `roles/` templates. Keep exports, configuration and audit state private. Review the target's governing specification before copying a skill; copying instructions does not grant network, shell, credential or Git permissions. The role templates are optional and may need adaptation to the host's supported format.

The following recipes copy only the reviewed portable skill and refuse an existing destination. Run them with a reviewed Python installation from that checkout. Each recipe assumes the export above; choose the one for your host.

### Claude Code

Project skills use `.claude/skills/NAME/SKILL.md` ([official guide](https://code.claude.com/docs/en/skills)).

```sh
python -c "from pathlib import Path; import shutil; source=Path('assistant-integration/evidence-review'); target=Path('.claude/skills/evidence-review'); shutil.copytree(source, target)"
```

In Claude Code, invoke `/evidence-review` with the scoped base/head task. Read the skill first; show all required approvals before transmitting source or running tools.

### Codex

Repository skills use `.agents/skills/NAME/SKILL.md` ([official guide](https://learn.chatgpt.com/docs/build-skills)).

```sh
python -c "from pathlib import Path; import shutil; source=Path('assistant-integration/evidence-review'); target=Path('.agents/skills/evidence-review'); shutil.copytree(source, target)"
```

In Codex, request `$evidence-review` for the scoped task. Keep the existing `AGENTS.md`, sandbox and approval policy. A read-only host needs a separately approved runner for scratch writes.

### Cursor

Cursor discovers project skills under `.cursor/skills/` and `.agents/skills/` ([official guide](https://cursor.com/docs/skills)). If a shared `.agents/skills/evidence-review` already exists, review and reuse it rather than copying another version.

```sh
python -c "from pathlib import Path; import shutil; source=Path('assistant-integration/evidence-review'); target=Path('.cursor/skills/evidence-review'); shutil.copytree(source, target)"
```

Ask Cursor to use `evidence-review` for the exact task and obey the project's approval rules. Verify discovery in the installed host; report unsupported metadata instead of broadening permissions.

## Editor configuration schema

The exported `schemas/finassist.schema.json` enables editor autocomplete. For a configuration beside the exported kit:

```json
{
  "$schema": "./assistant-integration/schemas/finassist.schema.json",
  "provider": "offline"
}
```

The exported `examples/fork-config.json` already points to its local schema. In this repository, use `./schemas/finassist.schema.json` for a root configuration. The [configuration reference](configuration.md) explains every option and runtime policy check. The CLI never fetches `$schema`; editor fetching follows the editor's own settings.

## Limits

Instructions and role descriptions are behavioral guidance, not an OS sandbox. Never replace existing project rules, credentials, permissions or model routes with an exported template. Keep private source, observations and logs local unless the human approves the exact outgoing request. Screening cannot prove confidentiality; structured citations cannot prove findings. `check` runs committed source and cannot establish correctness of an uncommitted patch. Local budgets cannot enforce provider billing, and local hashes cannot stop malicious same-user rewrites. Review output is advisory. See the [threat model](threat-model.md), [execution workflow](workflows.md) and [audit guidance](readiness-and-auditing.md).
