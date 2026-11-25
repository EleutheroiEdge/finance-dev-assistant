# Workflow contracts

Review committed changes, reproduce numerical behavior and prepare approved patches with finledgerpoli. Its command is `finassist`; follow the target project’s governing methodology throughout.

Saved records bind actions to exact source, configuration and execution hashes.

## Source review

Use the project's governing methodology/specification as authority. Open a scoped
task, resolve its commits, inspect the outgoing request and identify required
baseline/candidate cases. A source-only review cannot claim a run was executed.
Coverage omissions are explicit and block external model review by default.
Amend the allowlist and rebuild the outgoing request for complete review. You may
set `allow_partial_review` to true for a scoped review; its report remains labeled
partial and lists omissions. An outgoing request with no included source never calls a model.

Choose `finance-saas` for tenant authorization, money movement, audit and recovery;
`investment-research` for as-filed periods, source precedence, approved inputs and
revisions; `quant-review` for portfolio calculations and optimization invariants;
or `general` for ordinary engineering. Profiles are checklists, not economic canon.

## Evidence before conclusions

For material numerical changes, compare immutable baseline and candidate source
on the same synthetic book. Recompute final cash, fees, weights and disclosures.
Use order reversal, lot splitting, identity substitutions and mode boundaries
only where the specification says those should be invariant. Freeze prices and
label hypothetical values. A changed number can be correct; a matching number
can result from an unexercised path.

Research records carry entity, units, period kind, start/end, publication and
retrieval timestamps. A decision cannot use a later filing. Draft analyst
judgments never enter approved calculations. Missing evidence is reported as
missing, not replaced by zero or inferred from model memory.

## Test execution

Configure named `recipes`, for example `unit: ["python", "-m", "pytest", "-p",
"no:cacheprovider"]`. Build and inspect a suitable test image yourself, install
the project's pinned dependencies there, and configure its immutable
`runner_image` digest. The assistant does not pull images automatically. Only
allowlisted text files from the chosen commit enter the snapshot. Add synthetic
fixtures and build metadata to the allowlist as needed; never add private input roots.

An example test image is supplied at `examples/runner.Dockerfile`, with a pinned
public Python base and the exact development lock. The Docker build context is
allowlisted by `.dockerignore`. Build it explicitly, inspect its local image id,
and use that `sha256:` id as `runner_image`; no registry push is necessary.
The image does not bundle a project's engine or private data. Adapt dependencies
through a reviewed image build for your project. Git-dependent integration tests
also need Git installed in that project image.

The default container is network-disabled, non-root, capability-dropped and read-only, with scratch temporary storage and resource limits. A test requiring writable project files needs an explicit reviewed adapter; do not grant the real checkout write access.

`--backend local --approve-local` is for trusted recipes only. It receives a
minimal environment and temporary HOME.

In a container, a recipe's `python` is the image's. On the local backend it is the project's
interpreter, chosen by `recipe_python`. By default finassist takes the first `python`, then
`python3`, on an absolute PATH entry, so activate the project's environment (for example
`source .venv/bin/activate`, or `.venv\Scripts\activate` on Windows) before `check`. This matters
when finassist itself comes from `pipx` or `uv tool`: its own interpreter has none of the project's
packages. Set `recipe_python` to an absolute interpreter path to pin one, or to `"finassist"` when
finassist is installed in the project's environment. Other programs, such as `pytest` or `npm`, are
also taken from absolute PATH entries only; the current directory and the snapshot are never
searched, and `.cmd` or `.bat` files are refused however they are named.

Before a `python -m MODULE` recipe runs, the interpreter must find MODULE's top-level package, or
`check` stops with `recipe_python_module_missing` instead of a failed run. The lookup starts the
interpreter isolated and outside the snapshot, so none of the snapshot's code runs for it. If the
lookup fails for another reason and the interpreter works on its own, the recipe runs and its saved
check record shows the failure.

A program found on PATH, or written with a root, must not be one the change could supply
(`recipe_program_inside_change`). Every folder and link read on the way to it is checked, links
followed one at a time and `..` read as the system reads it. None may be in the snapshot, and none
may be in a top-level entry of the repository that Git tracks, in the index or at the commit being
checked. Names are compared without regard to case, and a folder reached under another name is
the same folder. An ignored `.venv` is fine; a folder with any tracked file, link or submodule is
not. When that can't be decided, the program is not run: `--repo` must be a folder of the checkout,
not its Git folder. A relative path such as `./run-tests.sh` still names the change's own script
in the snapshot, as before. On Windows, a path with a drive but no root (`C:tool.exe`) or a root
but no drive (`\tools\tool.exe`) is refused.

A folder or link on the way that can't be read, for example for lack of permission, is refused
with `recipe_program_not_found`. On Windows a junction is followed as a link, and a path without
a suffix is also checked as the `.exe` it would run. An app-execution alias, such as the Microsoft
Store's `python.exe`, is read as the file it is. Any other reparse point that Windows does not
read through by itself is refused; a cloud-synced folder is read through and is an ordinary folder.

`check` and `workflow run` read `recipes` and `recipe_python` from the `--config` file as it is
on disk when they run, not from the commit being checked. A change that edits that file edits
the commands too, so keep the reviewed configuration outside the change or review it first.

Your team owns that decision. Logs stay local; only saved recipe/exit/hash records are
intended as reduced evidence. Logs are not automatically sent to a provider.

## Proposed changes

A proposal is a JSON artifact containing the exact head and a text Git patch.
Inspect it, create a clean feature branch, then pass its approval hash to `apply`.
The assistant rejects protected paths, special files, rename/binary patches,
stale heads, dirty worktrees and common default branch names. Coordinate exclusive ownership of the worktree. Re-run the project's checks and ordinary PR review.

Backups are private under `.finassist`. Rollback requires the original head and
unchanged post-apply bytes; later work stops rollback. An interrupted
apply without its saved record requires manual reconciliation from the saved backup.
The assistant does not force history, stage, commit or push.

Build/dependency files and `scripts/` are protected from proposals by default.
Configure `protected_paths` deliberately for your project; entries also protect
descendants without a trailing slash. `protected_branches` accepts glob patterns.
The local branches named by fetched remote default-HEAD references are always
excluded from patch application. Verify fetched references and current server policy yourself.

New outgoing requests use schema2 and carry executable-mode metadata. Schema1
outgoing requests remain inspectable but cannot pass `verify-gate`; rebuild old outgoing requests.
Public image assets are listed as omissions without reading their bytes.
Sensitive data/key paths still block until resolved even outside the source allowlist.

Read [auditing/readiness](readiness-and-auditing.md) for event export, required
recipes, blocking severities and the explicit GitHub metadata inspection command.

## Proactive operation

`watch` is a bounded foreground observer of committed-head changes. It emits
risk and suggested checks when the head changes and stays quiet otherwise.
It does not install a timer, create accounts, call a paid model, submit issues
or restart services. Use its output to dispatch the next authorized task.

## Limits

Each saved check record carries its committed head, snapshot digest, recipe digest,
runtime image and cleanup result. `check` tests committed source; it does not
validate uncommitted applied patches. Commit a candidate on an isolated feature
branch before testing it, or use a separately reviewed project adapter.

Container isolation depends on the image, daemon and host kernel. Local execution has no OS filesystem isolation; process supervision provides cleanup only. Multi-file patch checks are not atomic against other same-user writers. Prompt/source text cannot authorize actions. See the [threat model](threat-model.md).
