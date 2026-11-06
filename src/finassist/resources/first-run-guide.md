# Your first run

This guide takes a repository from nothing to a first review in five steps. Every step
is offline until you choose a provider, and nothing in your repository is run.

## 1. Check the installation
```sh
finassist demo
finassist doctor
```
`demo` runs fictional finance checks with no key, model or container. `doctor` reports the
runtime and configuration, and warns about settings that have no effect.

## 2. Propose a configuration from your repository
From the repository's root:

```sh
finassist init --detect --purpose quant
```

It reads only what is committed and prints a proposal with the file and rule behind each
setting:
- which directories hold source, tests and docs;
- which files are generated or protected;
- a file limit that fits your largest source module;
- a gate policy draft;
- your test commands.

It runs none of those commands. Check the proposal, then write it:

```sh
finassist init --detect --purpose quant --write --output finassist.json
```

`--purpose` chooses the review checklist:

| Purpose | Profile |
| --- | --- |
| `quant` | `quant-review` |
| `accounting` | `finance-saas` |
| `research` | `investment-research` |
| `general` | `general` |

For a paid provider, add `--provider`, `--model`, `--input-usd-per-million` and
`--output-usd-per-million` with your provider's prices. See [configuration](configuration.md)
for every option.

## 3. Choose a flow
| You want to | Use | Why |
| --- | --- | --- |
| Review one change yourself | `plan`, then `review` | You inspect the exact outgoing request and approve its hash. |
| Check every pull request without a person | `gate run`, or the GitHub Action | One unattended command under a policy pinned at the base revision. |
| Know why a gate would refuse, before it spends anything | `doctor --policy` | Every blocker for a range in one offline run. |

**Automation calls `gate run`, not `plan` and `review`.** `gate run` plans, screens, sizes the
request, reserves the budget, calls the model and writes the report in one step, with the
same screening as the manual flow. A remote `review` needs a person to approve each request's
hash, which an unattended job can't do. See the [pre-merge gate](pre-merge-gate.md).

The manual flow, offline:

```sh
finassist --config finassist.json plan --repo . --base main --head HEAD --output .finassist/context.json
finassist --config finassist.json review --packet .finassist/context.json --output .finassist/review.json
```

## 4. Before the first gate run, preflight the range
Commit the gate policy on the base branch, then run the preflight until it reports `ready`:

```sh
finassist doctor --policy gate-policy.json --repo . --base BASE --head HEAD
```

It lists every blocker with a hint, names each refused file in this local output only, and
shows the policy's sha256 that `gate run` needs. It makes no network call and reads no key.

## 5. When something is refused
Every refusal is one JSON line on stderr with a stable `code` and a `hint`. Run:

```sh
finassist explain CODE
```

[Troubleshooting](troubleshooting.md) lists the codes most often seen on a first run. Fix the
cause the hint names. Never make an error go away by weakening screening, removing a pin or
editing an approved hash.

## What finledgerpoli never does
- **Run your code during setup:** detection reads files; `check` runs only recipes you approve.
- **Send anything without approval:** no provider call without a network setting, the per-command flag and an approved request.
- **Review private data:** data formats such as CSV, spreadsheets and databases are refused, except synthetic fixtures a reviewed gate policy admits.
- **Merge, deploy or trade:** a PASS means the review completed under its policy, nothing more.
