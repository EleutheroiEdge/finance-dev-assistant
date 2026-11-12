---
name: finassist-setup
description: Set up finassist review for a repository. Propose a configuration and a gate policy from committed files, show the person every field and the evidence behind it, write only what they confirm, then preflight a range until it is ready. Use when someone asks to add, configure or troubleshoot finassist or finledgerpoli in a repository.
license: MIT
metadata:
  requires: finassist Python CLI; every step is offline and needs no provider key
---

Every step below is offline. Nothing in the repository is executed. Doctor inspects only
selected key presence and emptiness; no key value is reported. Work from the repository's
root on a feature branch, never the default branch.

## 1. Check the installation

```sh
finassist --version
finassist doctor
```

If the command is missing, say so and stop. Do not install packages without the person's
request.

## 2. Ask what the code does

Ask the person which purpose fits, because it picks the review checklist: `quant`
(pricing, risk, backtests), `accounting` (ledgers, billing, tenants), `research`
(investment research and its sources) or `general`. Do not guess from file names.

## 3. Propose

```sh
finassist init --detect --repo . --purpose quant
```

It reads committed files only and prints one JSON proposal. It writes nothing and runs
none of the test commands it lists. Note the `head` it prints: step 5 writes from that same
revision.

## 4. Show every field before writing anything

Show the person each of these, with the `evidence` entry (file and rule) behind it:
- under `config`: `provider`, `model`, `profile`, `allow_paths`, `generated_paths`,
  `protected_paths`, `max_file_bytes`, `max_packet_bytes`, `input_usd_per_million` and
  `output_usd_per_million`;
- under `gate_policy_draft`: `enabled`, `allow_paths`, `deny_paths`, `fixture_roots`,
  `max_file_bytes`, `max_request_bytes`, `max_files`, `max_output_tokens`, `timeout_seconds`,
  `blocking_severities` and `profile`;
- `gate_policy_missing`: the policy fields the draft leaves out because they are the person's
  choice. Run `init --detect` again with their provider, model, key variable name and both
  prices, and it adds those fields and a run budget that covers one request at the proposed
  limit. An empty list means the draft is a whole policy;
- `private_paths`: the count and examples of files treated as private;
- `tests`: the commands found, which were not run;
- `warnings`, explained with `finassist explain CODE` for each code.

Ask the person to confirm or change each field. These choices are theirs, not yours:
- the provider, model, prices, budgets and `blocking_severities`;
- every `fixture_roots` entry: only directories of synthetic data may be fixtures;
- `private_paths` in the gate policy, `refuse` or `skip-and-report` (step 6).

## 5. Write the confirmed configuration

Write the proposal from the revision it was made from, so the file holds exactly what the
person saw even if the branch has moved since. Replace `HEAD_SHA` with the `head` from step 3:

```sh
finassist init --detect --repo . --revision HEAD_SHA --purpose quant --write --output finassist.json
```

Add `--provider`, `--model`, `--input-usd-per-million` and `--output-usd-per-million`
only with values the person gave. `--api-key-env` takes the variable's name, never a key.

The command writes the proposal as detected, not the person's changes from step 4. Apply
each of those by editing `finassist.json`, then show the whole file and check it:

```sh
finassist --config finassist.json doctor
```

`config_source` must be `file`. Explain every `config_warnings` entry. Setup is not done
until the file shows every confirmed value and nothing the person didn't confirm.

## 6. Draft the gate policy

The draft is partial: it has no provider, limits on spending or `private_paths`. Export
the kit to a new directory outside the repository:

```sh
finassist export-kit --output ../finassist-kit
```

Start from one of its examples and apply the confirmed fields:
- `examples/policies/quant-engine.json`: private data inside the reviewed tree is withheld
  unread (`skip-and-report`);
- `examples/policies/rebalancer.json`: any private file in a range refuses it (`refuse`,
  the default).

Explain this rule before the person chooses: the gate refuses a range that changes any
reviewable file outside `allow_paths`, or any file in `deny_paths`. By default it also
refuses a range that changes a private file, wherever that file is (the warning
`private_paths_outside_scope` counts those outside `allow_paths`). Either keep such files
out of pull requests, or choose `skip-and-report`. Then they are withheld before any read,
with no `allow_paths` entry needed, and the report says coverage is incomplete.

Save the policy where the person chooses, for example `gate-policy.json`, and show the
whole file. It takes effect only once committed on the base branch through their normal
review. Do not commit or push it yourself unless they ask.

## 7. Preflight until ready

```sh
finassist doctor --policy gate-policy.json --repo . --base BASE --head HEAD
```

It lists every blocker in one run, names refused files in local output only, and prints
the policy's sha256 that `gate run` needs. For each blocker:

```sh
finassist explain CODE
```

Fix the cause the hint names. Never weaken screening, remove a pin, edit an approved hash
or admit real data as a fixture to make a blocker go away. Repeat until the status is
`ready`.

## 8. Report

Tell the person:
- what was written, and where;
- the policy sha256 to pass as `--policy-sha256`;
- the coverage: how many files would be withheld, if any;
- the decisions left to them (step 4).

A PASS from the gate means the review completed under its policy. It does not approve a
merge, release, deployment or trade.

## Never

- Open, print or copy `.env` files, keys or credentials. Doctor alone may inspect selected
  process key variables for emptiness. key_variable_set means the variable exists;
  key_state is missing/empty/set and key_value_read reports whether emptiness was inspected.
  Values and lengths must never appear.
- Make a network call, call a provider or spend budget during setup.
- Run the detected test commands, or install hooks or workflows the person did not ask
  for.
- Put real client, account or holdings data in a fixture, an example or a public issue.
