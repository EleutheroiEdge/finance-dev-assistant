# The text view of `finassist doctor`

`finassist doctor` prints one line of JSON. That is right for scripts and
coding agents, and wrong for a person at a terminal on their first day. This
note designs a second, human view of the same report, rendered by
`finassist.text_view.render(report, *, width=80, color=False)`. Nothing new is
computed: every line below comes from fields the JSON report already carries.

## Principles

- **The verdict first.** The first thing after the title is READY, BLOCKED
  with the blocker count, or the installation's health. Nobody scrolls to
  learn whether they can proceed.
- **One blocker, one fix.** Each blocker is numbered, titled with its JSON
  code, given its details, then one `Fix:` line taken from the report's own
  `hint`. The hint is packaged text, so the view never invents advice.
- **Never hide a refusal.** A refused, withheld or omitted path stays visible:
  the range line counts every status, and refused paths are named under their
  blocker (the report already redacts names that fail screening). Coverage
  that is not complete says so on the range line.
- **The same words as the JSON.** Codes, setting names and path statuses are
  printed exactly as the JSON spells them, so a person can search the docs
  for `file_limit_exceeded` or run `finassist explain file_limit_exceeded`
  and land on the same word the terminal showed.
- **Fits 80 columns.** Prose wraps; a token that still does not fit (a long
  path or hash) is shortened in the middle with `...`. The caller chooses the
  width; 80 is the default.
- **Readable without colour and by a screen reader.** No box-drawing, no
  emoji, no layout that needs a monospaced grid beyond simple indentation.
  Colour, when the caller asks for it, only paints the verdict and headings;
  the words carry the meaning on their own.
- **Offline and honest about it.** A preflight that used no network, read no
  key value and opened no ledger says so in one line, because that is what a
  first-day user needs to trust the tool.

## Mock screens

Exactly as the renderer prints them at width 80.

### 1. A range that is ready, with the command to run next

```text
finassist doctor - configuration preflight
Verdict: READY
Range: main..feature/add-cash-check; 2 included; coverage complete
Provider: openai; model configured; network enabled; prices set
Key variable OPENAI_API_KEY: set
Packet: 41,230 of 240,000 bytes
Request: 45,120 bytes; reserves $0.0413
This run used no network, read no key value and opened no ledger.

Next steps:
  finassist --config finassist.json plan --repo . --base main --head
      feature/add-cash-check --output <new packet file>
  finassist --config finassist.json review --packet <packet file>
      --approve-packet <packet_hash shown by plan, after you inspect the packet>
      --allow-network --output <new review file>
```

### 2. A range blocked by one oversized file, with its two remedies

```text
finassist doctor - configuration preflight
Verdict: BLOCKED - 1 blocker
Range: main..feature/quarterly-metrics; 1 included; 1 refused; coverage
  incomplete
Provider: openai; model configured; network enabled; prices set
Key variable OPENAI_API_KEY: set
This run used no network, read no key value and opened no ledger.

Blockers
1. file_limit_exceeded
  1 file: data/metrics.csv
  Fix: Raise `max_file_bytes` (up to 2,000,000; `fixture_max_file_bytes` for
    gate fixtures) or keep the file out of the range. The error's `limit` shows
    the cap.
  Remedies:
  a) In the configuration, set unreviewable_paths to "skip-and-report".
     Effect: files are left out, so coverage is incomplete.
  b) In the configuration, set max_file_bytes to at least 360,000.
     Effect: more is sent to the provider.

Next step: Fix every blocker listed, then run this preflight again.
```

### 3. A range blocked by three things at once; only two have remedies

```text
finassist doctor - configuration preflight
Verdict: BLOCKED - 3 blockers
Range: main..feature/rebalance; 1 included; 1 refused; coverage incomplete
Provider: openai; model configured; network enabled; prices set
Key variable FINASSIST_API_KEY: not set
Request: 45,120 bytes; reserves $0.42
This run used no network, read no key value and opened no ledger.

Blockers
1. private_or_binary_path
  1 file: secrets/ledger.csv
  Fix: Keep such files out of the range, or set `private_paths` to
    `skip-and-report` to withhold them unread.
  Remedies:
  a) In the configuration, set private_paths to "skip-and-report".
     Effect: files are left out, so coverage is incomplete.
  b) In the configuration, add ".csv" to text_suffixes.
     Effect: more is sent to the provider.

2. run_budget_exceeded
  reserves $0.42; limit $0.25
  Fix: Review a smaller range, lower `max_output_tokens`, or raise `max_run_usd`
    in the reviewed configuration or gate policy after checking the prices.
  Remedies:
  a) In the configuration, set max_run_usd to at least $0.42.
     Effect: a larger spend is allowed.

3. provider_key_missing
  key variable FINASSIST_API_KEY is not set
  Fix: Set the variable named by `api_key_env` in this shell. Never put the key
    itself in a config or policy file.

Next step: Fix every blocker listed, then run this preflight again.
```

### 4. `doctor` with no range on a healthy installation

```text
finassist doctor - installation health
Status: healthy

finassist 0.12.0 on Python 3.13.1 (Linux)
Provider: offline; no model configured; network disabled
Provider key: no key variable configured
Configuration: file; profile: general; recipes: none
Containers: no docker or podman binary found
Updates: not checked

Next step: inspect a plan packet before enabling any provider or running a
  recipe
```

### 5. A gate range that is ready but carries two warnings

```text
finassist doctor - gate preflight
Verdict: READY
Range: main..feature/rebalance; 2 included; 2 withheld; 1 left out; coverage
  incomplete
Policy: gate-policy.json; from base; sha256 9f9f9f9...9f9f9f; pin matches
Provider: openai; prices set; allowed host api.openai.com
Key variable OPENAI_API_KEY: set
Request: 45,120 of 120,000 bytes; reserves $0.0413
This run used no network, read no key value and opened no ledger.

Warnings
1. private_paths_withheld
  2 files
  Fix: Nothing to fix if that is intended: the rest of the range is reviewed and
    the report counts what was withheld. Set `private_paths` to `refuse` to
    require complete coverage.
2. unreviewable_paths_left_out
  1 file
  Fix: Nothing to fix if that is intended: the rest of the range is reviewed,
    and the packet names each file left out with its reason. Set
    `unreviewable_paths` to `refuse` to require complete coverage.

Next step:
  finassist gate run --repo . --base main --head feature/rebalance --policy
      gate-policy.json --policy-sha256
      9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f
      --state-dir <private state directory> --output <new report file>
```

## Wording rules

- **Blocker title.** `1. file_limit_exceeded`: the number, then the JSON code
  verbatim. The code is the title because it is the stable, searchable word;
  the prose explanation belongs to `finassist explain CODE`.
- **Blocker details.** Known detail fields only, in a fixed order: grouped
  paths (`3 files: a, b, c (and 17 more)`, at most three examples), sizes
  (`size 360,000 bytes; limit 60,000 bytes`), file counts against limits, the
  missing key variable's name, missing price settings, reserved and limit
  dollars, policy fields, and the failed check's kind. Every other field
  stays in the JSON.
- **Remedy option.** A lettered line: `a) In the configuration, set
  unreviewable_paths to "skip-and-report".` The document is `the
  configuration` or `the gate policy`, exactly the two values the field
  takes. A change is phrased from its shape: `set X to "v"` for a value, `set
  X to at least N` for `at_least` (with `$` for a `*_usd` setting), `add "p"
  to X` for a path list, `give X a value` for `needs_value`. Strings are
  quoted with JSON syntax so they can be pasted into a file.
- **Remedy effect.** One indented `Effect:` line per option, one sentence per
  effect value: `sends_more` is "more is sent to the provider", `spends_more`
  is "a larger spend is allowed", `leaves_files_out` is "files are left out,
  so coverage is incomplete", `none` is "nothing more is sent or spent". The
  trade-off is stated, never recommended; the choice belongs to the person.
- **Numbers.** Integers take thousands separators (`360,000`). Byte counts
  always carry the unit (`45,120 of 120,000 bytes`). Dollar amounts print as
  the report's own decimal string with a `$` (`$0.0413`); the view never
  rounds money. Hashes are shortened (`9f9f9f9...9f9f9f`); the full value is
  in the JSON.
- **Never shown.** A key value (only the variable's name and whether it is
  set) and file contents (only paths, already redacted by the report when a
  name fails screening). The renderer prints only fields it names, so a
  secret cannot leak through a field it does not know.

## What the view leaves out, and why JSON stays the contract

The view drops everything a person does not act on at a glance: the schema
version, configuration and packet hashes, the figure-screen counts, the
per-path rows (their statuses are counted, not listed), deprecation lists
when empty, and any field it does not know. None of this is gone: the JSON on
stdout remains the complete, stable contract, versioned by `schema_version`
and consumed by scripts, the dashboard and coding agents. The text view is a
rendering of that contract for one terminal, not a second report; programs
must never parse it, and the JSON gains the `remedies` field so the view
stays a pure renderer. A report the view cannot recognise still renders what
it can; a missing field leaves its section out rather than failing.

## Decisions

The draft's open questions, settled:

1. **How the view is chosen.** By an explicit option, `doctor --format text`. JSON stays the default on every
   terminal: scripts, coding agents and CI read `doctor`'s output, and what a command prints must not depend on
   whether its output is a terminal.
2. **A report without `remedies`.** It renders without them. The view never derives a remedy from a hint: a
   remedy is listed only when the product knows it clears its blocker, and only the product can know that.
3. **Refused paths on the screen.** They are shown, as the JSON shows them locally, already redacted where a name
   fails screening. A person fixing a blocker needs the name.
4. **Long paths.** Shortened in the middle to fit the width. The full path is in the JSON, and the view is not a
   format to copy from.
5. **Remedies for warnings.** Not now. A warning does not stop a run, so it has nothing to clear.

The view also shows a commit by its first twelve characters, follows `key_state` when the report has it
(missing, empty, set), and names a remedy's setting by its place in the document, from the change's `pointer`,
when that is not the top level.
