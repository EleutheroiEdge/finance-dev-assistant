# Release readiness

This page says what must be measured, and what each measurement must show, before the next
release. It exists because 0.8.0, 0.9.0 and 0.10.0 each shipped with defects that a first
adopter found within a day. Each time the cause was the same: claims were checked against
synthetic look-alikes, not against real repositories and the published wheel.

The rule from now on: **a release is ready when every gate below passes on the candidate wheel,
and each number in the release notes comes from a command in this page.** The candidate is the
exact wheel the release workflow built, before anyone approves its publication. After publication
the same bytes are checked once more (gate C2).

## Where 0.10.0 stands

Measured on the published 0.10.0 wheel, offline, with no model call.

| Area | Measurement | Result |
|---|---|---|
| Figure screen | Generated cases in the notations 0.10.0 documents as read, each a listed figure the screen must refuse | 12,659 of 207,636 pass unrefused (6.1%) |
| Figure screen | Numbers that 225 real changes add, each listed alone, in each file that adds them | 9 of 1,128 pass unrefused |
| Figure screen | File versions refused when 1,000 random control figures are listed | 0 of 5,995 |
| Figure screen | Routes to a provider that run it | the gate only; not `review`, `propose` or `evaluate --suite` |
| First run, gate route | Changes a detected policy can review, of the 25 merged after setup, across nine repositories | 61 of 225 (27%) |
| First run, configuration route | The same, counting only setup blockers | 105 of 225 (47%) |
| `init --detect` | Repositories where the drafted gate policy is refused by the gate's own policy check | 4 of 9 |
| Credential screen | Ranges refused with `sensitive_content` | 40 of 225; at least 30 of the 138 refused file versions hold a function call or an environment lookup, not a credential |
| Hidden characters | Routes that screen file content for bidirectional and invisible characters | 0 of 3 |
| Review accuracy | Labelled cases scored with a live model | none yet |

The nine repositories are this one and eight private ones: four Python, two TypeScript and three
mixed. For each, `init --detect` ran at the revision before the oldest of the last 25 first-parent
changes, and `doctor` then checked each of those changes on both routes. Nothing was sent
anywhere.

The repositories keep moving, so a later run counts later changes. The two rows from real
changes were measured again after the script was corrected to count an added line that starts
with `++`; the other rows are from the first run.

## What 0.11.0 is

0.11.0 is a security release. Every release up to 0.10.0 could run a program from the current
directory on Windows (see the changelog), so the owner decided to publish the fix ahead of the
gates below that are still open. It holds everything merged up to that fix. It makes no claim
about review accuracy, gates D1 to D6 are not measured, and no adopter is told to rely on it for
that. The bar on this page still stands for the release that does make such a claim.

## Where the next release stands

Measured on the source tree of main at `b282da3`, offline, with no model call, on the reference set of 225
changes at pinned commits with the fingerprint `471b2dfe27d4dc2a` (see Commands). The figures that did not move
since the first measurement at `5c1af62` are marked so.

| Gate | Result | Met |
|---|---|---|
| A1 | The matrix test passes: no miss and no false alarm | Yes |
| A2 | 1,092 of 1,092 numbers that the reference changes add are refused when listed | Yes |
| A3 | 0 of 6,020 file versions refused with 1,000 control figures listed, and no collision. Measured at `5c1af62`; no change since touches the screen | Yes |
| A4 | 0 escapes in 10,000 generated payloads against a baseline guard (`tests/test_figure_digits.py`) | Yes |
| A5 | The route tests pass: every path to a provider runs the four screens | Yes |
| A6 | A reply is screened on the review, gate and proposal routes, hidden characters last | Yes |
| A7 | Not measured. It needs live calls | No |
| B1 | 9 of 9 drafted policies are accepted by the gate | Yes |
| B2 | 180 of 225 (80%). The threshold is 180 | Yes, with none to spare |
| B3 | 185 of 225 (82%). As drafted, 140, up from 137: `doctor` no longer blocks a file under `generated_paths` | Yes |
| B3a | With test paths listed: gate route 195 (87%), configuration route 202 (90%) | Reported |
| B4 | All 45 distinct lines refused for a credential hold a literal value under a credential label, 40 of them in test files. None is a call, a member expression or an environment lookup | Yes |
| B5 | The labelled set passes | Yes |
| B6 | `doctor`: median 0.50 s, slowest 11.89 s over 1,800 runs. The dense-number test passes | Yes |
| B7 | The configuration tests pass, and the installed upgrade from 0.3.1 and 0.4.0 passed on the 0.11.0 candidate wheel in its release build | Yes |
| B8 | 15 of 15 wrong setups, seven on the configuration route and eight on the gate route, give one named blocker; every remedy offered clears it; the first options reach `ready` | Yes |
| B9 | Following the remedies sets up 189 changes on the configuration route (84%) and 185 on the gate route (82%). No remedy fails, loops or is unexplained, every change a hand-set skip variant reviews is reached, and none grants a capability. The 36 and 40 left need a person: mostly a credential-like value in a test file (32 and 28) | Yes |
| C1 | Partly, for 0.11.0. On the workflow's wheel: its 147 package files equal the tagged tree, the screen, first-run and credential measurements (A2, B2, B3, B4, B6) repeated main's, and the upgrade check (B7) passed in the build. A7, D1 to D6, E1 and E3 were not run on it: 0.11.0 is a security release that the owner chose to publish ahead of those gates (see "What 0.11.0 is"). The full gate applies to every later candidate | Partly |
| D1 to D6 | Not measured. 133 labelled cases (64 defects, 69 controls) are bound to pinned policies and pass the live run's preflight offline; the run waits for the owner's provider, model and budget, and D1 needs 36 more defects | No |
| E1 | The release workflow attests every file. The README does not give the verifying command yet | No |
| E2 | `scripts/action_lock.py --check` passes | Yes |
| E3 | 6.2 on main at `edf4439` (Scorecard 5.6.0, read on 12 November). The checks at 0: no approved reviews, a repository under 90 days old, GitHub releases without signed files or provenance, no fuzzing, no best-practices badge, and no contributing company or organization detected. Branch protection was not readable by the workflow's token, so it is not scored. Two uv advisories (Vulnerabilities 8) are fixed by #140, and the private-reporting link now in SECURITY.md should lift Security-Policy from 4 to 10: about 6.7 with both | No |

B6 is wall-clock time and moves with the machine's load. On a busy shared machine the slowest run took up to
18.6 s, on the published 0.10.0 code as on 0.11.0; this measurement ran at a load of about 3. The bar should be
read on a quiet machine, and the slowest change profiled.

What the gate route still blocks, by number of changes: credential content 28, a change to an ignore file 7, a
request over the size limit 5, the run budget 3, the packet limit 1, a hidden character 1, the file count 1, a
range of private files only 1, and nothing to review 1. Some changes have more than one.

**B2 has nothing to spare.** One reference change fewer would miss it. What it still refuses for credential
content is a literal under a credential label, and 40 of those 45 lines are in test files.
`placeholder_credential_paths` is the setting for test files that hold only made-up logins; whether its numbers
(B3a) may count towards B2 and B3 is the owner's decision.

## Gates

Each gate has a number, a threshold and the command that produces it. A gate without a
measurement is not passed.

### A. Nothing confidential leaves unscreened

| Gate | Threshold | How it is measured |
|---|---|---|
| A1. Figure notations | 0 misses and 0 false alarms on the generated matrix (about 290,000 refusals, 7,000 near misses) | `pytest tests/test_figure_matrix.py` |
| A2. Figures in real changes | Every number of five or more significant digits that a reference change adds to a reviewable text file of up to 400,000 bytes, listed alone, is refused in each file that adds it: 0 misses | `scripts/seeded_figure_screen.py`, exit status 0 |
| A3. No false alarms on real code | With 1,000 random control figures, 0 file versions of the reference changes are refused. A control found in a file by an independent check is a collision: the run is inconclusive and is repeated with another seed | the same script |
| A4. Same result as an adopter's own guard | With the same figure sources, every payload the adopter's guard refuses is refused here: 0 escapes in 10,000 generated payloads | differential test, once digit matching lands |
| A5. One screen, every route | Every path to `providers.invoke` passes the credential, private-path, figure and hidden-character screens. A request without them is refused, not sent | `pytest tests/test_every_route_is_screened.py tests/test_hidden_text.py` |
| A6. Output is screened | Free text a model returns is screened on every route before it is shown or saved | route table test |
| A7. Injection | Across at least 60 adversarial packets, 0 changed verdicts and 0 echoes of screened data | needs live calls; see D |

### B. A stranger's repository works

| Gate | Threshold | How it is measured |
|---|---|---|
| B1. The draft is valid | On every reference repository, `init --detect` drafts a policy the gate accepts | `scripts/first_run_scenarios.py` |
| B2. First run, gate route | At least 80% of the 225 reference changes are ready with the drafted policy plus `skip-and-report` | the same script |
| B3. First run, configuration route | At least 80%, counting only setup blockers | the same script |
| B3a. First run, with test paths listed | The script also measures both routes with test files listed in `placeholder_credential_paths` on top of both skip settings. It is reported beside B2 and B3 and does not replace them: listing a path is a statement about a repository that only its owner can make | the same script, variants `gate+tests` and `config+tests` |
| B4. Every remaining refusal is deliberate | Each blocker code left in B2 and B3 is one of: a literal value under a credential label, a hidden character, a change to the review rules, a private file, a binary file, a size or a cost over a stated limit. No `sensitive_content` on a call, a member expression or an environment lookup | blocker histogram from the same script, which counts each content refusal by rule and file suffix |
| B5. Other languages | TypeScript, Go, SQL and YAML changes that assign from a variable, a call or the environment are not refused as credentials: 0 false refusals on a labelled set of 200 lines | `pytest tests/test_credential_references.py`, on the set in `tests/credential_cases.py` |
| B6. Speed | `doctor` median under 2 seconds and worst case under 15 on the reference changes; 1.6 MB of dense numbers screened in under 20 seconds | the script; `tests/test_figure_matrix.py` |
| B7. Upgrade | A 0.10.0 configuration and policy load unchanged, and an unchanged configuration keeps its hash | `tests/test_config_figure_screen.py`, `scripts/upgrade_smoke.py` |
| B8. Wrong setups | Each scenario of the misconfiguration matrix (a file over the limit, a file over it at both versions, a private file, a denied file type, a path outside the scope, a change too large, a budget under the reserve, on both routes, and a change over the gate's packet floor) gives exactly one named blocker with a hint. Every remedy `doctor` offers for it clears that blocker when applied, and following the first option each time reaches `ready` within four runs | `pytest tests/test_remedies.py` |
| B9. Remedies on real changes | Following the first option of every remedy on the 225 reference changes, on both routes: no remedy fails or never settles, every change that a hand-set skip variant reviews is reached, and no remedy grants a capability. Every change left needing a decision is blocked only by a code B4 allows, or has nothing left to review once the files a setting would leave out are out | `scripts/remedy_scenarios.py`, with the same `--tips` as B1 to B4 |

### C. Claims match the product

| Gate | Threshold | How it is measured |
|---|---|---|
| C1. Candidate wheel, before publication | Every gate in A, B and E is run on the exact wheel the release workflow built, installed into a fresh environment, not on the source tree. The owner approves publication only after that | release checklist |
| C2. Published wheel, after publication | The wheel installed from the index by hash has the candidate's digest, and A1, A2, A3 and B1 to B3 give the candidate's numbers | release checklist |
| C3. An adopter's ranges | Before any message to an adopter, their real ranges are rerun on the published wheel, and every claim in the message maps to a line of that output | release checklist |
| C4. Second reader | An independent reviewer reruns C3 before the message is sent | release checklist |

### D. Review accuracy

These need live model calls, so they need a spending decision first. Until they are measured,
the documentation says only what a PASS means: no blocking finding was reported. It never says
the code is free of defects.

| Gate | Threshold | Source of the threshold |
|---|---|---|
| D1. Labelled set | At least 100 real historical defects and 60 clean changes, from at least three repositories | benchmark practice: sets of 50 are too small for a stable rate |
| D2. Precision of blocking findings | Point estimate at least 90%, lower 95% bound at least 85% | Google's rule for checks shown in review: under 10% effective false positives |
| D3. Recall | Reported by severity with a 95% interval. Not promised | leading reviewers measure 26% to 60% |
| D4. Clean changes | At most 10% get FAIL | benchmark practice |
| D5. Repeat trials | Three runs per case; the verdict is the same in at least 90% of cases | benchmark practice |
| D6. Side by side | The same cases through an adopter's existing reviewer, scored the same way | `finassist score --compare` |

### E. The release itself can be trusted

| Gate | Threshold |
|---|---|
| E1. Provenance | Every release file carries a PEP 740 attestation, and the README gives the command that verifies it |
| E2. Workflows | Least-privilege permissions and actions pinned by commit, checked by `scripts/action_lock.py` |
| E3. Scorecard | OpenSSF Scorecard at 8 or above |

## Work, in order

Landed since 0.10.0, each with the gates it serves:

- The figure screen on every route, with one reader; digit matching and figure lists from delimited files
  (A1 to A6, B7).
- `init --detect` drafts policies the gate accepts (B1); unreviewable files can be left out and reported
  (B2, B3).
- The credential screen outside Python, and hidden characters on every route (A5, B4, B5).
- Tools found only through absolute `PATH` entries on Windows (the 0.11.0 security release).
- `doctor` lists remedies a program can apply, checked on fifteen wrong setups (B8) and on the 225
  reference changes (B9).
- Versioned JSON schemas, shipped in the package and exported offline, for the configuration, the gate and CI
  policies, packets, gate and review reports, review responses, and evaluation and history suites (#130). The
  workflow template (#141), workflow packs, evidence, evaluation results and triage documents are not covered yet.
- `doctor` checking its own installation, which key variable each command reads, and provider failures by code
  (#127).
- The command-line parser in its own module, which leaves `cli.py` room to grow (#137).
- `state status`, which shows what the tool keeps on the machine without writing anything, and
  `doctor --format text`, the same report for a person at a terminal; the JSON stays the contract (#138).

Left, in this order:

1. **State** (#120): one state location for every command, then `state archive` and `state clean`, built on
   `state status`. The gaps in #134 go with it.
2. **Accuracy programme:** gates D1 to D6 and A7.
   - **Done, offline:** 133 labelled cases from six of the maintainers' repositories are bound to pinned
     policies and pass the live run's own preflight: 64 defects, 69 controls.
   - **Needs the owner:** a public stratum to reach 100 defects (cloning public repositories), and the
     provider, model and budget. One trial of every case is about 18.5 million input tokens.
3. **Provenance:** gates E1 to E3. For E1 a maintainer verifies the attestations of a published release with `gh attestation verify`, then adds that exact command to the README. E3 needs more than this repository can change by itself: signed files or provenance on the GitHub releases, approved reviews on changes (an owner's decision for a repository with one maintainer), and the repository's 90th day.
4. **The candidate:** gates C1 to C4 on the wheel the release workflow builds, before the owner approves
   publishing.

## Commands

```bash
# A1
python -m pytest tests/test_figure_matrix.py

# A2 and A3: each REPO is a local checkout; nothing is written and nothing is sent
python scripts/seeded_figure_screen.py --changes 25 REPO [REPO ...]

# B5
python -m pytest tests/test_credential_references.py

# B1 to B4 and B6: --output is a new folder, created by the script, which writes tips.txt there
python scripts/first_run_scenarios.py --changes 25 --output /private/new-folder REPO [REPO ...]

# The same changes again, on another day or another tree: the repositories in the same order
python scripts/first_run_scenarios.py --changes 25 --tips /private/new-folder/tips.txt \
    --output /private/another-folder REPO [REPO ...]
python scripts/seeded_figure_screen.py --changes 25 --tips /private/new-folder/tips.txt REPO [REPO ...]

# B9, on the same changes
python scripts/remedy_scenarios.py --changes 25 --tips /private/new-folder/tips.txt \
    --output /private/a-third-folder REPO [REPO ...]
```

The scripts print codes, setting names, counts and timings only, under an anonymous number for each
repository: never a number, a line, a file name or a path.

- **The same changes, or no comparison.** The repositories keep moving, so the last 25 changes are
  different changes on a later day, and a count can move by itself. A whole run of the scenario
  script writes the commit it read each history from to `tips.txt` in its output folder, and
  both scripts print a fingerprint of the set they read. With `--tips` they read those commits
  again. Compare two counts only when their runs print the same fingerprint, and give it with
  every number that leaves this page.
- **Nothing is locked, and the objects are read as they are.** Neither script writes inside a
  repository. Both run every Git command with `GIT_OPTIONAL_LOCKS=0`, so a measurement never
  holds the index lock of a repository that someone is working in, and with
  `GIT_NO_REPLACE_OBJECTS=1` and none of the caller's own `GIT_` settings, so a replacement ref
  or a stray setting cannot put other changes in the place of the pinned ones. A legacy grafts
  file changes a history whatever the environment says, so a repository that holds one is not
  measured: the run is incomplete.
- **A private path is never read.** The seeded script decides by name, with the product's own
  path policy, before it diffs or opens a file, and counts what it leaves out.
- **An incomplete run is not a measurement.** A missing repository or branch, a failed Git read,
  a failed `init --detect`, a `doctor` run that gives no report, a grafts file, or a history with
  fewer changes than `--changes` asks for gives exit status 2, and the totals say how many repositories were
  measured. A range that `doctor` refuses is a measurement.
- **Raw output stays private.** `doctor` output, which names files, and the list of which number
  is which repository go to the output folder. The script creates that folder; it must not
  exist yet and must be outside every repository. Give each repository by its root folder.
- **To measure a wheel,** install it by hash into a fresh environment and run the scripts with
  that environment's interpreter (`--python` for the scenario script).
