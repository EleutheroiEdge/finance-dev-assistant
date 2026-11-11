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
| Figure screen | Numbers that 225 real changes add, each listed alone, in each file that adds them | 8 of 1,081 pass unrefused |
| Figure screen | File versions refused when 1,000 random control figures are listed | 0 of 5,937 |
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
| A5. One screen, every route | Every path to `providers.invoke` passes the credential, private-path, figure and hidden-character screens. A request without them is refused, not sent | route table test |
| A6. Output is screened | Free text a model returns is screened on every route before it is shown or saved | route table test |
| A7. Injection | Across at least 60 adversarial packets, 0 changed verdicts and 0 echoes of screened data | needs live calls; see D |

### B. A stranger's repository works

| Gate | Threshold | How it is measured |
|---|---|---|
| B1. The draft is valid | On every reference repository, `init --detect` drafts a policy the gate accepts | `scripts/first_run_scenarios.py` |
| B2. First run, gate route | At least 80% of the 225 reference changes are ready with the drafted policy plus `skip-and-report` | the same script |
| B3. First run, configuration route | At least 80%, counting only setup blockers | the same script |
| B4. Every remaining refusal is deliberate | Each blocker code left in B2 and B3 is one of: a change to the review rules, a private file, a binary file, a file over a stated limit. No `sensitive_content` on a call, a member expression or an environment lookup | blocker histogram from the same script |
| B5. Other languages | TypeScript, Go, SQL and YAML changes that assign from a variable, a call or the environment are not refused as credentials: 0 false refusals on a labelled set of 200 lines | labelled set, to be written |
| B6. Speed | `doctor` median under 2 seconds and worst case under 15 on the reference changes; 1.6 MB of dense numbers screened in under 20 seconds | the script; `tests/test_figure_matrix.py` |
| B7. Upgrade | A 0.10.0 configuration and policy load unchanged, and an unchanged configuration keeps its hash | `tests/test_config_figure_screen.py`, `scripts/upgrade_smoke.py` |

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

1. **Figure screen on every route, with one reader.** Gates A1, A5 and A6 for figures, and B7.
2. **`init --detect` stops drafting `deny_paths` the gate refuses,** and the policy check accepts a
   private name there. Gate B1.
3. **Digit matching and figure sources.** A list can be built from delimited files, and a figure is
   matched by its significant digits and its two-place rounding, as common guards do. Gates A2
   to A4.
4. **Credential screen outside Python.** Skip values that are identifiers, member expressions,
   calls and environment lookups, as the Python reading already does. Gates B4 and B5.
5. **Hidden and bidirectional characters in content,** on every route. Gate A5.
6. **Fit:** unsupported suffixes and files over the limit are left out and reported, not fatal to
   the whole range, when the operator chooses that. Gates B2 and B3.
7. **Accuracy programme.** Gates D1 to D6 and A7, after the spending decision.
8. **Provenance.** Gates E1 to E3.

## Commands

```bash
# A1
python -m pytest tests/test_figure_matrix.py

# A2 and A3: each REPO is a local checkout; nothing is written and nothing is sent
python scripts/seeded_figure_screen.py --changes 25 REPO [REPO ...]

# B1 to B4 and B6: --output is a new folder, created by the script
python scripts/first_run_scenarios.py --changes 25 --output /private/new-folder REPO [REPO ...]
```

Both scripts print codes, counts and timings only, under an anonymous number for each
repository: never a number, a line, a file name or a path.

- **A private path is never read.** The seeded script decides by name, with the product's own
  path policy, before it diffs or opens a file, and counts what it leaves out.
- **An incomplete run is not a measurement.** A missing repository or branch, a failed Git read
  or a failed `init --detect` gives exit status 2, and the totals say how many repositories
  were measured.
- **Raw output stays private.** `doctor` output, which names files, and the list of which number
  is which repository go to the output folder. The script creates that folder; it must not
  exist yet and must be outside every repository.
- **To measure a wheel,** install it by hash into a fresh environment and run the scripts with
  that environment's interpreter (`--python` for the scenario script).
