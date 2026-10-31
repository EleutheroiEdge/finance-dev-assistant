# Public history cases

These cases refer only to this project's own source history. No repository,
third-party source, model output or private adoption data is bundled here.
`repo_path` is relative to the suite file. Evaluation reads existing local Git
objects; it never fetches, checks out a revision or changes a working tree.

All three pairs are **intermediate review revisions in merged PR #31**, not
three separate releases. The final squashed merge is
`dc5234d7d60dc49a6e67e8866ae018a36dddb300`. Its reviewed final head was
`2e932252ee86fb1cfd2c1c5f633cdfa923573855`. A normal shallow/default-branch
clone may lack the intermediate objects. Have an authorized maintainer provide
the exact objects locally before running; a missing object is a refusal, not
permission for the evaluator to download it.

| Case | Ground truth and limits |
|---|---|
| `pr31-evidence-recovery-guard` | The initial compatibility implementation called the migration-only sidecar guard during ordinary read-only schema inspection. A hot rollback journal or a concurrent writer then prevented normal open/verify/recovery. Three recovery/wait regressions failed at the reviewed bad head and passed after `2e932252…`. The held-out target identifies this defect family once, even if a reviewer reports several symptoms. Other confirmed defects must be adjudicated separately. |
| `pr31-macos-smoke-path-control` | The four-line change canonicalizes an owned temporary staging root before comparing backup paths on macOS. It is a reviewed control with no known newly introduced defect, not proof that the whole historical repository is defect-free. |
| `pr31-ci-time-budget-control` | The change increases only existing Windows Python test-job timeouts from 15 to 20 minutes so historical-wheel smoke can finish. Other jobs retain 15 minutes. No known defect was introduced; a genuine new finding contaminates this control and needs fresh ground truth. |

Review provenance: [PR #31](https://github.com/EleutheroiEdge/finance-dev-assistant/pull/31),
[recovery finding](https://github.com/EleutheroiEdge/finance-dev-assistant/pull/31#issuecomment-6523361551),
[final approval](https://github.com/EleutheroiEdge/finance-dev-assistant/pull/31#issuecomment-6524713830).
The positive target's `high` weight is a benchmark label for the workflow
regression, not a claim of a financial loss or a security severity assessment.

The accompanying `history-offline-config.json` permits the text paths and sizes
needed for full offline inspection. It is **not** a model policy or network
authorization. The example intentionally supplies no provider/key or paid policy.
Keep private holdouts, labels, model outputs and journals outside public Git.
Public cases are for exercising the contract: memorization can overstate recall.
