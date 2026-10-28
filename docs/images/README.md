# Synthetic demo media

All shown spend, tokens, reviews, findings and readiness are fictional. No model
provider is called. Screenshots are captured from the actual prebuilt dashboard
with a fresh temporary config and ledger. The capture process receives only a
small OS/path environment allowlist, excluding provider keys. External browser
requests are refused. These images were captured against the 0.3.0 release-candidate
wheel; the seed script creates synthetic metadata, not measured provider results.

The recording uses a `.cast.txt` filename so the existing text-source policy can
inspect it without adding another allowed suffix. The asciinema v2 recording contains the actual `finassist demo` JSON, formatted for
reading. It includes no shell history, usernames, local paths, timestamp header,
credentials or environment dump. Play it locally; no account/upload is required.

## Regenerate

Install the project's development dependencies in a virtual environment. From
`dashboard/`, install the locked frontend dependencies and Chromium, then capture:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm exec playwright install chromium
node scripts/capture-docs.mjs
```

On Linux without browser libraries, follow Playwright's documented system-dependency
setup. The capture script defaults to the checkout's `.venv` Python; set
`FINASSIST_TEST_PYTHON` to another reviewed installed build if necessary. It binds
only to loopback, creates a new temporary project and removes only that project.
No production state or user's existing audit ledger is opened.

From the repository root:

```sh
python scripts/record_demo.py
# Inspect every image visually for privacy, readability and accurate labels first.
python scripts/catalog_docs_images.py
finassist scan --repo .
```

Review and stage the media and `manifest.json` explicitly before the scan. The
manifest names exact PNGs under `docs/images/` and binds their SHA-256 hashes.
The scanner still rejects undeclared images, links, oversized/malformed PNGs,
changed bytes and PNG metadata chunks. This narrow exception does not allow
arbitrary private image formats or exempt text from content screening. Pixel
privacy is a human review responsibility; a manifest hash cannot classify image
content. Source planning/snapshots retain their existing binary-asset exclusions.

After frontend changes, rebuild/compare shipped assets and regenerate affected
screenshots. After publication, add a PyPI badge only when the owner verifies the
actual package/version. No screenshots or recordings should use live account,
client, portfolio or provider data.
