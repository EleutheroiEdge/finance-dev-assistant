# Synthetic demo media

Reproduce finledgerpoli demo media using synthetic data and the packaged dashboard. Its command is `finassist`; the recording and screenshots are examples, not measured provider results.

All shown spend, tokens, reviews, findings and readiness are fictional. No model
provider is called. Screenshots are captured from the actual prebuilt dashboard
with a fresh temporary config and ledger. The capture process receives only a
small OS/path environment allowlist, excluding provider keys. External browser
requests are refused. Screenshots use the current local build in light mode; the
seed script creates synthetic metadata, not measured provider results.

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
# Also needs ffmpeg on PATH; copies the reviewed brand exports and renders the demo GIF.
node scripts/render-marketing.mjs
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

## Limits

Review and stage the media and `manifest.json` explicitly before the scan. The
manifest names exact documentation PNGs, reviewed PNG exports in `brand/`, the
packaged 32 px favicon and the bounded `hero.gif`, and binds their SHA-256 hashes.
The scanner still rejects undeclared images, links, oversized/malformed images,
changed bytes, PNG metadata chunks and GIF comment/text/arbitrary application extensions. This narrow exception does not allow
arbitrary private image formats or exempt text from content screening. Pixel
privacy is a human review responsibility; a manifest hash cannot classify image
content. Source planning/snapshots retain their existing binary-asset exclusions.

After frontend changes, rebuild/compare shipped assets and regenerate affected
screenshots. The hero GIF samples the existing cast at 5 fps and holds its final output for
two seconds. The compatibility paths `how-it-works.png` and `social-preview.png` are copied
byte-for-byte from `brand/how-it-works-light.png` and `brand/social-dark.png`.
README and maintainer links use the canonical brand paths directly; no additional
dark/light copies are kept here. See [brand artwork](../../brand/README.md). No external
fonts or image services are requested. No screenshots or recordings should use live account,
client, portfolio or provider data.
