import { createHash } from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = fileURLToPath(new URL("../../src/finassist/resources/dashboard/", import.meta.url));
const require = createRequire(import.meta.url);
const dependencies = ["react", "react-dom", "uplot"];
let notices = "Bundled third-party software\n============================\n\n";
for (const name of dependencies) {
  const license = path.join(path.dirname(require.resolve(`${name}/package.json`)), "LICENSE");
  notices += `${name}\n${"-".repeat(name.length)}\n${await readFile(license, "utf8")}\n\n`;
}
// React DOM bundles Scheduler into the production build; it shares React's MIT notice.
notices += "Scheduler: distributed under the React MIT license reproduced above.\n";
await writeFile(path.join(root, "THIRD_PARTY_NOTICES.txt"), notices, "utf8");
async function entries(folder) {
  const result = [];
  for (const entry of await readdir(folder, { withFileTypes: true })) {
    const full = path.join(folder, entry.name);
    if (entry.isDirectory()) result.push(...await entries(full));
    else if (entry.name !== "manifest.json") result.push(full);
  }
  return result;
}
const manifest = {};
for (const filename of (await entries(root)).sort()) {
  const name = path.relative(root, filename).split(path.sep).join("/");
  manifest[name] = createHash("sha256").update(await readFile(filename)).digest("hex");
}
await writeFile(path.join(root, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n", "utf8");
