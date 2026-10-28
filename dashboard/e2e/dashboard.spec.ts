import { expect, test } from "@playwright/test";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

let child: ChildProcess;
let root: string;
let origin: string;
test.beforeAll(async () => {
  root = await realpath(await mkdtemp(path.join(tmpdir(), "finassist-browser-")));
  const config = path.join(root, "configuration.json");
  await writeFile(config, JSON.stringify({provider: "offline", daily_budget_usd: 5, monthly_budget_usd: 100}), "utf8");
  const env: NodeJS.ProcessEnv = {};
  for (const name of ["PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE"]) {
    if (process.env[name]) env[name] = process.env[name];
  }
  const executable = process.env.FINASSIST_TEST_PYTHON || (process.platform === "win32" ? "python" : "../.venv/bin/python");
  const seed = spawnSync(executable, ["-c", `
from decimal import Decimal
from pathlib import Path
import sys
from finassist.ledger import Ledger
with Ledger(Path(sys.argv[1])) as ledger:
    reservation = ledger.reserve(Decimal("0.1"), Decimal(5), Decimal(1))
    ledger.append({"event": "review_requested", "reservation": reservation})
    ledger.append({"event": "model_usage", "reservation": reservation, "input_tokens": 100, "output_tokens": 20})
    ledger.settle(reservation, Decimal("0.01"))
    ledger.append({"event": "review_completed", "profile": "general", "findings_by_severity": {"low": 1}})
`, path.join(root, "state", "audit.sqlite")], {env, shell: false, encoding: "utf8"});
  if (seed.status !== 0) throw new Error("Synthetic audit fixture failed");
  child = spawn(executable, ["-m", "finassist", "--config", config, "dashboard", "--state-dir", path.join(root, "state")], {env, shell: false});
  origin = await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Dashboard startup timed out")), 15_000);
    let output = "";
    child.stdout!.on("data", block => {output += block.toString("utf8"); const match = output.match(/Dashboard: (http:\/\/127\.0\.0\.1:\d+)/); if (match) {clearTimeout(timer); resolve(match[1]);}});
    child.once("exit", code => {clearTimeout(timer); reject(new Error(`Dashboard exited: ${code}`));});
  });
});
test.afterAll(async () => {
  if (child && child.exitCode === null) {
    child.kill();
    await new Promise<void>(resolve => child.once("exit", () => resolve()));
  }
  if (root) await rm(root, {recursive: true, force: true});
});

test("offline configuration, confirmation, statistics and health work end to end", async ({page}) => {
  const external: string[] = [];
  const errors: string[] = [];
  page.on("request", request => {if (!request.url().startsWith(origin)) external.push(request.url());});
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(origin);
  await expect(page.getByRole("heading", {name: "Configuration", exact: true})).toBeVisible();
  await page.getByLabel("Daily spend limit (USD)", {exact: true}).fill("7");
  expect(JSON.parse(await readFile(path.join(root, "configuration.json"), "utf8")).daily_budget_usd).toBe(5);
  await page.getByRole("button", {name: "Preview changes"}).click();
  await expect(page.getByRole("heading", {name: "Proposed changes"})).toBeVisible();
  expect(JSON.parse(await readFile(path.join(root, "configuration.json"), "utf8")).daily_budget_usd).toBe(5);
  await page.getByRole("button", {name: "Confirm and save"}).click();
  await expect(page.getByText("Configuration saved.")).toBeVisible();
  expect(JSON.parse(await readFile(path.join(root, "configuration.json"), "utf8")).daily_budget_usd).toBe(7);
  await page.getByRole("button", {name: /^Statistics/}).click();
  await expect(page.getByRole("heading", {name: "Recent runs"})).toBeVisible();
  await expect(page.getByText("dashboard-save", {exact: true})).toBeVisible();
  await expect(page.getByRole("img", {name: "Recorded spend (USD)", exact: true})).toBeVisible();
  await expect(page.locator("canvas")).toHaveCount(2);
  await page.screenshot({path: "test-results/statistics.png", fullPage: true});
  await page.getByRole("button", {name: /^Health/}).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Configuration is valid")).toBeVisible();
  await page.getByRole("button", {name: /^Configuration/}).click();
  await page.screenshot({path: "test-results/configuration.png", fullPage: true});
  expect(external).toEqual([]);
  expect(errors).toEqual([]);
});
