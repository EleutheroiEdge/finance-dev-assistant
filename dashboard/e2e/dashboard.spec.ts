import { expect, test } from "@playwright/test";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

type Server = {child: ChildProcess; root: string; origin: string};

async function startServer(seedAudit: boolean): Promise<Server> {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), "finassist-browser-")));
  const config = path.join(root, "configuration.json");
  await writeFile(config, JSON.stringify({provider: "offline", daily_budget_usd: 5, monthly_budget_usd: 100}), "utf8");
  const env: NodeJS.ProcessEnv = {};
  for (const name of ["PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE"]) {
    if (process.env[name]) env[name] = process.env[name];
  }
  const executable = process.env.FINASSIST_TEST_PYTHON || (process.platform === "win32" ? "python" : "../.venv/bin/python");
  if (seedAudit) {
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
  }
  const child = spawn(executable, ["-m", "finassist", "--config", config, "dashboard", "--state-dir", path.join(root, "state")], {env, shell: false});
  const origin = await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Dashboard startup timed out")), 15_000);
    let output = "";
    child.stdout!.on("data", block => {output += block.toString("utf8"); const match = output.match(/Dashboard: (http:\/\/127\.0\.0\.1:\d+)/); if (match) {clearTimeout(timer); resolve(match[1]);}});
    child.once("exit", code => {clearTimeout(timer); reject(new Error(`Dashboard exited: ${code}`));});
  });
  return {child, root, origin};
}

async function stopServer(server: Server) {
  if (server.child && server.child.exitCode === null) {
    server.child.kill();
    await new Promise<void>(resolve => server.child.once("exit", () => resolve()));
  }
  if (server.root) await rm(server.root, {recursive: true, force: true});
}

test.describe("seeded audit trail", () => {
  let server: Server;
  test.beforeAll(async () => { server = await startServer(true); });
  test.afterAll(async () => { await stopServer(server); });

  test("offline configuration, confirmation, statistics and health work end to end", async ({page}) => {
    const external: string[] = [];
    const errors: string[] = [];
    page.on("request", request => {if (new URL(request.url()).origin !== server.origin) external.push(request.url());});
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(server.origin);
    await expect(page).toHaveTitle("finledgerpoli - local dashboard");
    await expect(page.locator("aside .brand")).toContainText("finledgerpoli");
    await expect(page.locator('meta[name="description"]')).toHaveAttribute("content", /^finledgerpoli local dashboard/);
    await expect(page.getByRole("heading", {name: "Configuration", exact: true})).toBeVisible();
    await page.getByLabel("Daily spend limit (USD)", {exact: true}).fill("7");
    expect(JSON.parse(await readFile(path.join(server.root, "configuration.json"), "utf8")).daily_budget_usd).toBe(5);
    await page.getByRole("button", {name: "Preview changes"}).click();
    await expect(page.getByRole("heading", {name: "Proposed changes"})).toBeVisible();
    expect(JSON.parse(await readFile(path.join(server.root, "configuration.json"), "utf8")).daily_budget_usd).toBe(5);
    await page.getByRole("button", {name: "Confirm and save"}).click();
    await expect(page.getByText("Configuration saved.")).toBeVisible();
    expect(JSON.parse(await readFile(path.join(server.root, "configuration.json"), "utf8")).daily_budget_usd).toBe(7);
    await page.getByRole("button", {name: /^Statistics/}).click();
    await expect(page.getByRole("heading", {name: "Recent runs"})).toBeVisible();
    await expect(page.getByRole("heading", {name: "Pending charges (not yet confirmed)"})).toBeVisible();
    await expect(page.getByRole("heading", {name: "Ready for human review"})).toBeVisible();
    await expect(page.getByRole("heading", {name: "Checks you've run"})).toBeVisible();
    await expect(page.getByText(/Eligibility grants no merge or deployment authority/)).toBeVisible();
    await expect(page.getByText("dashboard-save", {exact: true})).toBeVisible();
    await expect(page.getByRole("img", {name: "Recorded spend (USD)", exact: true})).toBeVisible();
    await expect(page.getByRole("heading", {name: "No activity recorded yet"})).toHaveCount(0);
    await expect(page.locator("canvas")).toHaveCount(2);
    await page.screenshot({path: "test-results/statistics.png", fullPage: true});
    await page.getByRole("button", {name: /^Health/}).focus();
    await page.keyboard.press("Enter");
    await expect(page.getByText("Configuration is valid")).toBeVisible();
    await page.getByRole("button", {name: /^Configuration/}).click();
    await page.screenshot({path: "test-results/configuration.png", fullPage: true});
    await writeFile(path.join(server.root, "configuration.json"), "invalid JSON", "utf8");
    await page.getByRole("button", {name: "Refresh local data"}).click();
    await expect(page.getByRole("alert")).toContainText("Configuration is invalid");
    for (const name of ["Statistics", "Health", "Configuration"]) {
      await page.getByRole("button", {name: new RegExp("^" + name)}).click();
      await expect(page.getByRole("alert")).toBeVisible();
      await expect(page.getByText("Loading local data…")).toHaveCount(0);
    }
    expect(external).toEqual([]);
    expect(errors).toEqual([]);
  });
});

test.describe("empty audit trail", () => {
  let server: Server;
  test.beforeAll(async () => { server = await startServer(false); });
  test.afterAll(async () => { await stopServer(server); });

  test("first-run statistics explain what to do next", async ({page}) => {
    const external: string[] = [];
    const errors: string[] = [];
    page.on("request", request => {if (new URL(request.url()).origin !== server.origin) external.push(request.url());});
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(server.origin);
    await expect(page).toHaveTitle("finledgerpoli - local dashboard");
    await expect(page.locator("aside .brand")).toContainText("finledgerpoli");
    await expect(page.locator('meta[name="description"]')).toHaveAttribute("content", /^finledgerpoli local dashboard/);
    await expect(page.getByRole("heading", {name: "Configuration", exact: true})).toBeVisible();
    await expect(page.getByText(/No provider keys detected/)).toBeVisible();
    await page.screenshot({path: "test-results/configuration-first-run.png", fullPage: true});
    await page.getByRole("button", {name: /^Statistics/}).click();
    await expect(page.getByRole("heading", {name: "No activity recorded yet"})).toBeVisible();
    await expect(page.getByText("finassist demo", {exact: true})).toBeVisible();
    await expect(page.getByText("finassist doctor", {exact: true})).toBeVisible();
    await expect(page.getByText("$0.00").first()).toBeVisible();
    await page.screenshot({path: "test-results/statistics-first-run.png", fullPage: true});
    expect(external).toEqual([]);
    expect(errors).toEqual([]);
  });
});
