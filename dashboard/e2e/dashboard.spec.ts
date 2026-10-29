import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

test.use({timezoneId: "America/New_York"});

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
    page.on("console", message => {if (message.type() === "error" && /content security|refused to load|violates.*policy/i.test(message.text())) errors.push(message.text());});
    page.on("request", request => {if (new URL(request.url()).origin !== server.origin) external.push(request.url());});
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(server.origin);
    await expect(page).toHaveTitle("finledgerpoli - local dashboard");
    await expect(page.locator("aside .brand")).toContainText("finledgerpoli");
    const logo = page.getByRole("img", {name: "finledgerpoli logo", exact: true});
    await expect(logo).toBeVisible();
    expect(await logo.evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth > 0)).toBe(true);
    const icons = [
      [await logo.getAttribute("src"), "mark.svg", "image/svg+xml"],
      [await page.locator('link[rel="icon"][type="image/svg+xml"]').getAttribute("href"), "favicon.svg", "image/svg+xml"],
      [await page.locator('link[rel="icon"][type="image/png"]').getAttribute("href"), "favicon-32.png", "image/png"],
    ];
    for (const [url, source, mime] of icons) {
      const local = new URL(url!, server.origin);
      expect(local.origin).toBe(server.origin);
      expect(local.pathname).toMatch(/^\/assets\//);
      const response = await page.request.get(local.href);
      expect(response.status()).toBe(200);
      expect(response.headers()["content-type"]).toBe(mime);
      expect(response.headers()["content-security-policy"]).toContain("img-src 'self';");
      const expected = await readFile(path.join("../brand", source!));
      expect(createHash("sha256").update(await response.body()).digest("hex")).toBe(createHash("sha256").update(expected).digest("hex"));
    }
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
    await expect(page.getByRole("heading", {name: "Pending charges", exact: true})).toHaveCount(2);
    await expect(page.getByRole("heading", {name: "Ready for human review"})).toBeVisible();
    await expect(page.getByRole("heading", {name: "Checks you've run"})).toBeVisible();
    await expect(page.getByText(/Ready for review does not approve a merge or deployment/)).toBeVisible();
    await expect(page.getByText("dashboard-save", {exact: true})).toBeVisible();
    await expect(page.getByRole("img", {name: "Recorded spend (USD)", exact: true})).toBeVisible();
    await expect(page.getByRole("heading", {name: "No activity recorded yet"})).toHaveCount(0);
    await expect(page.locator("canvas")).toHaveCount(2);
    const asof = page.locator(".asof time");
    await expect(asof).toHaveText(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/);
    const exact = await asof.getAttribute("title");
    expect(exact).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    await expect(asof).toHaveAttribute("datetime", exact!);
    await expect(asof).toHaveText(new Date(exact!).toISOString().slice(0, 16).replace("T", " ") + " UTC");
    await expect(page.locator("time").last()).toHaveText(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/);
    await expect(page.getByText(/Spend is grouped by the UTC date when funds were set aside/)).toBeVisible();
    // The sidebar background spans the long document; its controls stay viewport-height and sticky.
    const dimensions = await page.evaluate(() => ({
      sidebar: document.querySelector("aside")!.getBoundingClientRect().height,
      document: document.documentElement.scrollHeight,
      controls: document.querySelector(".sidebar-content")!.getBoundingClientRect().height,
      viewport: window.innerHeight,
    }));
    expect(dimensions.document).toBeGreaterThan(dimensions.viewport);
    expect(dimensions.sidebar).toBeGreaterThanOrEqual(dimensions.document - 1);
    expect(dimensions.controls).toBe(dimensions.viewport);
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await expect.poll(async () => Math.abs((await page.locator(".sidebar-content").boundingBox())!.y)).toBeLessThan(1);
    await expect(page.getByRole("button", {name: /^Health/})).toBeInViewport();
    await page.emulateMedia({colorScheme: "dark"});
    await expect(page.locator(".sidebar-content")).toHaveCSS("position", "sticky");
    await page.emulateMedia({colorScheme: "light"});
    await page.evaluate(() => window.scrollTo(0, 0));
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
    page.on("console", message => {if (message.type() === "error" && /content security|refused to load|violates.*policy/i.test(message.text())) errors.push(message.text());});
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
    await page.setViewportSize({width: 390, height: 844});
    await expect(page.locator(".sidebar-content")).toHaveCSS("position", "static");
    expect((await page.locator("aside").boundingBox())!.height).toBeLessThan(844);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
    await page.getByRole("button", {name: /^Health/}).click();
    await expect(page.getByRole("heading", {name: "Health", exact: true})).toBeVisible();
    expect(external).toEqual([]);
    expect(errors).toEqual([]);
  });
});

test("README diagram switches with the theme and keeps its plain-image fallback", async ({page}) => {
  const raw = "https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/brand/";
  const readme = await readFile("../README.md", "utf8");
  const picture = readme.match(/<picture>[\s\S]*?<\/picture>/)![0];
  await page.route("**/*", async route => {
    const url = route.request().url();
    const name = url.slice(raw.length);
    if (!url.startsWith(raw) || !["how-it-works-dark.png", "how-it-works-light.png"].includes(name)) return route.abort();
    await route.fulfill({contentType: "image/png", body: await readFile(path.join("../brand", name))});
  });
  const diagram = page.locator("picture img");
  for (const theme of ["dark", "light"] as const) {
    await page.emulateMedia({colorScheme: theme});
    await page.setContent(picture);
    await expect.poll(() => diagram.evaluate((img: HTMLImageElement) => img.currentSrc)).toBe(raw + `how-it-works-${theme}.png`);
    await expect.poll(() => diagram.evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth > 0)).toBe(true);
  }
  await page.emulateMedia({colorScheme: "dark"});
  await page.setContent(picture.replace(/<source[^>]*>/g, ""));
  await expect.poll(() => diagram.evaluate((img: HTMLImageElement) => img.currentSrc)).toBe(raw + "how-it-works-light.png");
  await expect.poll(() => diagram.evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth > 0)).toBe(true);
});
