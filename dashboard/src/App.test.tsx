import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { App } from "./App";

vi.mock("./Chart", () => ({Chart: ({label}: {label: string}) => <div aria-label={label} />}));
const values = {provider: "offline", model: "", daily_budget_usd: 5, monthly_budget_usd: 100,
  allow_paths: ["src/"], generated_paths: ["src/finassist/resources/dashboard/"], protected_paths: [".github/"], extra_sensitive_patterns: [], profile: "general",
  required_recipes: [], blocking_severities: ["critical", "high"], readiness_max_age_seconds: 86400};
const configuration = {revision: "revision", values, options: {providers: ["offline", "openai"], profiles: ["general"], recipes: []}, key_presence: {openai: true}};
const statistics = {as_of: "2026-10-29T00:14:21.916226+00:00", limits: {daily_usd: "5", monthly_usd: "100"}, spend: {today_usd: "1", month_usd: "2", open_reserved_usd: "0.5", available_today_usd: "3.5", available_month_usd: "97.5"}, daily: [], open_reservations: [],
  reviews: {total: 2, offline: 1, findings: {high: 1}, by_profile: {general: 2}, findings_by_profile: {general: 1}, unknown_findings: 1}, usage: {known_calls: 1, unknown_calls: 1},
  readiness: {eligible: 1, blocked: 1, unclassified: 1, reasons: {stale: 1}}, recipes: [{name: "unit", passed: 1, total: 2}], legacy_checks: 1, recent_runs: [{id: "synthetic-run", command: "review", status: "complete", started_at: "2026-10-28T20:14:21.123456-04:00"}], qualification: "Synthetic audit."};
let calls: {path: string; body: Record<string, unknown> | undefined; headers: Record<string, string>}[];
beforeEach(() => {
  calls = [];
  vi.stubGlobal("fetch", vi.fn(async (path: string, options: RequestInit = {}) => {
    const body = options.body ? JSON.parse(String(options.body)) : undefined;
    calls.push({path, body, headers: options.headers as Record<string, string>});
    let result: unknown = path === "/api/session" ? {token: "synthetic-session"} : path === "/api/statistics" ? statistics :
      path === "/api/health" ? {configuration: {valid: true}, doctor: {provider: "offline", docker_binary_present: false}} : configuration;
    if (path.endsWith("preview")) result = {proposal_id: "proposal", revision: "revision", diff: [{field: "daily_budget_usd", before: 5, after: 7}]};
    if (path.endsWith("confirm")) result = {...configuration, values: {...values, daily_budget_usd: 7}};
    return new Response(JSON.stringify(result), {status: 200, headers: {"Content-Type": "application/json"}});
  }));
});
afterEach(() => {cleanup(); vi.unstubAllGlobals();});

it("never saves on edit or preview and requires a separate explicit confirmation", async () => {
  render(<App />);
  const budget = await screen.findByLabelText("Daily spend limit (USD)");
  fireEvent.change(budget, {target: {value: "7"}});
  expect(calls.some(call => call.path.endsWith("confirm"))).toBe(false);
  fireEvent.click(screen.getByRole("button", {name: "Preview changes"}));
  await screen.findByRole("heading", {name: "Proposed changes"});
  expect(calls.some(call => call.path.endsWith("confirm"))).toBe(false);
  expect(screen.getByRole("columnheader", {name: "Before"})).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", {name: "Confirm and save"}));
  await screen.findByText("Configuration saved.");
  const call = calls.find(call => call.path.endsWith("confirm"))!;
  expect(call.body).toEqual({proposal_id: "proposal", confirm: true});
  expect(call.headers["X-Finassist-Token"]).toBe("synthetic-session");
});

it("discards a preview when a setting changes and offers no API-key input", async () => {
  render(<App />);
  await screen.findByLabelText("Model");
  expect(screen.getByText("openai: Set")).toBeInTheDocument();
  expect(document.querySelector('input[type="password"]')).toBeNull();
  fireEvent.click(screen.getByRole("button", {name: "Preview changes"}));
  await screen.findByRole("button", {name: "Confirm and save"});
  fireEvent.change(screen.getByLabelText("Model"), {target: {value: "selected"}});
  expect(screen.queryByRole("button", {name: "Confirm and save"})).toBeNull();
});

it("shows statistics coverage and health through keyboard-accessible navigation", async () => {
  render(<App />);
  await screen.findByLabelText("Model");
  fireEvent.click(screen.getByRole("button", {name: /^Statistics/}));
  expect(await screen.findByRole("heading", {name: "Reviews & findings"})).toBeInTheDocument();
  expect(screen.getByText(/older reviews lack finding metadata/)).toBeInTheDocument();
  expect(screen.getAllByRole("heading", {name: "Pending charges"})).toHaveLength(2);
  expect(screen.getByText("0 pending charges (not yet confirmed)")).toBeInTheDocument();
  expect(screen.getByText("No pending charges.")).toBeInTheDocument();
  expect(screen.getAllByText("2026-10-29 00:14 UTC")).toHaveLength(2);
  expect(screen.getByTitle(statistics.as_of)).toHaveAttribute("datetime", statistics.as_of);
  expect(screen.getByTitle(statistics.recent_runs[0].started_at)).toHaveAttribute("datetime", statistics.recent_runs[0].started_at);
  expect(screen.getByRole("heading", {name: "Ready for human review"})).toBeInTheDocument();
  expect(screen.getByRole("heading", {name: "Checks you've run"})).toBeInTheDocument();
  expect(screen.getByText(/Ready for review does not approve a merge or deployment/)).toBeInTheDocument();
  expect(document.querySelector("aside .brand")).toHaveTextContent("finledgerpoli");
  expect(screen.getByRole("img", {name: "finledgerpoli logo"})).toHaveAttribute("src", expect.stringContaining("mark.svg"));
  expect(document.querySelector("footer")).toHaveTextContent("finledgerpoli — local dashboard");
  expect(screen.getByText("50%")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", {name: /^Health/}));
  await waitFor(() => expect(screen.getByText("Configuration is valid")).toBeInTheDocument());
  expect(calls.every(call => call.path.startsWith("/api/"))).toBe(true);
});

it("preserves newlines while editing path lists and sensitive patterns", async () => {
  render(<App />);
  const paths = await screen.findByLabelText("Allowed paths");
  fireEvent.change(paths, {target: {value: "src/\n"}});
  expect(paths).toHaveValue("src/\n");
  fireEvent.change(paths, {target: {value: "src/\ntests/"}});
  fireEvent.change(screen.getByLabelText("Sensitive patterns"), {target: {value: "internal phrase\n"}});
  fireEvent.click(screen.getByRole("button", {name: "Preview changes"}));
  await screen.findByRole("heading", {name: "Proposed changes"});
  expect(calls.find(call => call.path.endsWith("preview"))!.body!.changes).toMatchObject({allow_paths: ["src/", "tests/"], extra_sensitive_patterns: ["internal phrase"]});
});

it("keeps a typed configuration error visible on every tab instead of loading forever", async () => {
  vi.stubGlobal("fetch", vi.fn(async (path: string) => {
    if (path === "/api/session") return new Response(JSON.stringify({token: "synthetic"}));
    if (path === "/api/health") return new Response(JSON.stringify({configuration: {valid: false}, doctor: {provider: "offline"}}));
    return new Response(JSON.stringify({kind: "configuration", code: "configuration_invalid"}), {status: 409});
  }));
  render(<App />);
  await screen.findByRole("alert");
  for (const name of ["Statistics", "Health", "Configuration"]) {
    fireEvent.click(screen.getByRole("button", {name: new RegExp("^" + name)}));
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.queryByText("Loading local data…")).toBeNull();
  }
});

it("removes stale settings when a refresh discovers an invalid configuration", async () => {
  render(<App />);
  await screen.findByLabelText("Model");
  vi.stubGlobal("fetch", vi.fn(async (path: string) => path === "/api/health" ?
    new Response(JSON.stringify({configuration: {valid: false}, doctor: {provider: "offline"}})) :
    new Response(JSON.stringify({kind: "configuration", code: "configuration_invalid"}), {status: 409})));
  fireEvent.click(screen.getByRole("button", {name: "Refresh local data"}));
  await screen.findByRole("alert");
  expect(screen.queryByLabelText("Model")).toBeNull();
});

it("explains what to do next when no activity has been recorded yet", async () => {
  const empty = {...statistics,
    spend: {today_usd: "0", month_usd: "0", open_reserved_usd: "0", available_today_usd: "5", available_month_usd: "100"},
    reviews: {total: 0, offline: 0, findings: {}, by_profile: {}, findings_by_profile: {}, unknown_findings: 0},
    usage: {known_calls: 0, unknown_calls: 0},
    readiness: {eligible: 0, blocked: 0, unclassified: 0, reasons: {}}, recipes: [], legacy_checks: 0, recent_runs: []};
  vi.stubGlobal("fetch", vi.fn(async (path: string, options: RequestInit = {}) => {
    const result: unknown = path === "/api/session" ? {token: "synthetic-session"} : path === "/api/statistics" ? empty :
      path === "/api/health" ? {configuration: {valid: true}, doctor: {provider: "offline"}} : configuration;
    void options;
    return new Response(JSON.stringify(result), {status: 200, headers: {"Content-Type": "application/json"}});
  }));
  render(<App />);
  await screen.findByLabelText("Model");
  fireEvent.click(screen.getByRole("button", {name: /^Statistics/}));
  expect(await screen.findByRole("heading", {name: "No activity recorded yet"})).toBeInTheDocument();
  expect(screen.getByText("finassist demo")).toBeInTheDocument();
  expect(screen.getByText("finassist doctor")).toBeInTheDocument();
  expect(screen.getByRole("heading", {name: "Spent today"})).toBeInTheDocument();
});

it("keeps the onboarding guide hidden once activity exists", async () => {
  render(<App />);
  await screen.findByLabelText("Model");
  fireEvent.click(screen.getByRole("button", {name: /^Statistics/}));
  await screen.findByRole("heading", {name: "Reviews & findings"});
  expect(screen.queryByRole("heading", {name: "No activity recorded yet"})).toBeNull();
});

it("notes when no provider keys are present without ever accepting one", async () => {
  vi.stubGlobal("fetch", vi.fn(async (path: string) => {
    const result: unknown = path === "/api/session" ? {token: "synthetic-session"} : path === "/api/statistics" ? statistics :
      path === "/api/health" ? {configuration: {valid: true}, doctor: {provider: "offline"}} :
      {...configuration, key_presence: {openai: false, anthropic: false}};
    return new Response(JSON.stringify(result), {status: 200, headers: {"Content-Type": "application/json"}});
  }));
  render(<App />);
  expect(await screen.findByText(/No provider keys detected/)).toBeInTheDocument();
  expect(screen.getByText("openai: Not set")).toBeInTheDocument();
  expect(document.querySelector('input[type="password"]')).toBeNull();
});
