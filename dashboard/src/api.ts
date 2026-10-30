export type Values = {
  provider: string; model: string; daily_budget_usd: number; monthly_budget_usd: number;
  allow_paths: string[]; generated_paths: string[]; protected_paths: string[]; extra_sensitive_patterns: string[];
  profile: string; required_recipes: string[]; blocking_severities: string[];
  readiness_max_age_seconds: number;
};
export type Configuration = {revision: string; values: Values; options: {providers: string[]; profiles: string[]; recipes: string[]}; key_presence: Record<string, boolean>};
export type Preview = {proposal_id: string; revision: string; diff: {field: string; before: unknown; after: unknown}[]};
export type Statistics = {
  as_of: string; limits: {daily_usd: string; monthly_usd: string};
  spend: {today_usd: string; month_usd: string; open_reserved_usd: string; available_today_usd: string; available_month_usd: string};
  daily: {date: string; usd: string; input: number; output: number; unknown: number}[];
  open_reservations: {id: string; reserved: string; day: string}[];
  reviews: {total: number; offline: number; findings: Record<string, number>; by_profile: Record<string, number>; findings_by_profile: Record<string, number>; unknown_findings: number};
  usage: {known_calls: number; unknown_calls: number; qualification: string};
  readiness: {eligible: number; blocked: number; unclassified: number; reasons: Record<string, number>};
  recipes: {name: string; passed: number; total: number}[]; legacy_checks: number;
  recent_runs: {id: string; command: string; status: string; started_at: string; duration_ms?: number; exit_code?: number}[];
  qualification: string;
};
export type UpdateStatus = {
  status: "not checked" | "update-available" | "up-to-date";
  installed_version: string; latest_version: string | null; checked_at: string | null; stale: boolean;
  install_method: string; upgrade_command: string | null; editable_install: boolean; can_upgrade: boolean;
  update_check: "off" | "notify" | "invalid"; checks_disabled_by_environment: boolean;
};
export type Health = {configuration: {valid: boolean; code: string | null}; doctor: Record<string, unknown> & {updates?: UpdateStatus}};

export type ErrorKind = "configuration" | "request";
export class ApiError extends Error {
  constructor(public code: string, public kind: ErrorKind = "request") {super(code);}
}

export async function request<T>(path: string, token?: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST", cache: "no-store", credentials: "omit", redirect: "error",
    headers: { ...(token ? {"X-Finassist-Token": token} : {}), ...(body === undefined ? {} : {"Content-Type": "application/json"}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const value = await response.json();
  if (!response.ok) throw new ApiError(value.code || "request_failed", value.kind === "configuration" ? "configuration" : "request");
  return value as T;
}
export function explain(error: unknown): string {
  const code = error instanceof Error ? error.message : "request_failed";
  const messages: Record<string, string> = {
    configuration_invalid: "Configuration is invalid. Fix the JSON file, then refresh local data.",
    invalid_evidence_age: "Evidence age must be a whole number from 1 to 2,000,000 seconds.",
    configuration_changed_reload: "The configuration changed elsewhere. Reload settings and preview again.",
    explicit_confirmation_required: "Review the proposed changes and explicitly confirm saving.",
    invalid_required_recipes: "Required recipes must already have definitions in your configuration file.",
    invalid_limit: "Evidence age must be a positive whole number.",
    invalid_cost_limit: "Spend limits must be finite, nonnegative amounts.",
    invalid_content_pattern: "A sensitive pattern is not a valid regular expression.",
    model_required: "Choose a model for the selected provider.",
    configuration_saved_audit_unknown_reload: "Configuration may already be saved. Reload and reconcile the audit status before trying again.",
    session_token_required: "This session expired. Reload the page.",
  };
  return messages[code] || `Unable to complete the request: ${code.replaceAll("_", " ")}.`;
}
