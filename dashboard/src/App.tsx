import { useEffect, useRef, useState } from "react";
import { explain, request, type Configuration, type Health, type Preview, type Statistics, type Values } from "./api";
import { Chart } from "./Chart";

const labels: Record<keyof Values, string> = {provider: "Provider", model: "Model", daily_budget_usd: "Daily spend limit (USD)", monthly_budget_usd: "Monthly spend limit (USD)", allow_paths: "Allowed paths", generated_paths: "Generated paths", protected_paths: "Protected paths", extra_sensitive_patterns: "Sensitive patterns", profile: "Review profile", required_recipes: "Required recipes", blocking_severities: "Blocking severities", readiness_max_age_seconds: "Evidence age (seconds)"};
const money = (value: string) => new Intl.NumberFormat("en-US", {style: "currency", currency: "USD", maximumFractionDigits: 4}).format(Number(value));
const entries = (value: Record<string, number>) => Object.entries(value);

export function App() {
  const [page, setPage] = useState("Configuration");
  const [token, setToken] = useState("");
  const [config, setConfig] = useState<Configuration | null>(null);
  const [values, setValues] = useState<Values | null>(null);
  const [stats, setStats] = useState<Statistics | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [listDrafts, setListDrafts] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const main = useRef<HTMLElement>(null);

  async function load(active: string) {
    const results = await Promise.allSettled([
      request<Configuration>("/api/config", active), request<Statistics>("/api/statistics", active), request<Health>("/api/health", active),
    ]);
    if (results[0].status === "fulfilled") { setConfig(results[0].value); setValues(results[0].value.values); setListDrafts({}); } else {setConfig(null); setValues(null); setListDrafts({});}
    if (results[1].status === "fulfilled") setStats(results[1].value); else setStats(null);
    if (results[2].status === "fulfilled") setHealth(results[2].value); else setHealth(null);
    const failure = results.find(result => result.status === "rejected");
    if (failure?.status === "rejected") setError(explain(failure.reason)); else setError("");
    return !failure;
  }
  useEffect(() => { request<{token: string}>("/api/session").then(session => {setToken(session.token); return load(session.token);}).catch(error => setError(explain(error))); }, []);

  function edit<K extends keyof Values>(key: K, value: Values[K]) {
    setValues(current => current ? {...current, [key]: value} : current);
    setPreview(null); setNotice(""); setError("");
  }
  async function prepare() {
    setBusy(true); setError(""); setNotice("");
    try { const result = await request<Preview>("/api/config/preview", token, {revision: config!.revision, changes: values}); setPreview(result); setNotice("Preview ready. Review changes before saving."); }
    catch (error) { setError(explain(error)); }
    finally { setBusy(false); }
  }
  async function save() {
    setBusy(true); setError("");
    try { const result = await request<Configuration>("/api/config/confirm", token, {proposal_id: preview!.proposal_id, confirm: true});
      setConfig(result); setValues(result.values); setPreview(null); setNotice("Configuration saved.");
      await load(token);
    } catch (error) {setError(explain(error)); setPreview(null);}
    finally {setBusy(false);}
  }
  async function reload() {setBusy(true); setError(""); setPreview(null); try {const success = await load(token); setNotice(success ? "Local data refreshed." : "");} finally {setBusy(false);}}

  function list(key: "allow_paths" | "generated_paths" | "protected_paths" | "extra_sensitive_patterns" | "required_recipes", help: string) {
    return <label className="field" htmlFor={key}>{labels[key]}<textarea id={key} rows={4} aria-label={labels[key]} value={listDrafts[key] ?? values![key].join("\n")} aria-describedby={key+"-help"}
      onChange={event => {setListDrafts(current => ({...current, [key]: event.target.value})); edit(key, event.target.value.split("\n").map(line => key === "extra_sensitive_patterns" ? line : line.trim()).filter(Boolean));}} /><span id={key+"-help"} className="help">{help}</span></label>;
  }

  return <div className="layout"><a className="skip" href="#main">Skip to content</a>
    <aside><div className="brand"><span className="brand-icon" aria-hidden="true">F</span><div>Finance Assistant<small>Developer workspace</small></div></div>
      <nav aria-label="Dashboard sections">{["Configuration", "Statistics", "Health"].map(name => <button key={name} aria-current={page === name ? "page" : undefined}
        onClick={() => {setPage(name); setNotice(""); main.current?.focus({preventScroll: true}); window.scrollTo({top: 0});}}>{name}<span aria-hidden="true">→</span></button>)}</nav>
      <div className="local"><span aria-hidden="true" className="dot" />Local session<p>Offline dashboard · Loopback only</p><p>Reviews and deployments stay under your normal project controls.</p></div>
    </aside>
    <main id="main" ref={main} tabIndex={-1}><header><div><p className="eyebrow">YOUR DEVELOPER WORKSPACE</p><h1>{page}</h1><p className="subtitle">{page === "Configuration" ? "Review your settings. Preview every change before saving." : page === "Statistics" ? "Understand activity from your verified local audit trail." : "Check local capabilities and configuration status."}</p></div><button className="secondary" disabled={busy || !token} onClick={reload}>Refresh local data</button></header>
      {error && <div role="alert" className="alert">{error}</div>}<p role="status" aria-live="polite" className="notice">{notice}</p>
      {page === "Configuration" && config && values && <form onSubmit={event => {event.preventDefault(); void prepare();}}>
        <section className="card"><div className="section-title"><span className="number">01</span><div><h2>Model & review</h2><p>Choose your provider and review checklist.</p></div></div><div className="grid">
          <label className="field" htmlFor="provider">Provider<select aria-label="Provider" id="provider" value={values.provider} onChange={event => edit("provider", event.target.value)}>{config.options.providers.map(name => <option key={name}>{name}</option>)}</select><span className="help">Provider changes do not authorize a network call.</span></label>
          <label className="field" htmlFor="model">Model<input aria-label="Model" id="model" value={values.model} placeholder="Your selected model" onChange={event => edit("model", event.target.value)} /><span className="help">Use the exact model identifier for your configured endpoint.</span></label>
          <label className="field" htmlFor="profile">Review profile<select aria-label="Review profile" id="profile" value={values.profile} onChange={event => edit("profile", event.target.value)}>{config.options.profiles.map(name => <option key={name}>{name}</option>)}</select><span className="help">A checklist supports your project specification.</span></label>
        </div><div className="key-status"><h3>Key availability</h3><p>Keys stay in environment variables. Only availability is shown.</p>{Object.entries(config.key_presence).map(([name, present]) => <span key={name} className="pill">{name}: {present ? "Set" : "Not set"}</span>)}</div></section>
        <section className="card"><div className="section-title"><span className="number">02</span><div><h2>Spend limits</h2><p>Local UTC admission budgets; provider billing can differ.</p></div></div><div className="grid">
          {(["daily_budget_usd", "monthly_budget_usd"] as const).map(key => <label className="field" key={key} htmlFor={key}>{labels[key]}<input aria-label={labels[key]} id={key} type="number" min="0" step="0.01" value={values[key]} onChange={event => edit(key, Number(event.target.value))} /><span className="help">Open or unknown reservations remain held across periods.</span></label>)}
        </div></section>
        <section className="card"><div className="section-title"><span className="number">03</span><div><h2>Source & privacy</h2><p>Keep review scope explicit and private material excluded.</p></div></div><div className="grid">
          {list("allow_paths", "One path per line. End directory prefixes with /.")}{list("protected_paths", "Paths that proposed patches must not change.")}
          {list("generated_paths", "One exact path or directory prefix per line. Excluded from reviews and snapshots; verify build integrity in CI.")}
          {list("extra_sensitive_patterns", "One case-insensitive regular expression per line. Matching content is blocked.")}
        </div></section>
        <section className="card"><div className="section-title"><span className="number">04</span><div><h2>Readiness policy</h2><p>Set evidence requirements for human review.</p></div></div><div className="grid">
          {list("required_recipes", config.options.recipes.length ? `Configured recipes: ${config.options.recipes.join(", ")}.` : "No recipes defined. Add recipe definitions in your configuration file first.")}
          <label className="field" htmlFor="readiness_max_age_seconds">Evidence age (seconds)<input aria-label="Evidence age (seconds)" id="readiness_max_age_seconds" type="number" min="1" step="1" value={values.readiness_max_age_seconds} onChange={event => edit("readiness_max_age_seconds", Number(event.target.value))} /><span className="help">Use 1 to 2,000,000 seconds. Older audit evidence blocks readiness.</span></label>
          <fieldset className="field"><legend>Blocking severities</legend>{["critical", "high", "medium", "low", "info"].map(severity => <label className="checkbox" key={severity}><input type="checkbox" checked={values.blocking_severities.includes(severity)} onChange={event => edit("blocking_severities", event.target.checked ? [...values.blocking_severities, severity] : values.blocking_severities.filter(item => item !== severity))} />{severity}</label>)}</fieldset>
        </div></section>
        <div className="actions"><p>Nothing saves automatically.</p><button type="submit" disabled={busy}>Preview changes</button></div>
        {preview && <section className="card preview" aria-label="Change preview"><h2>Proposed changes</h2>{preview.diff.length ? <><table><thead><tr><th>Setting</th><th>Before</th><th>After</th></tr></thead><tbody>{preview.diff.map(row => <tr key={row.field}><th>{labels[row.field as keyof Values] || row.field}</th><td><code>{JSON.stringify(row.before)}</code></td><td><code>{JSON.stringify(row.after)}</code></td></tr>)}</tbody></table><div className="actions"><button type="button" className="secondary" onClick={() => setPreview(null)}>Discard preview</button><button type="button" disabled={busy} onClick={save}>Confirm and save</button></div></> : <p>No changes to save.</p>}</section>}
      </form>}
      {page === "Statistics" && stats && <>
        <div className="metrics"><section className="metric"><h2>Today</h2><strong>{money(stats.spend.today_usd)}</strong><p>of {money(stats.limits.daily_usd)} daily limit · {money(stats.spend.available_today_usd)} available after holds</p></section><section className="metric"><h2>This month</h2><strong>{money(stats.spend.month_usd)}</strong><p>of {money(stats.limits.monthly_usd)} monthly limit · {money(stats.spend.available_month_usd)} available after holds</p></section><section className="metric"><h2>Open / unknown</h2><strong>{money(stats.spend.open_reserved_usd)}</strong><p>{stats.open_reservations.length} held reservations</p></section></div>
        <div className="grid"><section className="card"><h2>Recorded spend</h2><Chart rows={stats.daily} field="usd" label="Recorded spend (USD)" /></section><section className="card"><h2>Recorded tokens</h2><Chart rows={stats.daily} field="tokens" label="Recorded tokens" /><p className="help">{stats.usage.known_calls} known calls · {stats.usage.unknown_calls} with missing usage. Missing is not zero.</p></section></div>
        <section className="card"><h2>Reviews & findings</h2><p>{stats.reviews.total} model reviews · {stats.reviews.offline} offline analyses</p><div className="grid"><Counts title="Findings by severity" values={stats.reviews.findings} /><Counts title="Model reviews by profile" values={stats.reviews.by_profile} /><Counts title="Findings by profile" values={stats.reviews.findings_by_profile} /></div><p className="help">{stats.reviews.unknown_findings} older reviews lack finding metadata.</p></section>
        <section className="card"><h2>Readiness</h2><p>{stats.readiness.eligible} eligible for human review · {stats.readiness.blocked} blocked</p><Counts title="Blocking reasons" values={stats.readiness.reasons} /><p className="help">{stats.readiness.unclassified} older or failed evaluations lack result metadata. Eligibility grants no merge or deployment authority.</p></section>
        <section className="card"><h2>Check recipes</h2>{stats.recipes.length ? <table><thead><tr><th>Recipe</th><th>Passed</th><th>Pass rate</th></tr></thead><tbody>{stats.recipes.map(row => <tr key={row.name}><td>{row.name}</td><td>{row.passed} / {row.total}</td><td>{Math.round(100 * row.passed / row.total)}%</td></tr>)}</tbody></table> : <p>No classified recipe results yet.</p>}<p className="help">{stats.legacy_checks} older checks lack result metadata.</p></section>
        <section className="card"><h2>Open or unknown reservations</h2>{stats.open_reservations.length ? <table><thead><tr><th>Reservation</th><th>Amount</th><th>Booked (UTC)</th></tr></thead><tbody>{stats.open_reservations.map(row => <tr key={row.id}><td>{row.id.slice(0, 8)}</td><td>{money(row.reserved)}</td><td>{row.day}</td></tr>)}</tbody></table> : <p>No open reservations.</p>}</section>
        <section className="card"><h2>Recent runs</h2>{stats.recent_runs.length ? <table><thead><tr><th>Command</th><th>Started (UTC)</th><th>Outcome</th></tr></thead><tbody>{stats.recent_runs.map(run => <tr key={run.id}><td>{run.command}</td><td>{run.started_at}</td><td>{run.status === "unknown" ? "Open / unknown" : run.status === "blocked-or-failed" ? `Blocked / failed (exit ${run.exit_code})` : run.status}</td></tr>)}</tbody></table> : <p>No audited runs yet.</p>}</section><p className="help">{stats.qualification}</p>
      </>}
      {page === "Health" && health && <><section className="card"><h2>Configuration status</h2><p className={health.configuration.valid ? "healthy" : "alert"}>{health.configuration.valid ? "Configuration is valid" : "Configuration needs attention"}</p></section><section className="card"><h2>Local capabilities</h2><dl className="health">{Object.entries(health.doctor).map(([key, value]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{Array.isArray(value) ? value.join(", ") || "None" : typeof value === "boolean" ? (value ? "Yes" : "No") : value === null ? "Not applicable" : value}</dd></div>)}</dl><p className="help">This page inspects local metadata. It does not call a model or test a container daemon.</p></section></>}
      {((page === "Configuration" && !config) || (page === "Statistics" && !stats) || (page === "Health" && !health)) && !error && <p>Loading local data…</p>}
      <footer>Finance Developer Assistant <span>Local evidence. Human decisions.</span></footer>
    </main></div>;
}

function Counts({title, values}: {title: string; values: Record<string, number>}) {
  return <div><h3>{title}</h3>{entries(values).length ? <ul className="counts">{entries(values).map(([key, count]) => <li key={key}><span>{key.replaceAll("_", " ")}</span><strong>{count}</strong></li>)}</ul> : <p className="empty">No classified records yet.</p>}</div>;
}
