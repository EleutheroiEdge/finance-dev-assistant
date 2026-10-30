import type { UpdateStatus } from "./api";
import { Timestamp } from "./Timestamp";

export function Updates({value}: {value: UpdateStatus}) {
  const status = {"not checked": "Not checked", "update-available": "Update available", "up-to-date": "Up to date"}[value.status];
  return <section className="card" aria-label="Package updates"><h2>Package updates</h2>
    <dl className="health">
      <div><dt>Status</dt><dd>{status}</dd></div>
      <div><dt>Installed version</dt><dd>{value.installed_version}</dd></div>
      <div><dt>Latest version</dt><dd>{value.latest_version ?? "Not checked"}</dd></div>
      <div><dt>Install method</dt><dd>{value.install_method}</dd></div>
      <div><dt>Update notices</dt><dd>{value.checks_disabled_by_environment ? "Disabled by environment" : value.update_check === "off" ? "Off" : value.update_check === "notify" ? "Notify" : "Check user settings"}</dd></div>
      <div><dt>Last check</dt><dd>{value.checked_at ? <><Timestamp value={value.checked_at} />{value.stale && " (cached result may be out of date)"}</> : "Not checked"}</dd></div>
    </dl>
    {value.upgrade_command && <><h3>Upgrade command</h3><pre className="upgrade-command"><code>{value.upgrade_command}</code></pre></>}
    {value.editable_install && <p>Editable installation: update through your source workflow.</p>}
    {!value.can_upgrade && !value.editable_install && <p>Use the package manager that owns this installation; automatic execution is unavailable.</p>}
    <p className="help">This page reads cached metadata without contacting PyPI. To check once, run <code>finassist doctor --check-updates</code> with network use allowed in your project configuration.</p>
    <p className="help">Upgrades leave project configuration and evidence unchanged. Install only from your terminal with explicit confirmation. No automatic installs.</p>
  </section>;
}
