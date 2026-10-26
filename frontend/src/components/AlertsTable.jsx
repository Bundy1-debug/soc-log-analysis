import { useState } from "react";
import { sourceOf, shortTime } from "../lib/format.js";

const TABS = [
  { id: "ssh", label: "SSH" },
  { id: "http", label: "HTTP" },
  { id: "dns", label: "DNS" },
  { id: "host", label: "Host" },
  { id: "anom", label: "Anomaly" },
];

function Tag({ children, danger }) {
  return <span className={`chip ${danger ? "danger" : ""}`}>{children}</span>;
}

function Details({ a }) {
  const d = a.details || {};
  switch (a.type) {
    case "SSH_BRUTE_FORCE":
      return <>
        <div className="muted">peak {d.peak_in_window} in {d.window_seconds}s</div>
        <div className="tagline">{(d.users_targeted || []).slice(0, 6).map((u) =>
          <Tag key={u.user}>{u.user}×{u.attempts}{u.exists ? "" : " (inv)"}</Tag>)}</div>
      </>;
    case "SSH_LOGIN_AFTER_BRUTE_FORCE":
      return <div className="tagline">
        <span className="breach-tag">⚠ BREACH</span>
        {(d.compromised_users || []).map((u) => <Tag key={u} danger>{u}</Tag>)}
        <div className="muted">via {d.auth_method} after {d.failures_before} failures</div>
      </div>;
    case "HTTP_SCAN":
      return <div className="tagline">
        {(d.payloads || []).map((p) => <Tag key={p} danger>{p.replace(/_/g, " ")}</Tag>)}
        {(d.exposed_paths || []).map((p) => <Tag key={p} danger>2xx {p}</Tag>)}
        {(d.top_paths || []).slice(0, 3).map((p) => <Tag key={p}>{p}</Tag>)}
      </div>;
    case "WEB_LOGIN_BRUTE_FORCE":
      return <div className="tagline">
        {d.successful_logins ? <span className="breach-tag">⚠ LOGIN OK</span> : null}
        {(d.login_paths || []).map((p) => <Tag key={p}>{p}</Tag>)}
        <div className="muted">{d.failed_attempts} failures · peak {d.peak_in_window}</div>
      </div>;
    case "WEB_DIRECTORY_BRUTE_FORCE":
      return <div className="tagline">
        {(d.discovered_paths || []).slice(0, 4).map((p) => <Tag key={p} danger>{p}</Tag>)}
        <div className="muted">{d.not_found} × 404 · {(d.agents || []).join(", ")}</div>
      </div>;
    case "WEBSHELL":
      return <div className="tagline">
        {(d.scripts || []).map((p) => <Tag key={p} danger>{p}</Tag>)}
        <div className="muted">{d.command_requests} command req · {d.upload_dir_posts} upload POSTs</div>
      </div>;
    case "WEB_LARGE_TRANSFER":
      return <div className="tagline">
        {(d.sensitive_files || []).map((p) => <Tag key={p} danger>{p}</Tag>)}
        <div className="muted">served to this IP</div>
      </div>;
    case "SUSPICIOUS_DNS":
      return <div className="tagline">
        {(d.domains || []).map((p) => <Tag key={p} danger={!!d.indicators?.threat_intel}>{p}</Tag>)}
        <div className="muted">{Object.keys(d.indicators || {}).join(", ").replace(/_/g, " ")}</div>
      </div>;
    case "DNS_TUNNELING":
      return <div className="tagline">
        <Tag danger>{d.parent_domain}</Tag>
        {Object.keys(d.signals || {}).map((s) => <Tag key={s}>{s.replace(/_/g, " ")}</Tag>)}
        <div className="muted">{d.unique_subdomains} subdomains · ~{(d.encoded_bytes_estimate / 1024).toFixed(1)} KB</div>
      </div>;
    case "DNS_BEACONING":
      return <div className="tagline">
        <Tag danger>{d.parent_domain}</Tag>
        <div className="muted">every ~{d.interval_seconds}s · jitter {(d.jitter * 100).toFixed(1)}%</div>
      </div>;
    case "SUDO_ABUSE":
      return <div className="tagline">{(d.reasons || []).map((r) => <Tag key={r} danger={d.not_in_sudoers}>{r}</Tag>)}</div>;
    case "SU_BRUTE_FORCE":
      return <div className="muted">targeting {(d.targets || []).join(", ")}</div>;
    case "USER_CREATED":
      return <Tag>created by {d.tool}</Tag>;
    case "PRIV_GROUP_ADD":
      return <div className="tagline">{(d.groups || []).map((g) => <Tag key={g} danger>{g}</Tag>)}</div>;
    case "ANOMALY_VOLUME":
      return <div className="muted">{d.event_count} events vs {d.peer_average} avg · z={d.zscore}</div>;
    case "ANOMALY_NEW_SOURCE":
      return <div className="muted">not in baseline of {d.baseline_sources} sources</div>;
    case "ANOMALY_NEW_DOMAIN":
      return <div className="tagline">{(d.domains || []).map((x) => <Tag key={x}>{x}</Tag>)}</div>;
    default:
      if (a.type.startsWith("EDR_"))
        return <div className="cmd mono">{(d.commands || []).join("  ;  ")}</div>;
      return null;
  }
}

export function AlertsTable({ report, onIp }) {
  const [tab, setTab] = useState("ssh");
  const grouped = Object.fromEntries(TABS.map((t) => [t.id, report.alerts.filter((a) => sourceOf(a.type) === t.id)]));
  const rows = grouped[tab];

  return (
    <div className="view fade-up">
      <div className="panel alerts-panel">
        <div className="tabbar">
          {TABS.map((t) => (
            <button key={t.id} className={`tab ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>
              {t.label}<span className="tab-count mono">{grouped[t.id].length}</span>
            </button>
          ))}
        </div>

        {rows.length === 0 ? (
          <div className="chart-empty tall">No {tab.toUpperCase()} alerts ✓</div>
        ) : (
          <div className="table-scroll">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Source</th><th>Detection</th><th>Severity</th><th>Count</th>
                  <th>Details</th><th>Window</th><th>ATT&CK</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <button className="ip-link mono" onClick={() => onIp(a)}>{a.ip}</button>
                      <div className="muted">{a.ip_role}{a.intel_match ? " · blocklist" : ""}</div>
                    </td>
                    <td className="cell-detect">
                      <div className="detect-title">{a.title}</div>
                      <div className="muted">{a.summary}</div>
                    </td>
                    <td><span className={`sev-badge sev-${a.severity}`}>{a.severity}</span></td>
                    <td className="mono">{a.count}</td>
                    <td className="cell-details"><Details a={a} /></td>
                    <td className="muted mono nowrap">{shortTime(a.first_seen)}<br />{shortTime(a.last_seen)}</td>
                    <td>
                      <a className="tech-pill mono" href={a.mitre.url} target="_blank" rel="noreferrer">
                        {a.mitre.technique_id}
                      </a>
                      <div className="muted">{a.mitre.tactic}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
