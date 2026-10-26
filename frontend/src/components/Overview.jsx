import { SeverityDonut } from "./charts/SeverityDonut.jsx";
import { TacticsBar } from "./charts/TacticsBar.jsx";
import { ActivityTimeline } from "./charts/ActivityTimeline.jsx";
import { TopSources } from "./charts/TopSources.jsx";

function Kpi({ label, value, sub, tone }) {
  return (
    <div className={`kpi panel tone-${tone}`}>
      <div className="kpi-bar" />
      <div className="kpi-label">{label}</div>
      <div className="kpi-value mono">{value}</div>
      <div className="kpi-sub">{sub}</div>
    </div>
  );
}

export function Overview({ report, onIp }) {
  const s = report.summary;
  const techniques = new Set(report.alerts.map((a) => a.mitre.technique_id).filter((t) => t !== "N/A"));
  const bySource = Object.entries(s.events_by_source).map(([k, v]) => `${k} ${v}`).join(" · ");

  return (
    <div className="view fade-up">
      <div className="kpi-grid">
        <Kpi label="Incidents" value={s.incidents} sub="correlated by source" tone="cyan" />
        <Kpi label="Confirmed breaches" value={s.breaches} sub="attacker got in" tone="red" />
        <Kpi label="Alerts" value={s.alerts}
             sub={`${s.by_severity.CRITICAL} critical · ${s.by_severity.HIGH} high`} tone="orange" />
        <Kpi label="Flagged IPs" value={s.flagged_ips} sub={`of ${s.unique_ips} unique`} tone="purple" />
        <Kpi label="SSH failures" value={s.ssh_failures} sub="failed logins" tone="yellow" />
        <Kpi label="SSH logins" value={s.ssh_successes} sub="successful" tone="green" />
        <Kpi label="Events parsed" value={s.events_parsed} sub={bySource || "—"} tone="blue" />
        <Kpi label="ATT&CK techniques" value={techniques.size} sub={`${Object.keys(s.by_tactic).length} tactics`} tone="cyan" />
      </div>

      <div className="chart-row">
        <div className="panel chart-panel wide">
          <div className="chart-head"><span className="panel-title">Alert activity over time</span>
            <span className="chip">by severity</span></div>
          <ActivityTimeline report={report} />
        </div>
        <div className="panel chart-panel">
          <div className="chart-head"><span className="panel-title">Severity</span></div>
          <SeverityDonut report={report} />
        </div>
      </div>

      <div className="chart-row">
        <div className="panel chart-panel">
          <div className="chart-head"><span className="panel-title">ATT&CK tactics</span></div>
          <TacticsBar report={report} />
        </div>
        <div className="panel chart-panel wide">
          <div className="chart-head"><span className="panel-title">Most active sources</span>
            <span className="chip">events</span></div>
          <TopSources report={report} onIp={onIp} />
        </div>
      </div>
    </div>
  );
}
