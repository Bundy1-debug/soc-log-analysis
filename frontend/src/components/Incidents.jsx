import { useState } from "react";
import { KillChain } from "./KillChain.jsx";
import { IconChevron } from "../lib/icons.jsx";
import { shortTime } from "../lib/format.js";

export function Incidents({ report, onIp }) {
  const byId = Object.fromEntries(report.alerts.map((a) => [a.id, a]));
  if (!report.incidents.length)
    return <div className="view"><div className="chart-empty tall">No incidents above threshold ✓</div></div>;

  return (
    <div className="view fade-up incidents">
      {report.incidents.map((inc) => (
        <IncidentCard key={inc.id} inc={inc} alerts={inc.alert_ids.map((id) => byId[id])} onIp={onIp} />
      ))}
    </div>
  );
}

function IncidentCard({ inc, alerts, onIp }) {
  const [open, setOpen] = useState(inc.breach);
  const alertByIp = Object.fromEntries(alerts.map((a) => [a.ip, a]));

  return (
    <div className={`inc panel sev-border-${inc.severity} ${open ? "open" : ""}`}>
      <button className="inc-head" onClick={() => setOpen((o) => !o)}>
        <IconChevron svg={{ width: 15, height: 15, className: "inc-chev" }} />
        <span className="inc-id mono">{inc.id}</span>
        <button className="ip-link mono" onClick={(e) => { e.stopPropagation(); onIp(alertByIp[inc.ip] || alerts[0]); }}>
          {inc.ip}
        </button>
        <span className={`sev-badge sev-${inc.severity}`}>{inc.severity}</span>
        {inc.breach && <span className="breach-tag">⚠ BREACH</span>}
        <span className="inc-window mono">{shortTime(inc.first_seen)} → {shortTime(inc.last_seen)}</span>
        <span className="inc-count mono">{alerts.length} alerts</span>
      </button>

      <div className="inc-chainband">
        <KillChain alerts={alerts} />
      </div>

      {open && (
        <div className="inc-body">
          <div className="inc-col">
            <div className="panel-title inc-subhead">Timeline · {inc.timeline.length} events</div>
            <ul className="timeline">
              {inc.timeline.map((ev, i) => (
                <li key={i} className={`tl ${ev.source}`}>
                  <span className="tl-ts mono">{shortTime(ev.ts)}</span>
                  <span className="tl-alert">{ev.alert}</span>
                  <span className="tl-text mono">{ev.text}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="inc-col">
            <div className="panel-title inc-subhead">Recommended response</div>
            <ol className="response">
              {inc.response.map((step, i) => <li key={i}>{step}</li>)}
            </ol>
            <div className="panel-title inc-subhead">ATT&CK techniques</div>
            <div className="tech-list">
              {alerts.map((a) => (
                <a key={a.id} className="tech-pill mono" href={a.mitre.url} target="_blank" rel="noreferrer"
                   title={`${a.mitre.tactic} · ${a.mitre.technique}`}>
                  {a.mitre.technique_id === "N/A" ? "ANOMALY" : a.mitre.technique_id}
                </a>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
