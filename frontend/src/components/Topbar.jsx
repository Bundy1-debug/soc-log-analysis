import { useEffect, useState } from "react";
import { SEVERITIES } from "../lib/format.js";

export function Topbar({ report, status }) {
  const [clock, setClock] = useState("--:--:--");
  useEffect(() => {
    const t = setInterval(() => setClock(new Date().toLocaleTimeString("en-GB")), 1000);
    return () => clearInterval(t);
  }, []);

  const worst = report && SEVERITIES.find((s) => report.summary.by_severity[s] > 0);

  return (
    <header className="topbar">
      <div className="topbar-title">
        <span>Threat Detection Dashboard</span>
        <span className="mono topbar-crumbs">SSH · HTTP · DNS · HOST · ANOMALY</span>
      </div>
      <div className="topbar-right">
        {worst && (
          <div className={`threat-pill sev-${worst}`}>
            <span className="sev-dot" style={{ background: "currentColor" }} />
            THREAT LEVEL: {worst}
          </div>
        )}
        {status === "ready" && report && (
          <div className="topbar-stat mono">
            {report.summary.events_parsed} EVENTS
          </div>
        )}
        <div className="clock mono">{clock}</div>
      </div>
    </header>
  );
}
