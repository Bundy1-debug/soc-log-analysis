import { useMemo } from "react";
import { ATTACK_MATRIX } from "../lib/attack.js";
import { SEVERITIES, SEV_COLOR } from "../lib/format.js";

export function AttackMatrix({ report }) {
  // technique_id -> { count, severity (worst) }
  const hits = useMemo(() => {
    const m = {};
    for (const a of report.alerts) {
      const id = a.mitre.technique_id;
      if (id === "N/A") continue;
      const e = m[id] || { count: 0, severity: "LOW" };
      e.count += 1;
      if (SEVERITIES.indexOf(a.severity) < SEVERITIES.indexOf(e.severity)) e.severity = a.severity;
      m[id] = e;
    }
    return m;
  }, [report]);

  const detected = Object.keys(hits).length;
  const total = ATTACK_MATRIX.reduce((n, c) => n + c.techniques.length, 0);

  return (
    <div className="view fade-up">
      <div className="panel matrix-panel">
        <div className="chart-head">
          <span className="panel-title">MITRE ATT&CK coverage</span>
          <span className="chip accent">{detected} / {total} techniques observed</span>
        </div>

        <div className="matrix-scroll">
          <div className="matrix">
            {ATTACK_MATRIX.map((col) => (
              <div key={col.id} className="matrix-col">
                <div className="matrix-col-head">
                  <div className="matrix-tactic">{col.tactic}</div>
                  <div className="matrix-tid mono">{col.id}</div>
                </div>
                {col.techniques.map((t) => {
                  const hit = hits[t.id];
                  return (
                    <div key={t.id}
                         className={`matrix-cell ${hit ? "hit" : ""}`}
                         style={hit ? { "--c": SEV_COLOR[hit.severity] } : undefined}>
                      <div className="cell-tid mono">{t.id}</div>
                      <div className="cell-name">{t.name}</div>
                      {hit && <span className="cell-count mono">{hit.count}</span>}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </div>

        <div className="matrix-legend">
          <span className="muted">Observed in this analysis:</span>
          {SEVERITIES.map((s) => (
            <span key={s} className="legend-item">
              <span className="sev-dot" style={{ background: SEV_COLOR[s] }} /> {s}
            </span>
          ))}
          <span className="legend-item"><span className="sev-dot matrix-dim" /> not observed</span>
        </div>
      </div>
    </div>
  );
}
