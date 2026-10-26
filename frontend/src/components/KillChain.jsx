import { SEV_COLOR, isBreachAlert } from "../lib/format.js";

// Horizontal MITRE kill-chain: one node per alert in the incident, in time order.
export function KillChain({ alerts }) {
  return (
    <div className="killchain">
      {alerts.map((a, i) => {
        const color = SEV_COLOR[a.severity];
        const breach = isBreachAlert(a);
        return (
          <div className="kc-node-wrap" key={a.id}>
            {i > 0 && <div className="kc-arrow"><span /></div>}
            <div className={`kc-node ${breach ? "breach" : ""}`} style={{ "--kc": color }}>
              <div className="kc-tactic mono">{a.mitre.tactic}</div>
              <div className="kc-title">{a.title}</div>
              <div className="kc-meta">
                <span className="mono kc-tech">{a.mitre.technique_id}</span>
                <span className="mono kc-time">{(a.first_seen || "").slice(11, 16)}</span>
              </div>
              {breach && <div className="kc-breach mono">BREACH</div>}
            </div>
          </div>
        );
      })}
    </div>
  );
}
