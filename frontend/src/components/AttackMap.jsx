import { useMemo } from "react";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";
import worldData from "../lib/world-110m.json";
import { SEVERITIES, SEV_COLOR, flagEmoji } from "../lib/format.js";

const sevRank = (s) => SEVERITIES.indexOf(s);

export function AttackMap({ report, onIp }) {
  // Group flagged alerts by IP, keep the worst severity + any geo
  const points = useMemo(() => {
    const byIp = new Map();
    for (const a of report.alerts) {
      const cur = byIp.get(a.ip);
      if (!cur || sevRank(a.severity) < sevRank(cur.severity)) {
        byIp.set(a.ip, { ip: a.ip, severity: a.severity, geo: a.geo || {}, role: a.ip_role, alert: a });
      }
    }
    return [...byIp.values()];
  }, [report]);

  const located = points.filter((p) => p.geo && p.geo.lat != null && p.geo.lon != null);

  const byCountry = useMemo(() => {
    const m = new Map();
    for (const p of located) {
      const key = p.geo.country || "Unknown";
      const e = m.get(key) || { country: key, cc: p.geo.countryCode, count: 0 };
      e.count += 1; m.set(key, e);
    }
    return [...m.values()].sort((a, b) => b.count - a.count);
  }, [located]);

  return (
    <div className="view fade-up map-view">
      <div className="panel map-panel">
        <div className="chart-head">
          <span className="panel-title">Attacker geolocation</span>
          <span className="chip">{located.length} located · {points.length} flagged IPs</span>
        </div>

        <div className="map-canvas">
          <ComposableMap projectionConfig={{ scale: 150 }} width={900} height={440} style={{ width: "100%", height: "auto" }}>
            <Geographies geography={worldData}>
              {({ geographies }) =>
                geographies.map((geo) => (
                  <Geography key={geo.rsmKey} geography={geo}
                    fill="#0e1420" stroke="#1d2838" strokeWidth={0.5}
                    style={{ default: { outline: "none" }, hover: { fill: "#131c2b", outline: "none" }, pressed: { outline: "none" } }} />
                ))
              }
            </Geographies>
            {located.map((p) => (
              <Marker key={p.ip} coordinates={[p.geo.lon, p.geo.lat]} onClick={() => onIp(p.alert)}
                      style={{ default: { cursor: "pointer" } }}>
                <circle r={9} fill={SEV_COLOR[p.severity]} opacity={0.18} />
                <circle r={4} fill={SEV_COLOR[p.severity]} stroke="#06080d" strokeWidth={1}>
                  <animate attributeName="r" values="4;7;4" dur="2.4s" repeatCount="indefinite" />
                </circle>
              </Marker>
            ))}
          </ComposableMap>

          {located.length === 0 && (
            <div className="map-hint">
              No public geolocation to plot.<br />
              <span className="muted">Sample logs use private / reserved IPs. Upload real logs and run with geolocation enabled to populate the map.</span>
            </div>
          )}
        </div>
      </div>

      <div className="panel map-side">
        <div className="chart-head"><span className="panel-title">By country</span></div>
        {byCountry.length ? (
          <ul className="country-list">
            {byCountry.map((c) => (
              <li key={c.country}>
                <span className="cc-flag">{flagEmoji(c.cc)}</span>
                <span className="cc-name">{c.country}</span>
                <span className="cc-count mono">{c.count}</span>
              </li>
            ))}
          </ul>
        ) : <div className="chart-empty">—</div>}

        <div className="chart-head" style={{ marginTop: "1rem" }}><span className="panel-title">Flagged sources</span></div>
        <ul className="src-list">
          {points.map((p) => (
            <li key={p.ip} onClick={() => onIp(p.alert)}>
              <span className={`sev-dot`} style={{ background: SEV_COLOR[p.severity] }} />
              <span className="mono src-ip">{p.ip}</span>
              <span className="muted src-role">{p.geo.private ? "private" : (p.geo.country || p.role)}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
