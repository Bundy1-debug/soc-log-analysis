import { useEffect, useState } from "react";
import { geoip } from "../lib/api.js";
import { flagEmoji } from "../lib/format.js";
import { IconClose } from "../lib/icons.jsx";

export function GeoModal({ alert, onClose }) {
  const [geo, setGeo] = useState(alert.geo && Object.keys(alert.geo).length ? alert.geo : null);
  const [loading, setLoading] = useState(!geo);

  useEffect(() => {
    if (geo) return;
    let ok = true;
    geoip(alert.ip).then((d) => ok && (setGeo(d), setLoading(false))).catch(() => ok && setLoading(false));
    return () => { ok = false; };
  }, [alert.ip, geo]);

  const rows = [
    ["Role", alert.ip_role],
    ["Threat intel", alert.intel_match ? "On blocklist" : "No match"],
  ];
  if (geo) {
    if (geo.private) rows.push(["Network", "Private / reserved — no public location"]);
    else if (geo.error) rows.push(["Location", geo.error]);
    else rows.push(
      ["Country", `${flagEmoji(geo.countryCode)} ${geo.country || "—"} (${geo.countryCode || "??"})`],
      ["City", geo.city || "—"], ["ISP", geo.isp || "—"], ["ASN", geo.as || "—"],
    );
  }

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal panel">
        <div className="modal-head">
          <span className="panel-title">IP intelligence</span>
          <button className="modal-close" onClick={onClose}><IconClose svg={{ width: 16, height: 16 }} /></button>
        </div>
        <div className="modal-body">
          <div className="modal-ip mono">{alert.ip}</div>
          {loading ? (
            <div className="mono muted" style={{ padding: "1rem 0" }}>Looking up…</div>
          ) : (
            <div className="geo-grid">
              {rows.map(([k, v]) => (
                <div key={k} className="geo-row">
                  <span className="geo-k mono">{k}</span>
                  <span className="geo-v">{v}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
