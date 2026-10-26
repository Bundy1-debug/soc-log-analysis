import { IconShield, IconUpload, IconGrid, IconFlag, IconList, IconMap, IconMatrix, IconCode } from "../lib/icons.jsx";

const NAV = [
  { id: "upload", label: "Upload", Icon: IconUpload, group: "Ingest" },
  { id: "overview", label: "Overview", Icon: IconGrid, group: "Analyze" },
  { id: "incidents", label: "Incidents", Icon: IconFlag, group: "Analyze", badge: "incidents", badgeKind: "red" },
  { id: "alerts", label: "Alerts", Icon: IconList, group: "Analyze", badge: "alerts" },
  { id: "map", label: "Attack Map", Icon: IconMap, group: "Threat Intel" },
  { id: "matrix", label: "ATT&CK Matrix", Icon: IconMatrix, group: "Threat Intel" },
  { id: "raw", label: "Raw JSON", Icon: IconCode, group: "Export" },
];

export function Sidebar({ view, setView, counts, hasReport }) {
  let lastGroup = null;
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-mark"><IconShield svg={{ width: 20, height: 20 }} /></div>
        <div>
          <div className="brand-name">SOC<span>ANALYZER</span></div>
          <div className="brand-sub mono">threat detection console</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {NAV.map((item) => {
          const header = item.group !== lastGroup ? (lastGroup = item.group) : null;
          const disabled = item.id !== "upload" && !hasReport;
          const badge = item.badge && counts[item.badge];
          return (
            <div key={item.id}>
              {header && <div className="nav-group">{header}</div>}
              <button
                className={`nav-item ${view === item.id ? "active" : ""}`}
                disabled={disabled}
                onClick={() => setView(item.id)}
              >
                <item.Icon svg={{ width: 17, height: 17 }} />
                <span>{item.label}</span>
                {badge ? (
                  <span className={`nav-badge ${item.badgeKind || ""}`}>{badge}</span>
                ) : null}
              </button>
            </div>
          );
        })}
      </nav>

      <div className="sidebar-foot">
        <div className="status-line">
          <span className="live-dot" /> ENGINE ONLINE
        </div>
        <div className="mono foot-ver">v3.2 · MITRE ATT&amp;CK</div>
      </div>
    </aside>
  );
}
