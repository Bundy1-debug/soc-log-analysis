import { useCallback, useEffect, useMemo, useState } from "react";
import { analyzeFiles, analyzeSample } from "./lib/api.js";
import { Sidebar } from "./components/Sidebar.jsx";
import { Topbar } from "./components/Topbar.jsx";
import { UploadPanel } from "./components/UploadPanel.jsx";
import { Overview } from "./components/Overview.jsx";
import { Incidents } from "./components/Incidents.jsx";
import { AlertsTable } from "./components/AlertsTable.jsx";
import { AttackMap } from "./components/AttackMap.jsx";
import { AttackMatrix } from "./components/AttackMatrix.jsx";
import { RawJson } from "./components/RawJson.jsx";
import { GeoModal } from "./components/GeoModal.jsx";

export default function App() {
  const [view, setView] = useState("upload");
  const [status, setStatus] = useState("idle"); // idle | loading | ready | error
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [geoIp, setGeoIp] = useState(null); // alert object for the modal

  const run = useCallback(async (promise) => {
    setStatus("loading");
    setError("");
    try {
      const data = await promise;
      setReport(data);
      setStatus("ready");
      setView("overview");
    } catch (e) {
      setError(e.message);
      setStatus("error");
    }
  }, []);

  const onFiles = useCallback((files) => run(analyzeFiles(files)), [run]);
  const onSample = useCallback(() => run(analyzeSample()), [run]);

  const counts = useMemo(() => {
    if (!report) return {};
    return {
      incidents: report.summary.incidents,
      alerts: report.summary.alerts,
      breaches: report.summary.breaches,
    };
  }, [report]);

  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && setGeoIp(null);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="app">
      <Sidebar view={view} setView={setView} counts={counts} hasReport={!!report} />
      <div className="app-main">
        <Topbar report={report} status={status} />
        <main className="app-content">
          {view === "upload" && (
            <UploadPanel onFiles={onFiles} onSample={onSample} status={status} error={error} />
          )}

          {status === "loading" && view !== "upload" && <LoadingState />}

          {report && status !== "loading" && (
            <>
              {view === "overview" && <Overview report={report} onIp={setGeoIp} />}
              {view === "incidents" && <Incidents report={report} onIp={setGeoIp} />}
              {view === "alerts" && <AlertsTable report={report} onIp={setGeoIp} />}
              {view === "map" && <AttackMap report={report} onIp={setGeoIp} />}
              {view === "matrix" && <AttackMatrix report={report} />}
              {view === "raw" && <RawJson report={report} />}
            </>
          )}

          {!report && view !== "upload" && status !== "loading" && (
            <EmptyState onGo={() => setView("upload")} />
          )}
        </main>
      </div>

      {geoIp && <GeoModal alert={geoIp} onClose={() => setGeoIp(null)} />}
    </div>
  );
}

function LoadingState() {
  return (
    <div className="loading-state">
      <div className="spinner" />
      <div className="mono">PARSING → DETECTING → CORRELATING…</div>
    </div>
  );
}

function EmptyState({ onGo }) {
  return (
    <div className="empty-screen">
      <div className="empty-icon">⬡</div>
      <p>No analysis loaded yet.</p>
      <button className="btn btn-primary" onClick={onGo}>Go to upload</button>
    </div>
  );
}
