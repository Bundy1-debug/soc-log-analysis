import { useRef, useState } from "react";
import { IconUpload, IconAlert } from "../lib/icons.jsx";

const SOURCES = [
  { k: "SSH", d: "auth.log — brute force, breach, sudo" },
  { k: "WEB", d: "access.log — scans, exploits, webshell" },
  { k: "DNS", d: "named — tunneling, C2 beaconing" },
  { k: "HOST", d: "auditd — reverse shell, persistence" },
];

export function UploadPanel({ onFiles, onSample, status, error }) {
  const inputRef = useRef(null);
  const [over, setOver] = useState(false);

  return (
    <div className="upload-wrap">
      <div className="upload-hero">
        <div className="hero-tag mono">// LOG INGESTION</div>
        <h1>Drop logs. Get incidents.</h1>
        <p className="hero-sub">
          Parses SSH, web, DNS and auditd logs; detects attacks across the MITRE ATT&amp;CK
          lifecycle; correlates them into incidents with a timeline and response steps.
        </p>
      </div>

      <label
        className={`dropzone ${over ? "over" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setOver(true); }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault(); setOver(false);
          if (e.dataTransfer.files.length) onFiles(e.dataTransfer.files);
        }}
      >
        <input
          ref={inputRef}
          type="file"
          multiple
          hidden
          onChange={(e) => e.target.files.length && onFiles(e.target.files)}
        />
        <div className="dropzone-icon"><IconUpload svg={{ width: 30, height: 30 }} /></div>
        <div className="dropzone-title">Drag &amp; drop log files here</div>
        <div className="muted">several files are correlated together · max 32 MB</div>
        <div className="dropzone-actions">
          <button className="btn btn-primary" type="button" onClick={onSample} disabled={status === "loading"}>
            ▶ Run sample logs
          </button>
          <button className="btn" type="button" onClick={() => inputRef.current?.click()}>
            Browse files
          </button>
        </div>
      </label>

      {error && (
        <div className="error-banner">
          <IconAlert svg={{ width: 16, height: 16 }} /> {error}
        </div>
      )}

      <div className="source-grid">
        {SOURCES.map((s) => (
          <div key={s.k} className="source-card panel">
            <div className="source-k mono">{s.k}</div>
            <div className="muted">{s.d}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
