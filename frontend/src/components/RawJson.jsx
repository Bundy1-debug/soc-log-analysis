import { useMemo, useState } from "react";

export function RawJson({ report }) {
  const text = useMemo(() => JSON.stringify(report, null, 2), [report]);
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url; a.download = "soc_report.json"; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="view fade-up">
      <div className="panel json-panel">
        <div className="json-head">
          <span className="panel-title">Raw JSON report</span>
          <div className="json-actions">
            <button className="btn" onClick={copy}>{copied ? "Copied ✓" : "Copy"}</button>
            <button className="btn" onClick={download}>Download</button>
          </div>
        </div>
        <pre className="json-out mono" dangerouslySetInnerHTML={{ __html: highlight(text) }} />
      </div>
    </div>
  );
}

// JSON syntax highlight (safe: we escape first, then wrap already-escaped tokens).
function highlight(json) {
  const esc = json.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return esc.replace(
    /("(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
    (m) => {
      let cls = "jn";
      if (/^"/.test(m)) cls = /:$/.test(m) ? "jk" : "js";
      else if (/true|false/.test(m)) cls = "jb";
      else if (/null/.test(m)) cls = "jnull";
      return `<span class="${cls}">${m}</span>`;
    }
  );
}
