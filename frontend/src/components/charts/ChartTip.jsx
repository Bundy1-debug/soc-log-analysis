export function ChartTip({ active, payload, label, suffix = "" }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tip">
      {label != null && <div className="chart-tip-label mono">{label}</div>}
      {payload.map((p, i) => (
        <div key={i} className="chart-tip-row">
          <span className="sev-dot" style={{ background: p.color || p.fill || p.payload?.fill }} />
          <span className="mono">{p.name}</span>
          <span className="mono chart-tip-val">{p.value} {suffix}</span>
        </div>
      ))}
    </div>
  );
}
