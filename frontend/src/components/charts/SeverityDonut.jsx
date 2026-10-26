import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { SEVERITIES, SEV_COLOR } from "../../lib/format.js";
import { ChartTip } from "./ChartTip.jsx";

export function SeverityDonut({ report }) {
  const bs = report.summary.by_severity;
  const data = SEVERITIES.filter((s) => bs[s] > 0).map((s) => ({ name: s, value: bs[s] }));
  const total = data.reduce((a, d) => a + d.value, 0);

  if (!total) return <div className="chart-empty">No alerts</div>;

  return (
    <div className="donut-wrap">
      <ResponsiveContainer width="100%" height={180}>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius={52} outerRadius={78}
               paddingAngle={2} stroke="none">
            {data.map((d) => <Cell key={d.name} fill={SEV_COLOR[d.name]} />)}
          </Pie>
          <Tooltip content={<ChartTip suffix="alerts" />} />
        </PieChart>
      </ResponsiveContainer>
      <div className="donut-center">
        <div className="donut-total mono">{total}</div>
        <div className="muted">alerts</div>
      </div>
      <div className="donut-legend">
        {data.map((d) => (
          <div key={d.name} className="legend-item">
            <span className="sev-dot" style={{ background: SEV_COLOR[d.name] }} />
            <span className="mono">{d.name}</span>
            <span className="legend-val mono">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
