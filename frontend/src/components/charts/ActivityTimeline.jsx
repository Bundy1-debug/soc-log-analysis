import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, CartesianGrid } from "recharts";
import { SEVERITIES, SEV_COLOR } from "../../lib/format.js";
import { ChartTip } from "./ChartTip.jsx";

const parse = (ts) => new Date(ts.replace(" ", "T")).getTime();

export function ActivityTimeline({ report }) {
  const alerts = report.alerts.filter((a) => a.first_seen);
  if (!alerts.length) return <div className="chart-empty">No alerts</div>;

  const times = alerts.map((a) => parse(a.first_seen));
  const min = Math.min(...times), max = Math.max(...times);
  const N = 16;
  const span = Math.max(max - min, 1);
  const step = span / N;

  const buckets = Array.from({ length: N }, (_, i) => {
    const start = min + i * step;
    const row = { t: start, label: fmt(start, span) };
    SEVERITIES.forEach((s) => (row[s] = 0));
    return row;
  });

  alerts.forEach((a) => {
    const i = Math.min(N - 1, Math.floor((parse(a.first_seen) - min) / step));
    buckets[i][a.severity] += 1;
  });

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={buckets} margin={{ left: -18, right: 8, top: 8, bottom: 0 }} barCategoryGap={2}>
        <CartesianGrid strokeDasharray="2 4" stroke="var(--border)" vertical={false} />
        <XAxis dataKey="label" tick={{ fill: "var(--text-3)", fontSize: 9 }} tickLine={false}
               axisLine={{ stroke: "var(--border)" }} interval={Math.floor(N / 6)} />
        <YAxis tick={{ fill: "var(--text-3)", fontSize: 9 }} tickLine={false} axisLine={false} allowDecimals={false} />
        <Tooltip cursor={{ fill: "rgba(255,255,255,0.03)" }} content={<ChartTip />} />
        {SEVERITIES.slice().reverse().map((s) => (
          <Bar key={s} dataKey={s} stackId="a" fill={SEV_COLOR[s]} radius={s === "CRITICAL" ? [2, 2, 0, 0] : 0} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

function fmt(t, span) {
  const d = new Date(t);
  const p = (n) => String(n).padStart(2, "0");
  // show date when the whole window spans more than a day, else time
  return span > 864e5
    ? `${p(d.getMonth() + 1)}/${p(d.getDate())}`
    : `${p(d.getHours())}:${p(d.getMinutes())}`;
}
