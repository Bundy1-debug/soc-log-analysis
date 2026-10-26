import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from "recharts";
import { ChartTip } from "./ChartTip.jsx";

const TACTIC_COLOR = {
  "Reconnaissance": "var(--blue)",
  "Initial Access": "var(--red)",
  "Execution": "var(--magenta)",
  "Persistence": "var(--orange)",
  "Privilege Escalation": "var(--yellow)",
  "Credential Access": "var(--purple)",
  "Defense Evasion": "var(--cyan)",
  "Command and Control": "var(--green)",
  "Exfiltration": "#f87171",
  "Anomaly": "var(--text-3)",
};

export function TacticsBar({ report }) {
  const data = Object.entries(report.summary.by_tactic)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  if (!data.length) return <div className="chart-empty">No alerts</div>;

  return (
    <ResponsiveContainer width="100%" height={Math.max(180, data.length * 30)}>
      <BarChart data={data} layout="vertical" margin={{ left: 0, right: 16, top: 4, bottom: 4 }}>
        <XAxis type="number" hide />
        <YAxis type="category" dataKey="name" width={132} tickLine={false} axisLine={false}
               tick={{ fill: "var(--text-2)", fontSize: 10.5 }} />
        <Tooltip cursor={{ fill: "rgba(255,255,255,0.03)" }} content={<ChartTip suffix="alerts" />} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={14}>
          {data.map((d) => <Cell key={d.name} fill={TACTIC_COLOR[d.name] || "var(--cyan)"} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
