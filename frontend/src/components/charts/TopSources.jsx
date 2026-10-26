import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from "recharts";
import { ChartTip } from "./ChartTip.jsx";

export function TopSources({ report, onIp }) {
  const data = report.summary.top_ips.map((t) => ({ ...t, name: t.ip }));
  if (!data.length) return <div className="chart-empty">No activity</div>;

  const alertByIp = Object.fromEntries(report.alerts.map((a) => [a.ip, a]));

  return (
    <ResponsiveContainer width="100%" height={Math.max(180, data.length * 26)}>
      <BarChart data={data} layout="vertical" margin={{ left: 0, right: 20, top: 4, bottom: 4 }}>
        <XAxis type="number" hide />
        <YAxis type="category" dataKey="name" width={118} tickLine={false} axisLine={false}
               tick={{ fill: "var(--text-2)", fontSize: 10, fontFamily: "var(--mono)" }} />
        <Tooltip cursor={{ fill: "rgba(255,255,255,0.03)" }} content={<ChartTip suffix="events" />} />
        <Bar dataKey="events" radius={[0, 4, 4, 0]} barSize={13}
             onClick={(d) => alertByIp[d.ip] && onIp(alertByIp[d.ip])} cursor="pointer">
          {data.map((d) => (
            <Cell key={d.ip} fill={d.flagged ? "var(--red)" : "var(--border-2)"} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
