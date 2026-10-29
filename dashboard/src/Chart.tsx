import { useEffect, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import type { Statistics } from "./api";

export function Chart({rows, field, label}: {rows: Statistics["daily"]; field: "usd" | "tokens"; label: string}) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!host.current || !rows.length) return;
    const styles = getComputedStyle(host.current);
    const ink = styles.getPropertyValue("--chart").trim() || "#2f7a63";
    const fill = styles.getPropertyValue("--chart-fill").trim() || "rgba(47,122,99,.09)";
    const axis = styles.getPropertyValue("--muted").trim() || "#64736f";
    const grid = styles.getPropertyValue("--line").trim() || "#dfe6e0";
    const values = rows.map(row => field === "usd" ? Number(row.usd) : row.input + row.output);
    const times = rows.map(row => Date.parse(row.date + "T00:00:00Z") / 1000);
    const first = Math.min(...times), last = Math.max(...times);
    const padding = Math.max((last - first) * 0.05, 86400);
    const plot = new uPlot({ width: host.current.clientWidth || 640, height: 190,
      series: [{}, {label, stroke: ink, width: 2, fill}],
      axes: [{stroke: axis, grid: {stroke: grid}, ticks: {stroke: grid}}, {stroke: axis, size: 58, grid: {stroke: grid}, ticks: {stroke: grid}}],
      scales: {x: {time: true, range: () => [first - padding, last + padding]}}, cursor: {show: false}, legend: {show: false},
    }, [times, values], host.current);
    const observer = new ResizeObserver(() => plot.setSize({width: host.current!.clientWidth || 640, height: 190}));
    observer.observe(host.current);
    return () => { observer.disconnect(); plot.destroy(); };
  }, [rows, field, label]);
  if (!rows.length) return <p className="empty">No recorded usage yet.</p>;
  return <><div ref={host} role="img" aria-label={label} className="chart" />
    <details><summary>View {label.toLowerCase()} as a table</summary><table><thead><tr><th>Date (UTC)</th><th className="num">{label}</th></tr></thead>
      <tbody>{rows.map(row => <tr key={row.date}><td>{row.date}</td><td className="num">{field === "usd" ? `$${row.usd}` : row.input + row.output}</td></tr>)}</tbody></table></details></>;
}
