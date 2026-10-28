import { useEffect, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import type { Statistics } from "./api";

export function Chart({rows, field, label}: {rows: Statistics["daily"]; field: "usd" | "tokens"; label: string}) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!host.current || !rows.length) return;
    const values = rows.map(row => field === "usd" ? Number(row.usd) : row.input + row.output);
    const plot = new uPlot({ width: host.current.clientWidth || 640, height: 190,
      series: [{}, {label, stroke: "#287261", width: 2, fill: "rgba(40,114,97,.08)"}],
      axes: [{stroke: "#64736f"}, {stroke: "#64736f", size: 58}],
      scales: {x: {time: true, range: (_plot, min, max) => {const padding = Math.max((max - min) * 0.05, 43200); return [min - padding, max + padding];}}}, cursor: {show: false}, legend: {show: false},
    }, [rows.map(row => Date.parse(row.date + "T00:00:00Z") / 1000), values], host.current);
    const observer = new ResizeObserver(() => plot.setSize({width: host.current!.clientWidth || 640, height: 190}));
    observer.observe(host.current);
    return () => { observer.disconnect(); plot.destroy(); };
  }, [rows, field, label]);
  if (!rows.length) return <p className="empty">No recorded usage yet.</p>;
  return <><div ref={host} role="img" aria-label={label} className="chart" />
    <details><summary>View {label.toLowerCase()} as a table</summary><table><thead><tr><th>Date (UTC)</th><th>{label}</th></tr></thead>
      <tbody>{rows.map(row => <tr key={row.date}><td>{row.date}</td><td>{field === "usd" ? `$${row.usd}` : row.input + row.output}</td></tr>)}</tbody></table></details></>;
}
