/** Display UTC to the minute while preserving the original timestamp for inspection. */
export function Timestamp({value}: {value: string}) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return <span title={value}>Unknown time</span>;
  return <time dateTime={value} title={value}>{date.toISOString().slice(0, 16).replace("T", " ")} UTC</time>;
}
