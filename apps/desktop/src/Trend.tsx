export type TrendPoint = { month: string; malicious: number; vulnerable: number; suspicious: number };
type Key = "malicious" | "vulnerable" | "suspicious";

// Dash pattern + end label per line, so the series never rely on colour alone.
const SERIES: { key: Key; label: string; color: string; dash?: string }[] = [
  { key: "malicious", label: "Danger", color: "var(--malicious)" },
  { key: "vulnerable", label: "Warning", color: "var(--warning)", dash: "6 3" },
  { key: "suspicious", label: "Caution", color: "var(--ink-2)", dash: "2 3" },
];
const W = 600, H = 220, PAD = 8;

/** Cumulative entries per month as lines. The last value of each line is printed in the legend. */
export function Trend({ points }: { points: TrendPoint[] }) {
  if (points.length < 2) return <p className="hint">Not enough dated entries yet to draw a trend.</p>;
  const max = Math.max(1, ...points.flatMap((p) => SERIES.map((s) => p[s.key])));
  const x = (i: number) => PAD + (i * (W - 2 * PAD)) / (points.length - 1);
  const y = (v: number) => H - PAD - (v * (H - 2 * PAD)) / max;
  const last = points[points.length - 1];
  return (
    <figure className="trend">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Cumulative entries by verdict, ${points[0].month} to ${last.month}`}>
        <line x1={PAD} x2={W - PAD} y1={H - PAD} y2={H - PAD} stroke="var(--rule-strong)" />
        {SERIES.map((s) => (
          <polyline
            key={s.key}
            fill="none"
            stroke={s.color}
            strokeWidth="2.5"
            strokeDasharray={s.dash}
            points={points.map((p, i) => `${x(i)},${y(p[s.key])}`).join(" ")}
          />
        ))}
      </svg>
      <figcaption>
        <span className="mono">{points[0].month}</span>
        <ul>
          {SERIES.map((s) => (
            <li key={s.key}>
              <svg viewBox="0 0 24 6" aria-hidden="true"><line x1="0" x2="24" y1="3" y2="3" stroke={s.color} strokeWidth="2.5" strokeDasharray={s.dash} /></svg>
              {s.label} <strong>{last[s.key]}</strong>
            </li>
          ))}
        </ul>
        <span className="mono">{last.month}</span>
      </figcaption>
    </figure>
  );
}
