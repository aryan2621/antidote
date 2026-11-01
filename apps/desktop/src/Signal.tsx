import type { ReactNode } from "react";

/** Verdict as a signal field: drawn shape + signal word, so severity is never colour alone. */
export type SignalKind = "malicious" | "vulnerable" | "suspicious" | "incident";

const shapes: Record<SignalKind, ReactNode> = {
  malicious: <circle cx="6" cy="6" r="5.5" fill="currentColor" />,
  vulnerable: <path d="M6 0.4 11.6 6 6 11.6 0.4 6Z" fill="currentColor" />,
  suspicious: <path d="M6 0.8 11.6 11.2H0.4Z" fill="currentColor" />,
  incident: <rect x="1" y="1" width="10" height="10" fill="currentColor" />,
};
export const signalWord: Record<SignalKind, string> = { malicious: "Danger", vulnerable: "Warning", suspicious: "Caution", incident: "Notice" };

export type Severity = "critical" | "high" | "medium" | "low";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export function severityKind(severity: Severity): SignalKind {
  if (severity === "critical" || severity === "high") return "malicious";
  if (severity === "medium") return "vulnerable";
  return "suspicious";
}

export function Signal({ kind }: { kind: SignalKind }) {
  return (
    <span className={`signal ${kind}`}>
      <svg viewBox="0 0 12 12" aria-hidden="true">
        {shapes[kind]}
      </svg>
      {signalWord[kind]}
    </span>
  );
}
