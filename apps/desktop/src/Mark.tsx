import type { ReactNode } from "react";

/** Verdict / severity mark: shape + label so severity is not colour-only. */
export type MarkKind = "malicious" | "vulnerable" | "suspicious" | "incident" | "withdrawn";

const shapes: Record<MarkKind, ReactNode> = {
  malicious: <circle cx="6" cy="6" r="5.5" fill="currentColor" />,
  vulnerable: <path d="M6 0.4 11.6 6 6 11.6 0.4 6Z" fill="currentColor" />,
  suspicious: <path d="M6 0.8 11.6 11.2H0.4Z" fill="currentColor" />,
  incident: <rect x="1" y="1" width="10" height="10" fill="currentColor" />,
  withdrawn: (
    <>
      <circle cx="6" cy="6" r="4.9" fill="none" stroke="currentColor" strokeWidth="1.2" />
      <path d="M2.4 9.6 9.6 2.4" stroke="currentColor" strokeWidth="1.2" />
    </>
  ),
};

export function severityMark(severity: "critical" | "high" | "medium" | "low"): MarkKind {
  if (severity === "critical" || severity === "high") return "malicious";
  if (severity === "medium") return "vulnerable";
  return "suspicious";
}

export function Mark({ kind, label }: { kind: MarkKind; label: string }) {
  return (
    <span className={`mark mark-${kind}`}>
      <svg viewBox="0 0 12 12" aria-hidden="true">
        {shapes[kind]}
      </svg>
      {label}
    </span>
  );
}
