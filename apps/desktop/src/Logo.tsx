export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} aria-hidden="true">
      <circle cx="27" cy="33" r="14" fill="currentColor" />
      <path
        d="M27 33 46 17h10"
        fill="none"
        stroke="var(--moss-2)"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="27" cy="33" r="5" fill="var(--moss)" />
    </svg>
  );
}
