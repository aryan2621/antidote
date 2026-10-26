import techniqueMap from '../../../corpus/techniques.json';
import popularNpm from '../../../corpus/popular/npm.txt?raw';
import popularPypi from '../../../corpus/popular/pypi.txt?raw';
// Corpus is read at build time; the site is fully static.
const mods = import.meta.glob('../../../corpus/entries/*.json', { eager: true, import: 'default' });

export type Entry = Record<string, any> & { id: string; summary: string };

export const entries: Entry[] = (Object.values(mods) as Entry[]).sort((a, b) => a.id.localeCompare(b.id));

export const isIncident = (e: Entry) => e.kind === 'incident';

// OSV `withdrawn`: kept for history, never matched by the scanner
export const classification = (e: Entry): string =>
  e.withdrawn ? 'withdrawn' : isIncident(e) ? 'incident' : e.database_specific?.classification ?? 'suspicious';

export const pkgKey = (eco: string, name: string) => `${eco}/${name}`;

/** "ecosystem/name" → entries affecting it */
export const packages = new Map<string, { ecosystem: string; name: string; entries: Entry[] }>();
for (const e of entries) {
  for (const a of e.affected ?? []) {
    const k = pkgKey(a.package.ecosystem, a.package.name);
    if (!packages.has(k)) packages.set(k, { ecosystem: a.package.ecosystem, name: a.package.name, entries: [] });
    packages.get(k)!.entries.push(e);
  }
}

// shortcut: placeholder repo until the GitHub org exists; also used by submit and install pages
export const REPO = 'antidote-db/antidote';

export const artifactType = (e: Entry): string => (isIncident(e) ? 'incident' : e.database_specific?.artifact_type ?? 'package');

/** Plain-words label for a verification state. */
export const verificationText: Record<string, string> = {
  verified: 'Verified',
  reported: 'Reported, not yet independently verified',
  disputed: 'Disputed by the publisher',
};

const popular: Record<string, string[]> = {
  npm: popularNpm.split('\n').map((l: string) => l.trim()).filter(Boolean),
  pypi: popularPypi.split('\n').map((l: string) => l.trim()).filter(Boolean),
};

function levenshtein(a: string, b: string): number {
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length];
}

/** The popular package a name imitates, by the scanner's own rule (crates/core/src/mcp.rs `typosquat_of`). */
export function lookalikeOf(eco: string, name: string): string | null {
  const list = popular[eco.toLowerCase()] ?? [];
  if (name.length < 5 || list.includes(name)) return null;
  const max = name.length < 10 ? 1 : 2;
  return list.find((p) => levenshtein(name, p) <= max) ?? null;
}

/** Link inside the site, respecting the GitHub Pages base path. */
export const href = (p: string) => import.meta.env.BASE_URL.replace(/\/$/, '') + p;

export const entryHref = (id: string) => href(`/entry/${id}/`);
export const packageHref = (eco: string, name: string) => href(`/package/${eco}/${name}/`);

/** Human-readable affected versions from `versions` and OSV `ranges`. */
export function versionText(a: any): string {
  const parts: string[] = [...(a.versions ?? [])];
  for (const r of a.ranges ?? []) {
    let lo: string | undefined;
    for (const ev of r.events ?? []) {
      if (ev.introduced !== undefined) lo = ev.introduced;
      else if (ev.fixed !== undefined) parts.push(`${lo && lo !== '0' ? `>= ${lo}, ` : ''}< ${ev.fixed} (fixed in ${ev.fixed})`);
      else if (ev.last_affected !== undefined) parts.push(`${lo && lo !== '0' ? `>= ${lo}, ` : ''}<= ${ev.last_affected}`);
    }
    if (lo !== undefined && !(r.events ?? []).some((ev: any) => ev.fixed || ev.last_affected)) {
      parts.push(lo === '0' ? 'all versions' : `>= ${lo}, no fix`);
    }
  }
  return parts.length ? parts.join('; ') : 'all versions';
}

// antidote-api base URL (PUBLIC_API_URL at build time); badges are shown only once an API is deployed.
const api = (import.meta.env.PUBLIC_API_URL ?? '').replace(/\/$/, '');
/** README badge Markdown for an npm/PyPI package, or null when there's no API or the ecosystem has no checks. */
export function badgeMarkdown(eco: string, name: string): string | null {
  if (!api || !['npm', 'pypi'].includes(eco.toLowerCase())) return null;
  return `[![antidote](${api}/badge/${eco.toLowerCase()}/${name}.svg)](${new URL(packageHref(eco, name), import.meta.env.SITE).href})`;
}

const OWASP: Record<string, string> = {
  ASI01: 'Agent Goal Hijack', ASI02: 'Tool Misuse and Exploitation', ASI03: 'Identity and Privilege Abuse',
  ASI04: 'Agentic Supply Chain Vulnerabilities', ASI05: 'Unexpected Code Execution', ASI06: 'Memory and Context Poisoning',
  ASI07: 'Insecure Inter-Agent Communication', ASI08: 'Cascading Failures', ASI09: 'Human-Agent Trust Exploitation', ASI10: 'Rogue Agents',
};
/** OWASP Agentic Top 10 and MITRE ATLAS links for an entry's technique tags, deduplicated. */
export function frameworkRefs(techniques: string[] = []): { id: string; title: string; url: string }[] {
  const refs = new Map<string, { id: string; title: string; url: string }>();
  for (const t of techniques) {
    const m = (techniqueMap as Record<string, any>)[t] ?? {};
    for (const id of m.owasp ?? []) refs.set(id, { id, title: `OWASP Agentic ${id}: ${OWASP[id]}`, url: 'https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/' });
    for (const id of m.atlas ?? []) refs.set(id, { id, title: `MITRE ATLAS ${id}`, url: `https://atlas.mitre.org/techniques/${id}` });
  }
  return [...refs.values()];
}
