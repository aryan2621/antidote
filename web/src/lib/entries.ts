// Corpus is read at build time; the site is fully static.
const mods = import.meta.glob('../../../corpus/entries/*.json', { eager: true, import: 'default' });

export type Entry = Record<string, any> & { id: string; summary: string };

export const entries: Entry[] = (Object.values(mods) as Entry[]).sort((a, b) => a.id.localeCompare(b.id));

export const isIncident = (e: Entry) => e.kind === 'incident';

export const classification = (e: Entry): string =>
  isIncident(e) ? 'incident' : e.database_specific?.classification ?? 'suspicious';

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
