import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Logo } from "./Logo";
import { Trend, type TrendPoint } from "./Trend";
import { SEVERITIES, Signal, severityKind, type Severity } from "./Signal";

type Finding = {
  severity: Severity;
  id: string;
  summary: string;
  path: string;
  line: number | null;
  context: string | null;
  evidence: string | null;
  fix?: string;
};
type Info = { version: number; entries: number };

const DB_URL = "https://aryan2621.github.io/antidote/";
const bySeverity = (a: Finding, b: Finding) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity);
const IMPERATIVE: Record<Severity, string> = {
  critical: "Do not install or run this.",
  high: "Do not install or run this.",
  medium: "Review it before you install.",
  low: "Read the notes, then decide.",
};
// "2 critical · 1 high": counts per severity, worst first, so the verdict is readable before the list
const tally = (fs: Finding[]) =>
  SEVERITIES.map((s) => [s, fs.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n)
    .map(([s, n]) => `${n} ${s}`)
    .join(" · ");

export default function App() {
  const [info, setInfo] = useState<Info | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [scanned, setScanned] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [pkg, setPkg] = useState("");
  const [view, setView] = useState<"scan" | "trends">("scan");
  const [trend, setTrend] = useState<TrendPoint[]>([]);
  const pkgRef = useRef<HTMLInputElement>(null);

  useEffect(() => void invoke<Info>("info").then(setInfo), []);
  // re-read after "Update feed" swaps the corpus
  useEffect(() => void invoke<TrendPoint[]>("trend").then(setTrend), [info?.version]);

  // keyboard first: "/" jumps to the package field
  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === "/" && !/^(input|textarea)$/i.test((ev.target as HTMLElement).tagName)) {
        ev.preventDefault();
        pkgRef.current?.focus();
      }
    };
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, []);

  const run = async (label: string, f: () => Promise<void>) => {
    setBusy(label);
    setError("");
    setNote("");
    try {
      await f();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy("");
    }
  };

  const scan = (trees: string[], configs: string[]) =>
    run("Scanning…", async () => {
      setScanned([...trees, ...configs]);
      setFindings((await invoke<Finding[]>("scan", { trees, configs })).sort(bySeverity));
    });

  const scanSetup = () =>
    run("Finding agent configs…", async () => {
      const t = await invoke<{ trees: string[]; configs: string[] }>("targets");
      if (t.trees.length + t.configs.length === 0) {
        setNote("No Claude Code, Cursor, OpenClaw or Claude Desktop configs found on this machine.");
        return;
      }
      await scan(t.trees, t.configs);
    });

  const scanFolder = async () => {
    const dir = await open({ directory: true });
    if (typeof dir === "string") scan([dir], []);
  };

  const check = (e: React.FormEvent) => {
    e.preventDefault();
    run("Checking…", async () => {
      setScanned([pkg.trim()]);
      setFindings((await invoke<Finding[]>("check", { package: pkg })).sort(bySeverity));
    });
  };

  const update = () =>
    run("Updating…", async () => {
      const r = await invoke<Info & { changed: boolean }>("update");
      setInfo(r);
      setNote(r.changed ? `Updated to corpus ${r.version} (${r.entries} entries).` : "Already up to date.");
    });

  return (
    <div className="app">
      <header className="cover">
        <div className="cover-inner">
          <div className="brand" aria-label="Antidote">
            <Logo />
            <span>Antidote</span>
          </div>
          <div className="cover-meta">
            {info && (
              <span>
                <strong>{info.entries}</strong> entries ·{" "}
                {info.version ? <>database v<strong>{info.version}</strong></> : "built-in corpus"}
              </span>
            )}
            <button type="button" className="btn btn-cover" disabled={!!busy} onClick={update}>
              Update feed
            </button>
          </div>
        </div>
      </header>

      <main className="main">
        <div className="view-tabs" role="group" aria-label="View">
          <button type="button" className="btn btn-quiet" aria-pressed={view === "scan"} onClick={() => setView("scan")}>Scan</button>
          <button type="button" className="btn btn-quiet" aria-pressed={view === "trends"} onClick={() => setView("trends")}>Trends</button>
        </div>
        {view === "trends" ? (
          <>
            <h1>Database trend</h1>
            <p className="lede">Confirmed entries in this database, cumulative by month.</p>
            <Trend points={trend} />
          </>
        ) : (
        <>
        <h1>Check before you install</h1>
        <p className="lede">
          Scan your agent setup or a folder, or look up a package coordinate. Everything runs on this machine; nothing is
          uploaded.
        </p>

        <section className="actions" aria-label="Scan actions">
          <button type="button" className="btn btn-primary" disabled={!!busy} onClick={scanSetup}>
            Scan my agent setup
          </button>
          <button type="button" className="btn btn-quiet" disabled={!!busy} onClick={scanFolder}>
            Scan a folder…
          </button>
        </section>

        <form className="check-form" onSubmit={check} aria-label="Check package">
          <label className="sc-label" htmlFor="pkg">
            Package coordinate
          </label>
          <div className="check-row">
              <input
                id="pkg"
                ref={pkgRef}
                required
                placeholder="npm:mcp-remote@0.1.15 or pypi:name==1.0"
                value={pkg}
                onChange={(e) => setPkg(e.target.value)}
              />
            <button type="submit" className="btn btn-quiet" disabled={!!busy}>
              Check package
            </button>
          </div>
        </form>

        {busy && (
          <p role="status" className="status">
            {busy}
            <span className="busy-bar" aria-hidden="true" />
          </p>
        )}
        {error && (
          <p role="alert" className="status status-error">
            <strong>That did not finish.</strong> {error}
          </p>
        )}
        {note && (
          <p role="status" className="status">
            {note}
          </p>
        )}

        {!findings && !busy && !error && !note && (
          <p className="hint">
            "Scan my agent setup" looks for Claude Code, Cursor, OpenClaw and Claude Desktop configs on this machine.
          </p>
        )}

        {findings && !busy && (
          <section aria-label="Results">
            <details className="details">
              <summary>
                Checked {scanned.length} location{scanned.length === 1 ? "" : "s"}
              </summary>
              <ul>
                {scanned.map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ul>
            </details>

            {findings.length === 0 ? (
              <div className="verdict clear" role="status">
                <div className="band">No match</div>
                <p className="detail">
                  No known threats found in what was scanned. That is not a guarantee of safety, only that nothing in the corpus matched.
                </p>
              </div>
            ) : (
              <>
                <div className={`verdict ${severityKind(findings[0].severity)}`}>
                  <div className="band">
                    <Signal kind={severityKind(findings[0].severity)} />
                    <span className="what">{tally(findings)}</span>
                  </div>
                  <p className="imperative">{IMPERATIVE[findings[0].severity]}</p>
                </div>
                <h2 className="sc-label results-heading">
                  {findings.length} finding{findings.length === 1 ? "" : "s"}, worst first
                </h2>
                <ul className="plates">
                  {findings.map((f, i) => (
                    <li key={`${f.id}-${i}`} className={`plate ${severityKind(f.severity)}`}>
                      <div className="tab">
                        <Signal kind={severityKind(f.severity)} />
                        <span className="sev">{f.severity}</span>
                      </div>
                      <div className="plate-body">
                        <p className="plate-summary">{f.summary}</p>
                        <p className="plate-path">
                          <span className="plate-id">{f.id}</span> {f.path}
                          {f.line ? `:${f.line}` : ""}
                          {f.context ? ` (${f.context})` : ""}
                        </p>
                        {f.evidence && <pre className="plate-evidence">{f.evidence}</pre>}
                        {f.fix && (
                          <p className="plate-fix">
                            <strong>Fix:</strong> {f.fix}
                          </p>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </section>
        )}
        </>
        )}
      </main>

      <footer className="foot">
        Browse the open database at{" "}
        <a
          href={DB_URL}
          onClick={(e) => {
            e.preventDefault();
            openUrl(DB_URL);
          }}
        >
          aryan2621.github.io/antidote
        </a>
        . Data CC-BY-4.0 · code Apache-2.0.
      </footer>
    </div>
  );
}
