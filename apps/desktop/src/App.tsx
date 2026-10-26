import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { Logo } from "./Logo";
import { Mark, severityMark } from "./Mark";

type Finding = {
  severity: "critical" | "high" | "medium" | "low";
  id: string;
  summary: string;
  path: string;
  line: number | null;
  context: string | null;
  evidence: string | null;
  fix?: string;
};
type Info = { version: number; entries: number };

const DB_URL = "https://antidote-db.github.io/antidote/";

export default function App() {
  const [info, setInfo] = useState<Info | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [scanned, setScanned] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [pkg, setPkg] = useState("");

  useEffect(() => void invoke<Info>("info").then(setInfo), []);

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
      setFindings(await invoke<Finding[]>("scan", { trees, configs }));
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
      setFindings(await invoke<Finding[]>("check", { package: pkg }));
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
                {info.version ? <>corpus <strong>{info.version}</strong></> : "built-in corpus"}
              </span>
            )}
            <button type="button" className="btn btn-cover" disabled={!!busy} onClick={update}>
              Update feed
            </button>
          </div>
        </div>
      </header>

      <main className="main">
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
          </p>
        )}
        {error && (
          <p role="alert" className="status status-error">
            {error}
          </p>
        )}
        {note && (
          <p role="status" className="status">
            {note}
          </p>
        )}

        {findings && !busy && (
          <section aria-labelledby="results-heading">
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
              <p className="status-ok" role="status">
                No known threats found in what was scanned. That is not a guarantee of safety — only that nothing in the
                corpus matched.
              </p>
            ) : (
              <>
                <h2 id="results-heading" className="sc-label results-heading">
                  {findings.length} finding{findings.length === 1 ? "" : "s"}
                </h2>
                <ul className="plates">
                  {findings.map((f, i) => (
                    <li key={`${f.id}-${i}`} className={`plate sev-${f.severity}`}>
                      <div className="plate-head">
                        <Mark kind={severityMark(f.severity)} label={f.severity} />
                        <span className="plate-id">{f.id}</span>
                      </div>
                      <p className="plate-summary">{f.summary}</p>
                      <p className="plate-path">
                        {f.path}
                        {f.line ? `:${f.line}` : ""}
                        {f.context ? ` (${f.context})` : ""}
                      </p>
                      {f.evidence && <pre className="plate-evidence">{f.evidence}</pre>}
                      {f.fix && (
                        <p className="plate-fix">
                          <strong>Fix:</strong> {f.fix}
                        </p>
                      )}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </section>
        )}
      </main>

      <footer className="foot">
        Browse the open database at{" "}
        <a href={DB_URL} target="_blank" rel="noreferrer">
          antidote-db.github.io/antidote
        </a>
        . Data CC-BY-4.0 · code Apache-2.0.
      </footer>
    </div>
  );
}
