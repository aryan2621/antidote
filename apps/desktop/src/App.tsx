import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

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

const ui = {
  input: "w-full rounded border border-stone-300 bg-white px-2 py-1 dark:border-stone-700 dark:bg-stone-800",
  button: "whitespace-nowrap rounded border border-stone-300 px-3 py-1 text-sm hover:bg-stone-100 disabled:opacity-50 dark:border-stone-700 dark:hover:bg-stone-800",
  primary: "rounded bg-emerald-800 px-4 py-1.5 text-white disabled:opacity-50",
};
const sevClass: Record<Finding["severity"], string> = {
  critical: "bg-red-700 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-yellow-500 text-stone-900",
  low: "bg-stone-300 text-stone-900 dark:bg-stone-600 dark:text-stone-100",
};

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
    <div className="mx-auto flex h-full max-w-3xl flex-col gap-5 overflow-y-auto p-5">
      <header className="flex items-baseline justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold">Antidote</h1>
          <p className="text-sm text-stone-500">Checks agent skills, MCP servers and prompts against known threats. Runs on this machine; nothing is uploaded.</p>
        </div>
        <div className="shrink-0 text-right text-sm text-stone-500">
          {info && <div>{info.entries} entries · {info.version ? `corpus ${info.version}` : "built-in corpus"}</div>}
          <button className={ui.button} disabled={!!busy} onClick={update}>Update</button>
        </div>
      </header>

      <section className="flex flex-wrap gap-2">
        <button className={ui.primary} disabled={!!busy} onClick={scanSetup}>Scan my agent setup</button>
        <button className={ui.button} disabled={!!busy} onClick={scanFolder}>Scan a folder…</button>
      </section>

      <form onSubmit={check} className="flex gap-2">
        <input aria-label="Package" className={ui.input} required placeholder="npm:mcp-remote@0.1.15 or pypi:name==1.0" value={pkg} onChange={(e) => setPkg(e.target.value)} />
        <button className={ui.button} disabled={!!busy}>Check package</button>
      </form>

      {busy && <p role="status" className="text-sm text-stone-500">{busy}</p>}
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      {note && <p role="status" className="text-sm text-stone-600 dark:text-stone-300">{note}</p>}

      {findings && !busy && (
        <section className="space-y-3">
          <details className="text-xs text-stone-500">
            <summary>Checked {scanned.length} location{scanned.length === 1 ? "" : "s"}</summary>
            <ul className="mt-1 font-mono">{scanned.map((s) => <li key={s} className="break-all">{s}</li>)}</ul>
          </details>
          {findings.length === 0 ? (
            <p className="rounded border border-emerald-700/40 p-3 text-emerald-800 dark:text-emerald-300">No known threats found.</p>
          ) : (
            <>
              <h2 className="font-semibold">{findings.length} finding{findings.length === 1 ? "" : "s"}</h2>
              <ul className="space-y-2">
                {findings.map((f, i) => (
                  <li key={i} className="rounded border border-stone-200 p-3 text-sm dark:border-stone-700">
                    <div className="flex flex-wrap items-baseline gap-2">
                      <span className={`rounded px-1.5 py-0.5 text-xs font-semibold uppercase ${sevClass[f.severity]}`}>{f.severity}</span>
                      <span className="font-mono text-xs text-stone-500">{f.id}</span>
                      <span className="font-medium">{f.summary}</span>
                    </div>
                    <div className="mt-1 break-all font-mono text-xs text-stone-500">
                      {f.path}{f.line ? `:${f.line}` : ""}{f.context ? ` (${f.context})` : ""}
                    </div>
                    {f.evidence && <div className="mt-1 break-all font-mono text-xs">{f.evidence}</div>}
                    {f.fix && <div className="mt-1"><span className="font-semibold">Fix:</span> {f.fix}</div>}
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      )}
    </div>
  );
}
