// Pure helpers, kept free of the vscode module so `node --test` can run them.
const os = require('os');

const SIGNALS = {
  critical: { word: 'DANGER', shape: '●', level: 'error' },
  high: { word: 'DANGER', shape: '●', level: 'error' },
  medium: { word: 'WARNING', shape: '◆', level: 'warning' },
  low: { word: 'CAUTION', shape: '▲', level: 'info' },
};
const RANK = { critical: 0, high: 1, medium: 2, low: 3 };
const signalFor = (severity) => SIGNALS[severity] || SIGNALS.low;

// Release archive name for this machine, or null if there is no build for it.
function targetFor(platform = process.platform, arch = process.arch) {
  const t = {
    'darwin-arm64': 'aarch64-apple-darwin',
    'darwin-x64': 'x86_64-apple-darwin',
    'linux-x64': 'x86_64-unknown-linux-gnu',
    'linux-arm64': 'aarch64-unknown-linux-gnu',
    'win32-x64': 'x86_64-pc-windows-msvc',
  }[`${platform}-${arch}`];
  return t || null;
}

const DOWNLOAD = (target, base = 'https://github.com/aryan2621/antidote/releases/latest/download') => ({
  archive: `${base}/antidote-${target}.tar.gz`,
  sha: `${base}/antidote-${target}.tar.gz.sha256`,
});

// Group CLI findings by file: [{ path, items: [{ line, severity, message, id }] }]. Findings without a file are dropped.
function groupFindings(findings) {
  const by = new Map();
  for (const f of findings) {
    if (!f.path || !/^([a-zA-Z]:)?[\\/]/.test(f.path)) continue;
    const s = signalFor(f.severity);
    const message = `${s.shape} ${s.word}  ${f.summary}${f.fix ? `\nFix: ${f.fix}` : ''}`;
    if (!by.has(f.path)) by.set(f.path, []);
    by.get(f.path).push({ line: Math.max((f.line || 1) - 1, 0), severity: f.severity, message, id: f.id });
  }
  return [...by].map(([path, items]) => ({ path, items }));
}

// Worst signal among findings, or null.
function worst(findings) {
  let best = null;
  for (const f of findings) if (best === null || (RANK[f.severity] ?? 9) < (RANK[best] ?? 9)) best = f.severity;
  return best && { severity: best, ...signalFor(best) };
}

const entryUrl = (id) => (/^AGT-\d{4}-\d{4}$/.test(id || '') ? `https://aryan2621.github.io/antidote/entry/${id}/` : null);
const binName = () => (os.platform() === 'win32' ? 'antidote.exe' : 'antidote');

module.exports = { signalFor, targetFor, DOWNLOAD, groupFindings, worst, entryUrl, binName };
