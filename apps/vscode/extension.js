const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { execFile } = require('child_process');
const lib = require('./lib');

let diagnostics, statusBar, output, running = false, timer;

const cfg = () => vscode.workspace.getConfiguration('antidote');

function get(url, redirects = 5) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'user-agent': 'antidote-vscode' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
        res.resume();
        return resolve(get(res.headers.location, redirects - 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`${url}: HTTP ${res.statusCode}`)); }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject);
  });
}

const run = (bin, args, cwd) => new Promise((resolve, reject) => {
  execFile(bin, args, { cwd, maxBuffer: 64 * 1024 * 1024, timeout: 5 * 60 * 1000 }, (err, stdout, stderr) => {
    // exit code 1 means "findings at or above --fail-on"; we always pass --fail-on never, so any error is real
    if (err && err.code !== 0) return reject(new Error(stderr || err.message));
    resolve(stdout);
  });
});

// The binary: user setting, then PATH, then a checked download into extension storage.
async function ensureCli(context) {
  const set = cfg().get('path');
  if (set) return set;
  try { await run('antidote', ['--version']); return 'antidote'; } catch { /* not on PATH */ }
  const dir = context.globalStorageUri.fsPath;
  const bin = path.join(dir, lib.binName());
  if (fs.existsSync(bin)) return bin;
  const target = lib.targetFor();
  if (!target) throw new Error(`No Antidote build for ${process.platform}-${process.arch}. Set "antidote.path".`);
  return vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Downloading the Antidote scanner…' }, async () => {
    const { archive, sha } = lib.DOWNLOAD(target);
    const [tgz, want] = await Promise.all([get(archive), get(sha)]);
    const got = crypto.createHash('sha256').update(tgz).digest('hex');
    if (got !== want.toString().trim().split(/\s+/)[0]) throw new Error('Downloaded scanner failed its checksum; not installed.');
    fs.mkdirSync(dir, { recursive: true });
    const tmp = path.join(dir, 'antidote.tar.gz');
    fs.writeFileSync(tmp, tgz);
    await run('tar', ['xzf', tmp, '-C', dir]);
    fs.rmSync(tmp, { force: true });
    fs.chmodSync(bin, 0o755);
    return bin;
  });
}

async function scan(context, { setup = false } = {}) {
  if (running) return;
  const folders = (vscode.workspace.workspaceFolders || []).map((f) => f.uri.fsPath);
  if (!setup && !folders.length) { vscode.window.showInformationMessage('Open a folder to scan, or run "Antidote: Scan my agent setup".'); return; }
  running = true;
  statusBar.text = '$(sync~spin) Antidote scanning…';
  try {
    const bin = await ensureCli(context);
    const args = ['scan', '--format', 'json', '--fail-on', 'never', ...(cfg().get('noClassifier') ? ['--no-classifier'] : []), ...(setup ? [] : folders)];
    const findings = JSON.parse((await run(bin, args, folders[0])) || '[]');
    publish(findings);
  } catch (e) {
    output.appendLine(String(e.message || e));
    statusBar.text = '$(shield) Antidote: scan failed';
    statusBar.tooltip = 'Click for details';
    statusBar.command = 'antidote.showLog';
    vscode.window.showWarningMessage(`Antidote could not scan: ${String(e.message || e).split('\n')[0]}`);
  } finally {
    running = false;
  }
}

function publish(findings) {
  diagnostics.clear();
  for (const g of lib.groupFindings(findings)) {
    const list = g.items.map((i) => {
      const d = new vscode.Diagnostic(new vscode.Range(i.line, 0, i.line, 1000), i.message, { error: 0, warning: 1, info: 2 }[lib.signalFor(i.severity).level]);
      d.source = 'Antidote';
      const url = lib.entryUrl(i.id);
      d.code = url ? { value: i.id, target: vscode.Uri.parse(url) } : i.id;
      return d;
    });
    diagnostics.set(vscode.Uri.file(g.path), list);
  }
  const w = lib.worst(findings);
  statusBar.command = 'antidote.scanWorkspace';
  if (!w) {
    statusBar.text = '$(shield) Antidote: nothing found';
    statusBar.tooltip = 'Nothing in the database matched. That is not a guarantee of safety. Click to re-scan.';
  } else {
    statusBar.text = `$(shield) ${w.shape} ${w.word} · ${findings.length}`;
    statusBar.tooltip = `${findings.length} finding(s). Worst: ${w.word}. Click to re-scan.`;
  }
}

const WATCHED = /(^|[\\/])(\.mcp\.json|mcp\.json|mcp_config\.json|settings\.json|SKILL\.md|CLAUDE\.md|AGENTS\.md|[^\\/]+\.mdc)$|[\\/]\.(claude|cursor)[\\/]/;

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection('antidote');
  output = vscode.window.createOutputChannel('Antidote');
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  statusBar.text = '$(shield) Antidote';
  statusBar.command = 'antidote.scanWorkspace';
  statusBar.show();
  context.subscriptions.push(
    diagnostics, output, statusBar,
    vscode.commands.registerCommand('antidote.scanWorkspace', () => scan(context)),
    vscode.commands.registerCommand('antidote.scanSetup', () => scan(context, { setup: true })),
    vscode.commands.registerCommand('antidote.showLog', () => output.show()),
    vscode.commands.registerCommand('antidote.update', async () => {
      try { vscode.window.showInformationMessage((await run(await ensureCli(context), ['update'])).trim()); }
      catch (e) { vscode.window.showWarningMessage(`Antidote update failed: ${String(e.message).split('\n')[0]}`); }
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (!cfg().get('scanOnSave') || !WATCHED.test(doc.uri.fsPath)) return;
      clearTimeout(timer);
      timer = setTimeout(() => scan(context), 1500);
    }),
  );
  scan(context);
}

module.exports = { activate, deactivate() {} };
