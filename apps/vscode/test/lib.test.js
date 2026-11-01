const test = require('node:test');
const assert = require('node:assert');
const { targetFor, groupFindings, worst, entryUrl, DOWNLOAD } = require('../lib');

test('targetFor maps supported machines and rejects others', () => {
  assert.equal(targetFor('darwin', 'arm64'), 'aarch64-apple-darwin');
  assert.equal(targetFor('win32', 'x64'), 'x86_64-pc-windows-msvc');
  assert.equal(targetFor('linux', 'ia32'), null);
});

test('download urls match the release asset names', () => {
  assert.equal(DOWNLOAD('x86_64-unknown-linux-gnu').archive, 'https://github.com/aryan2621/antidote/releases/latest/download/antidote-x86_64-unknown-linux-gnu.tar.gz');
});

test('groupFindings keeps file findings, zero-bases lines and drops package-only ones', () => {
  const g = groupFindings([
    { path: '/w/.mcp.json', line: 4, severity: 'high', id: 'AGT-2026-0209', summary: 'Malicious code', fix: 'Remove it' },
    { path: 'npm:x@1', severity: 'low', id: 'X', summary: 'pkg' },
  ]);
  assert.equal(g.length, 1);
  assert.equal(g[0].items[0].line, 3);
  assert.match(g[0].items[0].message, /DANGER/);
  assert.match(g[0].items[0].message, /Fix: Remove it/);
});

test('worst picks the highest severity', () => {
  assert.equal(worst([{ severity: 'low' }, { severity: 'critical' }]).word, 'DANGER');
  assert.equal(worst([]), null);
});

test('entryUrl only links real entry ids', () => {
  assert.equal(entryUrl('AGT-2026-0209'), 'https://aryan2621.github.io/antidote/entry/AGT-2026-0209/');
  assert.equal(entryUrl('AGT-F-TYPOSQUAT'), null);
});
