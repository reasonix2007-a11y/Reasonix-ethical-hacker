import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { analyzeUploadedArtifact, completeArtifactToolReport } from './scan-server.mjs';

function zipFiles(files) {
  const localParts = [], centralParts = [];
  let localOffset = 0;
  for (const [name, source] of files) {
    const fileName = Buffer.from(name), data = Buffer.from(source), compressed = deflateRawSync(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(fileName.length, 26);
    localParts.push(local, fileName, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(fileName.length, 28);
    central.writeUInt32LE(localOffset, 42);
    centralParts.push(central, fileName);
    localOffset += local.length + fileName.length + compressed.length;
  }

  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localParts, centralDirectory, end]);
}

const secret = 'ReasonixFixtureCredential_2026_NotReal';
const source = [
  'const userInput = process.argv[2];',
  'eval(userInput);',
  'const tlsOptions = { rejectUnauthorized: false };',
  `const password = "${secret}";`,
].join('\n');

const page = '<!doctype html>\n<script>\neval(location.hash);\n</script>\n';
const analysis = await analyzeUploadedArtifact(zipFiles([
  ['src/client.mjs', source],
  ['src/page.html', page],
  ['package.json', '{"name":"repo-fixture","version":"1.0.0"}']
]), 'src.zip');
const report = await completeArtifactToolReport('src.zip', analysis.tools);
const semgrep = report.find(tool => tool.id === 'semgrep');

if (process.platform === 'win32') {
  assert.equal(semgrep?.status, 'disabled', 'Semgrep is disabled on Windows to avoid orphaned child processes');
  assert.match(semgrep.output, /عمليات فرعية/);
} else {
  assert.equal(semgrep?.status, 'ok', `Semgrep should execute with the bundled local rules: ${semgrep?.output || semgrep?.error || 'no result'}`);
  assert.match(semgrep.output, /locally/);
}
assert.ok(analysis.findings.some(finding => finding.k.includes('dynamic-eval')), 'Semgrep findings are normalized into scan findings');
assert.ok(analysis.findings.some(finding => finding.k.includes('dynamic-eval') && finding.file === 'src/page.html' && finding.line === 3),
  `inline HTML JavaScript preserves its real path and line: ${JSON.stringify(analysis.findings.map(({ k, file, line }) => ({ k, file, line })))}`);
assert.ok(analysis.findings.some(finding => finding.k.includes('disabled-tls')), 'TLS findings preserve source locations');
assert.ok(analysis.findings.every(finding => !JSON.stringify(finding).includes(secret)), 'reported findings redact the fixture credential');
assert.equal(report.find(tool => tool.id === 'gitleaks')?.status, 'ok', 'Gitleaks executes when installed');
assert.ok(report.find(tool => tool.id === 'gitleaks')?.output?.includes('redacted'));
for (const id of ['bandit', 'trivy', 'checkov', 'npm-audit']) {
  assert.equal(report.find(tool => tool.id === id)?.status, 'not-applicable',
    `${id} explains that the fixture lacks its required input files; ${JSON.stringify(analysis.tools.map(({ id: toolId, status, output }) => ({ id: toolId, status, output })))}`);
}
assert.ok(report.every(tool => tool.status && (tool.output || ['ok','timeout'].includes(tool.status))), 'repository tool statuses explain failures and skips');

console.log('local repository scanners return findings, locations, and redacted secret evidence');
