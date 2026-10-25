import assert from 'node:assert/strict';
import { analyzeUploadedArtifact, completeArtifactToolReport } from './scan-server.mjs';

const source = [
  '<manifest xmlns:android="http://schemas.android.com/apk/res/android">',
  '  <application android:allowBackup="true" android:debuggable="true">',
  '  </application>',
  '</manifest>',
].join('\n');

const result = await analyzeUploadedArtifact(Buffer.from(source), 'AndroidManifest.xml');
const toolReport = await completeArtifactToolReport('AndroidManifest.xml', result.tools);
const backup = result.findings.find(finding => finding.k === 'android-backup');
const debuggable = result.findings.find(finding => finding.k === 'android-debuggable');

assert.ok(backup, 'detects the actual allowBackup source setting');
assert.ok(backup.sourceCode.includes('android:allowBackup="true"'));
assert.ok(backup.fixedCode.includes('android:allowBackup="false"'));
assert.equal(backup.file, 'AndroidManifest.xml');
assert.equal(backup.line, 2);
assert.ok(debuggable, 'detects the actual debuggable source setting');
assert.ok(debuggable.sourceCode.includes('android:debuggable="true"'));
assert.ok(debuggable.fixedCode.includes('android:debuggable="false"'));

const secretValue = 'rnx_test_8f4c2a9d7e6b1c0a3f5d';
const sourceScan = await analyzeUploadedArtifact(Buffer.from([
  `const apiKey = "${secretValue}";`,
  'const password = "your-api-key-example";',
].join('\n')), 'config.js');
const secretFinding = sourceScan.findings.find(finding => ['embedded-secret', 'gitleaks'].includes(finding.k) && finding.line === 1);
assert.ok(secretFinding, 'detects a long hard-coded credential in source code');
assert.equal(secretFinding.line, 1);
assert.ok(!JSON.stringify(secretFinding).includes(secretValue), 'does not expose the secret in finding output');
assert.ok(!sourceScan.findings.some(finding => ['embedded-secret', 'gitleaks'].includes(finding.k) && finding.line === 2),
  'does not report common placeholder/example values as secrets');

assert.ok(toolReport.length >= 40, 'reports every catalogued tool for the file scan');
assert.equal(new Set(toolReport.map(tool => tool.id)).size, toolReport.length, 'tool report contains no duplicate IDs');
assert.ok(toolReport.every(tool => tool.status && (tool.output || tool.status === 'ok' || tool.status === 'error' || tool.status === 'timeout')));
assert.equal(toolReport.find(tool => tool.id === 'sqlmap')?.status, 'not-applicable');
assert.match(toolReport.find(tool => tool.id === 'sqlmap')?.output || '', /سبب عدم الفحص/);
assert.ok(toolReport.filter(tool => tool.status !== 'ok').every(tool => /سبب (?:عدم الفحص|تعذر|توقف)/u.test(tool.output || '')),
  'every skipped or unsuccessful tool explains why it did not complete');
const failedToolReport = await completeArtifactToolReport('sample.apk', [
  { id: 'jadx', name: 'jadx', category: 'artifact', status: 'error', error: 'Java runtime unavailable' },
]);
assert.match(failedToolReport.find(tool => tool.id === 'jadx')?.output || '', /سبب تعذر الأداة: Java runtime unavailable؛ استمر باقي الفحص/u);

console.log('artifact source snippets, deterministic fixes, and tool explanations passed');
