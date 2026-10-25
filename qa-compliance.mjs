import assert from 'node:assert/strict';
import { createDecipheriv, createHmac } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

process.env.NODE_ENV = 'development';
process.env.REASONIX_TENANT_ID = 'qa-tenant';
process.env.REASONIX_DATA_KEY = 'ab'.repeat(32);

const { remediationGuideFor, tenantScopeFor, trustedScanIdentity } =
  await import(`./scan-server.mjs?qa=${Date.now()}`);
const auditPath = await mkdtemp(path.join(os.tmpdir(), 'reasonix-audit-'));
process.env.REASONIX_AUDIT_LOG_PATH = path.join(auditPath, 'audit.log');
const { auditLog } = await import(`./scan-server.mjs?audit=${Date.now()}`);
function decryptRecord(record) {
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(process.env.REASONIX_DATA_KEY, 'hex'),
    Buffer.from(record.iv, 'base64'));
  decipher.setAAD(Buffer.from('reasonix-audit-log-v1'));
  decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
  return JSON.parse(Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, 'base64')), decipher.final(),
  ]).toString('utf8'));
}

assert.equal(tenantScopeFor('http://127.0.0.1:9000').localDevelopment, true);

const issuedAt = String(Date.now());
const tenantId = 'qa-tenant';
const user = 'tester@example.com';
const ip = '127.0.0.1';
const signature = createHmac('sha256', Buffer.from(process.env.REASONIX_DATA_KEY, 'hex'))
  .update([issuedAt, tenantId, user, ip].join('\n')).digest('hex');
const request = { headers: {
  'x-reasonix-issued-at': issuedAt,
  'x-reasonix-tenant': tenantId,
  'x-reasonix-user': user,
  'x-reasonix-ip': ip,
  'x-reasonix-signature': signature,
} };
assert.deepEqual(trustedScanIdentity(request), { tenantId, user, ip });
assert.equal(trustedScanIdentity({ headers: { ...request.headers, 'x-reasonix-user': 'forged@example.com' } }), null);
assert.equal(remediationGuideFor({ k: 'XSS_REFlected' }).source, 'illustrative');
assert.equal(remediationGuideFor({ k: 'MISSING_SECURITY_HEADERS' }).source, 'illustrative');

try {
  await auditLog({ action: 'qa-one', owner: user });
  await auditLog({ action: 'qa-two', owner: user });
  const records = (await readFile(process.env.REASONIX_AUDIT_LOG_PATH, 'utf8')).trim().split(/\r?\n/u);
  assert.equal(records.length, 2);
  for (const [index, line] of records.entries()) {
    const encrypted = JSON.parse(line);
    assert.equal(encrypted.algorithm, 'aes-256-gcm');
    assert.doesNotMatch(line, /qa-one|qa-two|tester@example\.com/u);
    const entry = decryptRecord(encrypted);
    const { integrityHash, ...content } = entry;
    assert.equal(entry.sequence, index + 1);
    assert.equal(entry.previousHash, index ? decryptRecord(JSON.parse(records[index - 1])).integrityHash : 'GENESIS');
    assert.equal(integrityHash, createHmac('sha256', Buffer.from(process.env.REASONIX_DATA_KEY, 'hex'))
      .update(JSON.stringify(content)).digest('hex'));
  }
  const tampered = JSON.parse(records[0]);
  tampered.ciphertext = `${tampered.ciphertext[0] === 'A' ? 'B' : 'A'}${tampered.ciphertext.slice(1)}`;
  await writeFile(process.env.REASONIX_AUDIT_LOG_PATH, [JSON.stringify(tampered), ...records.slice(1)].join('\n') + '\n');
  const { auditLog: tamperedAuditLog } = await import(`./scan-server.mjs?tampered-audit=${Date.now()}`);
  const originalConsoleError = console.error;
  console.error = () => {};
  try {
    await assert.rejects(tamperedAuditLog({ action: 'qa-after-tamper', owner: user }));
  } finally {
    console.error = originalConsoleError;
  }
} finally {
  await rm(auditPath, { recursive: true, force: true });
}

const [html, server, serve, docs] = await Promise.all([
  readFile(new URL('./index.html', import.meta.url), 'utf8'),
  readFile(new URL('./scan-server.mjs', import.meta.url), 'utf8'),
  readFile(new URL('./serve.mjs', import.meta.url), 'utf8'),
  readFile(new URL('./SECURITY-OPERATIONS.md', import.meta.url), 'utf8'),
]);
assert.match(html, /id="scan-consent-modal"/u);
assert.match(html, /consentToken:sessionConsent/u);
assert.doesNotMatch(html, /fetch\(SCAN_SERVER\+'\/verify\/(?:start|check)/u,
  'scanning UI must not require a DNS or file ownership challenge');
assert.match(server, /scan-refused-no-consent/u);
assert.match(server, /target-outside-tenant-scope/u);
assert.doesNotMatch(server, /isVerified\(|scan-refused-unverified/u,
  'the configured allowlist replaces the DNS/file verification gate');
assert.match(server, /authenticated-session-required/u);
assert.match(server, /integrity verification failed/u);
assert.match(serve, /x-reasonix-signature/u);
assert.match(serve, /const anonymousQuickScan = req\.method === 'POST' && pathname === '\/quick-scan'/u);
assert.match(serve, /if \(!session && !anonymousQuickScan\)/u,
  'only the quick-scan POST may pass the session gate anonymously');
assert.match(serve, /'\/file-scan', '\/quick-scan'/u);
assert.match(serve, /anonymous-\$\{identityIp\}/u);
assert.match(serve, /pathname === '\/quick-scan' \? 5/u,
  'anonymous quick scans retain a per-IP request limit');
assert.match(serve, /command: String\(tool\.command \|\| ''\)/u,
  'quick-scan responses include the bounded tool command');
assert.match(serve, /output: String\(tool\.output \|\| ''\)/u,
  'quick-scan responses include the bounded tool output');
assert.match(serve, /evidence: Array\.isArray\(finding\?\.evidence\)/u,
  'quick-scan responses include bounded finding evidence');
assert.match(serve, /real: finding\?\.real === true/u,
  'quick-scan responses preserve finding verification state');
const quickUiStart = html.indexOf('async function runQuickScan()');
const quickUiEnd = html.indexOf("$('#btn-quick-scan')?.addEventListener", quickUiStart);
assert.ok(quickUiStart >= 0 && quickUiEnd > quickUiStart, 'quick-scan UI handler is present');
assert.match(html.slice(quickUiStart, quickUiEnd), /tool\.command/u,
  'the quick-scan UI shows tool commands');
assert.match(html.slice(quickUiStart, quickUiEnd), /tool\.output/u,
  'the quick-scan UI shows tool output');
assert.match(html.slice(quickUiStart, quickUiEnd), /f\.evidence/u,
  'the quick-scan UI shows finding evidence');
assert.doesNotMatch(serve, /verify\/(?:start|check)/u,
  'the browser proxy must not expose removed verification endpoints');
assert.match(docs, /immutable\/WORM/u);
assert.match(docs, /does not require a DNS TXT record/u);
assert.match(docs, /cannot reliably prevent/u);
console.log('Tenant allowlist, login, consent, no DNS ownership challenge, audit-chain policy, and report privacy checks passed');
