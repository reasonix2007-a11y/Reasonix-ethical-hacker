import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const script = `
  import assert from 'node:assert/strict';
  import http from 'node:http';
  import { isLocalTarget, normalizeScanProfile, passiveDomainToolSkipReason, profileToolSkipReason, req } from './scan-server.mjs';
  if (!isLocalTarget('127.0.0.1')) process.exit(1);
  assert.match(passiveDomainToolSkipReason('amass', 'http://127.0.0.1:5500'), /عنوان IP/u);
  assert.match(passiveDomainToolSkipReason('amass', 'http://localhost:5500'), /محلي/u);
  assert.equal(passiveDomainToolSkipReason('amass', 'https://example.com'), '');
  assert.equal(passiveDomainToolSkipReason('nmap', 'http://127.0.0.1'), '');
  assert.equal(normalizeScanProfile('quick'), 'quick');
  assert.equal(normalizeScanProfile('unexpected'), 'full');
  assert.match(profileToolSkipReason('nmap', 'https://example.com', 'quick'), /السريع/u);
  assert.equal(profileToolSkipReason('nmap', 'https://example.com', 'full'), '');
  assert.match(profileToolSkipReason('amass', 'http://127.0.0.1', 'full'), /عنوان IP/u);
  const server = http.createServer((request, response) => response.end('x'.repeat(270000)));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    const result = await req('http://127.0.0.1:' + port + '/', {}, 3000);
    assert.equal(result.ok, true, 'large successful HTTP responses remain reachable');
    assert.equal(result.body.length, 200000, 'response capture stays bounded');
    assert.equal(result.bodyTruncated, true, 'truncated response is identified');
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
`;
const dev = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
  cwd: process.cwd(),
  encoding: 'utf8',
  env: { ...process.env, NODE_ENV: 'development', PORT: '5500' },
});
assert.equal(dev.status, 0, `local targets should work in development with PORT set: ${dev.stderr}`);

const production = spawnSync(process.execPath, ['--input-type=module', '-e', `
  import { isLocalTarget } from './scan-server.mjs';
  if (isLocalTarget('127.0.0.1')) process.exit(1);
`], {
  cwd: process.cwd(),
  encoding: 'utf8',
  env: { ...process.env, NODE_ENV: 'production', PORT: '5500' },
});
assert.equal(production.status, 0, `production must continue blocking local targets: ${production.stderr}`);

console.log('local scan mode respects NODE_ENV and preserves production target restrictions');
