import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';

async function startDemo(enabled) {
  const child = spawn(process.execPath, ['vulnerable-site.mjs'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      REASONIX_VULNERABLE_DEMO_PORT: '0',
      REASONIX_ENABLE_VULNERABLE_DEMO: enabled ? 'true' : 'false',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  const ready = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Demo server did not start.')), 5000);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      output += chunk;
      const match = output.match(/http:\/\/127\.0\.0\.1:(\d+)/u);
      if (match) {
        clearTimeout(timeout);
        resolve(Number(match[1]));
      }
    });
    child.once('error', reject);
    child.once('exit', code => reject(new Error(`Demo server exited (${code}): ${output}`)));
  });
  return { child, port: await ready };
}

function get(port, route) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: route }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body }));
    }).on('error', reject);
  });
}

for (const [enabled, expectedStatus] of [[false, 404], [true, 200]]) {
  const { child, port } = await startDemo(enabled);
  try {
    const root = await get(port, '/');
    assert.equal(root.status, 200);
    const exposed = await get(port, '/.env');
    assert.equal(exposed.status, expectedStatus);
    if (enabled) {
      assert.match(exposed.body, /DEMO_ONLY_NOT_A_SECRET/u);
      assert.doesNotMatch(exposed.body, /SuperSecret|sk_live|hunter2/u);
      assert.equal((await get(port, '/admin/')).status, 200);
    } else {
      assert.equal((await get(port, '/admin/')).status, 404);
    }
  } finally {
    child.kill();
  }
}

console.log('demo secrets and admin routes remain hidden unless local training mode is explicitly enabled');
