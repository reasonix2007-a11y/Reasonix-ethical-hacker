import { readFile } from 'node:fs/promises';
import { scan, runWithScanOptions } from './scan-server.mjs';
import { compareFindingKeys } from './scan-integrations.mjs';

const [target, truthPath] = process.argv.slice(2);
if (!target || !truthPath) {
  console.error('Usage: node benchmark.mjs http://127.0.0.1:3000 expected-findings.json');
  process.exit(2);
}

let parsedTarget;
try { parsedTarget = new URL(target); }
catch { throw new Error('Benchmark target must be an absolute local HTTP(S) URL.'); }
if (!['http:', 'https:'].includes(parsedTarget.protocol) ||
    !['localhost', '127.0.0.1', '[::1]'].includes(parsedTarget.hostname)) {
  throw new Error('Benchmark scans are restricted to localhost loopback targets.');
}

const parsedTruth = JSON.parse(await readFile(truthPath, 'utf8'));
const expectedList = Array.isArray(parsedTruth) ? parsedTruth : parsedTruth.expected;
if (!Array.isArray(expectedList) || expectedList.some(value => typeof value !== 'string' || !value.trim())) {
  throw new Error('Ground truth must be a JSON array of stable finding keys, or { "expected": [...] }.');
}

const options = {
  cookie: process.env.REASONIX_BENCHMARK_COOKIE || '',
  authorization: process.env.REASONIX_BENCHMARK_AUTHORIZATION || '',
  proxy: '',
};
const result = await runWithScanOptions(options, () => scan(target, undefined, 'deep'));
const metrics = compareFindingKeys(expectedList, result.findings.map(finding => finding.k).filter(Boolean));

console.log(JSON.stringify({
  target: parsedTarget.origin,
  profile: result.profile,
  elapsedMs: result.elapsed,
  unit: 'distinct finding keys (k), not individual instances or universal vulnerability coverage',
  counts: {
    ...metrics.counts,
  },
  truePositives: metrics.truePositives,
  falsePositives: metrics.falsePositives,
  falseNegatives: metrics.falseNegatives,
  limitations: 'Ground truth must be manually mapped to stable scanner finding keys. A missing key is only a false negative if the test environment confirms the corresponding vulnerability is present and reachable.',
}, null, 2));
