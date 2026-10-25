import assert from 'node:assert/strict';
import {
  isAllowedScanTarget,
  normalizeAllowedTargets,
  requiresActiveConfirmation,
} from './scan-server.mjs';

assert.deepEqual(
  normalizeAllowedTargets(['example.com', 'APP.example.com', '203.0.113.10', 'example.com']),
  ['example.com', 'app.example.com', '203.0.113.10'],
);
assert.throws(() => normalizeAllowedTargets(['https://example.com']), /Invalid allowed target/u);
assert.throws(() => normalizeAllowedTargets(['*.example.com']), /Invalid allowed target/u);
assert.throws(() => normalizeAllowedTargets('example.com'), /allowedTargets array/u);
assert.equal(isAllowedScanTarget('app.example.com', ['example.com']), true);
assert.equal(isAllowedScanTarget('notexample.com', ['example.com']), false);
const exactTarget = normalizeAllowedTargets([{ hostname: 'Example.com.', includeSubdomains: false }]);
assert.deepEqual(exactTarget, [{ hostname: 'example.com', includeSubdomains: false }]);
assert.equal(isAllowedScanTarget('example.com', exactTarget), true);
assert.equal(isAllowedScanTarget('app.example.com', exactTarget), false);
assert.throws(() => normalizeAllowedTargets([{ hostname: 'example.com' }]), /includeSubdomains boolean/u);
assert.equal(isAllowedScanTarget('203.0.113.10', ['203.0.113.10']), true);
assert.equal(isAllowedScanTarget('203.0.113.11', ['203.0.113.10']), false);
assert.equal(requiresActiveConfirmation('quick'), false);
assert.equal(requiresActiveConfirmation('full'), true);
assert.equal(requiresActiveConfirmation('deep'), true);
assert.equal(requiresActiveConfirmation('unknown'), true, 'unknown profiles normalize to full and require confirmation');

console.log('scan scope validation and active-profile confirmation checks passed');
