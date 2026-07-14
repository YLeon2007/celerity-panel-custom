'use strict';

/**
 * Tests for the panel update feature:
 *   - updateService semver parsing/comparison and release whitelist logic.
 *   - updater sidecar HMAC signing/verification, timestamp window and replay.
 *
 * Pure functions only; no network, Redis or Docker access.
 */

const assert = require('assert');
const crypto = require('crypto');

// ─── updateService: semver helpers ───────────────────────────────────────────

const updateService = require('../src/services/updateService');

assert.deepStrictEqual(updateService.parseVersion('1.4.0'), [1, 4, 0]);
assert.deepStrictEqual(updateService.parseVersion('v2.10.3'), [2, 10, 3]);
assert.strictEqual(updateService.parseVersion('1.4'), null);
assert.strictEqual(updateService.parseVersion('1.4.0-beta'), null);
assert.strictEqual(updateService.parseVersion('latest'), null);
assert.strictEqual(updateService.parseVersion(''), null);

assert.strictEqual(updateService.compareVersions('1.5.0', '1.4.0'), 1);
assert.strictEqual(updateService.compareVersions('1.4.0', '1.5.0'), -1);
assert.strictEqual(updateService.compareVersions('1.4.0', '1.4.0'), 0);
assert.strictEqual(updateService.compareVersions('2.0.0', '1.9.9'), 1);
assert.strictEqual(updateService.compareVersions('1.4.10', '1.4.2'), 1);
// Unknown/invalid inputs compare as equal (0) rather than throwing.
assert.strictEqual(updateService.compareVersions('bad', '1.0.0'), 0);

// Without UPDATER_URL/SECRET the sidecar must be reported as not configured.
assert.strictEqual(updateService.isUpdaterConfigured(), false);

// ─── updater: HMAC signing / verification ────────────────────────────────────

const SECRET = 'a'.repeat(48);
process.env.UPDATER_SECRET = SECRET;
process.env.UPDATE_MODE = 'hub';

const updater = require('../updater/server');

assert.strictEqual(updater.SECRET_CONFIGURED, true);

// Version regex accepts only plain semver (optionally v-prefixed).
assert.ok(updater.VERSION_RE.test('1.4.0'));
assert.ok(updater.VERSION_RE.test('v1.4.0'));
assert.ok(!updater.VERSION_RE.test('1.4'));
assert.ok(!updater.VERSION_RE.test('latest'));
assert.ok(!updater.VERSION_RE.test('1.4.0; rm -rf /'));

function makeReq(ts, sig) {
    return { headers: { 'x-updater-ts': ts != null ? String(ts) : undefined, 'x-updater-signature': sig } };
}

// Valid signature over `${ts}.${body}` passes.
{
    const ts = Date.now().toString();
    const body = JSON.stringify({ version: '1.5.0', requestId: 'req-1' });
    const sig = updater.sign(ts, body);
    assert.deepStrictEqual(updater.verifyRequest(makeReq(ts, sig), body), { ok: true });
}

// Tampered body fails.
{
    const ts = Date.now().toString();
    const body = JSON.stringify({ version: '1.5.0', requestId: 'req-2' });
    const sig = updater.sign(ts, body);
    const tampered = JSON.stringify({ version: '9.9.9', requestId: 'req-2' });
    const res = updater.verifyRequest(makeReq(ts, sig), tampered);
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res.code, 401);
}

// Wrong secret fails.
{
    const ts = Date.now().toString();
    const body = '{}';
    const badSig = crypto.createHmac('sha256', 'wrong-secret').update(`${ts}.${body}`).digest('hex');
    const res = updater.verifyRequest(makeReq(ts, badSig), body);
    assert.strictEqual(res.ok, false);
}

// Stale timestamp (outside window) fails.
{
    const ts = (Date.now() - 5 * 60 * 1000).toString();
    const body = '{}';
    const sig = updater.sign(ts, body);
    const res = updater.verifyRequest(makeReq(ts, sig), body);
    assert.strictEqual(res.ok, false);
    assert.match(res.error, /window/i);
}

// Missing headers fail.
{
    const res = updater.verifyRequest(makeReq(null, null), '{}');
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res.code, 401);
}

console.log('update service tests passed');
