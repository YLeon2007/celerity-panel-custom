const assert = require('assert');

const {
    normalizeClientOs,
    buildClientStats,
    attachClientStatsToUsers,
} = require('../src/utils/userClientStats');

const fixedNow = new Date('2026-07-03T09:30:00.000Z');

assert.strictEqual(normalizeClientOs({ platform: 'iOS' }), 'ios');
assert.strictEqual(normalizeClientOs({ platform: 'iPadOS' }), 'ios');
assert.strictEqual(normalizeClientOs({ platform: 'android 14' }), 'android');
assert.strictEqual(normalizeClientOs({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }), 'windows');
assert.strictEqual(normalizeClientOs({ userAgent: 'Hiddify/2.0 (Linux)' }), 'linux');
assert.strictEqual(normalizeClientOs({ platform: '', userAgent: '' }), 'unknown');

{
    const stats = buildClientStats([
        { platform: 'ios', lastSeenAt: new Date('2026-07-03T09:29:55.000Z') },
        { platform: 'android', lastSeenAt: new Date('2026-07-03T09:29:40.000Z') },
    ], { now: fixedNow, onlineTtlSeconds: 10, lang: 'ru' });

    assert.strictEqual(stats.online, true, 'any fresh device should make user online');
    assert.strictEqual(stats.onlineDeviceCount, 1, 'only devices inside ttl are online');
    assert.strictEqual(stats.deviceCount, 2);
    assert.deepStrictEqual(stats.osList, ['ios', 'android']);
    assert.strictEqual(stats.osSummary, '2 устройства ios+android');
}

{
    const stats = buildClientStats([
        { platform: 'Windows', lastSeenAt: new Date('2026-07-03T09:00:00.000Z') },
    ], { now: fixedNow, onlineTtlSeconds: 10, lang: 'ru' });

    assert.strictEqual(stats.online, false, 'stale device should be offline');
    assert.strictEqual(stats.osSummary, 'windows');
}

{
    const users = [{ userId: 'alice' }, { userId: 'bob' }];
    const result = attachClientStatsToUsers(users, [
        { userId: 'alice', platform: 'ios', lastSeenAt: new Date('2026-07-03T09:29:59.000Z') },
        { userId: 'alice', platform: 'android', lastSeenAt: new Date('2026-07-03T09:28:00.000Z') },
    ], { now: fixedNow, onlineTtlSeconds: 10, lang: 'ru' });

    assert.strictEqual(result[0].clientStats.online, true);
    assert.strictEqual(result[0].clientStats.osSummary, '2 устройства ios+android');
    assert.strictEqual(result[1].clientStats.online, false);
    assert.strictEqual(result[1].clientStats.osSummary, '—');
}

console.log('user client stats tests passed');
