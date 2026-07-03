const assert = require('assert');

const {
    normalizeClientOs,
    buildClientStats,
    attachClientStatsToUsers,
    extractXrayOnlineUserIds,
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
    ], { now: fixedNow, onlineUserIds: new Set(['alice']), userId: 'alice', lang: 'ru' });

    assert.strictEqual(stats.online, true, 'xray online cache should make user online');
    assert.strictEqual(stats.onlineDeviceCount, 1, 'onlineDeviceCount is per-user live session state, not fresh HWID devices');
    assert.strictEqual(stats.deviceCount, 2);
    assert.deepStrictEqual(stats.osList, ['ios', 'android']);
    assert.strictEqual(stats.osSummary, '2 устройства ios+android');
}

{
    const stats = buildClientStats([
        { platform: 'Windows', lastSeenAt: new Date('2026-07-03T09:29:59.000Z') },
    ], { now: fixedNow, onlineUserIds: new Set(), userId: 'bob', lang: 'ru' });

    assert.strictEqual(stats.online, false, 'fresh UserDevice heartbeat must not imply real VPN online');
    assert.strictEqual(stats.onlineDeviceCount, 0);
    assert.strictEqual(stats.osSummary, '1 устройство windows');
}

{
    const users = [{ userId: 'alice' }, { userId: 'bob' }];
    const result = attachClientStatsToUsers(users, [
        { userId: 'alice', platform: 'ios', lastSeenAt: new Date('2026-07-03T09:29:59.000Z') },
        { userId: 'alice', platform: 'android', lastSeenAt: new Date('2026-07-03T09:28:00.000Z') },
    ], { now: fixedNow, onlineUserIds: ['bob'], lang: 'ru' });

    assert.strictEqual(result[0].clientStats.online, false, 'OS device data alone should not mark online');
    assert.strictEqual(result[0].clientStats.osSummary, '2 устройства ios+android');
    assert.strictEqual(result[1].clientStats.online, true, 'online can come from Xray stats even without HWID device rows');
    assert.strictEqual(result[1].clientStats.osSummary, '0 устройств unknown');
}

{
    const users = extractXrayOnlineUserIds({
        alice: { tx: 0, rx: 0, online: true },
        bob: { tx: 0, rx: 12 },
        carol: { tx: 0, rx: 0, active: false },
        dave: { uplink: 1, downlink: 0 },
    });
    assert.deepStrictEqual(users.sort(), ['alice', 'bob', 'dave']);
}

console.log('user client stats tests passed');
