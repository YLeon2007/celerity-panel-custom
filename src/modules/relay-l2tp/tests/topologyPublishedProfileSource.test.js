'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { TopologyPublishedProfileSource } = require('../services/topologyPublishedProfileSource');

const UUID = '11111111-1111-4111-8111-111111111111';
const TOKEN = 'sensitiveSubscriptionToken123';
const node = Object.freeze({
    _id: 'portal-one', name: 'Portal One', flag: '🏁', type: 'xray', active: true,
    cascadeRole: 'portal', domain: 'portal.example', port: 443,
    xray: { realityPublicKey: 'public-key', realitySni: ['front.example'], realityShortIds: ['01234567'], transport: 'tcp', security: 'reality' },
});
function profile(n = node, uuid = UUID) {
    return {
        remarks: `${n.flag} ${n.name}`.trim(),
        outbounds: [
            { tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: n.domain, port: n.port, users: [{ id: uuid, encryption: 'none' }] }] }, streamSettings: { network: 'tcp', security: 'reality', realitySettings: { publicKey: n.xray.realityPublicKey, serverName: n.xray.realitySni[0], shortId: n.xray.realityShortIds[0] } } },
            { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' },
        ],
    };
}
function fixture({ rows = [profile()], user = { enabled: true, subscriptionToken: TOKEN, xrayUuid: UUID, trafficLimit: 0 }, userId = 'test_mobile', fetchImpl } = {}) {
    const calls = [];
    const HyUser = { findOne(query) {
        calls.push({ query });
        return { select(fields) {
            calls.push({ fields });
            return { lean: async () => user };
        } };
    } };
    const fetcher = fetchImpl || (async (url, options) => {
        calls.push({ url, options });
        return { ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => JSON.stringify(rows) };
    });
    return { source: new TopologyPublishedProfileSource({ HyUser, probeUserId: userId, fetchImpl: fetcher }), calls };
}

test('loads the exact loopback Happ Android xray-json response and consumes only the matching published profile', async () => {
    const other = { ...node, _id: 'portal-other', name: 'Other', domain: 'other.example' };
    const { source, calls } = fixture({ rows: [profile(other), profile()] });
    let consumed = 0;
    const result = await source.load({ portalNodes: [node], consumeProfile: async (id, published) => {
        assert.equal(id, node._id);
        assert.deepEqual(published, profile());
        consumed++;
        return { ok: true, secret: TOKEN };
    } });
    assert.deepEqual(result, { ok: true, verifiedCount: 1 });
    assert.equal(consumed, 1);
    assert.deepEqual(calls[0].query, { userId: 'test_mobile', enabled: true });
    assert.equal(calls[2].url, `http://127.0.0.1:3000/api/files/${TOKEN}?format=xray-json`);
    assert.match(calls[2].options.headers['User-Agent'], /Happ.*Android/i);
    assert(!JSON.stringify(result).includes(TOKEN));
    assert(!JSON.stringify(result).includes(UUID));
});

test('rejects stale duplicate with the same advertised portal name before consuming any profile', async () => {
    const { source } = fixture({ rows: [profile(), profile(node, '22222222-2222-4222-8222-222222222222')] });
    let consumed = 0;
    assert.deepEqual(await source.load({ portalNodes: [node], consumeProfile: async () => { consumed++; return { ok: true }; } }), { ok: false });
    assert.equal(consumed, 0);
});

test('requires explicit authorized active user with valid entitlement and never fetches otherwise', async () => {
    for (const user of [null, { enabled: false, subscriptionToken: TOKEN, xrayUuid: UUID },
        { enabled: true, expireAt: new Date(0), subscriptionToken: TOKEN, xrayUuid: UUID },
        { enabled: true, trafficLimit: 1, traffic: { tx: 1 }, subscriptionToken: TOKEN, xrayUuid: UUID },
        { enabled: true, xrayUuid: UUID }, { enabled: true, subscriptionToken: TOKEN }]) {
        const { source, calls } = fixture({ user });
        assert.deepEqual(await source.load({ portalNodes: [node], consumeProfile: async () => ({ ok: true }) }), { ok: false });
        assert.equal(calls.length, 2);
    }
    const { source, calls } = fixture({ userId: '' });
    assert.deepEqual(await source.load({ portalNodes: [node], consumeProfile: async () => ({ ok: true }) }), { ok: false });
    assert.equal(calls.length, 0);
});

test('refuses stale endpoint, missing profile, duplicate matching profile and ambiguous request', async () => {
    for (const rows of [[], [profile({ ...node, domain: 'stale.example' })], [profile(), profile()]]) {
        const { source } = fixture({ rows });
        let calls = 0;
        assert.deepEqual(await source.load({ portalNodes: [node], consumeProfile: async () => { calls++; return { ok: true }; } }), { ok: false });
        assert.equal(calls, 0);
    }
    const { source, calls } = fixture();
    assert.deepEqual(await source.load({ portalNodes: [node, node], consumeProfile: async () => ({ ok: true }) }), { ok: false });
    assert.equal(calls.length, 0);
});

test('validates every requested portal before giving any profile to the consumer', async () => {
    const second = { ...node, _id: 'portal-two', name: 'Portal Two', domain: 'two.example' };
    const { source } = fixture({ rows: [profile(second), profile()] });
    const observed = [];
    assert.deepEqual(await source.load({ portalNodes: [node, second], consumeProfile: async (id, published) => {
        observed.push(id);
        assert.equal(published.remarks, id === node._id ? profile().remarks : profile(second).remarks);
        return { ok: true };
    } }), { ok: true, verifiedCount: 2 });
    assert.deepEqual(observed, [node._id, second._id]);
    const { source: missing } = fixture({ rows: [profile()] });
    let touched = 0;
    assert.deepEqual(await missing.load({ portalNodes: [node, second], consumeProfile: async () => { touched++; return { ok: true }; } }), { ok: false });
    assert.equal(touched, 0);
});

test('bounds network timeout and redacts network and consumer exceptions', async () => {
    const source = new TopologyPublishedProfileSource({
        probeUserId: 'test_mobile', timeoutMs: 10,
        HyUser: { findOne: () => ({ select: () => ({ lean: async () => ({ enabled: true, subscriptionToken: TOKEN, xrayUuid: UUID }) }) }) },
        fetchImpl: async () => new Promise(() => {}),
    });
    assert.deepEqual(await source.load({ portalNodes: [node], consumeProfile: async () => ({ ok: true }) }), { ok: false });
    const { source: leaking } = fixture();
    const result = await leaking.load({ portalNodes: [node], consumeProfile: () => { throw Error(`${TOKEN} ${UUID}`); } });
    assert.deepEqual(result, { ok: false });
    assert(!JSON.stringify(result).includes(TOKEN));
    assert(!JSON.stringify(result).includes(UUID));
});
