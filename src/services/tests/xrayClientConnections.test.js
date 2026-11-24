'use strict';

const assert = require('node:assert/strict');
const { test, after } = require('node:test');
const http = require('node:http');
const { performance } = require('node:perf_hooks');

process.env.PANEL_DOMAIN ||= 'fixture.invalid';
process.env.ACME_EMAIL ||= 'fixture@fixture.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
const sync = require('../syncService');
const HyNode = require('../../models/hyNodeModel');
const HyUser = require('../../models/hyUserModel');
const cache = require('../cacheService');
const logger = require('../../utils/logger');
const ID = '507f1f77bcf86cd799439011';
const CLIENT = '198.51.100.220';
const iso = (offset = 0) => new Date(Date.now() + offset).toISOString();
const snapshot = (users = {}, updatedAt = iso()) => ({ supported: true, users, updatedAt });
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

test('positive agent clock skew does not extend snapshot or sample retention', () => {
    const { decodeSnapshot } = require('../../utils/xrayClientConnections');
    const wall = Date.parse('2026-11-24T10:00:00Z');
    const packet = snapshot({ subscriber: [{ ip: CLIENT, lastSeen: new Date(wall - 1000).toISOString() }] },
        new Date(wall + 4000).toISOString());
    const entry = decodeSnapshot(packet, wall, 100);
    assert.equal(entry.expiresAt, 60_100);
    assert.equal(entry.users.get('subscriber').get(CLIENT).expiresAt, 55_100);
    assert.equal(decodeSnapshot(packet, wall - 2000, 100), null);
});

after(() => require('../sshPoolService').closeAll());

async function fixture(t) {
    t.after(() => sync.clearXrayClientConnections?.());
    const paths = [];
    const logs = [];
    const mongo = [];
    const redis = [];
    let wire = () => snapshot({ subscriber: [{ ip: CLIENT, lastSeen: iso(-1000) },
        { ip: '2001:db8::1', lastSeen: iso(-1000) }], deleted: [{ ip: CLIENT, lastSeen: iso(-1000) }] });
    let status = 200;
    let live = true;
    let users = [ { userId: 'subscriber', username: 'Display Name', enabled: true, _id: ID } ];
    const server = http.createServer(async (req, res) => {
        paths.push(req.url);
        if (req.headers.authorization !== 'Bearer fixture-bearer') {
            res.writeHead(401).end();
            return;
        }
        res.setHeader('Content-Type', 'application/json');
        if (req.url === '/online-ips') {
            if (status !== 200) res.statusCode = status;
            const body = await wire(req, res);
            if (body !== undefined) res.end(JSON.stringify(body));
        } else if (req.url === '/stats') {
            res.end(JSON.stringify({ users: { legacy: { tx: 5, rx: 7 } }, node: { tx: 8, rx: 9 } }));
        } else if (req.url === '/info') {
            res.end(JSON.stringify({ agent_version: '1.6.0' }));
        } else if (req.url === '/xray-health') {
            res.end(JSON.stringify({ xray_status: 'online' }));
        } else if (req.url === '/online') {
            res.end(JSON.stringify({ users: { legacy: { online: true, ip: CLIENT } } }));
        } else res.writeHead(404).end();
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const node = { _id: ID, type: 'xray', name: 'fixture', active: true, status: 'online',
        cascadeRole: 'portal', ip: '127.0.0.1', agentVersion: '1.6.0', onlineUsers: 8,
        xray: { agentToken: 'fixture-bearer', agentPort: server.address().port, agentTls: false } };
    const query = get => ({ select() { return this; }, lean: async () => get(), then: (yes, no) => Promise.resolve(get()).then(yes, no) });
    const matches = filter => live && (!filter.type || filter.type === node.type)
        && (!filter.active || node.active) && (!filter.status || node.status === filter.status)
        && (!filter._id || String(filter._id) === ID);
    const read = () => structuredClone(node);
    t.mock.method(HyNode, 'find', filter => query(() => matches(filter) ? [read()] : []));
    t.mock.method(HyNode, 'findById', id => query(() => live && String(id) === ID ? read() : null));
    t.mock.method(HyNode, 'findOneAndUpdate', async (filter, update) => {
        mongo.push([filter, update]);
        const previous = read();
        Object.assign(node, update.$set);
        return previous;
    });
    t.mock.method(HyNode, 'updateOne', async (filter, update) => {
        mongo.push([filter, update]);
        if (!matches(filter)) return { matchedCount: 0 };
        if (update.$set?.onlineUsers !== undefined) node.onlineUsers = update.$set.onlineUsers;
        return { matchedCount: 1 };
    });
    t.mock.method(HyUser, 'find', filter => query(() => filter.nodes ? users.filter(user => user.enabled
        && (!filter.userId?.$in || filter.userId.$in.includes(user.userId))) : []));
    t.mock.method(HyUser, 'bulkWrite', async ops => { mongo.push(ops); return { modifiedCount: ops.length }; });
    t.mock.method(sync, 'enforceTrafficLimit', async () => {});
    t.mock.method(cache, 'isConnected', () => true);
    const previousRedis = cache.redis;
    cache.redis = { async setex(...args) { redis.push(args); }, async del() {} };
    t.after(() => { cache.redis = previousRedis; });
    for (const level of ['debug', 'info', 'warn', 'error']) t.mock.method(logger, level, (...args) => logs.push(args));
    sync.xrayNodeOnlineUsers.clear();
    sync.xrayTrafficLastActive.clear();
    return { paths, node, mongo, redis, logs, setWire(fn, code = 200) { wire = fn; status = code; },
        setUsers(list) { users = list; }, remove() { live = false; }, cached: () => JSON.parse(redis.at(-1)[2]) };
}

test('real pollers preserve stats and override the legacy count/cache, even when empty', async t => {
    const f = await fixture(t);
    await sync.collectAllStats();
    assert.deepEqual(f.paths, ['/stats', '/online']);
    assert.deepEqual(Object.keys(f.cached()), ['legacy']);
    await sync.collectXrayClientConnections();
    assert.equal(f.paths.at(-1), '/online-ips');
    assert.equal(f.node.onlineUsers, 1);
    assert.deepEqual(Object.keys(f.cached()), ['subscriber']);
    await sync.collectXrayAgentOnlineStates();
    assert.deepEqual(Object.keys(f.cached()), ['subscriber']);
    let read = await sync.readXrayClientConnections(ID, async () => ({ country: 'Fixture', extra: CLIENT }));
    assert.equal(read.state, 'ready');
    assert.deepEqual(read.rows.map(r => [r.username, r.ip, r.country]), [
        ['Display Name', CLIENT, 'Fixture'], ['Display Name', '2001:db8::1', 'Fixture']]);
    const keys = ['username', 'ip', 'country', 'region', 'city', 'asn', 'isp', 'lastSeen'].sort();
    assert.deepEqual(Object.keys(read.rows[0]).sort(), keys);
    f.setWire(() => snapshot());
    await sync.collectXrayClientConnections();
    assert.equal(f.node.onlineUsers, 0);
    assert.deepEqual(f.cached(), {});
    read = await sync.readXrayClientConnections(ID, async () => assert.fail('unexpected GeoIP lookup'));
    assert.deepEqual(read, { state: 'ready', rows: [] });
    f.setWire(() => ({ details: `axios refusal with ${CLIENT}` }), 502);
    await sync.collectXrayClientConnections();
    assert.equal(f.node.onlineUsers, 1);
    assert.deepEqual(Object.keys(f.cached()), ['legacy']);
    assert.equal((await sync.readXrayClientConnections(ID, async () => null)).state, 'unavailable');
    assert.equal(f.paths.filter(path => path === '/stats').length, 1);
    assert.equal(f.paths.filter(path => path === '/online').length, 2);
    assert(f.mongo.some(ops => Array.isArray(ops) && ops[0]?.updateOne?.update?.$inc?.['traffic.tx'] === 5));
    assert.doesNotMatch(require('node:util').inspect({ mongo: f.mongo, redis: f.redis, logs: f.logs }, { depth: null }), /198\.51\.100\.220|2001:db8::1/);
});

test('version is learned from the stock health metadata path; bridges/relays/old agents never get IP polls', async t => {
    const f = await fixture(t);
    f.node.agentVersion = 'installed';
    await sync.collectXrayClientConnections();
    assert.deepEqual(f.paths, []);
    await sync.checkXrayAgentHealth(structuredClone(f.node));
    assert.equal(f.node.agentVersion, '1.6.0');
    f.node.cascadeRole = 'standalone';
    await sync.collectXrayClientConnections();
    assert.equal(f.paths.at(-1), '/online-ips');
    const before = f.paths.length;
    for (const role of ['bridge', 'relay']) {
        f.node.cascadeRole = role;
        await sync.collectXrayClientConnections();
        assert.equal((await sync.readXrayClientConnections(ID, async () => null)).state, 'unavailable');
    }
    f.node.cascadeRole = 'portal';
    f.node.agentVersion = '1.5.99';
    await sync.collectXrayClientConnections();
    assert.equal((await sync.readXrayClientConnections(ID, async () => null)).state, 'old-agent');
    assert.equal(f.paths.length, before);
});

test('expired snapshots and rows are rejected and purge does not require another poll', async t => {
    const f = await fixture(t);
    const now = performance.now();
    f.setWire(() => snapshot({ subscriber: [{ ip: CLIENT, lastSeen: iso(-59_700) }] }));
    await sync.collectXrayClientConnections();
    assert.equal(f.node.onlineUsers, 1);
    await wait(350);
    assert(performance.now() - now >= 350);
    assert.deepEqual(await sync.readXrayClientConnections(ID, async () => assert.fail()), { state: 'ready', rows: [] });
    // Near-expired upstream timestamp means a 60 s receive-side cache cannot renew it.
    f.setWire(() => snapshot({ subscriber: [{ ip: CLIENT, lastSeen: iso(-59_700) }] }, iso(-59_700)));
    await sync.collectXrayClientConnections();
    await wait(350);
    assert.equal((await sync.readXrayClientConnections(ID, async () => null)).state, 'unavailable');
    await sync.collectXrayAgentOnlineStates();
    assert.deepEqual(Object.keys(f.cached()), ['legacy']);
});

test('malformed wire values and unsupported core are never authoritative', async t => {
    const f = await fixture(t);
    for (const payload of [
        { supported: false, users: {}, updatedAt: iso() },
        { supported: 'true', users: {}, updatedAt: iso() }, snapshot([]), snapshot({}, iso(-65_000)),
        snapshot({}, '2026-02-30T10:00:00Z'), snapshot({}, iso(600_000)),
        snapshot({ subscriber: [{ ip: `${CLIENT}:80`, lastSeen: iso() }] }),
        snapshot({ subscriber: [{ ip: 'fe80::1%eth0', lastSeen: iso() }] }),
        snapshot({ subscriber: [{ ip: CLIENT, lastSeen: 'yesterday' }] }),
    ]) {
        f.setWire(() => payload);
        await sync.collectXrayClientConnections();
        assert.equal((await sync.readXrayClientConnections(ID, async () => assert.fail())).state, 'unavailable');
    }
});

test('Axios and JSON parse failures discard private response bytes without logging them', async t => {
    const f = await fixture(t);
    await sync.collectXrayAgentOnlineStates();
    const failures = [
        res => res.end(`{"users":"${CLIENT}"`),
        res => res.end(CLIENT + 'a'.repeat(2 * 1024 * 1024)),
        res => { res.setHeader('Content-Length', 999); res.write(`${CLIENT}\n`); res.destroy(); },
    ];
    for (const fail of failures) {
        f.setWire((_req, res) => { fail(res); });
        await sync.collectXrayClientConnections();
        assert.deepEqual(await sync.readXrayClientConnections(ID, async () => assert.fail()), { state: 'unavailable', rows: [] });
        assert.deepEqual(Object.keys(f.cached()), ['legacy']);
    }
    assert.doesNotMatch(require('node:util').inspect({ mongo: f.mongo, redis: f.redis, logs: f.logs }, { depth: null }), /198\.51\.100\.220/);
});

test('read rejects a node removed/demoted or a user revoked during enrichment', async t => {
    const f = await fixture(t);
    await sync.collectXrayClientConnections();
    assert.deepEqual(await sync.readXrayClientConnections(ID, async () => { f.setUsers([]); return null; }), { state: 'ready', rows: [] });
    f.setUsers([{ userId: 'subscriber', username: 'Name', enabled: true, _id: ID }]);
    assert.deepEqual(await sync.readXrayClientConnections(ID, async () => { f.remove(); return null; }), { state: 'unavailable', rows: [] });
});
