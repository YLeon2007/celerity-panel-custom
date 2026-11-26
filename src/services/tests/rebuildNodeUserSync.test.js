'use strict';
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { compileFunction } = require('node:vm');
const { test } = require('node:test');
const locks = require('../rebuildLocks');
const { withNode, withNodes } = locks;

const sourcePath = require.resolve('../syncService');
const source = readFileSync(sourcePath, 'utf8');
const nodeId = '507f1f77bcf86cd799439011';
const otherId = '507f1f77bcf86cd799439012';
const groupId = '507f1f77bcf86cd799439013';
const uid = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const fixtureMarker = 'synthetic-private-marker';
const ack = (total, fields = {}) => ({ status: 200, data: JSON.stringify({ added: total, removed: 7, errors: 0, total, ...fields }) });
const exactTarget = { nodeId, ip: '2001:db8::44', agentTls: true, agentPort: 62081 };

function fixture() {
    const state = {
        mode: true, held: false, checks: [], requests: [], userReads: [], nodeReads: [], lockEntries: [],
        node: { _id: nodeId, type: 'xray', ip: exactTarget.ip, groups: [groupId],
            xray: { agentTls: true, agentPort: 62081, agentToken: fixtureMarker, security: 'reality', transport: 'tcp' } },
        users: [], reply: () => ack(0),
    };
    function query(record, read) {
        return {
            select(fields) { record.fields = fields; return this; },
            read(preference) { record.preference = preference; return this; },
            readConcern(concern) { record.concern = concern; return this; },
            maxTimeMS(ms) { record.ms = ms; return this; },
            async lean() { return structuredClone(await read()); },
        };
    }
    function matches(row, filter) {
        return Object.entries(filter).every(([key, value]) => {
            const field = row[key];
            if (key === '$or') return value.some(branch => matches(row, branch));
            if (value?.$in) return field?.some(item => value.$in.includes(item)) ?? false;
            if (value?.$size !== undefined) return field?.length === value.$size;
            if (value?.$exists !== undefined) return Object.hasOwn(row, key) === value.$exists;
            return Array.isArray(field) ? field.includes(value) : field === value;
        });
    }
    const dependencies = {
        '../models/hyNodeModel': { findById(id) {
            const record = { id };
            state.nodeReads.push(record);
            return query(record, () => state.node);
        }, updateOne(...args) {
            assert.equal(typeof state.updateNode, 'function', 'user-only path must not write the node card');
            return state.updateNode(...args);
        } },
        '../models/hyUserModel': { find(filter) {
            const record = { filter: structuredClone(filter) };
            state.userReads.push(record);
            return query(record, () => {
                if (state.mode) assert.equal(state.held, true);
                return state.readUsers ? state.readUsers() : state.users.filter(row => matches(row, filter));
            });
        } },
        './rebuildMode': { isRebuildEnabled: () => state.mode },
        './rebuildLocks': { ...locks, withNode(id, fn) { state.lockEntries.push(id); return withNode(id, fn); },
            async assertAgentWriterAllowed(id) { assert(locks.nodeLockVerifier(id)()); } },
        './topologyConfigOwnership': { usesTestTopologyConfig: () => false },
        '../../config': {},
        '../utils/logger': { info() {}, error() {} },
        '../utils/helpers': { invalidateNodesCache: async () => {} },
        axios: async options => {
            state.requests.push(options);
            return state.reply(options);
        },
    };
    const inert = new Set([
        '../models/settingsModel', '../modules/relay-l2tp/models/relayL2tpStateModel',
        '../modules/relay-l2tp/domain/l2tpXrayConfigMerge',
        './classicNodeConfigWrite', './classicL2tpConfigComposition', '../modules/relay-l2tp/domain/l2tpExecutionAuthorization',
        './configGenerator', '../utils/vlessEncryption', './vlessServerConfig', './cacheService',
        './webhookService', './nodeSetup',
    ]);
    const load = id => {
        if (Object.hasOwn(dependencies, id)) return dependencies[id];
        if (inert.has(id)) return {};
        if (id === './nodeSSH') return class { constructor() { assert.fail('SSH must not be constructed'); } };
        if (['https', 'node:perf_hooks', 'node:net', '../utils/agentOnlineState', '../utils/xrayClientConnections'].includes(id)) {
            return id.startsWith('../') ? require(`../../${id.slice(3)}`) : require(id);
        }
        assert.fail(`Unexpected sync service dependency: ${id}`);
    };
    const mod = { exports: {} };
    compileFunction(source, ['require', 'module'], { filename: sourcePath })(load, mod);
    const service = mod.exports;
    const scoped = fn => withNodes([otherId, nodeId], async () => {
        state.held = true;
        try { return await fn(); } finally { state.held = false; }
    });
    const verifyFence = async target => {
        state.checks.push(target);
        return state.held && (state.verify ? await state.verify(target) : true);
    };
    const sync = (id = nodeId, opts = { verifyFence }) => service.syncRebuildNodeUsersAfterResume(id, opts);
    return { state, service, scoped, sync };
}

function safe(code) {
    return err => {
        assert.equal(err.code, code);
        assert.equal(err.retryAllowed, false);
        assert.equal(err.message, code);
        assert.equal(err.cause, undefined);
        assert.doesNotMatch(JSON.stringify(err), /synthetic-private-marker/);
        return true;
    };
}
const fenceError = 'REBUILD_NODE_USER_SYNC_FENCE_UNPROVED';
const prepError = 'REBUILD_NODE_USER_SYNC_PREPARE_FAILED';
const unconfirmed = 'REBUILD_NODE_USER_SYNC_UNCONFIRMED';

test('fresh stock snapshot is acknowledged under the original node lock before queued deltas', { timeout: 5000 }, async () => {
    const { state, service, scoped, sync } = fixture();
    const entered = Promise.withResolvers();
    const reply = Promise.withResolvers();
    state.reply = opts => {
        if (new URL(opts.url).pathname !== '/sync') return { status: 200, data: {} };
        entered.resolve();
        return reply.promise;
    };
    state.users = [{ enabled: true, nodes: [nodeId], userId: 'removed-during-window', xrayUuid: uid(1) }];
    const mainWindow = scoped(async () => {
        // This is the caller's already-settled agent-start/reconcile boundary.
        state.users = [
            { enabled: true, nodes: [nodeId], groups: [otherId], userId: 'explicit', xrayUuid: uid(2) },
            { enabled: true, nodes: [], groups: [groupId], userId: 'group-empty-nodes', xrayUuid: uid(3) },
            { enabled: true, groups: [groupId], userId: 'group-absent-nodes', xrayUuid: uid(4) },
            { enabled: true, nodes: [otherId], groups: [groupId], userId: 'explicit-other', xrayUuid: uid(5) },
            { enabled: false, nodes: [nodeId], userId: 'disabled', xrayUuid: uid(6) },
            { enabled: true, nodes: [nodeId], userId: 'no-xray-uuid' },
        ];
        return sync();
    });
    // On RED or setup refusal, report its original error, not a fixture timeout.
    await Promise.race([entered.promise, mainWindow]);
    // Use IPv4 for the legacy (non-direct) URL construction.
    const deltaNode = { ...state.node, ip: '192.0.2.44' };
    const queued = service.removeXrayUser(deltaNode, { userId: 'disabled' });
    try {
        await Promise.resolve();
        assert.equal(state.requests.length, 1);
        assert.deepEqual(state.lockEntries, [nodeId]); // legacy delta only
        const [request] = state.requests;
        assert.equal(request.method, 'POST');
        assert.equal(request.url, 'https://[2001:db8::44]:62081/sync');
        assert.equal(request.headers.Authorization, `Bearer ${fixtureMarker}`);
        assert.equal(request.proxy, false);
        assert.equal(request.maxRedirects, 0);
        assert.ok(request.signal && request.timeout >= 60_000);
        assert.deepEqual(request.data, { users: [
            { id: uid(2), email: 'explicit', flow: 'xtls-rprx-vision' },
            { id: uid(3), email: 'group-empty-nodes', flow: 'xtls-rprx-vision' },
            { id: uid(4), email: 'group-absent-nodes', flow: 'xtls-rprx-vision' },
        ] });
        assert.deepEqual(state.checks, [exactTarget, exactTarget]);
        assert.equal(state.nodeReads.length, 1);
        assert.equal(state.nodeReads[0].id, nodeId);
        assert.equal(state.userReads.length, 1);
        for (const read of [...state.nodeReads, ...state.userReads]) {
            assert.equal(read.preference, 'primary');
            assert.equal(read.concern, 'majority');
            assert.equal(read.ms, 5000);
        }
        assert.equal(state.userReads[0].fields, 'userId xrayUuid');
    } finally {
        reply.resolve(ack(3));
        await Promise.allSettled([mainWindow, queued]);
    }
    assert.deepEqual(await mainWindow, { added: 3, removed: 7, errors: 0, total: 3 });
    assert.equal(await queued, true);
    assert.deepEqual(state.checks, [exactTarget, exactTarget, exactTarget]);
    assert.deepEqual(state.requests.map(r => [r.method, new URL(r.url).pathname]), [['POST', '/sync'], ['DELETE', '/users/disabled']]);
});

test('no-group selection and fresh explicit empty snapshot use the same user-only wire', async () => {
    const { state, scoped, sync } = fixture();
    state.node.groups = [];
    state.node.xray = { agentToken: fixtureMarker };
    state.reply = opts => ack(opts.data.users.length);
    state.users = [
        { enabled: true, nodes: [], groups: [], userId: 'ungrouped', xrayUuid: uid(10) },
        { enabled: true, groups: [groupId], userId: 'other-group', xrayUuid: uid(11) },
    ];
    await scoped(sync);
    assert.deepEqual(state.requests[0].data, { users: [{ id: uid(10), email: 'ungrouped', flow: 'xtls-rprx-vision' }] });
    assert.equal(state.requests[0].url, 'https://[2001:db8::44]:62080/sync');
    state.users = [];
    await scoped(sync);
    assert.deepEqual(state.requests[1].data, { users: [] });
});

test('requires Rebuild and a strictly affirmative verifier for the exact target', async () => {
    const { state, scoped, sync } = fixture();
    await scoped(() => assert.rejects(sync(nodeId, {}), safe(fenceError)));
    state.mode = false;
    await scoped(() => assert.rejects(sync(), safe(fenceError)));
    state.mode = true;
    await assert.rejects(sync(), safe(fenceError));
    for (const result of [false, undefined, { verified: true }]) {
        state.verify = target => {
            assert.deepEqual(target, exactTarget);
            assert.equal(Object.isFrozen(target), true);
            return result;
        };
        await scoped(() => assert.rejects(sync(), safe(fenceError)));
    }
    state.verify = target => target.nodeId === otherId && target.ip === exactTarget.ip;
    await scoped(() => assert.rejects(sync(), safe(fenceError)));
    state.node.xray.agentPort++;
    state.verify = target => target.nodeId === nodeId && target.agentPort === exactTarget.agentPort;
    await scoped(() => assert.rejects(sync(), safe(fenceError)));
    state.verify = () => { throw new Error(fixtureMarker); };
    await scoped(() => assert.rejects(sync(), safe(fenceError)));
    assert.equal(state.userReads.length, 0);
    assert.equal(state.requests.length, 0);
});

test('a valid-looking verifier cannot replace the current node lock or reuse a detached scope', async () => {
    const { state, sync } = fixture();
    const opts = { verifyFence: async () => true };
    await assert.rejects(sync(nodeId, opts), safe(fenceError));
    await withNode(otherId, () => assert.rejects(sync(nodeId, opts), safe(fenceError)));
    const afterExit = Promise.withResolvers();
    let detached;
    await withNode(nodeId, () => {
        detached = afterExit.promise.then(() => sync(nodeId, opts));
    });
    afterExit.resolve();
    await assert.rejects(detached, safe(fenceError));
    assert.equal(state.nodeReads.length, 0);
    assert.equal(state.requests.length, 0);
});

test('fence loss while loading users prevents dispatch', async () => {
    const { state, scoped, sync } = fixture();
    let authorized = true;
    state.verify = () => authorized;
    state.readUsers = async () => { authorized = false; return []; };
    await scoped(() => assert.rejects(sync(), safe(fenceError)));
    assert.equal(state.checks.length, 2);
    assert.equal(state.requests.length, 0);
});

test('unreadable inventory or invalid current target never becomes an empty snapshot', async () => {
    const { state, scoped, sync } = fixture();
    state.readUsers = () => { throw new Error(fixtureMarker); };
    await scoped(() => assert.rejects(sync(), safe(prepError)));
    const original = state.node;
    for (const node of [null, { ...original, _id: otherId }, { ...original, type: 'hysteria' }, { ...original, xray: {} }]) {
        state.node = node;
        await scoped(() => assert.rejects(sync(), safe(prepError)));
    }
    assert.equal(state.requests.length, 0);
});

test('fence loss with POST outstanding invalidates even a correct ACK without replay', async () => {
    const { state, scoped, sync } = fixture();
    let authorized = true;
    state.verify = () => authorized;
    state.reply = async () => { authorized = false; return ack(0); };
    await scoped(() => assert.rejects(sync(), safe(unconfirmed)));
    assert.equal(state.checks.length, 3);
    assert.equal(state.requests.length, 1);
});

test('exact-mode /sync refuses a rotated UUID at the same email before the POST', async () => {
    const { state, scoped, sync } = fixture();
    state.users = [{ enabled: true, nodes: [nodeId], userId: 'existing', xrayUuid: uid(2) }];
    let proved = 0;
    await scoped(() => assert.rejects(sync(nodeId, { verifyFence: () => true, verifyPayload(target, users) {
        assert.deepEqual(target, exactTarget);
        assert.deepEqual(users.map(({ id, email }) => [id, email]), [[uid(2), 'existing']]);
        proved++;
        return users[0].id === uid(1);
    } }), safe('REBUILD_NODE_USER_SYNC_PAYLOAD_UNPROVED')));
    assert.equal(proved, 1);
    assert.deepEqual(state.requests, []);
});

test('exact-mode /sync binds the original immutable payload before and after the only dispatch', async () => {
    const { state, scoped, sync } = fixture();
    state.users = [{ enabled: true, nodes: [nodeId], userId: 'retained', xrayUuid: uid(1) }];
    let proved = 0, original;
    const noDelta = ack(1, { added: 0, removed: 0 });
    const verifyPayload = (target, users) => {
        assert.deepEqual(target, exactTarget);
        assert(Object.isFrozen(users) && Object.isFrozen(users[0]));
        if (proved++ % 2 === 0) original = users;
        else assert.equal(users, original);
        return true;
    };
    state.reply = request => {
        assert.equal(request.data.users, original);
        assert(Object.isFrozen(request.data));
        return noDelta;
    };
    const opts = { verifyFence: () => true, verifyPayload };
    assert.deepEqual(await scoped(() => sync(nodeId, opts)), JSON.parse(noDelta.data));
    assert.equal(proved, 2);
    state.reply = () => ack(1, { added: 1, removed: 0 });
    await scoped(() => assert.rejects(sync(nodeId, opts), safe(unconfirmed)));
    assert.equal(proved, 3);
    assert.equal(state.requests.length, 2);
});

for (const [name, reply] of [
    ['HTTP refusal', () => ({ status: 503, data: fixtureMarker })],
    ['redirect', () => ({ status: 307, data: fixtureMarker })],
    ['non-stock 2xx', () => ({ ...ack(0), status: 202 })],
    ['legacy runtime errors', () => ack(0, { errors: 1 })],
    ['different accepted total', () => ack(1)],
    ['wrong counter type', () => ack(0, { errors: '0' })],
    ['impossible added count', () => ack(0, { added: 1 })],
    ['unexpected response keys', () => ack(0, { extra: fixtureMarker })],
    ['malformed response', () => ({ status: 200, data: fixtureMarker })],
    ['lost transport reply', opts => { throw Object.assign(new Error(fixtureMarker), { config: opts }); }],
]) {
    test(`${name} is unconfirmed, safe, and never replays POST`, async () => {
        const { state, scoped, sync } = fixture();
        state.reply = reply;
        await scoped(() => assert.rejects(sync(), safe(unconfirmed)));
        assert.equal(state.requests.length, 1);
    });
}

test('legacy managed configuration sync keeps its own payload, health, and result contract', async () => {
    const { state, service } = fixture();
    state.mode = false;
    state.node.ip = '192.0.2.44';
    state.node.xray.flow = 'legacy-flow';
    state.users = [{ enabled: true, groups: [groupId], userId: 'group-user', xrayUuid: uid(20) }];
    state.reply = () => ({ status: 200, data: { added: 0, removed: 0, errors: 1, total: 1 } });
    service._topologyManagesNode = async () => true;
    let healthChecks = 0;
    service.checkXrayAgentHealth = async () => { healthChecks++; return { online: true }; };
    state.updateNode = () => ({});
    assert.equal(await service.updateXrayNodeConfig(state.node), true);
    assert.equal(healthChecks, 1);
    assert.equal(state.userReads.length, 2);
    assert.equal(state.requests.length, 1);
    assert.equal(state.requests[0].url, 'https://192.0.2.44:62081/sync');
    assert.deepEqual(state.requests[0].data, { users: [{ id: uid(20), email: 'group-user', flow: 'legacy-flow' }] });
    assert.equal(state.requests[0].signal, undefined);
});
