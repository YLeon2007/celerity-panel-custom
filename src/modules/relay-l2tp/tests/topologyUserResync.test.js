'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    TopologyUserResync,
    USER_PUSH_ATTEMPTS,
} = require('../services/topologyUserResync');

function planFixture(kind = 'deploy') {
    return {
        kind,
        chains: [{ nodes: [{ nodeRef: 'portal' }] }],
        nodes: [
            { node: 'node-portal' },
            { node: 'node-bridge' },
            { node: 'node-portal' },
        ],
    };
}

function hyNodeFixture(map) {
    return {
        findById(id) {
            return { lean: async () => map[id] || null };
        },
    };
}

const silentLogger = { info() {}, warn() {}, error() {} };

test('restricted resync uses one finite nonempty batch and never calls config-capable agent', async () => {
    const { withTopologyReadinessScope } = require('../services/topologyReadinessScope');
    const calls = [];
    const users = [{ userId: 'alice', xrayUuid: '550e8400-e29b-41d4-a716-446655440000' }];
    const resync = new TopologyUserResync({ restrictedRunner: true,
        HyNode: hyNodeFixture({ 'node-portal': { _id: 'node-portal', type: 'xray' },
            'node-bridge': { _id: 'node-bridge', type: 'xray' } }),
        syncService: { async _getUsersForNode() { return users; },
            async addXrayUser() { throw new Error('Legacy HTTP must stay masked'); } }, logger: silentLogger });
    const entries = ['node-portal', 'node-bridge'].map((nodeId, index) => ({
        binding: { nodeId, targetProfile: index ? 'xray-bridge' : 'xray-main', commandIds: { verify: 'v-1' } },
        poison() {}, async invoke(command, request) { calls.push({ nodeId, command, users: request.users });
            return { ok: true, code: 'XRAY_USERS_RESTORED', userCount: 1, inboundCount: 1 }; },
    }));
    assert.equal((await resync.resyncPlan(planFixture())).ok, false, 'no held capability must refuse');
    const result = await withTopologyReadinessScope(entries, async () => {}, () => resync.resyncPlan(planFixture()));
    assert.equal(result.ok, true);
    assert.equal(result.userCount, 1);
    assert.deepEqual(calls, [{ nodeId: 'node-portal', command: 'restore-users',
        users: [{ id: users[0].xrayUuid, email: 'alice' }] }]);
});

test('TopologyUserResync: requires HyNode.findById', () => {
    assert.throws(() => new TopologyUserResync({}), TypeError);
});

test('TopologyUserResync: no users means a zero-count no-op', async () => {
    const resync = new TopologyUserResync({
        HyNode: hyNodeFixture({
            'node-portal': { _id: 'p', name: 'P', type: 'xray' },
            'node-bridge': { _id: 'b', name: 'B', type: 'hy2' },
        }),
        syncService: {
            async _getUsersForNode() { return []; },
            async addXrayUser() { return true; },
        },
        logger: silentLogger,
    });
    const result = await resync.resyncPlan(planFixture());
    assert.equal(result.nodeCount, 1);
    assert.equal(result.userCount, 0);
    assert.equal(result.ok, true);
    assert.deepEqual(result.failedUsers, []);
});

test('TopologyUserResync: pushes users to deduped xray nodes only', async () => {
    const pushed = [];
    const resync = new TopologyUserResync({
        HyNode: hyNodeFixture({
            'node-portal': { _id: 'node-portal', name: 'P', type: 'xray' },
            'node-bridge': { _id: 'node-bridge', name: 'B', type: 'hy2' },
        }),
        syncService: {
            async _getUsersForNode(node) {
                return node.name === 'P' ? [{ userId: 'u1' }, { userId: 'u2' }] : [];
            },
            async addXrayUser(node, user) {
                pushed.push(`${node.name}/${user.userId}`);
                return true;
            },
        },
        logger: silentLogger,
    });
    const result = await resync.resyncPlan(planFixture());
    assert.deepEqual(result, { nodeCount: 1, userCount: 2, failedUsers: [], ok: true });
    assert.deepEqual(pushed, ['P/u1', 'P/u2']);
});

test('TopologyUserResync: retries a failed push until the attempt budget is spent', async () => {
    const attempts = [];
    const resync = new TopologyUserResync({
        HyNode: hyNodeFixture({
            'node-portal': { _id: 'x', name: 'P', type: 'xray' },
            'node-bridge': { _id: 'b', name: 'B', type: 'hy2' },
        }),
        syncService: {
            async _getUsersForNode() { return [{ userId: 'u1' }, { userId: 'u2' }]; },
            async addXrayUser(node, user) {
                attempts.push(user.userId);
                if (user.userId === 'u1') throw new Error('agent down');
                return true;
            },
        },
        logger: silentLogger,
        sleep: async () => {},
    });
    const result = await resync.resyncPlan(planFixture());
    assert.equal(result.nodeCount, 1);
    assert.equal(result.userCount, 1);
    assert.equal(result.ok, false, 'an unpushable user must mark the resync not-ready');
    assert.equal(result.failedUsers.length, 1);
    assert.equal(result.failedUsers[0].node, 'node-portal');
    assert.equal(result.failedUsers[0].userId, 'u1');
    assert.equal(attempts.filter(id => id === 'u1').length, USER_PUSH_ATTEMPTS);
    assert.equal(USER_PUSH_ATTEMPTS >= 4, true, 'two attempts are not a durable retry budget');
    assert.deepEqual(attempts.at(-1), 'u2', 'one bad user must not starve the remaining users');
});

test('TopologyUserResync: a recovered push still reports ready', async () => {
    let calls = 0;
    const resync = new TopologyUserResync({
        HyNode: hyNodeFixture({
            'node-portal': { _id: 'x', name: 'P', type: 'xray' },
            'node-bridge': { _id: 'b', name: 'B', type: 'hy2' },
        }),
        syncService: {
            async _getUsersForNode() { return [{ userId: 'u1' }]; },
            async addXrayUser() {
                calls += 1;
                if (calls < 3) throw new Error('agent flapping');
                return true;
            },
        },
        logger: silentLogger,
        sleep: async () => {},
    });
    const result = await resync.resyncPlan(planFixture());
    assert.equal(result.ok, true);
    assert.equal(result.userCount, 1);
    assert.equal(calls, 3);
});

test('TopologyUserResync: a plan node missing from the panel fails closed', async () => {
    const resync = new TopologyUserResync({
        HyNode: hyNodeFixture({ 'node-portal': { _id: 'p', name: 'P', type: 'xray' } }),
        syncService: {
            async _getUsersForNode() { return []; },
            async addXrayUser() { return true; },
        },
        logger: silentLogger,
        sleep: async () => {},
    });
    const result = await resync.resyncPlan(planFixture());
    assert.equal(result.ok, false, 'a committed plan node that vanished cannot have its users verified');
    assert.ok(result.failedUsers.some(entry => entry.node === 'node-bridge'
        && entry.reason === 'NODE_NOT_FOUND'));
});

test('TopologyUserResync: addXrayUser returning false counts as a failed push', async () => {
    let calls = 0;
    const resync = new TopologyUserResync({
        HyNode: hyNodeFixture({
            'node-portal': { _id: 'x', name: 'P', type: 'xray' },
            'node-bridge': { _id: 'b', name: 'B', type: 'hy2' },
        }),
        syncService: {
            async _getUsersForNode() { return [{ userId: 'u1' }]; },
            async addXrayUser() { calls += 1; return false; },
        },
        logger: silentLogger,
        sleep: async () => {},
    });
    const result = await resync.resyncPlan(planFixture());
    assert.equal(result.ok, false);
    assert.equal(calls, USER_PUSH_ATTEMPTS);
    assert.equal(result.failedUsers[0].userId, 'u1');
});

test('TopologyUserResync: an ambiguous addXrayUser result cannot report readiness', async () => {
    const resync = new TopologyUserResync({
        HyNode: hyNodeFixture({
            'node-portal': { _id: 'x', name: 'P', type: 'xray' },
            'node-bridge': { _id: 'b', name: 'B', type: 'hy2' },
        }),
        syncService: {
            async _getUsersForNode() { return [{ userId: 'u1' }]; },
            async addXrayUser() { return undefined; },
        },
        logger: silentLogger,
        sleep: async () => {},
    });
    const result = await resync.resyncPlan(planFixture());
    assert.equal(result.ok, false);
    assert.equal(result.failedUsers[0].reason, 'PUSH_FAILED');
});

test('TopologyUserResync: missing user synchronization capability cannot report readiness', async () => {
    const resync = new TopologyUserResync({
        HyNode: hyNodeFixture({
            'node-portal': { _id: 'x', name: 'P', type: 'xray' },
            'node-bridge': { _id: 'b', name: 'B', type: 'hy2' },
        }),
        syncService: {},
        logger: silentLogger,
    });
    const result = await resync.resyncPlan(planFixture());
    assert.deepEqual(result, {
        nodeCount: 0,
        userCount: 0,
        failedUsers: [{ node: null, userId: null, reason: 'USER_SYNC_UNAVAILABLE' }],
        ok: false,
    });
});
