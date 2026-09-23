'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    TopologyUserResync,
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

test('TopologyUserResync: requires HyNode.findById', () => {
    assert.throws(() => new TopologyUserResync({}), TypeError);
});

test('TopologyUserResync: skips non-deploy plans', async () => {
    let called = 0;
    const resync = new TopologyUserResync({
        HyNode: hyNodeFixture({}),
        syncService: {
            async _getUsersForNode() { called += 1; return []; },
            async addXrayUser() { return true; },
        },
    });
    const result = await resync.resyncPlan(planFixture('undeploy'));
    assert.deepEqual(result, { nodeCount: 0, userCount: 0 });
    assert.equal(called, 0);
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
        logger: { info() {}, warn() {}, error() {} },
    });
    const result = await resync.resyncPlan(planFixture());
    assert.deepEqual(result, { nodeCount: 1, userCount: 2 });
    assert.deepEqual(pushed, ['P/u1', 'P/u2']);
});

test('TopologyUserResync: retries a failed push once and continues', async () => {
    const attempts = [];
    const resync = new TopologyUserResync({
        HyNode: hyNodeFixture({ 'node-portal': { _id: 'x', name: 'P', type: 'xray' } }),
        syncService: {
            async _getUsersForNode() { return [{ userId: 'u1' }, { userId: 'u2' }]; },
            async addXrayUser(node, user) {
                attempts.push(user.userId);
                if (user.userId === 'u1') throw new Error('agent down');
                return true;
            },
        },
        logger: { info() {}, warn() {}, error() {} },
        sleep: async () => {},
    });
    const result = await resync.resyncPlan(planFixture());
    assert.deepEqual(result, { nodeCount: 1, userCount: 1 });
    assert.deepEqual(attempts, ['u1', 'u1', 'u2']);
});

test('TopologyUserResync: no-op without legacy syncService user API', async () => {
    const resync = new TopologyUserResync({
        HyNode: hyNodeFixture({ 'node-portal': { _id: 'x', name: 'P', type: 'xray' } }),
        syncService: {},
        logger: { info() {}, warn() {}, error() {} },
    });
    const result = await resync.resyncPlan(planFixture());
    assert.deepEqual(result, { nodeCount: 0, userCount: 0 });
});
