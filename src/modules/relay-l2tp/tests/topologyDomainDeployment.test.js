'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    TopologyDeploymentService,
} = require('../services/topologyDeploymentService');

function fakeValidator() {
    return { valid: true, errors: [] };
}

function fakeCompiler() {
    return { valid: true, relays: [] };
}

function twoDomainSnapshot() {
    return {
        revision: 7,
        deployedRevision: 6,
        nodes: [
            { _id: 'pa', cascadeRole: 'portal' },
            { _id: 'ba', cascadeRole: 'bridge' },
            { _id: 'pb', cascadeRole: 'portal' },
            { _id: 'rb', cascadeRole: 'relay' },
            { _id: 'bb', cascadeRole: 'bridge' },
        ],
        links: [
            { _id: 'la1', portalNode: 'pa', bridgeNode: 'ba', mode: 'forward', active: true },
            { _id: 'lb1', portalNode: 'pb', bridgeNode: 'rb', mode: 'forward', active: true },
            { _id: 'lb2', portalNode: 'rb', bridgeNode: 'bb', mode: 'forward', active: true },
        ],
        groups: [],
    };
}

function createHarness(snapshot = twoDomainSnapshot()) {
    const calls = { applied: [], markDeployed: null };
    const repository = {
        async pinTopology({ prepare }) {
            const prepared = await prepare(snapshot);
            return { revision: snapshot.revision, deployedRevision: snapshot.deployedRevision, ...prepared };
        },
        async markDeployed(args) {
            calls.markDeployed = args;
            return { revision: args.expectedRevision, deployedRevision: args.expectedRevision };
        },
    };
    const nodeDeployer = {
        async applyNode({ nodeId }) {
            calls.applied.push(nodeId);
            return { ok: true, changed: false };
        },
        async verifyNode() {
            return { ok: true };
        },
        async rollbackNode() {
            return { ok: true };
        },
    };
    const service = new TopologyDeploymentService({
        repository,
        nodeDeployer,
        validator: fakeValidator,
        compiler: fakeCompiler,
        idFactory: prefix => `${prefix}-1`,
    });
    return { service, calls };
}

test('deploy without domainKey is rejected when multiple domains exist', async () => {
    const { service } = createHarness();
    await assert.rejects(
        service.deploy({ expectedTopologyRevision: 7 }),
        error => error.code === 'TOPOLOGY_DOMAIN_REQUIRED'
            && Array.isArray(error.domains)
            && error.domains.length === 2,
    );
});

test('deploy with domainKey slices the pinned topology to that domain only', async () => {
    const { service, calls } = createHarness();
    // domain B contains pb/rb/bb; its key is the lexicographically smallest id
    const result = await service.deploy({ expectedTopologyRevision: 7, domainKey: 'bb' });
    assert.deepEqual([...calls.applied].sort(), ['bb', 'pb', 'rb']);
    assert.equal(calls.markDeployed.domainKey, 'bb');
    assert.equal(typeof calls.markDeployed.domainLabel, 'string');
    assert.equal(result.domain.key, 'bb');
    assert.deepEqual(result.domain.nodeIds, ['bb', 'pb', 'rb']);
});

test('deploy with an unknown domainKey fails closed', async () => {
    const { service, calls } = createHarness();
    await assert.rejects(
        service.deploy({ expectedTopologyRevision: 7, domainKey: 'ghost' }),
        error => error.code === 'TOPOLOGY_DOMAIN_NOT_FOUND',
    );
    assert.deepEqual(calls.applied, []);
});

test('single-domain graph deploys through the legacy path without a key', async () => {
    const snapshot = twoDomainSnapshot();
    // drop domain B entirely
    snapshot.nodes = snapshot.nodes.filter(node => ['pa', 'ba'].includes(node._id));
    snapshot.links = snapshot.links.filter(link => link._id === 'la1');
    const { service, calls } = createHarness(snapshot);
    await service.deploy({ expectedTopologyRevision: 7 });
    assert.deepEqual([...calls.applied].sort(), ['ba', 'pa']);
    assert.equal(calls.markDeployed.domainKey, undefined);
});
