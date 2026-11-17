'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createProductionPhysicalAuthority } = require('../runtime/productionPhysicalAuthority');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');

// Separate the independently accepted runtime pins from the simulated SSH reply.
// No database, service or real node is used here.
function fixture(change) {
    const originalScope = { epoch: randomUUID(), bundleSha256: 'a'.repeat(64), ownerGeneration: randomUUID() };
    const n = { kind: 'node', policySha256: 'b'.repeat(64), physical: { machineId: '1'.repeat(32), bootId: randomUUID(), sshHostKeySha256: '2'.repeat(64) },
        endpoint: { ip: '192.0.2.1', port: 22, username: 'root' }, privateKeyPath: '/etc/celerity/fixture-not-read', maintenanceId: randomUUID(),
        nodeId: '1'.repeat(24), targetProfile: 'xray-main', proofRef: 'accepted-original', originalScope,
        originalSnapshot: { source: 'node-readback', configSha256: '3'.repeat(64), unitSha256: '4'.repeat(64), serviceActive: 'active', serviceEnabled: 'enabled' },
        acceptedOwner: { owner: 'topology', generation: originalScope.ownerGeneration } };
    const actions = [];
    const authority = createProductionPhysicalAuthority({ config: { version: 1, executionContext: PROD, mode: 'runtime', admission: { serverContext: PROD }, host: { ...n, kind: 'host' }, nodes: [n] },
        open: async () => ({ alive: true, close() {}, async request(action, value) {
            actions.push(action);
            if (action === 'observe') return { serverContext: PROD, kind: 'node', policySha256: n.policySha256, physical: n.physical, endpoint: n.endpoint,
                maintenanceId: n.maintenanceId, held: true, nodeId: n.nodeId, targetProfile: n.targetProfile, oldBackend: { instanceId: 'previous', pid: 22, processStartTime: '1' },
                journal: null, pristine: true, current: n.originalSnapshot };
            if (action === 'attach') assert.deepEqual(value, originalScope);
            assert.ok(['attach', 'read'].includes(action));
            return { ...originalScope, ...change, phase: 'captured-held' };
        } }) });
    return { authority, actions };
}
for (const [name, change] of [['accepted', {}], ['wrong epoch', { epoch: randomUUID() }], ['wrong original bytes', { bundleSha256: 'd'.repeat(64) }]]) {
    test(`runtime reattach verifies independent originals before enrollment callback: ${name}`, async () => {
        const { authority, actions } = fixture(change); let entered = 0;
        try {
            const work = authority.withHeldAuthority(PROD, c => c.withCapturedOwnerEnrollment(() => ++entered));
            if (name === 'accepted') assert.equal(await work, 1);
            else await assert.rejects(work, { code: 'PRODUCTION_PHYSICAL_AUTHORITY_UNKNOWN_RETAINED' });
            assert.equal(entered, name === 'accepted' ? 1 : 0);
            assert.equal(actions.filter(a => a === 'attach').length, 1);
            assert.ok(!actions.includes('capture'));
        } finally { authority.close(); }
    });
}
