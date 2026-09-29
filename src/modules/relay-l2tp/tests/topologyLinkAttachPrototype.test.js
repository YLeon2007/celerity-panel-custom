'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { TopologyOperationCoordinator } = require('../services/topologyOperationCoordinator');
const { buildL2tpXrayFragment } = require('../services/l2tpXrayFragmentProvider');
const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
const { TopologyPppReadinessGate } = require('../services/topologyPppReadinessGate');

// RED contract for an installed PPP owner with no published route-group path.
// A third POST must produce a private, complete candidate, never publish it at
// queue time, and must not mistake a verified PPP account for working egress.
test('link.attach queues a private complete path for the uniquely installed owner', async () => {
    const snapshot = {
        revision: 3, deployedRevision: 0,
        nodes: [
            { _id: 'p', cascadeRole: 'portal' },
            { _id: 'r1', cascadeRole: 'relay' },
            { _id: 'r2', cascadeRole: 'relay' },
            { _id: 'b', cascadeRole: 'bridge' },
        ],
        links: [
            { _id: 'pr1', portalNode: 'p', bridgeNode: 'r1', mode: 'reverse', active: true, status: 'staged' },
            { _id: 'r1r2', portalNode: 'r1', bridgeNode: 'r2', mode: 'reverse', active: true, status: 'staged' },
            { _id: 'r2b', portalNode: 'r2', bridgeNode: 'b', mode: 'reverse', active: true, status: 'pending' },
        ],
        groups: [{ _id: 'group', mode: 'reverse', strategy: 'priority-failover', paths: [] }],
        activeRouteGroupIds: ['group'], installedRouteGroupIds: ['group'],
        installedRouteOwners: [{ groupId: 'group', nodeId: 'r1', pathKey: 'main' }],
    };
    const before = structuredClone(snapshot);
    let frozen;
    let candidate;
    const session = { inTransaction: () => true };
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: { async admitTopology({ prepare, admit }) {
            const prepared = await prepare(snapshot, session);
            await admit({ revision: 3, deployedRevision: 0, ...prepared }, session);
            return { revision: 3, deployedRevision: 0, ...prepared };
        } },
        planMaterializer: { async materialize(input) {
            candidate = input.pinnedSnapshot.topology;
            return { nodes: [
                { nodeRef: 'portal', role: 'portal', candidate: { sha256: 'p' }, checks: [] },
                { nodeRef: 'relay-1', role: 'relay', candidate: { sha256: 'r1' }, checks: [] },
                { nodeRef: 'relay-2', role: 'relay', candidate: { sha256: 'r2' }, checks: [] },
                { nodeRef: 'bridge', role: 'bridge', candidate: { sha256: 'b' }, checks: [] },
            ] };
        } },
        operationRepository: { async createFrozen(input) { frozen = input; } },
        idFactory: () => 'attach-operation',
    });
    const result = await coordinator.queue({ expectedTopologyRevision: 3, scope: {
        kind: 'link.attach', linkId: 'r2b', linkIds: ['pr1', 'r1r2', 'r2b'],
        groupId: 'group', pathKey: 'main',
    } });
    assert.equal(result.status, 'queued');
    assert.deepEqual(snapshot, before, 'the DB snapshot must remain unchanged at admission');
    assert(Object.isFrozen(candidate));
    assert.deepEqual(candidate.groups[0].paths[0].linkIds, ['r1r2', 'r2b']);
    assert.equal(frozen.ownerNodeId, 'r1');
    assert.equal(frozen.heldTopologyAdmission, true);
});

test('a PPP fragment without a selected healthy path blocks even if topology provides a listener', () => {
    const tags = { inbound: 'ppp-in', blockOutbound: 'block' };
    const old = buildL2tpXrayFragment({
        plan: { group: { id: 'group' }, selectedPathKey: 'main', paths: [],
            relay: { controlPlaneIps: [] } }, tags, tproxyPort: 12345,
    });
    const privateCandidate = buildL2tpXrayFragment({
        plan: { group: { id: 'group' }, selectedPathKey: 'main', paths: [
            { pathKey: 'main', healthy: true, outboundTag: 'cascade-main' },
        ], relay: { controlPlaneIps: [] } }, tags, tproxyPort: 12345,
    });
    assert.deepEqual(old.outbounds, []);
    assert.equal(old.routingRules.at(-1).outboundTag, 'block');
    assert.equal(privateCandidate.outbounds[0].settings.servers[0].port,
        cascadePathIngressPort('group', 'main'));
    assert.equal(privateCandidate.routingRules.at(-1).outboundTag, 'cascade-main');
});

test('link.attach cannot pass PPP readiness on verify-users alone without fragment egress readback', async () => {
    const operationId = 'abcdef012345abcdef012345';
    const state = { node: 'r1', status: 'installed', desiredState: 'installed', secretRevision: 3 };
    const user = { relayNode: 'r1', enabled: true, desiredRevision: 3,
        appliedRevision: 3, syncStatus: 'synced', syncOperationId: operationId };
    const gate = new TopologyPppReadinessGate({
        RelayL2tpState: { findOne: () => ({ select: () => ({ lean: async () => state }) }) },
        L2tpUser: { find: () => ({ select: () => ({ lean: async () => [user] }) }) },
        L2tpOperation: { findOne: () => ({ sort: () => ({ select: () => ({ lean: async () => ({
            _id: operationId, node: 'r1', kind: 'sync_users', status: 'succeeded',
            plan: { operationId, relayId: 'r1', desired: { credentialRevision: 3 } },
        }) }) }) }) },
        transportResolver: async () => ({ runArtifactCommand: async () => ({
            ok: true, code: 'USERS_VERIFIED', credentialRevision: 3,
            enabledUserCount: 1, managedUserCount: 1,
        }) }),
    });
    const result = await gate.verifyPlan({ kind: 'link.attach', groupId: 'group',
        pathKey: 'main', ownerNodeId: 'r1', nodes: [
            { role: 'portal', node: 'p' }, { role: 'relay', node: 'r1' },
            { role: 'bridge', node: 'b' },
        ] });
    assert.equal(result.ok, false, 'unverified L2TP fragment route must fence attach success');
});
