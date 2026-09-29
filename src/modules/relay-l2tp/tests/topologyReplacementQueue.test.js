'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { TopologyOperationCoordinator } = require('../services/topologyOperationCoordinator');
const TopologyOperation = require('../models/topologyOperationModel');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const nodes = ['portal', 'relay', 'bridge'].map(role => ({ _id: role, cascadeRole: role }));
const links = [
    ['upstream', 'portal', 'relay', 'deployed'],
    ['old', 'relay', 'bridge', 'online'],
    ['new', 'relay', 'bridge', 'pending'],
].map(([_id, portalNode, bridgeNode, status]) => ({
    _id, portalNode, bridgeNode, mode: 'reverse', active: true, status,
}));
const snapshot = {
    revision: 7, deployedRevision: 5, nodes, links,
    groups: [{ _id: 'group', mode: 'reverse', strategy: 'priority-failover', paths: [
        { pathKey: 'main', linkIds: ['upstream', 'old'], priority: 1, enabled: true },
    ] }],
    activeRouteGroupIds: ['group'], installedRouteGroupIds: ['group'],
    installedRouteOwners: [{ groupId: 'group', nodeId: 'relay' }],
};

test('queues a frozen replacement without mutating the installed path', async () => {
    const pinnedSnapshot = structuredClone(snapshot);
    pinnedSnapshot.nodes.push({ _id: 'other-portal', cascadeRole: 'portal' },
        { _id: 'other-relay', cascadeRole: 'relay' });
    pinnedSnapshot.links.push({ _id: 'unrelated-pending', portalNode: 'other-portal',
        bridgeNode: 'other-relay', mode: 'reverse', active: true, status: 'pending' });
    const before = structuredClone(pinnedSnapshot);
    let frozen;
    let planInput;
    const session = { inTransaction: () => true };
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: { async admitTopology({prepare,admit}) {
            const prepared = await prepare(pinnedSnapshot, session);
            await admit({revision:7,deployedRevision:5,...prepared}, session);
            return {revision:7,deployedRevision:5,...prepared};
        } },
        planMaterializer: { async materialize(input) {
            planInput = input;
            return {nodes: [
                {nodeRef:'portal',role:'portal',candidate:{sha256:'p'},checks:[]},
                {nodeRef:'relay-1',role:'relay',candidate:{sha256:'r'},checks:[]},
                {nodeRef:'bridge',role:'bridge',candidate:{sha256:'b'},checks:[]},
            ]};
        } },
        operationRepository: {async createFrozen(input) { frozen = input; }},
        validator: () => ({valid:true}),
        idFactory: () => 'operation-replacement',
    });
    const result = await coordinator.queue({expectedTopologyRevision:7,scope:{
        kind:'link.replace',linkId:'new',linkIds:['upstream','new'],
        oldLinkId:'old',groupId:'group',pathKey:'main',
    }});
    assert.equal(result.operationId,'operation-replacement');
    assert.deepEqual(pinnedSnapshot,before);
    assert(Object.isFrozen(planInput.pinnedSnapshot));
    assert(Object.isFrozen(planInput.pinnedSnapshot.topology.groups[0].paths[0].linkIds));
    assert.deepEqual(planInput.pinnedSnapshot.topology.links.map(link => link.id),['new','upstream']);
    assert.deepEqual(planInput.pinnedSnapshot.topology.groups[0].paths[0].linkIds,['upstream','new']);
    assert.equal(frozen.kind,'link.replace');
    assert.equal(frozen.oldLinkId,'old');
    assert.equal(frozen.groupId,'group');
    assert.equal(frozen.pathKey,'main');
    assert.equal(frozen.ownerNodeId,'relay');
    assert.deepEqual(frozen.oldPathLinkIds, ['upstream', 'old']);
    assert.equal(frozen.heldTopologyAdmission,true);
});

test('replacement idempotency never acknowledges a different old path for the same new link', async () => {
    let admissions = 0;
    const session = { inTransaction: () => true };
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: { async admitTopology({ prepare, admit }) {
            admissions += 1;
            const prepared = await prepare(structuredClone(snapshot), session);
            await admit({ revision: 7, deployedRevision: 5, ...prepared }, session);
            return { revision: 7, deployedRevision: 5, ...prepared };
        } },
        planMaterializer: { async materialize() { return { nodes: [] }; } },
        operationRepository: { async createFrozen() {} },
        validator: () => ({ valid: true }),
        idFactory: () => 'replacement-op',
    });
    const scope = { kind: 'link.replace', linkId: 'new',
        linkIds: ['upstream', 'new'], oldLinkId: 'old',
        groupId: 'group', pathKey: 'main' };
    await coordinator.queue({ expectedTopologyRevision: 7, scope });
    await assert.rejects(coordinator.queue({ expectedTopologyRevision: 7,
        scope: { ...scope, pathKey: 'nonexistent' } }),
    error => error.code === 'INVALID_TOPOLOGY_DEPLOYMENT');
    assert.equal(admissions, 2);
});

test('durable replacement identity requires distinct source and target links', async () => {
    const ids = ['a','b','c','d'].map(char => char.repeat(24));
    const base = { topologyRevision:7, priorDeployedRevision:5,
        kind:'link.replace', linkId:ids[0], linkIds:[ids[0],ids[1]],
        oldLinkId:ids[2], groupId:ids[3], pathKey:'main', ownerNodeId:ids[1],
        oldPathLinkIds:[ids[1], ids[2]],
        status:'queued', nodes:[] };
    await new TopologyOperation(base).validate();
    await assert.rejects(new TopologyOperation({...base, oldLinkId:ids[0]}).validate());
    await assert.rejects(new TopologyOperation({...base, groupId:undefined}).validate());
    await assert.rejects(new TopologyOperation({...base, ownerNodeId:undefined}).validate());
});

test('frozen insertion retains replacement path identity in the same session', async () => {
    const ids = ['a','b','c','d'].map(char => char.repeat(24));
    let stored;
    const repository = new TopologyOperationRepository({model:{
        async create(rows, options) { assert.equal(options.session.inTransaction(), true);
            stored = rows[0]; return rows; },
        findOneAndUpdate() {}, updateOne() {},
    }});
    const input = {operationId:ids[0],topologyRevision:7,priorDeployedRevision:5,
        kind:'link.replace',linkId:ids[1],linkIds:[ids[1]],
        oldLinkId:ids[2],groupId:ids[3],pathKey:'main',ownerNodeId:ids[1],
        oldPathLinkIds:[ids[1],ids[2]],nodes:[],
        heldTopologyAdmission:true,admissionFingerprint:'f'.repeat(64),
        session:{inTransaction:()=>true}};
    await repository.createFrozen(input);
    assert.equal(stored.oldLinkId,ids[2]);
    assert.equal(stored.pathKey,'main');
    assert.equal(stored.ownerNodeId,ids[1]);
});
