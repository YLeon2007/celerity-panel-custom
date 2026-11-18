'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createProductionPhysicalAuthority } = require('../runtime/productionPhysicalAuthority');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');

// Separate the independently accepted runtime pins from the simulated SSH reply.
// No database, service or real node is used here.
function fixture(change, pairCase) {
    const originalScope = { epoch: randomUUID(), bundleSha256: 'a'.repeat(64), ownerGeneration: randomUUID() };
    const n = { kind: 'node', policySha256: 'b'.repeat(64), physical: { machineId: '1'.repeat(32), bootId: randomUUID(), sshHostKeySha256: '2'.repeat(64) },
        endpoint: { ip: '192.0.2.1', port: 22, username: 'root' }, privateKeyPath: '/etc/celerity/fixture-not-read', maintenanceId: randomUUID(),
        nodeId: '1'.repeat(24), targetProfile: 'xray-main', proofRef: 'accepted-original', originalScope,
        originalSnapshot: { source: 'node-readback', configSha256: '3'.repeat(64), unitSha256: '4'.repeat(64), serviceActive: 'active', serviceEnabled: 'enabled' },
        acceptedOwner: { owner: 'topology', generation: originalScope.ownerGeneration } };
    const b = { ...structuredClone(n), nodeId:'2'.repeat(24), targetProfile:'xray-bridge', endpoint:{...n.endpoint,ip:'192.0.2.2'},
        physical:{machineId:'2'.repeat(32),bootId:randomUUID(),sshHostKeySha256:'5'.repeat(64)}, maintenanceId:randomUUID() };
    const nodes = pairCase ? [n,b] : [n];
    const actions = [];
    const authority = createProductionPhysicalAuthority({ config: { version: 1, executionContext: PROD, mode: 'runtime', admission: { serverContext: PROD }, host: { ...n, kind: 'host' }, nodes },
        open: async pin => ({ alive: true, close() {}, async request(action, value) {
            actions.push(action);
            const node = nodes.find(c=>c.nodeId===pin.nodeId);
            if (action === 'observe') return { serverContext: PROD, kind: 'node', policySha256: node.policySha256, physical: node.physical, endpoint: node.endpoint,
                maintenanceId: node.maintenanceId, held: true, nodeId: node.nodeId, targetProfile: node.targetProfile, oldBackend: { instanceId: 'previous', pid: 22, processStartTime: '1' },
                journal: null, pristine: true, current: node.originalSnapshot, ...(node===b ? pairCase : {}) };
            if (action === 'attach') assert.deepEqual(value, node.originalScope);
            assert.ok(['attach', 'read'].includes(action));
            return { ...node.originalScope, ...change, phase: 'captured-held' };
        } }) });
    const pair = nodes.map(node=>({nodeId:node.nodeId,targetProfile:node.targetProfile,maintenanceId:node.maintenanceId,
        ownerGeneration:node.acceptedOwner.generation,bootId:node.physical.bootId,nodeIdentity:{machineId:node.physical.machineId,
            sshHostKeySha256:node.physical.sshHostKeySha256},endpoint:node.endpoint,
        originalSnapshot:Object.fromEntries(Object.entries(node.originalSnapshot).filter(([k])=>k!=='source'))}));
    return { authority, actions, pair };
}
for (const [label, override] of [['clean',{}],['prior journal',{journal:{}}],['legacy files',{pristine:false}],['original drift',{current:{}}]]) {
    test(`partial reservation: require both attached originals and untouched roots: ${label}`, async()=>{
        const {authority,pair,actions}=fixture({},override);
        try {
            const held=authority.withHeldAuthority(PROD,c=>c.withCapturedOwnerEnrollment(async()=>c.checkPristineReservationPair(pair)));
            if(label==='clean') assert.equal(await held,true);
            else await assert.rejects(held,{code:'PRODUCTION_PHYSICAL_AUTHORITY_UNKNOWN_RETAINED'});
            assert.equal(actions.filter(a=>a==='attach').length,2);
            assert.ok(actions.every(a=>['observe','attach','read'].includes(a)));
        } finally {authority.close();}
    });
}
test('partial reservation refuses a different durable original even if the current physical profile matches its pin', async t => {
    for (const [field,value] of [['configSha256','9'.repeat(64)],['unitSha256','8'.repeat(64)],
        ['serviceActive','inactive'],['serviceEnabled','masked']]) await t.test(field,async()=>{
        const {authority,pair,actions}=fixture({},{});
        pair[1].originalSnapshot[field]=value;
        try {
            await assert.rejects(authority.withHeldAuthority(PROD,c=>c.withCapturedOwnerEnrollment(()=>c.checkPristineReservationPair(pair))),
                {code:'PRODUCTION_PHYSICAL_AUTHORITY_UNKNOWN_RETAINED'});
            assert.ok(actions.every(a=>['observe','attach','read'].includes(a)));
        } finally {authority.close();}
    });
});
test('one physical observation per shared host/node per checkpoint, no cross-checkpoint cache', async () => {
    const {authority,actions}=fixture({});
    try {
        await authority.withHeldAuthority(PROD,async c=>{
            assert.deepEqual(actions,['observe']);
            await c.assertHeld(); await c.assertHeld();
            assert.deepEqual(actions,['observe','observe','observe']);
        });
        assert.equal(actions.filter(a=>a==='observe').length,4);
    } finally { authority.close(); }
});
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
