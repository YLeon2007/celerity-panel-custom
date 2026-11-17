'use strict';
// LOCAL observation-only fixtures; no runtime authority or terminal proof import.
const test = require('node:test'), assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { createDedicatedTestAuthority } = require('../runtime/dedicatedTestAuthority');
const sha = s => createHash('sha256').update(s).digest('hex');
const context = { target: 'test', hostIdentity: 'test.infograd.online' };
function fixture(count) {
    const observations = new Map(), bootId = randomUUID();
    const nodes = Array.from({ length: count }, (_, index) => {
        const digit = String(index + 1), nodeId = digit.repeat(24), machineId = digit.repeat(32);
        const snapshot = { source: 'node-readback', configSha256: sha('{}'), unitSha256: sha('unit'), serviceActive: 'active', serviceEnabled: 'enabled' };
        const provision = { nodeId, machineId, targetProfile: 'xray-bridge', applicationSha256: 'a'.repeat(64), originalSnapshot: snapshot };
        observations.set(nodeId, { provision, bootId, current: { 'xray-bridge': snapshot }, journal: { head: 'local-observation-only' }, runnerIdle: true });
        return { nodeId, machineId, targetProfile: 'xray-bridge', hostKeySha256: digit.repeat(64), provisionSha256: sha(JSON.stringify(provision)), maintenanceId: randomUUID(), endpoint: { ip: '192.0.2.' + (index + 1), port: 2223, username: 'root' }, privateKeyPath: '/etc/celerity/synthetic' };
    });
    const authority = createDedicatedTestAuthority({ config: { version: 1, executionContext: context, applicationSha256: 'a'.repeat(64), predecessor: { status: 'joined-and-removed', exit: 0, pid: 12, processStartTime: '123', instanceId: 'b'.repeat(64) }, nodes }, predecessorAbsent: () => true,
        open: async pin => { let alive = true; return { get alive() { return alive; }, observe: async () => structuredClone(observations.get(pin.nodeId)), close() { alive = false; } }; } });
    return { authority, observations, nodes, bindings: nodes.map(n => ({ executionContext: context.hostIdentity, nodeId: n.nodeId, targetProfile: n.targetProfile, maintenanceId: n.maintenanceId, bootId, endpoint: n.endpoint, nodeIdentity: { machineId: n.machineId, sshHostKeySha256: n.hostKeySha256 } })) };
}
for (const count of [1, 2, 3, 4]) test(`settled observation reads every independently enrolled node (${count}), without a two-node assumption`, async () => {
    const f = fixture(count); let calls = 0;
    await f.authority.withHeldAuthority(context, cap => cap.withRetainedVerifyObservation(f.bindings, async (observed, check) => { calls++; assert.equal(observed.nodes.length, count); await check(); }));
    assert.equal(calls, 1);
});
test('fresh same authority restores verified native beforeimages and grants exact classic transfer without inventing an old original holder', async () => {
    const f=fixture(4);let restores=0;
    const pins=f.nodes.map(n=>{const v=f.observations.get(n.nodeId);v.current[n.targetProfile]={...v.current[n.targetProfile],configSha256:sha('native')};
        v.journal={head:'actual-modeled-head',generations:{'actual-modeled-head':{phase:'closed',binding:{candidateHash:'sha256:'+sha('native')}}}};
        const {source,...originalSnapshot}=v.provision.originalSnapshot;
        return {nodeId:n.nodeId,targetProfile:n.targetProfile,ownerGeneration:randomUUID(),nodeIdentity:{machineId:n.machineId,sshHostKeySha256:n.hostKeySha256},originalSnapshot};});
    await f.authority.restoreClassicSnapshots(pins,async()=>{restores++;for(const n of f.nodes){const v=f.observations.get(n.nodeId);v.current[n.targetProfile]=structuredClone(v.provision.originalSnapshot);}});
    for(const p of pins)await f.authority.withHeldAuthority(context,c=>c.withVerifiedMaintenance({binding:{action:'handback',node:p.nodeId,profile:p.targetProfile,generation:p.ownerGeneration,nodeIdentity:p.nodeIdentity},proofRef:'dedicated-'+f.nodes.find(n=>n.nodeId===p.nodeId).maintenanceId},async proof=>{
        assert.equal(proof.status,'verified');assert.equal(proof.readback.configSha256,p.originalSnapshot.configSha256);
    }));
    await f.authority.releaseClassicSnapshots();assert.equal(restores,1);
});
for (const fault of ['duplicate', 'foreign', 'boot', 'maintenance', 'endpoint', 'physical-key']) test(`settled multi-node observation retains independent ${fault} rejection`, async () => {
    const f = fixture(3), bindings = structuredClone(f.bindings);
    if (fault === 'duplicate') bindings[1] = bindings[0];
    if (fault === 'foreign') bindings[1].nodeId = 'f'.repeat(24);
    if (fault === 'boot') bindings[1].bootId = randomUUID();
    if (fault === 'maintenance') bindings[1].maintenanceId = randomUUID();
    if (fault === 'endpoint') bindings[1].endpoint.port = 22;
    if (fault === 'physical-key') bindings[1].nodeIdentity.sshHostKeySha256 = 'f'.repeat(64);
    await assert.rejects(f.authority.withHeldAuthority(context, cap => cap.withRetainedVerifyObservation(bindings, () => assert.fail('must not grant observation'))));
});
