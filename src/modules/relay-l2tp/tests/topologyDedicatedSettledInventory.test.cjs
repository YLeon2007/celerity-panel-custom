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
    return { authority, bindings: nodes.map(n => ({ executionContext: context.hostIdentity, nodeId: n.nodeId, targetProfile: n.targetProfile, maintenanceId: n.maintenanceId, bootId, endpoint: n.endpoint, nodeIdentity: { machineId: n.machineId, sshHostKeySha256: n.hostKeySha256 } })) };
}
for (const count of [1, 2, 3, 4]) test(`settled observation reads every independently enrolled node (${count}), without a two-node assumption`, async () => {
    const f = fixture(count); let calls = 0;
    await f.authority.withHeldAuthority(context, cap => cap.withRetainedVerifyObservation(f.bindings, async (observed, check) => { calls++; assert.equal(observed.nodes.length, count); await check(); }));
    assert.equal(calls, 1);
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
