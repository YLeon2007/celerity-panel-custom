'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createRootTestPhysicalAuthority } = require('../runtime/testPhysicalController');
const env = Object.freeze({ PANEL_DOMAIN: 'test.infograd.online', L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' });
test('ordinary TEST factory reports missing activation input instead of returning an unbound runtime', () => {
    assert.throws(() => createRootTestPhysicalAuthority({ env, read() { throw Object.assign(new Error('missing'), { code: 'ENOENT' }); } }),
        { code: 'TOPOLOGY_TEST_ACTIVATION_REQUIRED' });
});
test('dormant and PROD factories keep their existing no-authority behavior', () => {
    for (const e of [{}, { ...env, PANEL_DOMAIN: 'lm1.infograd.online' }, { ...env, L2TP_EXECUTION_ENABLED: 'false' }]) {
        assert.equal(createRootTestPhysicalAuthority({ env: e, read() { assert.fail('must not read'); } }), undefined);
    }
});

const { createDedicatedTestAuthority } = require('../runtime/dedicatedTestAuthority');
const { createHash } = require('node:crypto');
const sha = x => createHash('sha256').update(x).digest('hex');
const id = '123456789012345678901234';
const mid = '11111111-1111-4111-8111-111111111111';
function dedicatedFixture() {
    const snapshot = { source: 'node-readback', configSha256: sha('{}'), unitSha256: sha('unit'), serviceActive: 'inactive', serviceEnabled: 'disabled' };
    const provision = { nodeId: id, targetProfile: 'xray-bridge', machineId: '1'.repeat(32), applicationSha256: '2'.repeat(64), originalSnapshot: snapshot };
    const pin = { nodeId: id, targetProfile: 'xray-bridge', machineId: provision.machineId,
        hostKeySha256: '3'.repeat(64), provisionSha256: sha(JSON.stringify(provision)), maintenanceId: mid,
        endpoint: { ip: '10.203.61.3', port: 2223, username: 'root' }, privateKeyPath: '/etc/celerity/key' };
    const config = { version: 1, executionContext: { target: 'test', hostIdentity: 'test.infograd.online' }, applicationSha256: provision.applicationSha256,
        predecessor: { status: 'joined-and-removed', exit: 0, pid: 12, processStartTime: '123', instanceId: '4'.repeat(64) }, nodes: [pin] };
    const observed = { provision, bootId: mid, current: { 'xray-bridge': snapshot }, journal: null };
    const state = { alive: true, absent: true, closes: 0 };
    const authority = createDedicatedTestAuthority({ config, predecessorAbsent: () => state.absent,
        open: async () => ({ get alive() { return state.alive; }, observe: async () => structuredClone(observed), close() { state.closes++; state.alive = false; } }) });
    return { authority, config, state, observed };
}
test('real factory selects the dedicated startup only by explicit TEST mode and validates its installed input', () => {
    const f = dedicatedFixture();
    const a = createRootTestPhysicalAuthority({ env: { ...env, TOPOLOGY_TEST_STARTUP_MODE: 'dedicated-runtime-v1' }, read(p) {
        assert.equal(p, '/etc/celerity/topology-test-dedicated.json'); return Buffer.from(JSON.stringify(f.config));
    } });
    assert.equal(a.executionContext.hostIdentity, 'test.infograd.online');
    a.close();
    assert.throws(() => createRootTestPhysicalAuthority({ env: { ...env, TOPOLOGY_TEST_STARTUP_MODE: 'skip' } }), { code: 'TOPOLOGY_TEST_STARTUP_MODE_INVALID' });
});
test('dedicated scope uses observed pristine snapshots and excludes a live predecessor', async () => {
    const f = dedicatedFixture(); f.state.absent = false;
    await assert.rejects(f.authority.withHeldAuthority(f.config.executionContext, () => assert.fail('no callback')), { code: 'TOPOLOGY_TEST_DEDICATED_UNPROVEN' });
    f.state.absent = true;
    await f.authority.withHeldAuthority(f.config.executionContext, async capability => {
        const result = await capability.withCapturedTestOwnerEnrollment(async (plan, check) => { await check(); return plan; });
        assert.equal(result.nodes[0].nodeId, id);
        assert.equal(result.nodes[0].originalSnapshot.configSha256, sha('{}'));
    });
    assert.equal(f.state.closes, 1);
});
test('changed physical provisioning and old/unknown journal cannot become a fresh enrollment', async () => {
    for (const mutate of [o => { o.provision.machineId = '9'.repeat(32); }, o => { o.journal = { version: 2 }; }, o => { o.current['xray-bridge'].configSha256 = '9'.repeat(64); }]) {
        const f = dedicatedFixture(); mutate(f.observed);
        await assert.rejects(f.authority.withHeldAuthority(f.config.executionContext, c => c.withCapturedTestOwnerEnrollment(() => assert.fail('not a genuine new runtime'))));
        assert.equal(f.state.closes, 1);
    }
});
test('revocation closes the scoped observer and prevents escaped or repeated activation', async () => {
    const f = dedicatedFixture(); let captured;
    await f.authority.withHeldAuthority(f.config.executionContext, c => { captured = c; });
    await assert.rejects(captured.assertHeld());
    await assert.rejects(f.authority.withHeldAuthority(f.config.executionContext, c => c.assertHeld()));
});

test('successor uses fresh held journal close status, not the stored close response', async () => {
    const f = dedicatedFixture();
    const { randomUUID } = require('node:crypto');
    const binding = { executionContext: f.config.executionContext.hostIdentity, operationId: id,
        nodeId: id, candidateHash: 'sha256:' + 'a'.repeat(64), backupId: 'backup', targetProfile: 'xray-bridge',
        attemptId: randomUUID(), generation: randomUUID(), predecessorGeneration: 'none', bootId: mid,
        commandIds: { close: randomUUID() } };
    const receipt = { ...Object.fromEntries(['executionContext','operationId','nodeId','candidateHash','backupId','targetProfile','attemptId','generation','predecessorGeneration'].map(k => [k,binding[k]])),
        ok: true, command: 'close', commandId: binding.commandIds.close, protocolVersion: 2,
        completion: 'completed', phase: 'closed', terminal: true, ownershipRetained: true,
        terminalOutcome: 'cancelled', bootId: mid, systemdJob: 'not-applicable', serviceState: 'not-applicable', completedCommand: 'close' };
    f.observed.journal = { head: binding.generation, generations: { [binding.generation]: {
        phase: 'closed', commands: { [binding.commandIds.close]: { command: 'close', state: 'completed', receipt } } } } };
    await f.authority.withHeldAuthority(f.config.executionContext, async cap => {
        await cap.withVerifiedAuthority({ action: 'successor', executionContext: f.config.executionContext,
            enrollment: { nodeId:id, targetProfile:'xray-bridge', endpoint:f.config.nodes[0].endpoint,
                nodeIdentity:{machineId:'1'.repeat(32),sshHostKeySha256:'3'.repeat(64)}, bootId:mid },
            predecessor: { bindingId:randomUUID(), binding } }, async proof => {
            assert.equal(proof.predecessor.receipt.command, 'status');
            assert.equal(proof.predecessor.headGeneration, binding.generation);
        });
    });
    assert.equal(receipt.command, 'close');
});

