'use strict';
// Local subprocess protocol fixtures. Physical/kernel/UID/SSH facts are SIMULATED.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const { TOPOLOGY_RUNNER_SHA256 } = require('../services/topologyRunnerBootstrapper');
let api;
try { api = require('../runtime/testPhysicalController'); } catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; }
const NODES = {
    '6ab18adc63913ebd4a917471': ['132.243.230.19', 'xray-main'],
    '6ab93ad2646b4b7d2f43c907': ['94.103.2.186', 'xray-main'],
    '6ab18d9c63913ebd4a917670': ['50.114.160.63', 'xray-bridge'],
    '6ab4b53bc4c0304573e06c72': ['104.143.201.72', 'xray-bridge'],
    '6ab189dc63913ebd4a917399': ['212.119.42.100', 'xray-main'],
};
function pins() {
    return { version: 1, executionContext: TEST, nodes: Object.entries(NODES).map(([nodeId, [ip, targetProfile]], i) => ({
        nodeId, targetProfile, endpoint: { ip, port: 2222, username: 'c3-test-runner' },
        physical: { machineId: nodeId === '6ab189dc63913ebd4a917399' ? '7fa266f995fe4aa69e96cf7d01359e34' : String(i + 1).repeat(32), sshHostKeySha256: String(i + 1).repeat(64), bootId: randomUUID() },
        maintenanceId: randomUUID(), planHash: 'a'.repeat(64),
        guard: { pid: 100 + i, start: '123', socket: '/var/lib/c3-test-node-isolation/recovery.sock' },
        operatorKeyPath: '/etc/celerity/test-operator.key',
    })), host: { owner: randomUUID(), guard: { pid: 200, start: '321', socket: '/var/lib/c3-test-node-isolation/host.sock',
        owner: '', planHash: 'a'.repeat(64), session: { pid: 201, start: '320' } },
        backend: { instanceId: 'a'.repeat(64), pid: 333, processStartTime: '42' } } };
}
function observation(config, pin) {
    return { ...structuredClone(pin), installation: { runner: { path: '/usr/local/bin/celerity-topology-node-runner', sha256: TOPOLOGY_RUNNER_SHA256,
        mode: '0750', owner: 'root', regularFile: true, symlink: false, writableByRunner: false }, profile: {
        targetProfile: pin.targetProfile, configDirectoryReady: true, bridgeUnitSha256: pin.targetProfile === 'xray-main' ? null : api.BRIDGE_SHA256,
        bridgeUnitDropIns: pin.targetProfile === 'xray-main' ? null : 'absent' } },
        runnerState: { head: null, journal: 'absent', legacyState: 'absent', terminal: null }, host: pin.nodeId === '6ab189dc63913ebd4a917399' ? config.host : null };
}
function setup(t, mutate = value => value) {
    assert.ok(api?.createTestPhysicalController, 'operational TEST controller missing');
    const config = pins(); config.host.guard.owner = config.host.owner;
    const children = [], channels = [];
    const controller = api.createTestPhysicalController({ config, openChannel: async pin => {
        const value = mutate(observation(config, pin), pin);
        const child = spawn(process.execPath, [path.join(__dirname, 'helpers/physicalObservationProcess.js'), JSON.stringify(value)], { stdio: ['pipe', 'pipe', 'pipe'] });
        children.push(child);
        const channel = new api.AttestationChannel(child.stdout, child.stdin, child, { timeoutMs: 500 });
        channels.push(channel); return channel;
    } });
    t.after(async () => { controller.close(); for (const child of children) if (child.exitCode === null && child.signalCode === null) { const done = new Promise(r => child.once('exit', r)); child.kill(); await done; } });
    return { controller, config, children, channels };
}
test('real subprocess nonce channel supplies current independent observations to scoped binding/runner proofs', async t => {
    const { controller, config } = setup(t);
    const pin = config.nodes[0]; let escaped;
    const enrollment = { nodeId: pin.nodeId, targetProfile: pin.targetProfile, endpoint: pin.endpoint,
        nodeIdentity: { machineId: pin.physical.machineId, sshHostKeySha256: pin.physical.sshHostKeySha256 },
        bootId: pin.physical.bootId, predecessorGeneration: 'none' };
    const challenge = { action: 'enroll', executionContext: TEST, enrollment };
    const result = await controller.withHeldAuthority(TEST, async capability => {
        escaped = capability;
        await capability.withVerifiedAuthority(challenge, async proof => {
            assert.equal(proof.physicalIdentity.machineId, pin.physical.machineId);
            assert.equal(proof.predecessor.journal, 'absent'); assert.deepEqual(proof.oldBackend, { ...config.host.backend, processTree: 'stopped', dispatch: 'disabled' });
        });
        const runnerChallenge = { binding: { executionContext: TEST.hostIdentity, nodeId: pin.nodeId, targetProfile: pin.targetProfile,
            bootId: pin.physical.bootId, maintenanceId: pin.maintenanceId },
            connection: { expectedEndpoint: pin.endpoint, expectedHostKeySha256: pin.physical.sshHostKeySha256 }, role: 'portal' };
        return capability.withVerifiedPreinstalledRunner(runnerChallenge, async (proof, check) => {
            await check(); assert.equal(proof.runner.sha256, TOPOLOGY_RUNNER_SHA256); return 17;
        });
    });
    assert.equal(result, 17);
    await assert.rejects(() => escaped.assertHeld());
});
test('physical drift, any node channel loss and installation drift revoke the complete five-node hold', async t => {
    for (const fault of ['machine', 'plan', 'guard', 'host', 'hash']) await t.test(fault, async t => {
        const { controller, config } = setup(t, (value, pin) => {
            if (fault === 'machine') value.physical.machineId = 'f'.repeat(32);
            if (fault === 'plan') value.planHash = 'f'.repeat(64);
            if (fault === 'guard') value.guard.start = '456';
            if (fault === 'host' && value.host) value.host.guard.pid++;
            if (fault === 'hash') value.installation.runner.sha256 = 'sha256:' + 'f'.repeat(64);
            return value;
        });
        let called = false;
        await assert.rejects(() => controller.withHeldAuthority(TEST, async capability => {
            const pin = config.nodes[0];
            return capability.withVerifiedPreinstalledRunner({ binding: { nodeId: pin.nodeId, targetProfile: pin.targetProfile,
                executionContext: TEST.hostIdentity, bootId: pin.physical.bootId, maintenanceId: pin.maintenanceId },
                connection: { expectedEndpoint: pin.endpoint, expectedHostKeySha256: pin.physical.sshHostKeySha256 }, role: 'portal' }, () => { called = true; });
        }));
        assert.equal(called, false);
        await assert.rejects(() => controller.withHeldAuthority(TEST, () => assert.fail('poisoned scope reused')));
    });
    const { controller, children } = setup(t);
    await assert.rejects(() => controller.withHeldAuthority(TEST, async capability => {
        children.at(-1).kill('SIGKILL');
        await new Promise(resolve => children.at(-1).once('exit', resolve));
        await capability.assertHeld();
    }));
});

test('wrong nonce, malformed output and read deadline never enter work and permanently refuse reuse', async t => {
    for (const fault of ['silent', 'wrong-nonce', 'malformed']) await t.test(fault, async t => {
        const { controller } = setup(t, value => ({ ...value, fixtureBehavior: fault }));
        let calls = 0;
        await assert.rejects(() => controller.withHeldAuthority(TEST, () => { calls++; }));
        await assert.rejects(() => controller.withHeldAuthority(TEST, () => { calls++; }));
        assert.equal(calls, 0);
    });
});

test('missing/shared-foreign/duplicate/cross-paired pins refuse before opening any channel', () => {
    for (const fault of ['missing', 'shared-machine', 'duplicate', 'endpoint', 'guard-array', 'profile', 'maintenance-array']) {
        const config = pins(); config.host.guard.owner = config.host.owner;
        if (fault === 'missing') config.nodes.pop();
        if (fault === 'shared-machine') config.nodes.at(-1).physical.machineId = 'f'.repeat(32);
        if (fault === 'duplicate') config.nodes[1] = config.nodes[0];
        if (fault === 'endpoint') config.nodes[0].endpoint.port = 22;
        if (fault === 'guard-array') config.nodes[0].guard.start = ['123'];
        if (fault === 'profile') config.nodes[0].targetProfile = 'xray-bridge';
        if (fault === 'maintenance-array') config.nodes[0].maintenanceId = [config.nodes[0].maintenanceId];
        let calls = 0;
        assert.throws(() => api.createTestPhysicalController({ config, openChannel() { calls++; } }), /TEST_PHYSICAL_AUTHORITY/);
        assert.equal(calls, 0);
    }
});

test('disabled/wrong/missing private authority performs zero reads or SSH and wrong context cannot connect', async () => {
    let reads = 0, opens = 0;
    for (const env of [{}, { L2TP_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: 'lm1.infograd.online' },
        { L2TP_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: TEST.hostIdentity, TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' }]) {
        assert.equal(api.createRootTestPhysicalAuthority({ env, read() { reads++; assert.fail('private config read'); }, openChannel() { opens++; } }), undefined);
    }
    assert.equal(api.createRootTestPhysicalAuthority({ env: { L2TP_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: TEST.hostIdentity },
        read() { reads++; throw Object.assign(new Error('absent'), { code: 'ENOENT' }); }, openChannel() { opens++; } }), undefined);
    assert.equal(reads, 1); assert.equal(opens, 0);
    const controller = api.createTestPhysicalController({ config: (() => { const c = pins(); c.host.guard.owner = c.host.owner; return c; })(), openChannel() { opens++; } });
    await assert.rejects(() => controller.withHeldAuthority({ target: 'production', hostIdentity: 'lm1.infograd.online' }, () => {}));
    assert.equal(opens, 0); controller.close();
});
