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
function setup(t, mutate = value => value, configure = () => {}) {
    assert.ok(api?.createTestPhysicalController, 'operational TEST controller missing');
    const config = pins(); config.host.guard.owner = config.host.owner;
    configure(config);
    const children = [], channels = [];
    const controller = api.createTestPhysicalController({ config, openChannel: async pin => {
        const value = mutate(observation(config, pin), pin);
        const child = value.maintenanceRoot
            ? spawn('/usr/bin/python3', [path.join(__dirname, '../../../../scripts/test-node-isolation/physical_maintenance_fixture.py'), JSON.stringify(value)], { stdio: ['pipe', 'pipe', 'pipe'] })
            : spawn(process.execPath, [path.join(__dirname, 'helpers/physicalObservationProcess.js'), JSON.stringify(value)], { stdio: ['pipe', 'pipe', 'pipe'] });
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

test('ordinary default authority observes all five durable originals without invoking the one-shot capture adapter', async t => {
    const config = pins(); config.host.guard.owner = config.host.owner;
    for (const pin of config.nodes) pin.originalSnapshot = { proofRef: 'accepted-original', configSha256: 'b'.repeat(64),
        unitSha256: 'c'.repeat(64), serviceActive: 'active', serviceEnabled: 'enabled' };
    let observations = 0, escaped;
    const controller = api.createRootTestPhysicalAuthority({
        env: { L2TP_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: TEST.hostIdentity },
        read(file) { assert.equal(file, '/etc/celerity/topology-test-physical.json', 'ordinary runtime must never read capture configuration'); return Buffer.from(JSON.stringify(config)); },
        captureSpawn() { assert.fail('ordinary runtime must never capture or recapture'); },
        openChannel: async pin => ({ alive: true, close() {}, async request() {
            observations++;
            const { proofRef: _ref, ...snapshot } = pin.originalSnapshot;
            return { ...observation(config, pin), durableOriginals: { version: 1, bundleSha256: 'd'.repeat(64),
                readback: { source: 'node-readback', ...snapshot } } };
        } }),
    });
    t.after(() => controller.close());
    for (let i = 0; i < 2; i++) assert.equal(await controller.withHeldAuthority(TEST, async capability => {
        escaped = capability.assertHeld; await capability.assertHeld(); return 17;
    }), 17);
    assert.ok(observations >= 30, 'fresh all-five observations must span each ordinary held invocation');
    await assert.rejects(escaped);
});

test('ordinary default refuses any missing/drifted durable original and never falls back to capture or repaired observations', async t => {
    for (const nodeId of Object.keys(NODES)) for (const fault of ['missing', 'digest']) await t.test(`${nodeId}:${fault}`, async t => {
        const config = pins(); config.host.guard.owner = config.host.owner;
        for (const pin of config.nodes) pin.originalSnapshot = { proofRef: 'accepted-original', configSha256: 'b'.repeat(64),
            unitSha256: 'c'.repeat(64), serviceActive: 'active', serviceEnabled: 'enabled' };
        let changed = false, entered = 0;
        const controller = api.createRootTestPhysicalAuthority({
            env: { L2TP_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: TEST.hostIdentity,
                TOPOLOGY_TEST_OWNER_ENROLLMENT: 'true' }, // ignored; not an authority selector
            read(file) { assert.equal(file, '/etc/celerity/topology-test-physical.json'); return Buffer.from(JSON.stringify(config)); },
            captureSpawn() { assert.fail('no capture fallback'); },
            openChannel: async pin => ({ alive: true, close() {}, async request() {
                const { proofRef: _ref, ...snapshot } = pin.originalSnapshot;
                const value = { ...observation(config, pin), durableOriginals: { version: 1, bundleSha256: 'd'.repeat(64),
                    readback: { source: 'node-readback', ...snapshot } } };
                if (changed && pin.nodeId === nodeId) {
                    if (fault === 'missing') delete value.durableOriginals;
                    else value.durableOriginals.readback.configSha256 = 'f'.repeat(64);
                }
                return value;
            } }),
        });
        t.after(() => controller.close());
        await assert.rejects(controller.withHeldAuthority(TEST, async capability => {
            entered++; changed = true; await assert.rejects(capability.assertHeld());
            changed = false; await assert.rejects(capability.assertHeld());
        }));
        assert.equal(entered, 1);
        await assert.rejects(controller.withHeldAuthority(TEST, () => assert.fail('poisoned runtime reused')));
    });
    const config = pins(); config.host.guard.owner = config.host.owner;
    assert.throws(() => api.createRootTestPhysicalAuthority({
        env: { L2TP_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: TEST.hostIdentity },
        read: () => Buffer.from(JSON.stringify(config)), captureSpawn() { assert.fail('missing pins cannot select capture'); },
    }), /TEST_PHYSICAL_AUTHORITY/);
});

test('held physical controller exposes actual config-transfer maintenance (not a caller callback)', async t => {
    const { controller } = setup(t);
    let method;
    await controller.withHeldAuthority(TEST, async capability => { method = capability.withVerifiedMaintenance; });
    assert.equal(typeof method, 'function', 'physical owner-transfer authority missing');
});

const fs = require('node:fs');
const { createHash } = require('node:crypto');
const { TopologyExecutionAuthorityLifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function maintenanceSetup(t, configure = () => {}, transform = value => value) {
    assert.ok(process.env.TMPDIR, 'scratch root required');
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR, 'physical-original-'));
    const bytes = { config: Buffer.from('{"private":"fixture-not-for-logs"}\r\n'), unit: Buffer.from('[Service]\n# exact original\r\n') };
    fs.writeFileSync(path.join(root, 'config.json'), bytes.config, { mode: 0o600 });
    fs.writeFileSync(path.join(root, 'xray.service'), bytes.unit, { mode: 0o644 });
    const state = { serviceActive: 'active', serviceEnabled: 'enabled' };
    fs.writeFileSync(path.join(root, 'service-state.json'), JSON.stringify(state));
    fs.writeFileSync(path.join(root, 'guard-alive'), 'held');
    fs.writeFileSync(path.join(root, 'lock'), '');
    fs.mkdirSync(path.join(root, 'config-directory'), { mode: 0o755 });
    fs.copyFileSync(path.join(__dirname, '../node-artifacts/topology/runner.sh'), path.join(root, 'runner'));
    fs.chmodSync(path.join(root, 'runner'), 0o750);
    const accepted = { proofRef: 'independently-accepted-original-v1', configSha256: sha(bytes.config), unitSha256: sha(bytes.unit), ...state };
    const fixture = setup(t, (value, pin) => pin.nodeId === Object.keys(NODES)[0] ? transform({ ...value, maintenanceRoot: root }) : value,
        config => { config.nodes[0].originalSnapshot = accepted; configure(config); });
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const pin = fixture.config.nodes[0];
    const lifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext: TEST, controller: fixture.controller });
    const challenge = { proofRef: accepted.proofRef, binding: { executionContext: TEST, node: pin.nodeId, profile: pin.targetProfile,
        nodeIdentity: { machineId: pin.physical.machineId, sshHostKeySha256: pin.physical.sshHostKeySha256 },
        generation: randomUUID(), nextGeneration: randomUUID(), action: 'adopt',
        paths: { configPath: '/usr/local/etc/xray/config.json', unitPath: '/etc/systemd/system/xray.service', service: 'xray' } } };
    return { ...fixture, root, bytes, accepted, lifecycle, challenge };
}
test('lifecycle transfers maintenance from real finite Python file readback and revokes escaped checks', async t => {
    const f = maintenanceSetup(t); let check, evidence;
    assert.equal(typeof f.lifecycle.withVerifiedMaintenance, 'function', 'held lifecycle maintenance wiring missing');
    const result = await f.lifecycle.run(() => f.lifecycle.withVerifiedMaintenance(f.challenge, async (proof, held) => {
        evidence = proof; check = held;
        await held(); return 41;
    }));
    assert.equal(result, 41);
    assert.deepEqual(evidence.readback, { source: 'node-readback', ...Object.fromEntries(Object.entries(f.accepted).filter(([key]) => key !== 'proofRef')) });
    assert.equal(JSON.stringify(evidence).includes('fixture-not-for-logs'), false);
    assert.equal(evidence.configBase64, undefined);
    assert.deepEqual(fs.readFileSync(path.join(f.root, 'config.json')), f.bytes.config);
    assert.equal(fs.readFileSync(path.join(f.root, 'guard-alive'), 'utf8'), 'held');
    await assert.rejects(check);
    await assert.rejects(() => f.lifecycle.withVerifiedMaintenance(f.challenge, () => assert.fail('escaped callback')));
});

test('maintenance refuses unaccepted snapshots and exact challenge drift before callback', async t => {
    for (const fault of ['missing-pin', 'wrong-pin', 'context', 'identity', 'path', 'profile', 'proof-ref']) await t.test(fault, async t => {
        const f = maintenanceSetup(t, config => {
            if (fault === 'missing-pin') delete config.nodes[0].originalSnapshot;
            if (fault === 'wrong-pin') config.nodes[0].originalSnapshot.configSha256 = 'f'.repeat(64);
        });
        if (fault === 'context') f.challenge.binding.executionContext = { target: 'production', hostIdentity: 'lm1.infograd.online' };
        if (fault === 'identity') f.challenge.binding.nodeIdentity.machineId = 'f'.repeat(32);
        if (fault === 'path') f.challenge.binding.paths.unitPath = '/untrusted';
        if (fault === 'profile') f.challenge.binding.profile = 'xray-bridge';
        if (fault === 'proof-ref') f.challenge.proofRef = 'not-accepted';
        let calls = 0;
        await assert.rejects(() => f.lifecycle.run(() => f.lifecycle.withVerifiedMaintenance(f.challenge, () => { calls++; })));
        assert.equal(calls, 0);
        assert.deepEqual(fs.readFileSync(path.join(f.root, 'config.json')), f.bytes.config);
        assert.equal(fs.readFileSync(path.join(f.root, 'guard-alive'), 'utf8'), 'held');
    });
});
test('original bytes and independent states must match again for handback; no restore on mismatch', async t => {
    for (const fault of ['none', 'config', 'unit', 'state', 'generation', 'no-capture']) await t.test(fault, async t => {
        const f = maintenanceSetup(t);
        if (fault !== 'no-capture') await f.lifecycle.run(() => f.lifecycle.withVerifiedMaintenance(f.challenge, async () => 1));
        const handback = structuredClone(f.challenge);
        handback.binding = { ...handback.binding, action: 'handback', generation: f.challenge.binding.nextGeneration, nextGeneration: randomUUID() };
        if (fault === 'config') fs.writeFileSync(path.join(f.root, 'config.json'), 'topology replacement');
        if (fault === 'unit') fs.writeFileSync(path.join(f.root, 'xray.service'), 'changed unit');
        if (fault === 'state') fs.writeFileSync(path.join(f.root, 'service-state.json'), JSON.stringify({ serviceActive: 'inactive', serviceEnabled: 'enabled' }));
        if (fault === 'generation') handback.binding.generation = randomUUID();
        let calls = 0;
        const run = () => f.lifecycle.run(() => f.lifecycle.withVerifiedMaintenance(handback, async () => ++calls));
        if (fault === 'none') assert.equal(await run(), 1);
        else { await assert.rejects(run); assert.equal(calls, 0); }
        assert.equal(fs.readFileSync(path.join(f.root, 'guard-alive'), 'utf8'), 'held');
        if (fault === 'config') assert.equal(fs.readFileSync(path.join(f.root, 'config.json'), 'utf8'), 'topology replacement');
        if (fault === 'unit') assert.equal(fs.readFileSync(path.join(f.root, 'xray.service'), 'utf8'), 'changed unit');
    });
});
test('guard loss or swallowed readback failure during await latches revocation without restoring bytes', async t => {
    for (const fault of ['guard', 'bytes', 'callback']) await t.test(fault, async t => {
        const f = maintenanceSetup(t);
        await assert.rejects(() => f.lifecycle.run(() => f.lifecycle.withVerifiedMaintenance(f.challenge, async (_, check) => {
            if (fault === 'guard') fs.writeFileSync(path.join(f.root, 'guard-alive'), 'lost');
            if (fault === 'bytes') fs.writeFileSync(path.join(f.root, 'config.json'), 'new-bytes-remain');
            if (fault === 'callback') throw new Error('uncertain database confirmation');
            await assert.rejects(check); // Swallowing must not resurrect the hold.
        })));
        await assert.rejects(() => f.lifecycle.run(() => assert.fail('poisoned scope reused')));
        if (fault === 'bytes') assert.equal(fs.readFileSync(path.join(f.root, 'config.json'), 'utf8'), 'new-bytes-remain');
        if (fault === 'callback') assert.deepEqual(fs.readFileSync(path.join(f.root, 'config.json')), f.bytes.config);
    });
});

test('private byte codec rejects noncanonical/forged/oversize/missing payloads without exposing contents', async t => {
    for (const fault of ['base64', 'digest', 'oversize', 'missing', 'extra', 'state-array']) await t.test(fault, async t => {
        const f = maintenanceSetup(t, () => {}, value => {
            if (fault === 'oversize') return { ...value, snapshotFault: 'oversize' }; // Generated inside child, not oversized argv.
            delete value.maintenanceRoot; // Explicit malicious observation double, not a physical proof.
            const readback = { source: 'node-readback', configSha256: f.accepted.configSha256, unitSha256: f.accepted.unitSha256,
                serviceActive: 'active', serviceEnabled: 'enabled' };
            value.configTransfer = { configBase64: f.bytes.config.toString('base64'), unitBase64: f.bytes.unit.toString('base64'), readback };
            if (fault === 'base64') value.configTransfer.configBase64 += '\n';
            if (fault === 'digest') value.configTransfer.configBase64 = Buffer.from('fixture-not-for-logs-forged').toString('base64');
            if (fault === 'missing') delete value.configTransfer;
            if (fault === 'extra') value.configTransfer.path = '/untrusted';
            if (fault === 'state-array') readback.serviceActive = ['active'];
            return value;
        });
        let calls = 0;
        await assert.rejects(() => f.lifecycle.run(() => f.lifecycle.withVerifiedMaintenance(f.challenge, () => { calls++; })), error => {
            assert.equal(String(error).includes('fixture-not-for-logs'), false); return true;
        });
        assert.equal(calls, 0);
        assert.deepEqual(fs.readFileSync(path.join(f.root, 'config.json')), f.bytes.config);
    });
});

test('raw maintenance capability latches a swallowed drift even if bytes are put back before return', async t => {
    const f = maintenanceSetup(t);
    await assert.rejects(() => f.controller.withHeldAuthority(TEST, capability => capability.withVerifiedMaintenance(f.challenge, async (_, check) => {
        fs.writeFileSync(path.join(f.root, 'config.json'), 'transient-drift');
        await assert.rejects(check);
        fs.writeFileSync(path.join(f.root, 'config.json'), f.bytes.config);
    })));
});

test('public initializeClassic → physical adopt → real-store preEnroll → verified unchanged handback on scratch Mongo',
    { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to isolated local binary' }, async t => {
    const mongoose = require('mongoose'), net = require('node:net');
    const dbroot = fs.mkdtempSync(path.join(process.env.TMPDIR, 'physical-owner-mongo-'));
    const port = await new Promise(resolve => { const server = net.createServer(); server.listen(0, '127.0.0.1', () => {
        const p = server.address().port; server.close(() => resolve(p));
    }); });
    const child = spawn(process.env.C3_MONGOD, ['--dbpath', dbroot, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', 'physicalOwnerScratch', '--logpath', path.join(dbroot, 'mongo.log')], { stdio: 'ignore' });
    let connection;
    t.after(async () => {
        if (connection) { await connection.dropDatabase();
            assert.equal((await connection.getClient().db('admin').admin().listDatabases()).databases.some(db => db.name === 'physical_owner_scratch'), false);
            await connection.close(); }
        if (child.exitCode === null) { const done = new Promise(r => child.once('exit', r)); child.kill('SIGTERM'); await done; }
        fs.rmSync(dbroot, { recursive: true, force: true });
    });
    const retry = async work => { let last; for (let i = 0; i < 100; ++i) {
        try { return await work(); } catch (e) { last = e; await new Promise(r => setTimeout(r, 50)); }
    } throw last; };
    const client = new mongoose.mongo.MongoClient(`mongodb://127.0.0.1:${port}/admin?directConnection=true`, { serverSelectionTimeoutMS: 100 });
    try {
        await retry(() => client.connect());
        await client.db('admin').command({ replSetInitiate: { _id: 'physicalOwnerScratch', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await retry(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    } finally { await client.close(); }
    connection = await mongoose.createConnection(`mongodb://127.0.0.1:${port}/physical_owner_scratch?replicaSet=physicalOwnerScratch`,
        { serverSelectionTimeoutMS: 1000, monitorCommands: true }).asPromise();
    const model = (name, location) => connection.model(name, require(location).schema);
    const models = {
        Owner: model('TopologyConfigOwner', '../../../models/topologyConfigOwnerModel'),
        Operation: model('TopologyOperation', '../models/topologyOperationModel'),
        Lock: model('NodeOperationLock', '../models/nodeOperationLockModel'),
        Enrollment: model('TopologyExecutionEnrollment', '../models/topologyExecutionEnrollmentModel'),
        Binding: model('TopologyExecutionBinding', '../models/topologyExecutionBindingModel'),
        HyNode: model('PhysicalMaintenanceLocalNode', '../../../models/hyNodeModel'),
    };
    await Promise.all(Object.values(models).map(m => m.init()));
    const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
    const { TopologyExecutionBindingStore } = require('../repositories/topologyExecutionBindingStore');
    const f = maintenanceSetup(t), pin = f.config.nodes[0], nodeIdentity = f.challenge.binding.nodeIdentity;
    const transfer = new TopologyConfigTransfer({ executionContext: TEST, TopologyConfigOwner: models.Owner,
        withVerifiedMaintenance: f.lifecycle.withVerifiedMaintenance.bind(f.lifecycle) });
    const classic = await transfer.initializeClassic({ node: pin.nodeId, profile: pin.targetProfile, nodeIdentity });
    assert.equal(classic.owner, 'classic'); assert.equal(classic.originalSnapshot, undefined);
    await models.HyNode.create({ _id: pin.nodeId, name: 'local-physical-maintenance-only', ip: pin.endpoint.ip,
        type: 'xray', active: true, cascadeRole: 'portal', ssh: { port: pin.endpoint.port, username: pin.endpoint.username } });
    const commands = [];
    let held = false;
    const monitor = event => {
        if (['update', 'commitTransaction'].includes(event.commandName)) {
            assert.equal(held, true, 'transfer/store write escaped real held lifecycle'); commands.push(event.commandName);
        }
    };
    const store = new TopologyExecutionBindingStore({ executionContext: TEST, ...models,
        withVerifiedAuthority: f.lifecycle.withVerifiedAuthority.bind(f.lifecycle) });
    let adopted, restored;
    connection.getClient().on('commandStarted', monitor);
    try {
        await f.lifecycle.run(async () => {
            held = true;
            try {
                adopted = await transfer.adopt({ node: pin.nodeId, profile: pin.targetProfile, generation: classic.generation, proofRef: f.accepted.proofRef });
                const enrollment = await store.preEnroll({ nodeId: pin.nodeId, targetProfile: pin.targetProfile, endpoint: pin.endpoint,
                    nodeIdentity, ownerGeneration: adopted.generation, predecessorGeneration: 'none', bootId: pin.physical.bootId });
                assert.equal(enrollment.ownerGeneration, adopted.generation);
                const persisted = await models.Enrollment.findById(enrollment.enrollmentId).read('primary').readConcern('majority').lean();
                assert.deepEqual(persisted.endpoint, pin.endpoint);
                assert.equal(persisted.provisioningReceipt.writers, 'excluded');
                restored = await transfer.handback({ node: pin.nodeId, profile: pin.targetProfile, generation: adopted.generation, proofRef: f.accepted.proofRef });
            } finally { held = false; }
        });
    } finally { connection.getClient().off('commandStarted', monitor); }
    assert.ok(commands.includes('commitTransaction'));
    assert.deepEqual(adopted.originalSnapshot, { configSha256: sha(f.bytes.config), unitSha256: sha(f.bytes.unit), serviceActive: 'active', serviceEnabled: 'enabled' });
    assert.equal(restored.owner, 'classic'); assert.equal(restored.handbackReceipt.fromGeneration, adopted.generation);
    assert.deepEqual(restored.adoptionReceipt, adopted.adoptionReceipt);
    const readback = await models.Owner.findOne({ node: pin.nodeId }).read('primary').readConcern('majority').lean();
    assert.equal(readback.generation, restored.generation);
    assert.deepEqual(fs.readFileSync(path.join(f.root, 'config.json')), f.bytes.config);
    assert.deepEqual(fs.readFileSync(path.join(f.root, 'xray.service')), f.bytes.unit);
    assert.equal(await models.Operation.countDocuments(), 0); assert.equal(await models.Lock.countDocuments(), 0);
    await t.test('guard loss delivering committed majority confirmation retains owner and original bytes, never handbacks', async t => {
        const second = maintenanceSetup(t);
        const uncertain = new TopologyConfigTransfer({ executionContext: TEST, TopologyConfigOwner: models.Owner,
            withVerifiedMaintenance: second.lifecycle.withVerifiedMaintenance.bind(second.lifecycle) });
        let interrupted = false;
        const loseGuard = event => {
            if (!interrupted && event.commandName === 'find' && event.reply.cursor?.firstBatch?.some(row => row.owner === 'topology')) {
                interrupted = true;
                fs.writeFileSync(path.join(second.root, 'guard-alive'), 'lost');
            }
        };
        connection.getClient().on('commandSucceeded', loseGuard);
        try {
            await assert.rejects(() => second.lifecycle.run(() => uncertain.adopt({ node: pin.nodeId, profile: pin.targetProfile,
                generation: restored.generation, proofRef: second.accepted.proofRef })));
        } finally { connection.getClient().off('commandSucceeded', loseGuard); }
        assert.equal(interrupted, true);
        const retained = await models.Owner.findOne({ node: pin.nodeId }).read('primary').readConcern('majority').lean();
        assert.equal(retained.owner, 'topology'); assert.notEqual(retained.generation, restored.generation);
        assert.equal(retained.handbackReceipt, undefined);
        assert.deepEqual(retained.originalSnapshot, adopted.originalSnapshot);
        assert.deepEqual(fs.readFileSync(path.join(second.root, 'config.json')), second.bytes.config);
        assert.deepEqual(fs.readFileSync(path.join(second.root, 'xray.service')), second.bytes.unit);
        assert.equal(fs.readFileSync(path.join(second.root, 'guard-alive'), 'utf8'), 'lost');
        await assert.rejects(() => second.lifecycle.run(() => assert.fail('uncertain controller reused')));
    });
});
