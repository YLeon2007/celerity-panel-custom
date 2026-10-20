'use strict';
// Assembled local Mongo + fake-root runner evidence, NOT operational authorization.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID, randomBytes, createHash } = require('node:crypto');
const mongoose = require('mongoose');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const { freeze } = require('./helpers/topologyV2Fixture');
const { fakeRunner } = require('./helpers/topologyTerminalFakeRunner');
const { TopologyExecutionBindingStore } = require('../repositories/topologyExecutionBindingStore');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { createL2tpPanelHost } = require('../../createL2tpPanelHost');
const entry = require('..');
let connection, child, directory, models;
const NODE = new mongoose.Types.ObjectId().toString();
// Independently fixed SIMULATED physical facts; never derive these from a challenge/node row.
const ENDPOINT = freeze({ ip: '192.0.2.17', port: 22, username: 'synthetic' });
const IDENTITY = freeze({ machineId: randomBytes(16).toString('hex'), sshHostKeySha256: randomBytes(32).toString('hex') });
const BOOT = randomUUID(), MAINTENANCE = randomUUID(), OWNER = randomUUID();
const content = '{"inbounds":[],"outbounds":[{"tag":"direct"}],"routing":{"rules":[]}}\n';
const hash = createHash('sha256').update(content).digest('hex');
const node = freeze({ node: NODE, nodeRef: 'portal', role: 'portal', targetProfile: 'xray-main',
    configPath: '/usr/local/etc/xray/config.json', serviceUnit: 'xray.service',
    serviceUnitPath: '/etc/systemd/system/xray.service', checks: [], candidateHash: hash,
    candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1', bytes: [...Buffer.from(content)], sha256: hash } });
async function until(work) {
    let last;
    for (let n = 0; n < 120; n++) {
        try { return await work(); } catch (error) { last = error; }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw last;
}
test.before(async () => {
    assert.ok(process.env.C3_MONGOD); assert.ok(process.env.TMPDIR);
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-test-host-binding-'));
    const port = await new Promise(resolve => {
        const server = net.createServer(); server.listen(0, '127.0.0.1', () => {
            const port = server.address().port; server.close(() => resolve(port));
        });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', 'hostBindingScratch', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const uri = `mongodb://127.0.0.1:${port}/host_binding_scratch_${randomUUID().replaceAll('-', '')}`;
    const client = new mongoose.mongo.MongoClient(`${uri}?directConnection=true`, { serverSelectionTimeoutMS: 100 });
    try {
        await until(() => client.connect());
        await client.db('admin').command({ replSetInitiate: { _id: 'hostBindingScratch', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    } finally { await client.close(); }
    connection = await mongoose.createConnection(`${uri}?replicaSet=hostBindingScratch`, { monitorCommands: true }).asPromise();
    models = {};
    for (const [name, location] of Object.entries({
        HyNode: '../../../models/hyNodeModel', CascadeLink: '../../../models/cascadeLinkModel',
        TopologyConfigOwner: '../../../models/topologyConfigOwnerModel',
        TopologyOperation: '../models/topologyOperationModel', NodeOperationLock: '../models/nodeOperationLockModel',
        TopologyExecutionBinding: '../models/topologyExecutionBindingModel', TopologyExecutionEnrollment: '../models/topologyExecutionEnrollmentModel',
        CascadeTopologyState: '../models/cascadeTopologyStateModel', CascadeRouteGroup: '../models/cascadeRouteGroupModel',
        RelayL2tpState: '../models/relayL2tpStateModel', L2tpUser: '../models/l2tpUserModel', L2tpOperation: '../models/l2tpOperationModel',
    })) models[name] = connection.model(name, require(location).schema);
    await Promise.all(Object.values(models).map(model => model.init()));
});
test.after(async () => {
    try {
        if (connection) { assert.match(connection.name, /^host_binding_scratch_[a-f0-9]{32}$/); await connection.dropDatabase(); await connection.close(); }
    } finally {
        if (child && child.exitCode === null) { const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM'); await exited; }
        if (directory) await fs.rm(directory, { recursive: true, force: true });
    }
});
async function fixture(t, fault, executionContext = TEST) {
    for (const model of Object.values(models)) await model.collection.deleteMany({});
    await models.HyNode.create({ _id: NODE, name: 'local-only', ip: ENDPOINT.ip, type: 'xray', active: true, cascadeRole: 'portal',
        ssh: { port: ENDPOINT.port, username: ENDPOINT.username, privateKey: randomBytes(32).toString('hex') } });
    await models.TopologyConfigOwner.create({ executionContext, node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY,
        owner: 'topology', generation: OWNER,
        originalSnapshot: { configSha256: hash, unitSha256: hash, serviceActive: 'active', serviceEnabled: 'enabled' },
        adoptionReceipt: { proofId: randomUUID(), maintenanceId: MAINTENANCE, fromGeneration: randomUUID(), toGeneration: OWNER,
            oldBackendInstanceId: 'simulated-controller', oldPid: 42, oldProcessStartTime: 'local-start', verifiedAt: new Date() } });
    const runner = fakeRunner(t, BOOT), events = [];
    let active = false, revoked = false, first;
    const assertHeld = async () => { if (!active || revoked) throw new Error('Simulated hold revoked'); };
    const attest = async (challenge, work) => {
        await assertHeld();
        if (['create', 'successor'].includes(challenge.action)) {
            const claimed = await models.TopologyOperation.findById(challenge.expected.operationId).lean();
            const locked = await models.NodeOperationLock.findOne({ node: NODE }).lean();
            assert.equal(claimed.status, 'preparing'); assert.equal(claimed.attempts, challenge.expected.attempt);
            assert.equal(claimed.leaseOwner, challenge.expected.owner);
            assert.equal(locked.generation, challenge.expected.generation); assert.equal(locked.remoteUncertain, true);
        }
        let predecessor = challenge.action === 'enroll'
            ? { generation: 'none', bootId: BOOT, status: 'empty', protocolVersion: 2, journal: 'absent', legacyState: 'absent', writers: 'excluded' }
            : { generation: 'none', bootId: BOOT, status: 'pre-enrolled' };
        if (challenge.predecessor) {
            assert.ok(first);
            const request = `/usr/local/bin/celerity-topology-node-runner --command status --operation-id ${first.operationId} --node-id ${NODE} --candidate-hash ${first.candidateHash} --backup-id ${first.backupId} --target-profile xray-main --execution-context ${executionContext.hostIdentity} --attempt-id ${first.attemptId} --generation ${first.generation} --predecessor-generation ${first.predecessorGeneration} --command-id ${first.commandIds.close}`;
            const receipt = JSON.parse(runner.execute(request).stdout);
            const journal = JSON.parse(await fs.readFile(path.join(runner.root, 'var/lib/celerity/topology/fences/xray-main/journal.json'), 'utf8'));
            predecessor = { bindingId: first._id, generation: first.generation, headGeneration: journal.head, bootId: BOOT, status: 'terminal', receipt };
        }
        const result = await work({ authority: 'external-execution-maintenance-v1', status: 'verified', challenge: structuredClone(challenge),
            proofId: randomUUID(), maintenanceId: MAINTENANCE, maintenance: 'held', allWriters: 'drained', bootstrapWriters: 'excluded',
            physicalIdentity: IDENTITY, owner: 'topology', predecessor,
            connectionAttestation: { authority: 'server-physical-ssh-endpoint-v1', endpoint: ENDPOINT, physicalIdentity: IDENTITY,
                maintenanceId: MAINTENANCE, aliases: 'excluded', hostKeyDigest: 'raw-ssh-public-key-sha256', endpointReassignment: 'excluded' },
            oldBackend: { instanceId: 'simulated-controller', pid: 42, processStartTime: 'local-start', processTree: 'stopped', dispatch: 'disabled' } });
        if (challenge.action === 'create') {
            if (fault === 'hold-lost') revoked = true;
            if (fault === 'endpoint-change') await models.HyNode.updateOne({ _id: NODE }, { $set: { ip: '192.0.2.99' } });
        }
        return result;
    };
    const authority = { async withHeldAuthority(context, work) {
        assert.deepEqual(context, TEST); assert.equal(active, false); active = true;
        try { return await work(Object.freeze({ assertHeld, withVerifiedAuthority: attest })); }
        finally { active = false; }
    } };
    // Enrollment is separate explicit server maintenance, never implicit worker adoption.
    active = true;
    try {
        const store = new TopologyExecutionBindingStore({ executionContext, withVerifiedAuthority: attest,
            Operation: models.TopologyOperation, Lock: models.NodeOperationLock, Owner: models.TopologyConfigOwner,
            Enrollment: models.TopologyExecutionEnrollment, Binding: models.TopologyExecutionBinding, HyNode: models.HyNode });
        if (fault !== 'no-enrollment') await store.preEnroll(freeze({ nodeId: NODE, targetProfile: 'xray-main', endpoint: ENDPOINT, nodeIdentity: IDENTITY,
            ownerGeneration: OWNER, predecessorGeneration: 'none', bootId: BOOT }));
    } finally { active = false; }
    class LocalSSH {
        constructor(actual, trusted) {
            events.push('ssh');
            assert.equal(active, true);
            assert.deepEqual(trusted, { expectedEndpoint: ENDPOINT, expectedHostKeySha256: IDENTITY.sshHostKeySha256 });
            assert.equal(actual.ip, ENDPOINT.ip);
        }
        async writeFile() { assert.fail('preinstalled local runner requires no upload'); }
        async exec(command, options) {
            // Do not give this local SSH seam a revocation gate that the actual
            // adapter lacks: only source-owned lifecycle/store checks may refuse.
            assert.equal(active, true); events.push(command);
            if (command.startsWith('if /usr/bin/test -f')) {
                const { TOPOLOGY_RUNNER_SHA256, TOPOLOGY_RUNNER_PATH } = require('../services/topologyRunnerBootstrapper');
                return { code: 0, stdout: `${TOPOLOGY_RUNNER_SHA256.slice(7)}  ${TOPOLOGY_RUNNER_PATH}\n750\n`, stderr: '' };
            }
            if (command.startsWith('/usr/bin/install -d')) return { code: 0, stdout: '', stderr: '' };
            const result = runner.execute(command, options);
            if (fault === 'hold-lost-after-close' && command.includes('--command close ')) revoked = true;
            return result;
        }
    }
    let service;
    const host = createL2tpPanelHost({ env: { PANEL_DOMAIN: executionContext.hostIdentity, L2TP_EXECUTION_ENABLED: 'true',
        L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: executionContext === PROD ? 'true' : undefined },
        topologyExecutionAuthority: fault === 'missing-authority' ? undefined : authority,
        HyNode: models.HyNode, CascadeLink: models.CascadeLink, NodeSSH: LocalSSH,
        moduleEntry: { ...entry, registerModels: () => models,
            createTopologyDeploymentService(options) { service = entry.createTopologyDeploymentService(options); return service; },
            createTopologyIntentService: undefined },
        topologyRuntime: {}, Repository: class {}, createRepositoryAdapters: () => ({}), createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime: () => ({ runtime: { stateManagementService: {} }, start() {}, async stop() {} }),
        createTopologyRecoveryLifecycle: () => ({ start() {}, async stop() {} }), workerId: 'assembled-host', leaseMs: 120000 });
    t.after(() => host.stop());
    assert.ok(service?.operationWorker, 'actual host/runtime must compose real worker');
    // Local user RPC seam only; keep actual resync/gate/finalizer/executor implementations.
    service.operationWorker.userResync._syncService = { async _getUsersForNode() { await assertHeld(); return []; }, async addXrayUser() { assert.fail('no users'); } };
    async function operation(revision) {
        await models.CascadeTopologyState.deleteMany({});
        await models.CascadeTopologyState.create({ _id: 'singleton', revision, deployedRevision: revision - 1, topologyAdmissionCount: 1 });
        const operationId = new mongoose.Types.ObjectId().toString();
        await connection.transaction(session => new TopologyOperationRepository({ model: models.TopologyOperation }).createFrozen({ operationId,
            executionContext, idempotencyKey: `topology:${executionContext.target}:revision-${revision}:host-${executionContext.hostIdentity}:${randomUUID()}`,
            topologyRevision: revision, priorDeployedRevision: revision - 1, nodes: [node], heldTopologyAdmission: true, admissionFingerprint: hash, session }));
        return operationId;
    }
    return { worker: service.operationWorker, operation, events, revoke: () => { revoked = true; }, setFirst: row => { first = row; } };
}
test('actual TEST host provisions after exact claim/locks and settles two serial real-store runner generations', async t => {
    const f = await fixture(t);
    for (const revision of [17, 18]) {
        const id = await f.operation(revision);
        assert.equal((await models.TopologyOperation.findById(id).lean()).attempts, 0);
        const result = await f.worker.run(id);
        assert.equal(result.status, 'succeeded', JSON.stringify(result));
        assert.equal(await models.NodeOperationLock.countDocuments(), 0);
        assert.equal((await models.CascadeTopologyState.findOne().lean()).topologyAdmissionCount, 0);
        const row = await models.TopologyExecutionBinding.findOne({ operationId: id }).lean();
        assert.ok(row); assert.equal(row.attempt, 1);
        if (revision === 17) f.setFirst(row);
        else {
            const prior = await models.TopologyExecutionBinding.findOne({ operationId: { $ne: id } }).lean();
            assert.equal(row.predecessorBindingId, prior._id); assert.equal(row.predecessorGeneration, prior.generation);
        }
        const before = [...f.events]; assert.equal((await f.worker.run(id)).status, 'succeeded'); assert.deepEqual(f.events, before);
    }
    assert.equal(await models.TopologyExecutionEnrollment.countDocuments(), 1);
    assert.equal(await models.TopologyExecutionBinding.countDocuments(), 2);
});
test('before-prepare authority/endpoint refusal retains exact locks and admission with zero SSH/bootstrap', async t => {
    for (const fault of ['hold-lost', 'endpoint-change', 'missing-authority', 'no-enrollment']) await t.test(fault, async t => {
        const f = await fixture(t, fault), id = await f.operation(17);
        const result = await f.worker.run(id);
        assert.equal(result.stopped, true); assert.equal(result.drainUncertain, true);
        assert.deepEqual(f.events, []);
        assert.equal((await models.TopologyOperation.findById(id).lean()).heldTopologyAdmission, true);
        assert.equal(await models.NodeOperationLock.countDocuments({ operationId: id, owner: 'assembled-host-topology', remoteUncertain: true }), 1);
        assert.equal((await models.CascadeTopologyState.findOne().lean()).topologyAdmissionCount, 1);
    });
});
test('public TEST schemas reject cross-paired owners and arbitrary enrollment hosts', async t => {
    await fixture(t);
    const owner = await models.TopologyConfigOwner.findOne().lean();
    for (const executionContext of [{ ...TEST, hostIdentity: PROD.hostIdentity }, { ...PROD, hostIdentity: TEST.hostIdentity }]) {
        await assert.rejects(new models.TopologyConfigOwner({ ...owner, executionContext }).validate());
    }
    const enrolled = await models.TopologyExecutionEnrollment.findOne().lean();
    await assert.rejects(new models.TopologyExecutionEnrollment({ ...enrolled, executionContext: 'arbitrary.invalid' }).validate());
    assert.equal(await models.TopologyConfigOwner.countDocuments(), 1);
    assert.equal(await models.TopologyExecutionEnrollment.countDocuments(), 1);
});

test('revocation inside a reused held store scope prevents status dispatch and retains ownership', async t => {
    const f = await fixture(t, 'hold-lost-after-close'), id = await f.operation(17);
    const result = await f.worker.run(id);
    assert.equal(result.stopped, true); assert.equal(result.drainUncertain, true);
    const { runnerRequest } = require('./helpers/topologyV2Fixture');
    const commands = f.events.filter(event => event !== 'ssh').map(event => runnerRequest(event).command).filter(Boolean);
    assert.deepEqual(commands, ['prepare', 'commit', 'verify', 'close']);
    assert.equal(await models.NodeOperationLock.countDocuments({ operationId: id }), 1);
    assert.equal((await models.TopologyOperation.findById(id).lean()).heldTopologyAdmission, true);
});

test('assembled terminal recovery is read-only and never provisions or bootstraps', async t => {
    const f = await fixture(t), id = await f.operation(17);
    const finalize = f.worker.finalizer.finalizeV2Succeeded;
    f.worker.finalizer.finalizeV2Succeeded = async () => { throw new Error('local settlement interruption'); };
    try { assert.equal((await f.worker.run(id)).errorCode, 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED'); }
    finally { f.worker.finalizer.finalizeV2Succeeded = finalize; }
    const before = await Promise.all([models.TopologyOperation, models.TopologyExecutionBinding,
        models.TopologyExecutionEnrollment, models.TopologyConfigOwner, models.NodeOperationLock].map(model => model.findOne().lean()));
    f.events.length = 0;
    const commands = [], observe = event => commands.push(event.commandName);
    connection.getClient().on('commandStarted', observe);
    let result;
    try { result = await f.worker.run(id); }
    finally { connection.getClient().off('commandStarted', observe); }
    assert.equal(result.errorCode, 'TOPOLOGY_V2_RECOVERY_REQUIRES_SETTLEMENT_REVIEW');
    assert.deepEqual(commands.filter(name => ['update', 'insert', 'delete', 'commitTransaction', 'abortTransaction'].includes(name)), []);
    assert.deepEqual(await Promise.all([models.TopologyOperation, models.TopologyExecutionBinding,
        models.TopologyExecutionEnrollment, models.TopologyConfigOwner, models.NodeOperationLock].map(model => model.findOne().lean())), before);
    const { runnerRequest } = require('./helpers/topologyV2Fixture');
    assert.deepEqual(f.events.filter(event => event !== 'ssh').map(event => runnerRequest(event).command), ['status']);
});

test('actual PROD worker refuses before claim even with server authority supplied', async t => {
    const f = await fixture(t, undefined, PROD), id = await f.operation(17);
    assert.equal((await f.worker.run(id)).errorCode, 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN');
    assert.equal((await models.TopologyOperation.findById(id).lean()).attempts, 0); assert.deepEqual(f.events, []);
});
