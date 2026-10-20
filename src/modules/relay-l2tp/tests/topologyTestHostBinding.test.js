'use strict';
// Assembled local Mongo + fake-root runner evidence, NOT operational authorization.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');
const { TOPOLOGY_RUNNER_PATH, TOPOLOGY_RUNNER_SHA256, TOPOLOGY_RUNNER_MODE } = require('../services/topologyRunnerBootstrapper');
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
const NODE = '6ab18adc63913ebd4a917471';
// Independently fixed SIMULATED physical facts; never derive these from a challenge/node row.
const ENDPOINT = freeze({ ip: '132.243.230.19', port: 2222, username: 'c3-test-runner' });
const IDENTITY = freeze({ machineId: randomBytes(16).toString('hex'), sshHostKeySha256: randomBytes(32).toString('hex') });
const BOOT = randomUUID(), MAINTENANCE = randomUUID(), OWNER = randomUUID();
const content = '{"inbounds":[],"outbounds":[{"tag":"direct"}],"routing":{"rules":[]}}\n';
const hash = createHash('sha256').update(content).digest('hex');
const node = freeze({ node: NODE, nodeRef: 'portal', role: 'portal', targetProfile: 'xray-main',
    configPath: '/usr/local/etc/xray/config.json', serviceUnit: 'xray.service',
    serviceUnitPath: '/etc/systemd/system/xray.service', checks: [], candidateHash: hash,
    candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1', bytes: [...Buffer.from(content)], sha256: hash } });
// Load the REAL independently maintained finite V2 parser. Never emulate
// successful shell inspection/mkdir replies or widen the forced-command grammar.
function restrictedExecute(runner, command, options) {
    assert.ok(process.env.C3_RESTRICTED_RUNNER_HELPER, 'set reviewed isolation.py path');
    const parsed = spawnSync('python3', ['-I', '-c', `
import importlib.util,json,sys
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('isolation',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
print(json.dumps(m.parse_runner(sys.argv[2],json.loads(sys.argv[3]))))
`, process.env.C3_RESTRICTED_RUNNER_HELPER, command, JSON.stringify({ nodeId: NODE, targetProfile: 'xray-main' })], { encoding: 'utf8' });
    assert.equal(parsed.status, 0, parsed.stderr);
    return runner.execute(`${TOPOLOGY_RUNNER_PATH} ${JSON.parse(parsed.stdout).join(' ')}`, options);
}
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
    const runner = fakeRunner(t, BOOT), events = [], runnerExecutions = [];
    let active = false, revoked = false, first, runnerHeld = 0, runnerRevoked = false;
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
            const receipt = JSON.parse(restrictedExecute(runner, request).stdout);
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
    // Explicitly SIMULATED independent installation/physical attestor. The
    // source lifecycle must hold and recheck it; LocalSSH has no revocation gate.
    const runnerCheck = async () => {
        await assertHeld();
        if (runnerRevoked) throw new Error('Simulated installation guard lost');
    };
    const attestRunner = async (challenge, work) => {
        await runnerCheck();
        assert.equal(challenge.binding.bootId, BOOT);
        assert.equal(challenge.binding.maintenanceId, MAINTENANCE);
        const proof = { authority: 'server-preinstalled-topology-runner-v1',
            binding: structuredClone(challenge.binding), bootId: BOOT, maintenanceId: MAINTENANCE,
            connection: { expectedEndpoint: ENDPOINT, expectedHostKeySha256: IDENTITY.sshHostKeySha256 },
            runner: { path: TOPOLOGY_RUNNER_PATH, sha256: TOPOLOGY_RUNNER_SHA256, mode: TOPOLOGY_RUNNER_MODE,
                owner: 'root', regularFile: true, symlink: false, writableByRunner: false },
            profile: { targetProfile: 'xray-main', configDirectoryReady: true, bridgeUnitSha256: null, bridgeUnitDropIns: null },
            writers: 'excluded' };
        if (fault === 'runner-hash') proof.runner.sha256 = `sha256:${'f'.repeat(64)}`;
        if (fault === 'runner-endpoint') proof.connection.expectedEndpoint = { ...ENDPOINT, port: 22 };
        if (fault === 'runner-key') proof.connection.expectedHostKeySha256 = 'f'.repeat(64);
        if (fault === 'runner-boot') proof.bootId = randomUUID();
        if (fault === 'runner-profile') proof.profile.configDirectoryReady = false;
        if (fault === 'runner-malformed') proof.runner.sha256 = [TOPOLOGY_RUNNER_SHA256];
        if (fault === 'runner-missing-proof') return;
        if (fault === 'runner-guard-loss') runnerRevoked = true;
        freeze(proof);
        runnerHeld++;
        try { return await work(proof, runnerCheck); }
        finally { runnerHeld--; }
    };
    let authority = { runnerTransport: 'preinstalled-attested-v1', async withHeldAuthority(context, work) {
        assert.deepEqual(context, TEST); assert.equal(active, false); active = true;
        try { return await work(Object.freeze({ assertHeld, withVerifiedAuthority: attest,
            ...(fault === 'runner-missing-capability' ? {} : { withVerifiedPreinstalledRunner: attestRunner }) })); }
        finally { active = false; }
    } };
    if (fault === 'operational-root') {
        const { physicalControllerFixture } = require('./helpers/physicalControllerFixture');
        const physical = physicalControllerFixture(t, { nodeId: NODE, identity: IDENTITY, bootId: BOOT, maintenanceId: MAINTENANCE, runnerRoot: runner.root });
        authority = { runnerTransport: physical.runnerTransport, close: () => physical.close(),
            withHeldAuthority: (context, work) => physical.withHeldAuthority(context, async capability => {
                active = true;
                try { return await work({ ...capability, withVerifiedPreinstalledRunner: (challenge, callback) =>
                    capability.withVerifiedPreinstalledRunner(challenge, async (proof, check) => {
                        runnerHeld++;
                        try { return await callback(proof, check); } finally { runnerHeld--; }
                    }) }); } finally { active = false; }
            }),
        };
    }
    // Enrollment is separate explicit server maintenance, never implicit worker adoption.
    active = true;
    try {
        const store = new TopologyExecutionBindingStore({ executionContext, withVerifiedAuthority: fault === 'operational-root'
            ? (challenge, callback) => authority.withHeldAuthority(TEST, capability => capability.withVerifiedAuthority(challenge, callback)) : attest,
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
            if (fault === 'runner-loss-on-resolve') runnerRevoked = true;
        }
        async writeFile() { events.push('upload'); assert.fail('preinstalled local runner requires no upload'); }
        async exec(command, options) {
            // Do not give this local SSH seam a revocation gate that the actual
            // adapter lacks: only source-owned lifecycle/store checks may refuse.
            events.push(command); // Count attempts even if a local assertion refuses.
            assert.equal(active, true);
            assert.ok(runnerHeld > 0, 'attestor callback must span real dispatch');
            const result = restrictedExecute(runner, command, options);
            assert.equal(result.code, 0, result.stderr);
            runnerExecutions.push(command);
            if (fault === 'hold-lost-after-close' && command.includes('--command close ')) revoked = true;
            if (fault === 'runner-loss-after-commit' && command.includes('--command commit ')) runnerRevoked = true;
            return result;
        }
    }
    let service;
    const hostOptions = { env: { PANEL_DOMAIN: executionContext.hostIdentity, L2TP_EXECUTION_ENABLED: 'true',
        L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: executionContext === PROD ? 'true' : undefined },
        topologyExecutionAuthority: fault === 'missing-authority' ? undefined : authority,
        HyNode: models.HyNode, CascadeLink: models.CascadeLink, NodeSSH: LocalSSH,
        moduleEntry: { ...entry, registerModels: () => models,
            createTopologyDeploymentService(options) { service = entry.createTopologyDeploymentService(options); return service; },
            createTopologyIntentService: undefined },
        topologyRuntime: {}, Repository: class {}, createRepositoryAdapters: () => ({}), createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime: () => ({ runtime: { stateManagementService: {} }, start() {}, async stop() {} }),
        createTopologyRecoveryLifecycle: () => ({ start() {}, async stop() {} }), workerId: 'assembled-host', leaseMs: 120000 };
    let host;
    if (fault === 'operational-root') {
        // Non-topology L2TP services are inert local seams; topology remains real.
        const noop = () => {};
        hostOptions.createExecutionRuntime = () => ({ runtime: {
            service: { getStatus: noop, preflight: noop, install: noop, getOperation: noop },
            stateManagementService: { configureRelay: noop },
            userManagementService: { createUser: noop, listUsers: noop, updateUser: noop, disableUser: noop },
        }, start() {}, async stop() {} });
        const { createL2tpRootLifecycle, createL2tpRootHostDependencies, createL2tpRuntimeLifecycleHook } = require('../../l2tpRuntimeLifecycleHook');
        const { createL2tpStartupLifecycle } = require('../../createL2tpStartupLifecycle');
        const noWork = () => {};
        const root = createL2tpRootLifecycle({ env: hostOptions.env,
            createMigrationBootstrap: () => ({ async run() {} }),
            ensureModelIndexes: async () => { await Promise.all(Object.values(models).map(model => model.init())); },
            createHostDependencies: ({ env }) => createL2tpRootHostDependencies({ ...hostOptions, env,
                // The ordinary root factory selects the real operational controller;
                // its subprocess physical/SSH boundary is explicitly simulated.
                topologyExecutionAuthority: undefined,
                createTopologyExecutionAuthority: () => authority,
                candidateUserResolver: async () => [], syncService: null,
                requireAuth: noWork, requireOnboarding: noWork, csrf: noWork, rateLimiter: noWork, renderPage: noWork,
                secretBox: { encrypt() {}, decrypt() {} }, secretKey: 'local-only',
                timer: { setInterval() {}, clearInterval() {} }, logger: { error() {} } }),
            createRuntimeLifecycleHook: options => createL2tpRuntimeLifecycleHook({ ...options,
                createStartupLifecycle: options => createL2tpStartupLifecycle({ ...options,
                    createPanelHost(dependencies) { host = createL2tpPanelHost({ ...hostOptions, ...dependencies }); return host; } }) }),
        });
        await root.startAfterDatabase();
        t.after(() => root.stop());
    } else {
        host = createL2tpPanelHost(hostOptions);
        t.after(() => host.stop());
    }
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
    return { operationalRoot: fault === 'operational-root', worker: service.operationWorker, operation, events, runnerExecutions, revoke: () => { revoked = true; }, setFirst: row => { first = row; },
        replayFirst: () => restrictedExecute(runner, events.find(event => event.includes('--command prepare ')), { stdin: content }) };
}
test('ordinary root reaches real TEST store/default worker through operational subprocess controller for two serial generations', async t => {
    const f = await fixture(t, 'operational-root');
    assert.equal(f.operationalRoot, true, 'ordinary root + operational controller assembly missing');
    for (const revision of [27, 28]) {
        const id = await f.operation(revision);
        const result = await f.worker.run(id);
        assert.equal(result.status, 'succeeded', JSON.stringify(result));
        const row = await models.TopologyExecutionBinding.findOne({ operationId: id }).lean();
        assert.ok(row); f.setFirst(row);
        assert.equal(await models.NodeOperationLock.countDocuments(), 0);
    }
    assert.equal(await models.TopologyExecutionBinding.countDocuments(), 2);
    assert.equal(await models.TopologyExecutionEnrollment.countDocuments(), 1);
    assert.equal(f.runnerExecutions.length, 10);
});

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
    const { runnerRequest } = require('./helpers/topologyV2Fixture');
    assert.deepEqual(f.events.filter(event => event !== 'ssh').map(event => runnerRequest(event).command),
        ['prepare', 'commit', 'verify', 'close', 'status', 'prepare', 'commit', 'verify', 'close', 'status']);
    const replay = f.replayFirst();
    assert.notEqual(replay.code, 0, 'actual runner refuses stale first generation after successor');
});
test('preinstalled evidence refuses before credentials with zero shell, SFTP or runner dispatch', async t => {
    for (const fault of ['runner-hash', 'runner-endpoint', 'runner-key', 'runner-boot', 'runner-profile',
        'runner-malformed', 'runner-missing-proof', 'runner-missing-capability', 'runner-guard-loss']) await t.test(fault, async t => {
        const f = await fixture(t, fault), id = await f.operation(17);
        const result = await f.worker.run(id);
        assert.equal(result.stopped, true);
        assert.deepEqual(f.events, []);
        assert.equal(await models.NodeOperationLock.countDocuments({ operationId: id, remoteUncertain: true }), 1);
        assert.equal((await models.TopologyOperation.findById(id).lean()).heldTopologyAdmission, true);
        assert.equal((await models.CascadeTopologyState.findOne().lean()).topologyAdmissionCount, 1);
    });
});
test('runner guard loss at resolution or after commit prevents the next real dispatch and retains ownership', async t => {
    for (const fault of ['runner-loss-on-resolve', 'runner-loss-after-commit']) await t.test(fault, async t => {
        const f = await fixture(t, fault), id = await f.operation(17);
        const result = await f.worker.run(id);
        assert.equal(result.stopped, true);
        const { runnerRequest } = require('./helpers/topologyV2Fixture');
        assert.deepEqual(f.events.filter(event => event !== 'ssh').map(event => runnerRequest(event).command),
            fault === 'runner-loss-on-resolve' ? [] : ['prepare', 'commit']);
        assert.equal(await models.NodeOperationLock.countDocuments({ operationId: id, remoteUncertain: true }), 1);
        assert.equal((await models.TopologyOperation.findById(id).lean()).heldTopologyAdmission, true);
        assert.equal((await models.CascadeTopologyState.findOne().lean()).topologyAdmissionCount, 1);
    });
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
    f.events.length = 0; f.runnerExecutions.length = 0;
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
    assert.deepEqual(f.runnerExecutions.map(command => runnerRequest(command).command), ['status']);
});

test('actual PROD worker refuses before claim even with server authority supplied', async t => {
    const f = await fixture(t, undefined, PROD), id = await f.operation(17);
    assert.equal((await f.worker.run(id)).errorCode, 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN');
    assert.equal((await models.TopologyOperation.findById(id).lean()).attempts, 0); assert.deepEqual(f.events, []);
});
