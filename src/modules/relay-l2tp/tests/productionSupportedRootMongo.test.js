'use strict';
// Real default root/host/consumers/lifecycle/ownership/store + OWN Mongo and held
// local flock. SSH/node observation/effects are explicitly MODELED remote IO.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');
const { randomUUID, createHash } = require('node:crypto');
const mongoose = require('mongoose');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const { REVIEWED_MANIFEST_SHA256 } = require('../services/productionAdmissionInitializer');
const { createRootTopologyExecutionAuthority } = require('../runtime/productionPhysicalAuthority');
const { createL2tpRootLifecycle, createL2tpRootHostDependencies } = require('../../../modules/l2tpRuntimeLifecycleHook');
const sha = value => createHash('sha256').update(value).digest('hex');
const NODE = '111111111111111111111111';
let mongod, guard, directory, models, config, root, client, events = [], held = false;
let original, current, originalScope, stored, generation, prepared, restored = false, released = false, fault;
let liveStore, liveLifecycle, coordinator, entryMethod, runtimeMethod, runner;
const observations = {}, commands = [];
function journalPath() { return runner && path.join(runner.root, 'var/lib/celerity/topology/fences/xray-main/journal.json'); }
function journalBytes() { const p = journalPath(); return p && fs.existsSync(p) ? fs.readFileSync(p) : null; }
class ModeledNodeSSH {
    constructor(node, pin) {
        assert.ok(runner, 'no modeled connection before runner setup');
        assert.equal(String(node._id), NODE); assert.deepEqual(pin.expectedEndpoint, config.nodes[0].endpoint);
        assert.equal(pin.expectedHostKeySha256, config.nodes[0].physical.sshHostKeySha256);
    }
    async exec(command, options) {
        if (command.startsWith('if /usr/bin/test -e /usr/local/bin/.celerity-topology-node-runner-v2.upload')) {
            const file = path.join(runner.root, 'usr/local/bin/celerity-topology-node-runner-v2');
            return { code: 0, stdout: `${sha(fs.readFileSync(file))}  /usr/local/bin/celerity-topology-node-runner-v2\n${(fs.statSync(file).mode & 0o777).toString(8)}\n`, stderr: '' };
        }
        if (command === '/usr/bin/install -d -m 0755 -o root -g root /usr/local/etc/xray') {
            fs.mkdirSync(path.join(runner.root, 'usr/local/etc/xray'), { recursive: true }); return { code: 0, stdout: '', stderr: '' };
        }
        assert.ok(command.startsWith('/usr/local/bin/celerity-topology-node-runner-v2 '), 'no arbitrary shell or real SSH');
        const result = runner.execute(command, options);
        observations.nativeRunnerCommands ??= []; observations.nativeRunnerCommands.push({ command, ...result });
        current.config = fs.readFileSync(path.join(runner.root, 'usr/local/etc/xray/config.json'));
        return result;
    }
    async writeFile() { assert.fail('local runner is pre-provisioned; no SFTP'); }
}
const env = { PANEL_DOMAIN: PROD.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' };
async function until(work) { const deadline = Date.now() + 15000; while (true) { try { return await work(); } catch (e) {
    if (Date.now() > deadline) throw e; await new Promise(resolve => setTimeout(resolve, 25)); } } }
async function stop(child) { if (!child || child.exitCode !== null || child.signalCode !== null) return;
    if (child.startTicks) assert.equal(fs.readFileSync(`/proc/${child.pid}/stat`, 'utf8').split(') ')[1].split(' ')[19], child.startTicks);
    const closed = new Promise(resolve => child.once('close', resolve)); child.kill('SIGTERM'); const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    try { await closed; } finally { clearTimeout(timer); } }
function assertHeld() {
    assert.equal(guard.exitCode, null); assert.equal(held, true);
    const rival = spawnSync('/usr/bin/flock', ['-n', path.join(directory, 'held.lock'), '/usr/bin/true']);
    assert.equal(rival.status, 1); if (fault === 'stale') throw Error('MODELED_REMOTE_SCOPE_REVOKED');
}
function readback() { return { source: 'node-readback', configSha256: sha(current.config), unitSha256: sha(current.unit), serviceActive: current.active, serviceEnabled: current.enabled }; }
function view() { return { epoch: originalScope.epoch, bundleSha256: originalScope.bundleSha256, ownerGeneration: generation,
    phase: restored ? 'restored-held' : 'captured-held', readback: readback() }; }
async function open(pin) {
    events.push('open-' + pin.kind);
    return { alive: true, close() { this.alive = false; }, async request(action, value) {
        assertHeld(); events.push(action);
        const observedKind = config.host.policySha256 === config.nodes[0].policySha256 ? 'node' : pin.kind;
        if (action === 'observe') return { serverContext: PROD, kind: observedKind, policySha256: fault === 'mismatch' ? '0'.repeat(64) : pin.policySha256,
            physical: pin.physical, endpoint: pin.endpoint, maintenanceId: pin.maintenanceId, held: true,
            oldBackend: { instanceId: 'owned-prior-joined', pid: 42, processStartTime: '123' },
            ...(observedKind === 'node' ? { nodeId: NODE, targetProfile: 'xray-main', current: readback(),
                journal: journalBytes() ? JSON.parse(journalBytes()) : null, pristine: !journalBytes() } : {}) };
        if (action === 'capture') { assert.equal(stored, undefined); stored = structuredClone(current); originalScope = { epoch: randomUUID(), bundleSha256: sha(Buffer.concat([stored.config, stored.unit])) }; generation = null; return view(); }
        if (action === 'bind') { assert.equal(generation, null); generation = value.ownerGeneration; return view(); }
        if (action === 'read' || action === 'verify') { if (action === 'verify') assert.deepEqual(current, stored); return view(); }
        if (action === 'current') return { configSha256: sha(current.config), unitSha256: sha(current.unit), active: current.active, enabled: current.enabled, journalSha256: journalBytes() ? sha(journalBytes()) : null };
        if (action === 'prepare') { assert.equal(value.epoch, originalScope.epoch); assert.equal(value.ownerGeneration, generation); prepared = structuredClone(value.current); return view(); }
        if (action === 'restore') { assert.ok(prepared); current = structuredClone(stored); fs.writeFileSync(path.join(directory, 'remote-config.bin'), current.config);
            fs.writeFileSync(path.join(directory, 'remote-unit.bin'), current.unit); restored = true; return view(); }
        if (action === 'release') { assert.equal(restored, true); released = true; return { phase: 'handback-released', epoch: originalScope.epoch, ownerGeneration: generation }; }
        throw Error('unexpected remote model action');
    } };
}
function factory(options) { return createRootTopologyExecutionAuthority({ ...options,
    read(file) { assert.equal(file, '/etc/celerity/topology-production.json'); return JSON.stringify(config); }, open }); }
test.before(async () => {
    assert.ok(process.env.TMPDIR && process.env.C3_MONGOD);
    directory = fs.mkdtempSync(path.join(process.env.TMPDIR, 'prod-root-'));
    guard = spawn('/usr/bin/python3', ['-I', '-B', '-c', 'import fcntl,os,sys; f=open(sys.argv[1],"x");fcntl.flock(f,fcntl.LOCK_EX);print("held",flush=True);sys.stdin.buffer.read()', path.join(directory, 'held.lock')], { stdio: ['pipe', 'pipe', 'pipe'] });
    await new Promise((resolve, reject) => { guard.stdout.once('data', () => { held = true; resolve(); }); guard.once('error', reject); });
    guard.startTicks = fs.readFileSync(`/proc/${guard.pid}/stat`, 'utf8').split(') ')[1].split(' ')[19];
    const port = await new Promise(resolve => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
    mongod = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1', '--replSet', 'prodRootOwned',
        '--wiredTigerCacheSizeGB', '0.25', '--oplogSize', '32', '--logpath', path.join(directory, 'mongod.log')], { stdio: 'ignore' });
    mongod.startTicks = fs.readFileSync(`/proc/${mongod.pid}/stat`, 'utf8').split(') ')[1].split(' ')[19];
    client = new mongoose.mongo.MongoClient(`mongodb://127.0.0.1:${port}/admin?directConnection=true`, { serverSelectionTimeoutMS: 250 });
    await until(() => client.connect()); await client.db('admin').command({ replSetInitiate: { _id: 'prodRootOwned', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
    await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    const { config: replica } = await client.db('admin').command({ replSetGetConfig: 1 }); await client.close(); client = undefined;
    mongoose.set('autoCreate', false); mongoose.set('autoIndex', false);
    await mongoose.connect(`mongodb://127.0.0.1:${port}/prod_root_owned?replicaSet=prodRootOwned`, { autoCreate: false, autoIndex: false, monitorCommands: true });
    mongoose.connection.getClient().on('commandStarted', e => commands.push({ name: e.commandName, command: e.command }));
    models = { ...require('..').registerModels(), HyNode: require('../../../models/hyNodeModel'), CascadeLink: require('../../../models/cascadeLinkModel') };
    for (const model of Object.values(models)) { await model.init(); await model.createCollection(); for (const [key, options] of model.schema.indexes()) await model.collection.createIndex(key, options); }
    await models.CascadeTopologyState.collection.insertOne({ _id: 'singleton', revision: 9, deployedRevision: 7, stateTransitionRevision: 2,
        replacementEpoch: 3, remoteAdmissionCount: 0, topologyAdmissionCount: 0 });
    await models.HyNode.create({ _id: NODE, name: 'OWN remote IO model', type: 'xray', active: true, cascadeRole: 'portal', ip: '192.0.2.1',
        port: 443, ssh: { port: 22, username: 'root', privateKey: 'owned-fixture-placeholder-not-a-key' }, xray: { security: 'none', transport: 'tcp' } });
    // This lifecycle fixture has no classic links. Use the genuinely empty
    // supported bootstrap, not an unimportable nonempty profile descriptor.
    original = { config: Buffer.from('{}\n'), unit: Buffer.from('OWN exact original unit\n'), active: 'active', enabled: 'enabled' };
    current = structuredClone(original); // Uint8Array identity is preserved as actual bytes in hashes/effects.
    const pin = (kind, digit) => ({ kind, policySha256: digit.repeat(64), physical: { machineId: digit.repeat(32), bootId: randomUUID(), sshHostKeySha256: digit.repeat(64) },
        endpoint: { ip: `192.0.2.${digit}`, port: 22, username: 'root' }, privateKeyPath: '/etc/celerity/not-read-local-model', maintenanceId: randomUUID() });
    config = { version: 1, executionContext: PROD, mode: 'enroll', admission: { serverContext: PROD, databaseName: 'prod_root_owned',
        maintenanceGeneration: randomUUID(), deployment: { setName: replica._id, replicaSetId: String(replica.settings.replicaSetId) }, manifestSha256: REVIEWED_MANIFEST_SHA256 },
        host: pin('host', '9'), nodes: [{ ...pin('node', '1'), nodeId: NODE, targetProfile: 'xray-main', proofRef: 'owned-original-epoch',
            originalSnapshot: readback(), acceptedOwner: { owner: 'absent' } }] };
    // Explicit complete host+node policy equality, not same-IP role inference.
    config.host = { ...config.nodes[0], kind: 'host' };
    const entry = require('../services/productionOwnerEntry'), api = require('..');
    entryMethod = entry.enrollProductionOwners; runtimeMethod = api.createTopologyDeploymentService;
    entry.enrollProductionOwners = options => { liveStore = options.store; liveLifecycle = options.lifecycle; return entryMethod(options); };
    api.createTopologyDeploymentService = options => { coordinator = runtimeMethod(options); return coordinator; };
});
test.after(async () => {
    await root?.stop(); require('../../../services/sshPoolService').closeAll();
    if (entryMethod) require('../services/productionOwnerEntry').enrollProductionOwners = entryMethod;
    if (runtimeMethod) require('..').createTopologyDeploymentService = runtimeMethod;
    if (client) await client.close(); await mongoose.disconnect(); guard?.stdin.end(); await stop(mongod); await stop(guard); held = false;
    const cleanup = { mongodPid: mongod?.pid, guardPid: guard?.pid, mongodReaped: !fs.existsSync(`/proc/${mongod?.pid}`), guardReaped: !fs.existsSync(`/proc/${guard?.pid}`),
        mongodStartTicks: mongod?.startTicks, guardStartTicks: guard?.startTicks,
        mongodExit: { code: mongod?.exitCode, signal: mongod?.signalCode }, guardExit: { code: guard?.exitCode, signal: guard?.signalCode },
        remoteIO: 'MODELED; actual producer/root/Mongo/consumers/local exclusive flock; actual V2 shell runner in OWN fake-root', events, observations, commands };
    assert.equal(cleanup.mongodReaped && cleanup.guardReaped, true);
    if (directory && process.env.C3_PROD_ROOT_EVIDENCE) fs.copyFileSync(path.join(directory, 'mongod.log'), process.env.C3_PROD_ROOT_EVIDENCE + '.mongod.log');
    if (directory) fs.rmSync(directory, { recursive: true, force: true });
    if (process.env.C3_PROD_ROOT_EVIDENCE) fs.writeFileSync(process.env.C3_PROD_ROOT_EVIDENCE, JSON.stringify(cleanup, null, 2));
});
test('actual default root dependency selector supplies a canonical PROD producer, not the TEST-only omission', () => {
    const api = require('../runtime/productionPhysicalAuthority'), previous = api.createRootTopologyExecutionAuthority;
    api.createRootTopologyExecutionAuthority = factory; // only its private-file/remote-IO seam; real producer constructor
    try {
        const dependencies = createL2tpRootHostDependencies({ env });
        assert.equal(typeof dependencies.topologyExecutionAuthority?.withHeldAuthority, 'function');
        assert.deepEqual(dependencies.topologyExecutionAuthority.executionContext, PROD);
        assert.equal(dependencies.topologyExecutionAuthority.runnerTransport, undefined, 'normal shell/SFTP bootstrapper');
        dependencies.topologyExecutionAuthority.close();
    } finally { api.createRootTopologyExecutionAuthority = previous; }
});
test('canonical PROD ordinary ROOT uses real producer: schema → capture → adopt generation → preEnroll → actual consumers → drain → exact originals → verified handback', async () => {
    root = createL2tpRootLifecycle({ env, createTopologyExecutionAuthority: factory,
        createMigrationBootstrap() { assert.fail('no production startup migration'); }, ensureModelIndexes() { assert.fail('no production automatic DDL'); } });
    const lifecycle = await root.startAfterDatabase();
    assert.equal(lifecycle.start().running, true);
    const owner = await models.TopologyConfigOwner.findOne({ node: NODE }).lean();
    const enrollment = await models.TopologyExecutionEnrollment.findOne({ nodeId: NODE }).lean();
    assert.equal(owner.owner, 'topology'); assert.equal(owner.generation, generation); assert.equal(enrollment.ownerGeneration, owner.generation);
    assert.ok(events.indexOf('capture') < events.indexOf('bind'));
    assert.equal(events.filter(e => e === 'open-node').length, 0, 'one cohost helper/OFD, separate exact host/node roles');
    // Physical/current IO is modeled, but restore must use the exact private OWN
    // bytes captured BEFORE adoption, never this changed current configuration.
    current = { ...current, config: Buffer.from('{"inbounds":[],"outbounds":[{"tag":"OWN-changed","protocol":"freedom"}],"routing":{"rules":[]}}\n'), unit: Buffer.from('OWN changed runtime unit\n') };
    const acceptedCurrent = { [NODE]: { configSha256: sha(current.config), unitSha256: sha(current.unit), active: current.active, enabled: current.enabled, journalSha256: null } };
    const returned = await root.handbackProductionOriginalsAfterDatabase(acceptedCurrent);
    assert.equal(returned.status, 'handed-back'); assert.equal(released, true);
    assert.deepEqual(Buffer.from(fs.readFileSync(path.join(directory, 'remote-config.bin'))), Buffer.from(original.config));
    assert.deepEqual(Buffer.from(fs.readFileSync(path.join(directory, 'remote-unit.bin'))), Buffer.from(original.unit));
    assert.equal((await models.TopologyConfigOwner.findOne({ node: NODE }).lean()).owner, 'classic');
    assert.equal(await models.TopologyExecutionEnrollment.countDocuments(), 1, 'history retained');
    await root.stop(); root = undefined;
});
for (const scenario of ['already-topology', 'foreign-owner', 'stale-accepted-generation', 'missing-handback', 'unjoined-handback', 'unknown-retained-operation', 'unknown-retained-lock', 'unknown-remote-admission']) {
    test(`pre-capture refusal, immutable history retained: ${scenario}`, async () => {
        const before = await models.TopologyConfigOwner.collection.findOne({ node: new mongoose.Types.ObjectId(NODE) });
        const alias = mongoose.mongo.BSON.serialize(await models.TopologyExecutionEnrollment.collection.findOne({ nodeId: NODE }));
        const oldConfig = structuredClone(config), captures = events.filter(e => e === 'capture').length;
        config.nodes[0].acceptedOwner = { owner: 'classic', generation: before.generation };
        if (scenario === 'already-topology') await models.TopologyConfigOwner.collection.updateOne({ _id: before._id }, { $set: { owner: 'topology' } });
        if (scenario === 'foreign-owner') await models.TopologyConfigOwner.collection.updateOne({ _id: before._id }, { $set: { executionContext: { target: 'test', hostIdentity: 'test.infograd.online' } } });
        if (scenario === 'stale-accepted-generation') config.nodes[0].acceptedOwner.generation = randomUUID();
        if (scenario === 'missing-handback') await models.TopologyConfigOwner.collection.updateOne({ _id: before._id }, { $unset: { handbackReceipt: 1 } });
        if (scenario === 'unjoined-handback') await models.TopologyConfigOwner.collection.updateOne({ _id: before._id }, { $set: { 'handbackReceipt.fromGeneration': randomUUID() } });
        let fixtureRow;
        // Deliberately malformed retained WORK seeded only for this refusal case;
        // never an erased legitimate operation/enrollment/binding history.
        if (scenario === 'unknown-retained-operation') fixtureRow = [models.TopologyOperation, { _id: new mongoose.Types.ObjectId(), nodes: [{ node: new mongoose.Types.ObjectId(NODE) }], retainedFixture: scenario }];
        if (scenario === 'unknown-retained-lock') fixtureRow = [models.NodeOperationLock, { _id: new mongoose.Types.ObjectId(), node: new mongoose.Types.ObjectId(NODE), retainedFixture: scenario }];
        if (scenario === 'unknown-remote-admission') fixtureRow = [models.RemoteAdmission, { _id: new mongoose.Types.ObjectId(), nodeId: NODE, retainedFixture: scenario }];
        if (fixtureRow) await fixtureRow[0].collection.insertOne(fixtureRow[1]);
        const rejected = createL2tpRootLifecycle({ env, createTopologyExecutionAuthority: factory });
        try {
            await assert.rejects(rejected.startAfterDatabase());
            assert.equal(events.filter(e => e === 'capture').length, captures, 'refuse BEFORE creating another captured epoch');
            if (fixtureRow) assert.deepEqual(await fixtureRow[0].collection.findOne({ _id: fixtureRow[1]._id }), fixtureRow[1]);
        } finally {
            await rejected.stop();
            await models.TopologyConfigOwner.collection.replaceOne({ _id: before._id }, before);
            if (fixtureRow) await fixtureRow[0].collection.deleteOne({ _id: fixtureRow[1]._id, retainedFixture: scenario });
            config = oldConfig;
        }
        assert.deepEqual(mongoose.mongo.BSON.serialize(await models.TopologyExecutionEnrollment.collection.findOne({ nodeId: NODE })), alias);
        observations.preCaptureRefusals ??= []; observations.preCaptureRefusals.push({ scenario, captureDelta: 0 });
    });
}
test('TRACER: public handback retains immutable alias; second fresh adoption → current binding/native terminal/default finalizer → handback', async t => {

    const aliasBefore = await models.TopologyExecutionEnrollment.collection.findOne({ nodeId: NODE });
    const aliasBytes = mongoose.mongo.BSON.serialize(aliasBefore);
    observations.aliasBeforeBsonHex = aliasBytes.toString('hex');
    observations.aliasIndexesBefore = await models.TopologyExecutionEnrollment.collection.indexes();
    const prior = await models.TopologyConfigOwner.findOne({ node: NODE }).lean();
    assert.equal(prior.owner, 'classic'); assert.equal(prior.handbackReceipt.fromGeneration, aliasBefore.ownerGeneration);
    const firstEpoch = originalScope.epoch;
    // MODELED physical helper: previously released originals are retained in the
    // fixture archive; the new holder captures new bytes, never attach/rearm.
    assert.equal(released, true); stored = undefined; restored = false; released = false; prepared = undefined;
    config.nodes[0].acceptedOwner = { owner: 'classic', generation: prior.generation };
    config.nodes[0].maintenanceId = randomUUID(); config.nodes[0].physical.bootId = randomUUID();
    config.host = { ...config.nodes[0], kind: 'host' };
    root = createL2tpRootLifecycle({ env, createTopologyExecutionAuthority: factory,
        createHostDependencies: options => createL2tpRootHostDependencies({ ...options, NodeSSH: ModeledNodeSSH }),
        createMigrationBootstrap() { assert.fail('no production startup migration'); }, ensureModelIndexes() { assert.fail('no startup DDL'); } });
    const lifecycle = await root.startAfterDatabase();
    assert.equal(lifecycle.start().running, true);
    const adopted = await models.TopologyConfigOwner.findOne({ node: NODE }).lean();
    assert.notEqual(adopted.generation, aliasBefore.ownerGeneration); assert.notEqual(originalScope.epoch, firstEpoch);
    assert.equal(adopted.adoptionReceipt.fromGeneration, prior.generation);
    const evidence = await models.TopologyConfigOwner.findOne({ node: NODE }).select('+executionEnrollment').lean();
    assert.equal(evidence.executionEnrollment.enrollment.ownerGeneration, adopted.generation);
    assert.equal(evidence.executionEnrollment.enrollment.bootId, config.nodes[0].physical.bootId);
    assert.notEqual(evidence.executionEnrollment.enrollment.maintenanceId, aliasBefore.maintenanceId);
    await verifyCurrentBinding(t);
    assert.deepEqual(mongoose.mongo.BSON.serialize(await models.TopologyExecutionEnrollment.collection.findOne({ nodeId: NODE })), aliasBytes);
    const accepted = { [NODE]: { configSha256: sha(current.config), unitSha256: sha(current.unit), active: current.active, enabled: current.enabled,
        journalSha256: journalBytes() ? sha(journalBytes()) : null } };
    assert.equal((await root.handbackProductionOriginalsAfterDatabase(accepted)).status, 'handed-back');
    observations.aliasAfterBsonHex = mongoose.mongo.BSON.serialize(await models.TopologyExecutionEnrollment.collection.findOne({ nodeId: NODE })).toString('hex');
    observations.aliasIndexesAfter = await models.TopologyExecutionEnrollment.collection.indexes();
    assert.deepEqual(observations.aliasIndexesAfter, observations.aliasIndexesBefore);
    assert.equal(observations.aliasAfterBsonHex, observations.aliasBeforeBsonHex);
    observations.join = { aliasId: aliasBefore._id, historicalOwnerGeneration: aliasBefore.ownerGeneration,
        previousClassicGeneration: prior.generation, newOwnerGeneration: adopted.generation, firstEpoch, secondEpoch: originalScope.epoch,
        currentBoot: config.nodes[0].physical.bootId, aliasCount: await models.TopologyExecutionEnrollment.countDocuments(),
        bindingCount: await models.TopologyExecutionBinding.countDocuments(), operationCount: await models.TopologyOperation.countDocuments() };
    await root.stop(); root = undefined;
});
test('native DDL still enforces permanent node/profile, machine, raw SSH key and listener alias reservations', async () => {
    const alias = await models.TopologyExecutionEnrollment.collection.findOne({ nodeId: NODE });
    const before = mongoose.mongo.BSON.serialize(alias);
    observations.aliasCollisions = [];
    for (const kind of ['node-profile', 'machine', 'ssh-key', 'endpoint']) {
        const clone = { ...alias, _id: randomUUID(), nodeId: '222222222222222222222222', targetProfile: 'xray-bridge',
            nodeIdentity: { machineId: '2'.repeat(32), sshHostKeySha256: '2'.repeat(64) }, endpoint: { ip: '192.0.2.2', port: 2222, username: 'different-user' } };
        if (kind === 'node-profile') { clone.nodeId = alias.nodeId; clone.targetProfile = alias.targetProfile; }
        if (kind === 'machine') clone.nodeIdentity.machineId = alias.nodeIdentity.machineId;
        if (kind === 'ssh-key') clone.nodeIdentity.sshHostKeySha256 = alias.nodeIdentity.sshHostKeySha256;
        if (kind === 'endpoint') clone.endpoint = { ...alias.endpoint, username: 'different-user' };
        await assert.rejects(models.TopologyExecutionEnrollment.collection.insertOne(clone), error => {
            assert.equal(error.code, 11000); observations.aliasCollisions.push({ kind, code: error.code, keyPattern: error.keyPattern }); return true;
        });
        assert.equal(await models.TopologyExecutionEnrollment.countDocuments(), 1);
        assert.deepEqual(mongoose.mongo.BSON.serialize(await models.TopologyExecutionEnrollment.collection.findOne({ nodeId: NODE })), before);
    }
    await assert.rejects(models.TopologyExecutionEnrollment.updateOne({ _id: alias._id }, { $set: { ownerGeneration: randomUUID() } }));
    await assert.rejects(models.TopologyExecutionEnrollment.deleteOne({ _id: alias._id }));
});
test('successful retained previous BUSINESS binding is explicitly UNSUPPORTED for another ordinary adoption, before capture', async () => {
    const before = await models.TopologyConfigOwner.collection.findOne({ node: new mongoose.Types.ObjectId(NODE) });
    const binding = await models.TopologyExecutionBinding.collection.findOne({ nodeId: NODE });
    const operation = await models.TopologyOperation.collection.findOne({ _id: new mongoose.Types.ObjectId(binding.operationId) });
    assert.equal(before.owner, 'classic'); assert.equal(operation.status, 'succeeded');
    const captures = events.filter(e => e === 'capture').length;
    config.nodes[0].acceptedOwner = { owner: 'classic', generation: before.generation };
    const rejected = createL2tpRootLifecycle({ env, createTopologyExecutionAuthority: factory });
    try { await assert.rejects(rejected.startAfterDatabase()); }
    finally { await rejected.stop(); }
    assert.equal(events.filter(e => e === 'capture').length, captures);
    assert.deepEqual(mongoose.mongo.BSON.serialize(await models.TopologyConfigOwner.collection.findOne({ _id: before._id })), mongoose.mongo.BSON.serialize(before));
    assert.deepEqual(mongoose.mongo.BSON.serialize(await models.TopologyExecutionBinding.collection.findOne({ _id: binding._id })), mongoose.mongo.BSON.serialize(binding));
    assert.deepEqual(mongoose.mongo.BSON.serialize(await models.TopologyOperation.collection.findOne({ _id: operation._id })), mongoose.mongo.BSON.serialize(operation));
    observations.successfulPreviousBusinessCycle = 'REFUSED_BEFORE_CAPTURE; support not implemented';
});
async function verifyCurrentBinding(t) {
    // Real Mongo admission/claim/store, default executor/terminal/finalizer and
    // real V2 runner in OWN fake-root. SSH/files/systemd observations are modeled.
    const { freeze } = require('../models/topologyExecutionBindingContract');
    const { bindingRecord } = require('./helpers/topologyV2Fixture');
    const repository = coordinator.operationRepository;
    const operationId = new mongoose.Types.ObjectId().toString(), owner = 'owned-local-binding-probe';
    const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n', hash = sha(content);
    const node = freeze({ node: NODE, nodeRef: 'portal', role: 'portal', targetProfile: 'xray-main',
        configPath: '/usr/local/etc/xray/config.json', serviceUnit: 'xray.service', serviceUnitPath: '/etc/systemd/system/xray.service',
        checks: [], candidateHash: hash, candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1', bytes: [...Buffer.from(content)], sha256: hash } });
    const baseline = await models.CascadeTopologyState.findById('singleton').lean();
    await coordinator.topologyRepository.admitTopology({ expectedRevision: baseline.revision, prepare: async () => ({}),
        admit: (pin, session) => repository.createFrozen({ operationId, executionContext: PROD,
            idempotencyKey: `topology:production:revision-${pin.revision}:host-${PROD.hostIdentity}:${randomUUID()}`,
            topologyRevision: pin.revision, priorDeployedRevision: pin.deployedRevision, nodes: [node], heldTopologyAdmission: true,
            admissionFingerprint: 'f'.repeat(64), session }) });
    await repository.claim({ operationId, executionContext: PROD, owner, now: new Date(), leaseMs: 120000 });
    const lockGeneration = randomUUID();
    const locks = new (require('../services/nodeOperationLockRepository').NodeOperationLockRepository)({ model: models.NodeOperationLock });
    await locks.acquireLease({ node: NODE, operationId, owner, generation: lockGeneration, leaseUntil: new Date(Date.now() + 120000) });
    const context = { operationId, node, topologyRevision: baseline.revision, priorDeployedRevision: baseline.deployedRevision,
        executionFence: freeze({ owner, attempt: 1, generation: lockGeneration }) };
    const { attemptId: _a, predecessorGeneration: _p, commandIds: _c, bootId: _b, maintenanceId: _m, ...input } = bindingRecord(context, PROD.hostIdentity);
    const expected = freeze(input);
    await liveLifecycle.run(async () => {
        const b = await liveStore.reserveBinding(expected);
        assert.deepEqual(await liveStore.readVerified(expected), b);
        const raw = await models.TopologyExecutionBinding.collection.findOne({ operationId });
        assert.equal(raw.ownerGeneration, generation); assert.equal(b.bootId, config.nodes[0].physical.bootId);
        assert.notEqual(raw.ownerGeneration, (await models.TopologyExecutionEnrollment.findOne({ nodeId: NODE }).lean()).ownerGeneration);
        let reads = 0; const connection = liveStore.readVerifiedConnection;
        liveStore.readVerifiedConnection = async function (...args) { reads++; return connection.apply(this, args); };
        try {
            // Actual default consumer's executor consumes the SAME current store.
            // The fixture has NO SSH credential, so resolution stops locally,
            // AFTER readVerifiedConnection, with zero network dispatch.
            await assert.rejects(coordinator.operationWorker.executor.probeTerminalBinding(b), { code: 'TOPOLOGY_NODE_EXECUTION_UNAVAILABLE' });
            assert.ok(reads > 0);
        } finally { liveStore.readVerifiedConnection = connection; }
        await liveStore.withVerifiedBinding(expected, async (currentBinding, check) => {
            assert.deepEqual(currentBinding, b); await check();
            assert.equal((await liveStore.readVerifiedConnection(expected, currentBinding)).binding.bootId, b.bootId);
        });
        const privateOwner = await models.TopologyConfigOwner.collection.findOne({ node: new mongoose.Types.ObjectId(NODE) });
        await t.test('raw Mixed previousEnrollment: absent and valid prior record accepted; present null rejected', async () => {
            const alias = await models.TopologyExecutionEnrollment.collection.findOne({ nodeId: NODE });
            observations.rawPreviousEnrollment = [];
            for (const [kind, value] of [['absent', undefined], ['valid-prior-record', alias], ['present-null', null]]) {
                const changed = structuredClone(privateOwner.executionEnrollment);
                if (kind === 'absent') delete changed.previousEnrollment;
                else changed.previousEnrollment = value;
                await models.TopologyConfigOwner.collection.updateOne({ _id: privateOwner._id }, { $set: { executionEnrollment: changed } });
                try {
                    if (kind === 'present-null') await assert.rejects(liveStore.readVerified(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
                    else assert.deepEqual(await liveStore.readVerified(expected), b);
                    observations.rawPreviousEnrollment.push({ kind, result: kind === 'present-null' ? 'refused' : 'accepted' });
                } finally { await models.TopologyConfigOwner.collection.replaceOne({ _id: privateOwner._id }, privateOwner); }
            }
        });
        // Fixture-only corruption probes: current epoch authority, not immutable
        // alias/history. Each exact owner BSON is restored in finally.
        for (const change of ['missing-current-proof', 'stale-owner', 'stale-boot', 'stale-endpoint']) {
            const changed = structuredClone(privateOwner.executionEnrollment);
            if (change === 'missing-current-proof') delete changed.enrollment;
            if (change === 'stale-owner') changed.enrollment.ownerGeneration = changed.previousAdoptionReceipt.toGeneration;
            if (change === 'stale-boot') changed.enrollment.bootId = randomUUID();
            if (change === 'stale-endpoint') changed.enrollment.endpoint.ip = '192.0.2.254';
            await models.TopologyConfigOwner.collection.updateOne({ _id: privateOwner._id }, { $set: { executionEnrollment: changed } });
            try { await assert.rejects(liveStore.readVerified(expected)); }
            finally { await models.TopologyConfigOwner.collection.replaceOne({ _id: privateOwner._id }, privateOwner); }
        }
        assert.deepEqual(await liveStore.readVerified(expected), b);
        observations.binding = { operationId, bindingId: raw._id, bindingBsonHex: mongoose.mongo.BSON.serialize(raw).toString('hex'),
            ownerGeneration: raw.ownerGeneration, bootId: raw.bootId, maintenanceId: raw.maintenanceId, aliasId: raw.enrollmentId,
            defaultExecutorVerifiedConnectionReads: reads, currentAuthorityControls: 4 };
        runner = require('./helpers/topologyTerminalFakeRunner').fakeRunner(t, b.bootId);
        runner.put('usr/local/etc/xray/config.json', Buffer.from(current.config));
        runner.put('usr/local/bin/celerity-topology-node-runner-v2', fs.readFileSync(path.join(__dirname, '../node-artifacts/topology/runner.sh')), 0o750);
        const executor = coordinator.operationWorker.executor;
        const preparedResult = await executor.prepare(context);
        const active = { ...context, backupId: preparedResult.backupId, prepared: preparedResult.prepared };
        assert.ok(await executor.commit(active));
        assert.ok(await executor.verify(active));
        assert.equal(await repository.recordNode({ operationId, owner, now: new Date(), node: NODE, state: 'committed', backupId: active.backupId }), true);
        assert.equal(await repository.setPhase({ operationId, owner, now: new Date(), from: 'preparing', to: 'committing' }), true);
        const claimed = await models.TopologyOperation.findById(operationId).lean();
        const request = { operationId, owner, topologyRevision: baseline.revision, priorDeployedRevision: baseline.deployedRevision, leaseUntil: claimed.leaseUntil };
        const finalizer = coordinator.operationWorker.finalizer;
        const terminalOwner = await models.TopologyConfigOwner.collection.findOne({ node: new mongoose.Types.ObjectId(NODE) });
        for (const stale of ['owner', 'boot']) {
            const changed = structuredClone(terminalOwner.executionEnrollment);
            if (stale === 'owner') changed.enrollment.ownerGeneration = changed.previousAdoptionReceipt.toGeneration;
            else { changed.enrollment.bootId = randomUUID(); changed.enrollment.provisioningReceipt.bootId = changed.enrollment.bootId; }
            await models.TopologyConfigOwner.collection.updateOne({ _id: terminalOwner._id }, { $set: { executionEnrollment: changed } });
            try { await assert.rejects(finalizer.beginV2Closure({ ...request, bindings: [b] })); }
            finally { await models.TopologyConfigOwner.collection.replaceOne({ _id: terminalOwner._id }, terminalOwner); }
            assert.equal((await models.TopologyOperation.findById(operationId).lean()).v2Terminal, undefined);
            assert.equal(await models.NodeOperationLock.countDocuments(), 1);
        }
        observations.currentTerminalRefusals = ['stale-owner-generation', 'stale-boot'];
        assert.ok(await finalizer.beginV2Closure({ ...request, bindings: await executor.terminalBindings([active]) }));
        const proof = await executor.close(active);
        assert.ok(await finalizer.persistV2TerminalProofs({ ...request, proofs: [proof], sideEffects: { usersVerified: true, attachVerified: false, pppProof: [] } }));
        assert.ok(await finalizer.finalizeV2Succeeded(request));
        const settled = await finalizer.probeV2Settlement({ operationId });
        assert.equal(settled.status, 'succeeded'); assert.equal(settled.retained, false);
        observations.nativeTerminal = { proof, operationId, state: settled.terminal.state,
            ownerFence: settled.terminal.ownerFences[0], originalBaseline: baseline.deployedRevision,
            newSuccessfulBaseline: (await models.CascadeTopologyState.findById('singleton').lean()).deployedRevision };
        assert.equal((await models.TopologyOperation.findById(operationId).lean()).heldTopologyAdmission, false);
        assert.equal(await models.NodeOperationLock.countDocuments(), 0);
        assert.deepEqual(mongoose.mongo.BSON.serialize(await models.TopologyExecutionBinding.collection.findOne({ operationId })), mongoose.mongo.BSON.serialize(raw));
    });
}
for (const mode of ['stale', 'mismatch']) test(`${mode} physical authority refuses before owner mutation/consumer assembly`, async () => {
    fault = mode; const before = await models.TopologyConfigOwner.findOne({ node: NODE }).lean(); let hosts = 0;
    const rejected = createL2tpRootLifecycle({ env, createTopologyExecutionAuthority: factory, createHostDependencies() { hosts++; assert.fail('no host before authority'); } });
    try { await assert.rejects(rejected.startAfterDatabase()); } finally { fault = undefined; await rejected.stop(); }
    assert.equal(hosts, 0); assert.deepEqual(await models.TopologyConfigOwner.findOne({ node: NODE }).lean(), before);
});
