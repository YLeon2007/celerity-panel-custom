'use strict';
// Focused REAL loopback Mongo regression. Authority is simulated here only;
// operational TEST exclusion is verified separately, never inferred from this suite.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { mongo } = require('mongoose');
const impl = require('../services/productionAdmissionInitializer');
const { rawDocumentFingerprint: fingerprint } = require('../services/productionAdmissionInitializationPreflight');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const { verifyProductionStartupSchema } = require('../services/productionAdmissionReadiness');
const name = `production_existing_${randomUUID().replaceAll('-', '')}`;
let client, child, directory, db, deployment, uri;
const commands = [];
async function until(fn) {
    let error;
    for (let i = 0; i < 150; i++) {
        try { return await fn(); } catch (caught) { error = caught; }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw error;
}
async function reset({ missing = ['remoteAdmissionCount', 'topologyAdmissionCount'], fullIndexes = false } = {}) {
    for (const entry of await db.listCollections().toArray()) await db.collection(entry.name).drop();
    for (const entry of impl.REVIEWED_MANIFEST.collections) {
        await db.createCollection(entry.name);
        if (fullIndexes || entry.name !== 'cascadelinks') {
            for (const { key, ...options } of entry.indexes.filter(x => x.name !== '_id_')) {
                await db.collection(entry.name).createIndex(key, options);
            }
        }
    }
    const link = { _id: new mongo.ObjectId(), mode: 'reverse', active: true, status: 'online',
        portalNode: new mongo.ObjectId(), bridgeNode: new mongo.ObjectId(), tunnelUuid: 'fixture-only',
        createdAt: new Date('2026-11-16T00:00:00Z'), statusMetadata: { untouched: true } };
    const state = { _id: 'singleton', revision: 1, deployedRevision: 0, replacementEpoch: 0,
        stateTransitionRevision: 0, __v: 0, createdAt: new Date('2026-11-16T00:00:00Z'),
        updatedAt: new Date('2026-11-16T00:00:00Z'), remoteAdmissionCount: 0, topologyAdmissionCount: 0 };
    missing.forEach(key => delete state[key]);
    await db.collection('cascadelinks').insertOne(link);
    await db.collection('cascadetopologystates').insertOne(state);
    await db.createCollection('topologyconfigowners');
    await db.createCollection('hyusers');
    await db.collection('hyusers').insertOne({ _id: new mongo.ObjectId(), name: 'preserve-user' });
    return { link, state, pins: [{ id: String(link._id), sha256: fingerprint(link) }] };
}
function authority(hook = async () => {}) {
    const state = { retained: false, checks: 0 };
    return { state, async withHeldMaintenance(challenge, work) {
        assert.equal(Object.isFrozen(challenge), true);
        assert.equal(challenge.serverContext, context);
        return work({ async assertHeld(same) {
            assert.equal(same, challenge); state.checks++; await hook(challenge, state);
        }, async retainUnknown(same) { assert.equal(same, challenge); state.retained = true; } });
    } };
}
function assemble(fixture, held = authority(), overrides = {}) {
    assert.equal(typeof impl.createProductionAdmissionExistingStatePreparation, 'function',
        'missing supported existing-state maintenance preparation');
    return impl.createProductionAdmissionExistingStatePreparation({ db, serverContext: context,
        expectedDatabaseName: name, expectedDeployment: deployment,
        acceptedClassicLinks: fixture.pins, expectedStateSha256: fingerprint(fixture.state),
        acceptedManifestSha256: impl.REVIEWED_MANIFEST_SHA256,
        maintenanceGeneration: randomUUID(), maintenanceAuthority: held, ...overrides });
}
async function docs() {
    const out = {};
    for (const row of await db.listCollections().toArray()) {
        out[row.name] = await db.collection(row.name).find({}).sort({ _id: 1 }).toArray();
    }
    return out;
}
const writes = rows => rows.filter(x => ['insert', 'update', 'delete', 'create', 'createIndexes', 'drop',
    'dropDatabase', 'findAndModify'].includes(x.commandName));
test.before(async () => {
    assert.ok(process.env.C3_MONGOD); assert.ok(process.env.TMPDIR);
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-existing-'));
    const port = await new Promise(resolve => {
        const s = net.createServer(); s.listen(0, '127.0.0.1', () => {
            const p = s.address().port; s.close(() => resolve(p));
        });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port),
        '--bind_ip', '127.0.0.1', '--replSet', 'productionExistingScratch', '--setParameter',
        'enableTestCommands=1', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    uri = `mongodb://127.0.0.1:${port}/${name}?directConnection=true`;
    client = new mongo.MongoClient(uri,
        { serverSelectionTimeoutMS: 250, monitorCommands: true, retryWrites: false });
    client.on('commandStarted', x => commands.push(x));
    await until(() => client.connect());
    await client.db('admin').command({ replSetInitiate: { _id: 'productionExistingScratch',
        members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
    await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    db = client.db(name);
    const { config } = await client.db('admin').command({ replSetGetConfig: 1 });
    deployment = { setName: config._id, replicaSetId: String(config.settings.replicaSetId) };
});
test.after(async () => {
    if (client) await client.close();
    if (child && child.exitCode === null) {
        const exit = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM'); await exit;
    }
    // Retain genuine OWN fixture files/logs for receipts; no external DB touched.
});
test('one-link legacy existing state: missing counters only, preserved deployed revision/user/link, ordinary read-only check', async () => {
    const f = await reset(); const before = await docs(); const held = authority(); const start = commands.length;
    const prep = assemble(f, held); const result = await prep.prepare();
    assert.equal(result.mode, 'existing-state-counters'); assert.equal(result.prepared, true);
    assert.equal(result.ready, false); assert.equal(result.dormant, true);
    assert.deepEqual(result.addedFields, ['remoteAdmissionCount', 'topologyAdmissionCount']);
    const after = await docs();
    assert.deepEqual(after, { ...before, cascadetopologystates: [{ ...f.state, remoteAdmissionCount: 0, topologyAdmissionCount: 0 }] });
    const observed = commands.slice(start);
    assert.equal(observed.filter(x => x.commandName === 'update').length, 1);
    assert.equal(observed.filter(x => x.commandName === 'commitTransaction').length, 1);
    assert.equal(observed.filter(x => x.commandName === 'insert').length, 0);
    assert.equal(held.state.retained, false); assert.ok(held.state.checks > 20);
    await assert.rejects(prep.prepare(), { code: 'PRODUCTION_INITIALIZATION_ALREADY_ATTEMPTED' });
    const checkStart = commands.length;
    const ordinary = await verifyProductionStartupSchema({ db, accepted: { serverContext: context,
        databaseName: name, deployment, maintenanceGeneration: randomUUID(), manifestSha256: impl.REVIEWED_MANIFEST_SHA256 },
    scope: { async assertHeld() {} } });
    assert.equal(ordinary.schemaVerified, true); assert.equal(ordinary.executionEnabled, false);
    assert.equal(writes(commands.slice(checkStart)).length, 0);
});
test('repeat is idempotent and partially present zero is preserved', async () => {
    for (const missing of [['remoteAdmissionCount'], ['topologyAdmissionCount'], []]) {
        const f = await reset({ missing, fullIndexes: true }); await assemble(f).prepare();
        const state = await db.collection('cascadetopologystates').findOne({});
        const before = await docs(); const start = commands.length;
        const result = await assemble({ ...f, state }).prepare();
        assert.deepEqual(result.addedFields, []); assert.deepEqual(await docs(), before);
        assert.equal(writes(commands.slice(start)).length, 0);
    }
});
test('finite maintenance entry reuses its same held scope for the explicit existing-state mode', async () => {
    const f = await reset({ fullIndexes: true }); const before = await docs(); let holds = 0;
    const { testing: { runAccepted } } = require('../runtime/productionAdmissionMaintenanceEntry');
    const challenge = { serverContext: context, databaseName: name, deployment,
        maintenanceGeneration: randomUUID(), mode: 'existing-state-counters', expectedStateSha256: fingerprint(f.state),
        acceptedClassicLinks: f.pins, manifestSha256: impl.REVIEWED_MANIFEST_SHA256, acceptedMissingCollections: [] };
    const result = await runAccepted({ config: { challenge, mongoUri: uri },
        authority: { async withHeldMaintenance(same, work) {
            holds++; assert.deepEqual(same, challenge);
            return work({ async assertHeld(supplied) { assert.deepEqual(supplied, challenge); },
                async retainUnknown() { assert.fail('no unknown expected'); } });
        } }, createClient(address, options) { assert.equal(address, uri); return new mongo.MongoClient(address, options); } });
    assert.equal(holds, 1); assert.equal(result.prepared, true);
    assert.deepEqual(await docs(), { ...before, cascadetopologystates: [{ ...f.state,
        remoteAdmissionCount: 0, topologyAdmissionCount: 0 }] });
});
test('disagreement, active/retained history, reservations and incomplete catalogs refuse without erasing', async () => {
    const cases = [
        async () => db.collection('cascadetopologystates').updateOne({}, { $set: { remoteAdmissionCount: 2 } }),
        async () => db.collection('cascadetopologystates').updateOne({}, { $set: { topologyAdmissionCount: 1 } }),
        async () => db.collection('cascadetopologystates').updateOne({}, { $set: { remoteDrain: { ownerToken: 'real-retained', epoch: 2 } } }),
        async () => db.collection('cascadetopologystates').updateOne({}, { $set: { replacementReservation: { ownerToken: 'retained', epoch: 2 } } }),
        async () => db.collection('cascadetopologystates').updateOne({}, { $set: { classicLifecycleAttempt: { phase: 'dispatching' } } }),
        async () => db.collection('remoteadmissions').insertOne({ _id: 'active', phase: 'running' }),
        async () => db.collection('remoteadmissions').insertOne({ _id: 'uncertain', phase: 'recovery_required' }),
        async () => db.collection('remoteadmissions').insertOne({ _id: 'history', phase: 'completed' }),
        async () => db.collection('topologyoperations').insertOne({ _id: 'held', heldTopologyAdmission: true }),
        async () => db.collection('nodeoperationlocks').insertOne({ _id: 'retained', node: 'p' }),
        async () => db.collection('topologyconfigowners').insertOne({ _id: 'owner', node: 'p' }),
        async () => db.collection('topologyintentqueuestates').insertOne({ _id: 'singleton', nextOrdinal: 3 }),
        async () => db.collection('remoteadmissions').drop(),
    ];
    for (const change of cases) {
        const f = await reset(); await change(); f.state = await db.collection('cascadetopologystates').findOne({});
        const before = await docs(); const start = commands.length;
        await assert.rejects(assemble(f).prepare());
        assert.deepEqual(await docs(), before); assert.equal(writes(commands.slice(start)).length, 0);
    }
});
test('stale whole-state pin and transaction CAS conflict preserve the foreign winner', async () => {
    const f = await reset({ fullIndexes: true });
    await db.collection('cascadetopologystates').updateOne({}, { $set: { revision: 2 } });
    const before = await docs(); const start = commands.length;
    await assert.rejects(assemble(f).prepare()); assert.deepEqual(await docs(), before);
    assert.equal(writes(commands.slice(start)).length, 0);
    const g = await reset({ fullIndexes: true }); let changed = false;
    const held = authority(async () => {
        if (!changed && commands.some(x => x.commandName === 'find' && x.command.find === 'cascadetopologystates' && x.command.autocommit === false)) {
            changed = true; await db.collection('cascadetopologystates').updateOne({}, { $set: { revision: 9 } });
        }
    });
    // Limit the hook to this run, not prior fixture transactions.
    commands.length = 0;
    await assert.rejects(assemble(g, held).prepare()); assert.equal(changed, true);
    assert.deepEqual(await db.collection('cascadetopologystates').findOne({}), { ...g.state, revision: 9 });
});
test('old ten-link insert-only contract remains separate; existing entry cannot create absent singleton', async () => {
    const f = await reset({ fullIndexes: true });
    assert.throws(() => impl.createProductionAdmissionInitializer({ db, serverContext: context,
        expectedDatabaseName: name, expectedDeployment: deployment, acceptedClassicLinks: f.pins,
        initialState: { _id: 'singleton', revision: 0, deployedRevision: 0, replacementEpoch: 0,
            stateTransitionRevision: 0, remoteAdmissionCount: 0, topologyAdmissionCount: 0 },
        acceptedManifestSha256: impl.REVIEWED_MANIFEST_SHA256, maintenanceGeneration: randomUUID(),
        maintenanceAuthority: authority() }), { code: 'PRODUCTION_INITIALIZATION_INPUT_REFUSED' });
    await db.collection('cascadetopologystates').deleteOne({}); const before = await docs();
    await assert.rejects(assemble(f).prepare()); assert.deepEqual(await docs(), before);
});
