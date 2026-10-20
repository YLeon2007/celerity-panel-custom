'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID, createHash } = require('node:crypto');
const { mongo } = require('mongoose');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
let implementation = {};
try { implementation = require('../services/productionAdmissionInitializer'); }
catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }
const models = [require('../../../models/cascadeLinkModel'),
    ...['cascadeTopologyState', 'topologyOperation', 'topologyCreateIntent', 'topologyIntentQueueState',
        'l2tpOperation', 'nodeOperationLock', 'remoteAdmission', 'topologyExecutionBinding',
        'topologyExecutionEnrollment', 'cascadeRouteGroup'].map(file => require(`../models/${file}Model`))];
const name = `production_init_write_${randomUUID().replaceAll('-', '')}`;
let client, child, directory, db, deployment;
const commands = [], replies = [];
function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object') return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, canonical(value[key])]));
    return value;
}
function fingerprint(row) {
    return createHash('sha256').update(JSON.stringify(canonical(
        mongo.BSON.EJSON.serialize(row, { relaxed: false })))).digest('hex');
}
async function until(fn) {
    let error;
    for (let i = 0; i < 150; i++) {
        try { return await fn(); } catch (caught) { error = caught; }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw error;
}
async function reset() {
    for (const entry of await db.listCollections().toArray()) await db.collection(entry.name).drop();
    for (const model of models) {
        await db.createCollection(model.collection.name);
        for (const [key, options] of model.schema.indexes()) {
            const { background, ...rest } = options;
            await db.collection(model.collection.name).createIndex(key, rest);
        }
    }
    const links = Array.from({ length: 10 }, (_, i) => ({ _id: new mongo.ObjectId(),
        mode: i < 8 ? 'reverse' : 'forward', active: true, status: 'online',
        portalNode: new mongo.ObjectId(), bridgeNode: new mongo.ObjectId(),
        tunnelPort: 11000 + i, tunnelUuid: `synthetic-secret-${i}`, classicOwnership: 'unchanged' }));
    await db.collection('cascadelinks').insertMany(links);
    return links.map(row => ({ id: String(row._id), sha256: fingerprint(row) }));
}
// SIMULATION ONLY: this fixture provides no real process/writer exclusion.
function simulatedAuthority(hook = async () => {}) {
    const state = { held: false, retained: false, assertions: 0, released: false };
    return { state, async withHeldMaintenance(challenge, run) {
        assert.equal(Object.isFrozen(challenge), true);
        assert.equal(challenge.serverContext, context);
        state.held = true;
        try {
            return await run({ async assertHeld(same) {
                assert.equal(same, challenge);
                assert.equal(state.held, true);
                state.assertions++;
                await hook(challenge, state);
                assert.equal(state.held, true);
            }, async retainUnknown(same) {
                assert.equal(same, challenge);
                state.retained = true;
            } });
        } finally {
            if (!state.retained) { state.held = false; state.released = true; }
        }
    } };
}
const initialState = Object.freeze({ _id: 'singleton', revision: 7, deployedRevision: 7,
    stateTransitionRevision: 3, replacementEpoch: 2, remoteAdmissionCount: 0, topologyAdmissionCount: 0 });
function assemble(pins, authority = simulatedAuthority(), overrides = {}) {
    assert.equal(typeof implementation.createProductionAdmissionInitializer, 'function',
        'missing insert-only one-shot initializer');
    return implementation.createProductionAdmissionInitializer({ db, serverContext: context,
        expectedDatabaseName: name, expectedDeployment: deployment, acceptedClassicLinks: pins,
        initialState, acceptedManifestSha256: implementation.REVIEWED_MANIFEST_SHA256,
        maintenanceAuthority: authority, maintenanceGeneration: randomUUID(), ...overrides });
}

test.before(async () => {
    assert.ok(process.env.C3_MONGOD);
    assert.ok(process.env.TMPDIR);
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-prod-init-write-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => {
            const value = server.address().port;
            server.close(() => resolve(value));
        });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port),
        '--bind_ip', '127.0.0.1', '--replSet', 'productionInitWriteScratch',
        '--setParameter', 'enableTestCommands=1', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    client = new mongo.MongoClient(`mongodb://127.0.0.1:${port}/${name}?directConnection=true`,
        { serverSelectionTimeoutMS: 250, monitorCommands: true, retryWrites: false });
    client.on('commandStarted', event => commands.push(event));
    client.on('commandSucceeded', event => replies.push(event));
    await until(() => client.connect());
    await client.db('admin').command({ replSetInitiate: { _id: 'productionInitWriteScratch',
        members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
    await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    db = client.db(name);
    const { config } = await client.db('admin').command({ replSetGetConfig: 1 });
    deployment = { setName: config._id, replicaSetId: String(config.settings.replicaSetId) };
});
test.after(async () => {
    try { if (db) { assert.match(name, /^production_init_write_[a-f0-9]{32}$/); await db.dropDatabase(); } }
    finally {
        if (client) await client.close();
        if (child && child.exitCode === null) {
            const exit = new Promise(resolve => child.once('exit', resolve));
            child.kill('SIGTERM'); await exit;
        }
        if (directory) await fs.rm(directory, { recursive: true, force: true });
    }
});

test('insert-only success uses reviewed explicit fields, leaves ten classic links and runtime dormant', async () => {
    const pins = await reset();
    const links = await db.collection('cascadelinks').find({}).sort({ _id: 1 }).toArray();
    const authority = simulatedAuthority();
    const initializer = assemble(pins, authority);
    const start = commands.length;
    const result = await initializer.initialize();
    const observed = commands.slice(start);
    assert.deepEqual(result, { initialized: true, ready: false, dormant: true, mode: 'insert-only',
        stateSha256: fingerprint(initialState) });
    assert.deepEqual(await db.collection('cascadetopologystates').findOne({}), initialState);
    assert.deepEqual(await db.collection('cascadelinks').find({}).sort({ _id: 1 }).toArray(), links);
    assert.ok(authority.state.assertions > 20);
    assert.equal(authority.state.released, true);
    assert.equal(authority.state.retained, false);
    const catalogReads = observed.filter(event => event.commandName === 'listIndexes');
    assert.deepEqual([...new Set(catalogReads.map(event => event.command.listIndexes))].sort(),
        models.map(model => model.collection.name).sort());
    for (const event of catalogReads) {
        assert.equal(event.command.includeBuildUUIDs, true);
        assert.ok(event.command.maxTimeMS > 0 && event.command.maxTimeMS <= 2000);
    }
    const pages = observed.filter(event => event.commandName === 'getMore');
    assert.ok(pages.length > 0, 'bounded raw index cursor pagination exercised');
    for (const event of pages) assert.equal(event.command.maxTimeMS, undefined,
        'non-awaitData getMore inherits cursor server deadline and must not send maxTimeMS');
    const inserts = observed.filter(event => event.commandName === 'insert');
    assert.equal(inserts.length, 1);
    assert.equal(inserts[0].command.insert, 'cascadetopologystates');
    const snapshot = observed.find(event => event.commandName === 'find' && event.command.startTransaction);
    assert.equal(snapshot.command.readConcern.level, 'snapshot');
    const commits = observed.filter(event => event.commandName === 'commitTransaction');
    assert.equal(commits.length, 1);
    assert.equal(commits[0].command.writeConcern.w, 'majority');
    const confirmed = observed.filter(event => event.commandName === 'find' && event.command.autocommit === undefined);
    assert.ok(confirmed.some(event => event.command.find === 'cascadetopologystates'));
    for (const event of confirmed) {
        assert.equal(event.command.readConcern.level, 'majority');
        assert.ok(event.command.maxTimeMS > 0 && event.command.maxTimeMS <= 2000);
    }
    await assert.rejects(initializer.initialize(), { code: 'PRODUCTION_INITIALIZATION_ALREADY_ATTEMPTED' });
});

// Production-like first install: legacy links/locks/L2TP/groups exist; new stores do not.
const firstInstallMissing = ['cascadetopologystates', 'topologyoperations', 'topologycreateintents',
    'topologyintentqueuestates', 'remoteadmissions', 'topologyexecutionbindings', 'topologyexecutionenrollments'];
async function firstInstall() {
    const pins = await reset();
    for (const name of firstInstallMissing) await db.collection(name).drop();
    return { pins, plan: firstInstallMissing.map(name => ({ name, options: {} })) };
}
async function catalogIdentity() {
    return (await db.listCollections().toArray()).map(row => ({ name: row.name, uuid: row.info?.uuid,
        type: row.type, options: row.options })).sort((a, b) => a.name.localeCompare(b.name));
}
const writes = events => events.filter(event => ['create', 'createIndexes', 'drop', 'dropIndexes',
    'collMod', 'insert', 'update', 'delete', 'commitTransaction'].includes(event.commandName));

test('explicit missing-collection plan initializes production-like first install without replacing existing UUIDs', async () => {
    const { pins, plan } = await firstInstall();
    const before = await catalogIdentity();
    const links = await db.collection('cascadelinks').find({}).sort({ _id: 1 }).toArray();
    const authority = simulatedAuthority(async challenge => {
        assert.deepEqual(challenge.acceptedMissingCollections, plan);
        assert.equal(Object.isFrozen(challenge.acceptedMissingCollections), true);
        assert.equal(Object.isFrozen(challenge.acceptedMissingCollections[0].options), true);
    });
    const start = commands.length;
    const result = await assemble(pins, authority, { acceptedMissingCollections: plan }).initialize();
    const observed = commands.slice(start);
    assert.equal(result.initialized, true);
    assert.equal(result.ready, false);
    assert.equal(result.dormant, true);
    const after = await catalogIdentity();
    for (const entry of before) assert.deepEqual(after.find(row => row.name === entry.name), entry);
    assert.deepEqual(after.map(row => row.name).sort(), models.map(model => model.collection.name).sort());
    assert.deepEqual(await db.collection('cascadelinks').find({}).sort({ _id: 1 }).toArray(), links);
    assert.deepEqual(await db.collection('cascadetopologystates').findOne({}), initialState);
    const creates = observed.filter(event => event.commandName === 'create');
    assert.deepEqual(creates.map(event => event.command.create), firstInstallMissing);
    for (const event of creates) {
        assert.ok(event.command.maxTimeMS > 0 && event.command.maxTimeMS <= 2000);
        assert.equal(event.command.autocommit, false);
    }
    const proof = observed.find(event => event.commandName === 'aggregate' && event.command.pipeline?.[0]?.$changeStream);
    assert.ok(proof.command.pipeline[0].$changeStream.showExpandedEvents);
    const match = proof.command.pipeline[1].$match;
    assert.deepEqual(match['lsid.id'], creates[0].command.lsid.id);
    assert.equal(String(match.txnNumber), String(creates[0].command.txnNumber));
    const proofPages = observed.filter(event => event.commandName === 'getMore' && event.command.collection === '$cmd.aggregate');
    assert.equal(proofPages.length, 1);
    assert.deepEqual(proofPages[0].command.lsid, proof.command.lsid, 'explicit evidence cursor session retained');
    const events = replies.find(event => event.requestId === proofPages[0].requestId).reply.cursor.nextBatch;
    assert.equal(events.length, plan.length);
    for (const event of events) assert.deepEqual(after.find(row => row.name === event.ns.coll).uuid, event.collectionUUID);
    const commits = observed.filter(event => event.commandName === 'commitTransaction');
    assert.equal(commits.length, 2, 'one schema-create commit and one singleton commit, without retry');
    for (const event of commits) assert.equal(event.command.writeConcern.w, 'majority');
    assert.deepEqual(observed.filter(event => ['drop', 'dropIndexes', 'update', 'delete', 'collMod'].includes(event.commandName)), []);
    assert.equal(authority.state.retained, false);
});

async function failCommand(command, data) {
    await client.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 },
        data: { failCommands: [command], ...data } });
}
async function disableFailure() {
    await client.db('admin').command({ configureFailPoint: 'failCommand', mode: 'off' });
}
function afterCommand(predicate, action) {
    let fired = false;
    const authority = simulatedAuthority(async () => {
        if (!fired && predicate(commands.at(-1))) { fired = true; await action(); }
    });
    return { authority, fired: () => fired };
}

test('no accepted missing plan, or absent/present drift, refuses before any initializer write', async t => {
    for (const [label, setup] of [
        ['no plan', async () => { const fixture = await firstInstall(); return { ...fixture, plan: undefined }; }],
        ['unlisted absence', async () => { const fixture = await firstInstall(); return { ...fixture, plan: fixture.plan.slice(1) }; }],
        ['planned collection already exists', async () => { const fixture = await firstInstall();
            await db.createCollection(firstInstallMissing[0]); return fixture; }],
        ['legacy links absent', async () => { const fixture = await firstInstall(); await db.collection('cascadelinks').drop(); return fixture; }],
        ['planned namespace is a view', async () => { const fixture = await firstInstall();
            await db.createCollection(firstInstallMissing[0], { viewOn: 'cascadelinks', pipeline: [] }); return fixture; }],
        ['existing options', async () => { const fixture = await firstInstall();
            await db.collection('nodeoperationlocks').drop();
            await db.createCollection('nodeoperationlocks', { validator: { node: { $type: 'objectId' } } }); return fixture; }],
        ['existing index conflict', async () => { const fixture = await firstInstall();
            await db.collection('nodeoperationlocks').dropIndex('node_1');
            await db.collection('nodeoperationlocks').createIndex({ node: 1 }); return fixture; }],
        ['existing history row', async () => { const fixture = await firstInstall();
            await db.collection('l2tpoperations').insertOne({ _id: 'foreign', idempotencyKey: 'keep' }); return fixture; }],
    ]) await t.test(label, async () => {
        const { pins, plan } = await setup();
        const before = await catalogIdentity();
        const links = await db.collection('cascadelinks').find({}).sort({ _id: 1 }).toArray();
        const start = commands.length;
        await assert.rejects(assemble(pins, simulatedAuthority(), { acceptedMissingCollections: plan }).initialize(),
            /PRODUCTION_INITIALIZATION_(CATALOG_REFUSED|INDEX_CONFLICT|HISTORY_PRESENT)/);
        assert.deepEqual(writes(commands.slice(start)), []);
        assert.deepEqual(await catalogIdentity(), before);
        assert.deepEqual(await db.collection('cascadelinks').find({}).sort({ _id: 1 }).toArray(), links);
    });
});

test('missing collection names and exact options require independent explicit allowlist acceptance', async t => {
    const pins = await reset();
    for (const plan of [null, {}, new Array(1), ['remoteadmissions'], [{ name: 'remoteadmissions', options: new Date(0) }],
        [{ name: 'cascadelinks', options: {} }],
        [{ name: 'system.users', options: {} }], [{ name: 'remoteadmissions' }],
        [{ name: ['remoteadmissions'], options: {} }], [{ name: 'remoteadmissions', options: [] }],
        [{ name: 'remoteadmissions', options: { capped: false } }],
        [{ name: 'remoteadmissions', options: {}, uuid: randomUUID() }],
        [{ name: 'remoteadmissions', options: {} }, { name: 'remoteadmissions', options: {} }]]) {
        await t.test(JSON.stringify(plan), () => {
            const start = commands.length;
            assert.throws(() => assemble(pins, simulatedAuthority(), { acceptedMissingCollections: plan }),
                { code: 'PRODUCTION_INITIALIZATION_INPUT_REFUSED' });
            assert.equal(commands.length, start);
        });
    }
});

test('plan is copied and deeply frozen before await; source mutation cannot authorize other namespaces', async () => {
    const { pins, plan } = await firstInstall();
    const accepted = structuredClone(plan);
    const authority = simulatedAuthority(async challenge => {
        assert.deepEqual(challenge.acceptedMissingCollections, accepted);
        assert.equal(Object.isFrozen(challenge.acceptedMissingCollections[0]), true);
        plan[0].name = 'cascadelinks';
        plan[0].options.capped = true;
        plan.push({ name: 'foreign', options: {} });
    });
    await assemble(pins, authority, { acceptedMissingCollections: plan }).initialize();
    assert.equal((await catalogIdentity()).some(row => row.name === 'foreign'), false);
});

test('foreign create in the last absence-check/create gap is retained, never adopted', async t => {
    for (const kind of ['compatible empty', 'foreign row', 'view', 'options', 'conflicting index']) await t.test(kind, async () => {
        const pins = await reset();
        await db.collection('remoteadmissions').drop();
        await db.collection('cascadetopologystates').drop();
        const plan = ['cascadetopologystates', 'remoteadmissions'].map(name => ({ name, options: {} }));
        const start = commands.length;
        let winner;
        const row = { _id: 'foreign', operationId: 'keep', kind: 'sync_users' };
        const race = afterCommand(() => commands.slice(start).filter(event => event.commandName === 'listCollections').length === 4,
            async () => {
                await db.createCollection('remoteadmissions', kind === 'view' ? { viewOn: 'cascadelinks', pipeline: [] }
                    : kind === 'options' ? { validator: { kind: { $type: 'string' } } } : {});
                if (kind === 'foreign row') await db.collection('remoteadmissions').insertOne(row);
                if (kind === 'conflicting index') await db.collection('remoteadmissions').createIndex({ foreign: 1 });
                winner = (await catalogIdentity()).find(row => row.name === 'remoteadmissions');
            });
        const initializer = assemble(pins, race.authority, { acceptedMissingCollections: plan });
        await assert.rejects(initializer.initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
        const observed = commands.slice(start);
        assert.equal(race.fired(), true);
        assert.deepEqual((await catalogIdentity()).find(row => row.name === 'remoteadmissions'), winner);
        assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
        assert.equal(race.authority.state.retained, true);
        const create = observed.find(event => event.command.create === 'remoteadmissions' && event.command.autocommit === false);
        assert.ok(create);
        assert.equal(observed.filter(event => event.command.create === 'remoteadmissions'
            && event.command.autocommit === false).length, 1, 'exactly one create attempt, no retry');
        if (['compatible empty', 'foreign row', 'conflicting index'].includes(kind)) {
            assert.equal(replies.find(event => event.requestId === create.requestId)?.reply.ok, 1,
                'real Mongo accepts a compatible foreign namespace; ok:1 alone is NOT creation proof');
            assert.equal(observed.filter(event => event.commandName === 'commitTransaction').length, 1);
            assert.equal(observed.filter(event => event.commandName === 'abortTransaction').length, 0);
        }
        if (kind === 'foreign row') assert.deepEqual(await db.collection('remoteadmissions').findOne({ _id: 'foreign' }), row);
        if (kind === 'conflicting index') assert.ok((await db.collection('remoteadmissions').listIndexes().toArray())
            .some(index => index.name === 'foreign_1'));
        assert.deepEqual(observed.filter(event => ['drop', 'dropIndexes', 'update', 'delete'].includes(event.commandName)), []);
        await assert.rejects(initializer.initialize(), { code: 'PRODUCTION_INITIALIZATION_ALREADY_ATTEMPTED' });
    });
});

test('existing UUID replacement after reviewed inventory is refused before DDL', async () => {
    const pins = await reset();
    await db.collection('remoteadmissions').drop();
    let winner, afterForeign;
    const race = afterCommand(event => event?.commandName === 'find' && event.command.find === 'cascadetopologystates', async () => {
        await db.collection('nodeoperationlocks').drop();
        await db.createCollection('nodeoperationlocks');
        await db.collection('nodeoperationlocks').createIndex({ node: 1 }, { unique: true });
        winner = (await catalogIdentity()).find(row => row.name === 'nodeoperationlocks');
        afterForeign = commands.length;
    });
    await assert.rejects(assemble(pins, race.authority,
        { acceptedMissingCollections: [{ name: 'remoteadmissions', options: {} }] }).initialize(),
    { code: 'PRODUCTION_INITIALIZATION_SCHEMA_DRIFT' });
    assert.equal(race.fired(), true);
    assert.deepEqual(writes(commands.slice(afterForeign)), []);
    assert.deepEqual((await catalogIdentity()).find(row => row.name === 'nodeoperationlocks'), winner);
});

test('created UUID is bound to own transactional event, not a replacement catalog row', async () => {
    const pins = await reset();
    await db.collection('remoteadmissions').drop();
    let winner;
    const race = afterCommand(event => event?.commandName === 'commitTransaction', async () => {
        await db.collection('remoteadmissions').drop();
        await db.createCollection('remoteadmissions');
        winner = (await catalogIdentity()).find(row => row.name === 'remoteadmissions');
    });
    await assert.rejects(assemble(pins, race.authority,
        { acceptedMissingCollections: [{ name: 'remoteadmissions', options: {} }] }).initialize(),
    { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
    assert.equal(race.fired(), true);
    assert.equal(race.authority.state.retained, true);
    assert.deepEqual((await catalogIdentity()).find(row => row.name === 'remoteadmissions'), winner);
    assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
});

test('uncertain creation, creation commit, receipt and partial schema never retry or compensate', async t => {
    for (const phase of ['create', 'second create', 'commit', 'receipt', 'receipt getMore', 'index']) await t.test(phase, async () => {
        const { pins, plan } = await firstInstall();
        const before = await catalogIdentity();
        const links = await db.collection('cascadelinks').find({}).sort({ _id: 1 }).toArray();
        let authority = simulatedAuthority();
        if (phase === 'create') await failCommand('create', { closeConnection: true });
        if (phase === 'second create') authority = afterCommand(event => event?.commandName === 'create',
            () => failCommand('create', { errorCode: 50, errorLabels: [] })).authority;
        if (phase === 'commit') await failCommand('commitTransaction', {
            writeConcernError: { code: 64, errmsg: 'synthetic schema commit uncertainty' }, errorLabels: ['UnknownTransactionCommitResult'] });
        if (phase.startsWith('receipt')) authority = afterCommand(event => event?.commandName === 'commitTransaction',
            () => failCommand(phase === 'receipt' ? 'aggregate' : 'getMore', { errorCode: 50, errorLabels: [] })).authority;
        if (phase === 'index') authority = afterCommand(event => event?.commandName === 'createIndexes',
            () => failCommand('createIndexes', { errorCode: 50, errorLabels: [] })).authority;
        const start = commands.length;
        try {
            await assert.rejects(assemble(pins, authority, { acceptedMissingCollections: plan }).initialize(),
                { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
        } finally { await disableFailure(); }
        assert.equal(authority.state.retained, true);
        assert.equal(authority.state.released, false);
        const observed = commands.slice(start);
        const creates = observed.filter(event => event.commandName === 'create');
        assert.equal(new Set(creates.map(event => event.command.create)).size, creates.length);
        assert.ok(observed.filter(event => event.commandName === 'commitTransaction').length <= 1);
        assert.deepEqual(observed.filter(event => ['drop', 'dropIndexes', 'collMod', 'update', 'delete'].includes(event.commandName)), []);
        assert.deepEqual(await db.collection('cascadelinks').find({}).sort({ _id: 1 }).toArray(), links);
        const after = await catalogIdentity();
        for (const entry of before) assert.deepEqual(after.find(row => row.name === entry.name), entry);
        assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
        if (phase.startsWith('receipt') || phase === 'index') {
            assert.equal(after.length, models.length, 'committed schema retained after later uncertainty');
            assert.equal(observed.filter(event => event.commandName === 'abortTransaction').length, 0);
        }
        if (phase === 'receipt getMore') assert.equal(observed.filter(event => event.commandName === 'getMore'
            && event.command.collection === '$cmd.aggregate').length, 1, 'no resume/retry after creation receipt failure');
        if (phase === 'index') {
            const indexes = observed.filter(event => event.commandName === 'createIndexes');
            assert.equal(indexes.length, 2, 'first reviewed index persists, second attempt fails');
            assert.ok((await db.collection(indexes[0].command.createIndexes).listIndexes().toArray())
                .some(index => index.name === indexes[0].command.indexes[0].name));
        }
    });
});

test('existing or partial singleton is never defaulted or overwritten', async t => {
    for (const row of [{ _id: 'singleton' }, { ...initialState },
        { _id: 'singleton', remoteDrain: { ownerToken: 'winner', epoch: 1 } },
        { _id: 'foreign', replacementReservation: { ownerToken: 'winner', epoch: 2 } }]) {
        await t.test(JSON.stringify(row), async () => {
            const pins = await reset();
            await db.collection('cascadetopologystates').insertOne(row);
            await assert.rejects(assemble(pins).initialize(), { code: 'PRODUCTION_INITIALIZATION_STATE_PRESENT' });
            assert.deepEqual(await db.collection('cascadetopologystates').findOne({}), row);
        });
    }
});

test('all reviewed history including terminal rows veto initialization and preserve winners', async t => {
    for (const model of models.filter(model => !['cascadelinks', 'cascadetopologystates'].includes(model.collection.name))) {
        await t.test(model.collection.name, async () => {
            const pins = await reset();
            const row = { _id: new mongo.ObjectId(), status: 'succeeded', owner: 'winner', generation: 7 };
            await db.collection(model.collection.name).insertOne(row);
            await assert.rejects(assemble(pins).initialize(), { code: 'PRODUCTION_INITIALIZATION_HISTORY_PRESENT' });
            assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
            assert.deepEqual(await db.collection(model.collection.name).findOne({}), row);
        });
    }
});

test('unfinished foreign unique index is not readiness; refusal retains held scope before singleton write', async () => {
    const pins = await reset();
    await db.collection('nodeoperationlocks').dropIndex('node_1');
    const seed = { _id: new mongo.ObjectId(), node: new mongo.ObjectId() };
    await db.collection('nodeoperationlocks').insertOne(seed);
    const admin = client.db('admin');
    const configured = await admin.command({ configureFailPoint: 'hangAfterStartingIndexBuild', mode: 'alwaysOn' });
    let pending;
    try {
        pending = db.collection('nodeoperationlocks').createIndex({ node: 1 }, { unique: true })
            .then(value => ({ value }), error => ({ error }));
        await admin.command({ waitForFailPoint: 'hangAfterStartingIndexBuild',
            timesEntered: configured.count + 1, maxTimeMS: 5000 });
        await db.collection('nodeoperationlocks').deleteOne({ _id: seed._id });
        const regular = await db.collection('nodeoperationlocks').listIndexes().toArray();
        assert.equal(regular.find(row => row.name === 'node_1').buildUUID, undefined,
            'ordinary listIndexes hides in-progress build metadata');
        const detailed = await db.command({ listIndexes: 'nodeoperationlocks', includeBuildUUIDs: true });
        assert.ok(detailed.cursor.firstBatch.some(row => row.buildUUID));
        const authority = simulatedAuthority();
        const start = commands.length;
        await assert.rejects(assemble(pins, authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
        assert.deepEqual(writes(commands.slice(start)), []);
        assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
        assert.equal(authority.state.retained, true);
        const after = await db.command({ listIndexes: 'nodeoperationlocks', includeBuildUUIDs: true });
        assert.deepEqual(after.cursor.firstBatch, detailed.cursor.firstBatch, 'foreign build retained, not awaited or cancelled');
    } finally {
        await admin.command({ configureFailPoint: 'hangAfterStartingIndexBuild', mode: 'off' });
        if (pending) assert.equal((await pending).error, undefined);
    }
    // Exactly the same catalog is admissible once the foreign build has completed,
    // but a fresh operator attempt is needed (not a retry by the initializer).
    const authority = simulatedAuthority();
    assert.equal((await assemble(pins, authority).initialize()).initialized, true);
    assert.equal(authority.state.retained, false);
});

test('late foreign builds on paginated catalogs veto pretransaction and postcommit confirmation', async t => {
    for (const phase of ['before singleton transaction', 'after singleton commit']) await t.test(phase, async () => {
        const pins = await reset();
        const name = 'topologyexecutionenrollments';
        const admin = client.db('admin');
        let pending, configured;
        const start = commands.length;
        const race = afterCommand(event => phase === 'after singleton commit'
            ? event?.commandName === 'commitTransaction'
            : event?.commandName === 'hello'
                && commands.slice(start).filter(row => row.commandName === 'hello').length === 2,
        async () => {
            await db.collection(name).dropIndex('endpoint.ip_1_endpoint.port_1');
            const seed = { _id: new mongo.ObjectId() };
            await db.collection(name).insertOne(seed);
            configured = await admin.command({ configureFailPoint: 'hangAfterStartingIndexBuild', mode: 'alwaysOn' });
            pending = db.collection(name).createIndex({ 'endpoint.ip': 1, 'endpoint.port': 1 }, { unique: true })
                .then(value => ({ value }), error => ({ error }));
            await admin.command({ waitForFailPoint: 'hangAfterStartingIndexBuild',
                timesEntered: configured.count + 1, maxTimeMS: 5000 });
            await db.collection(name).deleteOne({ _id: seed._id });
        });
        try {
            await assert.rejects(assemble(pins, race.authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
            assert.equal(race.fired(), true);
            assert.equal(race.authority.state.retained, true);
            assert.equal(await db.collection('cascadetopologystates').countDocuments(), phase === 'after singleton commit' ? 1 : 0);
            const detailed = await db.command({ listIndexes: name, includeBuildUUIDs: true });
            assert.ok(detailed.cursor.firstBatch.some(row => row.buildUUID));
            assert.ok(commands.slice(start).some(event => event.commandName === 'getMore'
                && event.command.collection === name), 'real pagination examined, not only firstBatch');
        } finally {
            if (configured) await admin.command({ configureFailPoint: 'hangAfterStartingIndexBuild', mode: 'off' });
            if (pending) assert.equal((await pending).error, undefined);
        }
    });
});

test('failed index getMore refuses incomplete inventory without retry, before writes or after commit', async t => {
    for (const postcommit of [false, true]) await t.test(String(postcommit), async () => {
        const pins = await reset();
        let armedAt;
        const race = afterCommand(event => postcommit ? event?.commandName === 'commitTransaction'
            : event?.commandName === 'listIndexes' && event.command.listIndexes === 'cascadelinks',
        async () => { await failCommand('getMore', { errorCode: 50, errorLabels: [] }); armedAt = commands.length; });
        try {
            await assert.rejects(assemble(pins, race.authority).initialize(),
                { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
        } finally { await disableFailure(); }
        assert.equal(race.fired(), true);
        assert.equal(commands.slice(armedAt).filter(event => event.commandName === 'getMore').length, 1);
        assert.equal(await db.collection('cascadetopologystates').countDocuments(), postcommit ? 1 : 0);
        // An incomplete prewrite inventory also cannot exclude an ongoing build.
        assert.equal(race.authority.state.retained, true);
        if (!postcommit) assert.deepEqual(writes(commands.slice(armedAt)), []);
    });
});

test('raw index getMore has a client deadline without invalid server maxTimeMS', async () => {
    const pins = await reset();
    const race = afterCommand(event => event?.commandName === 'listIndexes' && event.command.listIndexes === 'cascadelinks',
        () => failCommand('getMore', { blockConnection: true, blockTimeMS: 5000 }));
    const start = commands.length;
    let requestAt, failedAt;
    const onStart = event => { if (event.commandName === 'getMore') requestAt = performance.now(); };
    const onFailure = event => { if (event.commandName === 'getMore') failedAt = performance.now(); };
    client.on('commandStarted', onStart);
    client.on('commandFailed', onFailure);
    try {
        await assert.rejects(assemble(pins, race.authority).initialize(),
            { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
    } finally {
        await disableFailure();
        client.removeListener('commandStarted', onStart);
        client.removeListener('commandFailed', onFailure);
    }
    // Measure the transport deadline, not the separate cursor-cleanup/admin
    // teardown budgets (the server's blocked thread can outlive client abort).
    assert.ok(Number.isFinite(failedAt) && failedAt - requestAt < 3000,
        'getMore abort deadline, not the five-second server stall');
    assert.equal(race.fired(), true);
    const pages = commands.slice(start).filter(event => event.commandName === 'getMore');
    assert.equal(pages.length, 1, 'cancelled inventory is not retried');
    assert.equal(pages[0].command.maxTimeMS, undefined, 'non-awaitData getMore forbids server maxTimeMS');
    assert.equal(race.authority.state.retained, true);
    assert.equal(race.authority.state.released, false);
    assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
});

test('surplus completed indexes cannot release maintenance before a later unfinished build is inspected', async () => {
    const pins = await reset();
    await db.collection('nodeoperationlocks').dropIndex('node_1');
    for (let i = 0; i < 2; i++) await db.collection('nodeoperationlocks').createIndex({ [`foreign${i}`]: 1 });
    const seed = { _id: new mongo.ObjectId(), node: new mongo.ObjectId() };
    await db.collection('nodeoperationlocks').insertOne(seed);
    const admin = client.db('admin');
    const configured = await admin.command({ configureFailPoint: 'hangAfterStartingIndexBuild', mode: 'alwaysOn' });
    let pending;
    try {
        pending = db.collection('nodeoperationlocks').createIndex({ node: 1 }, { unique: true })
            .then(value => ({ value }), error => ({ error }));
        await admin.command({ waitForFailPoint: 'hangAfterStartingIndexBuild', timesEntered: configured.count + 1, maxTimeMS: 5000 });
        await db.collection('nodeoperationlocks').deleteOne({ _id: seed._id });
        const before = await db.command({ listIndexes: 'nodeoperationlocks', includeBuildUUIDs: true });
        assert.ok(before.cursor.firstBatch.some(row => row.buildUUID));
        const authority = simulatedAuthority();
        await assert.rejects(assemble(pins, authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
        assert.equal(authority.state.retained, true);
        assert.equal(authority.state.released, false);
        assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
        const after = await db.command({ listIndexes: 'nodeoperationlocks', includeBuildUUIDs: true });
        assert.deepEqual(after.cursor.firstBatch, before.cursor.firstBatch);
    } finally {
        await admin.command({ configureFailPoint: 'hangAfterStartingIndexBuild', mode: 'off' });
        if (pending) assert.equal((await pending).error, undefined);
    }
});

test('failed index cursor cleanup is observed and retains maintenance, never swallowed by native close', async () => {
    const pins = await reset();
    for (let i = 0; i < 5; i++) await db.collection('nodeoperationlocks').createIndex({ [`foreign${i}`]: 1 });
    const failures = [];
    const listener = event => failures.push(event);
    client.on('commandFailed', listener);
    const race = afterCommand(event => event?.commandName === 'listIndexes' && event.command.listIndexes === 'nodeoperationlocks',
        () => failCommand('killCursors', { errorCode: 50, errorLabels: [] }));
    const start = commands.length;
    try {
        await assert.rejects(assemble(pins, race.authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
    } finally { await disableFailure(); client.removeListener('commandFailed', listener); }
    assert.equal(race.fired(), true);
    const kills = commands.slice(start).filter(event => event.commandName === 'killCursors' && event.command.killCursors === 'nodeoperationlocks');
    assert.equal(kills.length, 1, 'one checked cleanup attempt, no hidden retry');
    assert.ok(failures.some(event => event.requestId === kills[0].requestId));
    assert.equal(race.authority.state.retained, true);
    assert.equal(race.authority.state.released, false);
    assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
});

test('additive indexes match actual source schemas, with no sync/drop or conflict repair', async t => {
    await t.test('missing reviewed indexes are created', async () => {
        const pins = await reset();
        await db.collection('nodeoperationlocks').dropIndex('node_1');
        const authority = simulatedAuthority();
        const start = commands.length;
        await assemble(pins, authority).initialize();
        const observed = commands.slice(start);
        const ddl = observed.filter(event => event.commandName === 'createIndexes');
        assert.equal(ddl.length, 1);
        assert.equal(ddl[0].command.autocommit, undefined, 'DDL outside the transaction');
        assert.equal(ddl[0].command.indexes[0].unique, true);
        assert.deepEqual(observed.filter(event => ['drop', 'dropIndexes', 'collMod', 'update', 'delete'].includes(event.commandName)), []);
        assert.equal((await db.collection('nodeoperationlocks').listIndexes().toArray()).find(row => row.name === 'node_1').unique, true);
    });
    for (const [label, mutate] of [
        ['wrong uniqueness', async () => {
            await db.collection('nodeoperationlocks').dropIndex('node_1');
            await db.collection('nodeoperationlocks').createIndex({ node: 1 });
        }],
        ['foreign index', () => db.collection('nodeoperationlocks').createIndex({ foreign: 1 })],
        ['hidden', () => db.command({ collMod: 'nodeoperationlocks', index: { name: 'node_1', hidden: true } })],
        ['view', async () => {
            await db.collection('remoteadmissions').drop();
            await db.createCollection('remoteadmissions', { viewOn: 'cascadelinks', pipeline: [] });
        }],
        ['missing collection', () => db.collection('remoteadmissions').drop()],
    ]) await t.test(label, async () => {
        const pins = await reset();
        await mutate();
        const start = commands.length;
        const authority = simulatedAuthority();
        await assert.rejects(assemble(pins, authority).initialize(), label === 'foreign index'
            ? { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' }
            : /PRODUCTION_INITIALIZATION_(INDEX_CONFLICT|CATALOG_REFUSED)/);
        if (label === 'foreign index') {
            assert.equal(authority.state.retained, true, 'bounded incomplete inventory cannot authorize release');
        }
        assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
        assert.deepEqual(commands.slice(start).filter(event => ['createIndexes', 'dropIndexes', 'drop', 'insert', 'update', 'delete'].includes(event.commandName)), []);
    });
});

test('singleton collision after snapshot preserves exact foreign winner without transaction retry', async () => {
    const pins = await reset();
    const row = { _id: 'singleton', replacementReservation: { ownerToken: 'foreign', epoch: 21 } };
    const race = afterCommand(event => event?.commandName === 'find'
        && event.command.find === 'cascadetopologystates' && event.command.autocommit === false,
    () => db.collection('cascadetopologystates').insertOne(row));
    const start = commands.length;
    await assert.rejects(assemble(pins, race.authority).initialize(), /PRODUCTION_INITIALIZATION_(REFUSED|UNKNOWN_HOLD)/);
    assert.equal(race.fired(), true);
    assert.deepEqual(await db.collection('cascadetopologystates').findOne({}), row);
    assert.equal(commands.slice(start).filter(event => event.command.startTransaction).length, 1);
    assert.equal(commands.slice(start).filter(event => event.commandName === 'commitTransaction').length, 0);
});

test('pin drift before transaction aborts and pin drift after snapshot remains unknown/dormant', async t => {
    for (const afterSnapshot of [false, true]) await t.test(String(afterSnapshot), async () => {
        const pins = await reset();
        const race = afterCommand(event => afterSnapshot
            ? event?.commandName === 'find' && event.command.find === 'cascadelinks' && event.command.autocommit === false
            : event?.commandName === 'hello',
        () => db.collection('cascadelinks').updateOne({}, { $set: { tunnelPort: 23456 } }));
        await assert.rejects(assemble(pins, race.authority).initialize(), { code: afterSnapshot
            ? 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' : 'PRODUCTION_INITIALIZATION_PIN_DRIFT' });
        assert.equal(race.fired(), true);
        assert.equal((await db.collection('cascadelinks').findOne({ tunnelPort: 23456 })).tunnelPort, 23456);
        assert.equal(await db.collection('cascadetopologystates').countDocuments(), afterSnapshot ? 1 : 0);
        assert.equal(race.authority.state.retained, afterSnapshot);
    });
});

test('scope loss after insert rolls transaction back and retains maintenance', async () => {
    const pins = await reset();
    const authority = simulatedAuthority(async () => {
        const event = commands.at(-1);
        if (event?.commandName === 'insert' && event.command.insert === 'cascadetopologystates') {
            throw new Error('simulated external authority generation loss');
        }
    });
    const start = commands.length;
    await assert.rejects(assemble(pins, authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
    assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
    assert.equal(authority.state.retained, true);
    assert.equal(commands.slice(start).filter(event => event.commandName === 'commitTransaction').length, 0);
    assert.equal(commands.slice(start).filter(event => event.commandName === 'abortTransaction').length, 1);
});

test('real uncertain commit writeConcern error retains possibly durable state, never retries/aborts/acks', async () => {
    const pins = await reset();
    const authority = simulatedAuthority();
    await failCommand('commitTransaction', { writeConcernError: { code: 64, codeName: 'WriteConcernFailed', errmsg: 'synthetic uncertain majority' },
        errorLabels: ['UnknownTransactionCommitResult'] });
    const start = commands.length;
    try {
        await assert.rejects(assemble(pins, authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
    } finally { await disableFailure(); }
    assert.equal(authority.state.retained, true);
    assert.equal(authority.state.released, false);
    const commitReply = replies.findLast(event => event.commandName === 'commitTransaction').reply;
    assert.equal(commitReply.writeConcernError.code, 64);
    assert.ok(commitReply.errorLabels.includes('UnknownTransactionCommitResult'));
    // failCommand returns a real WCE but this server need not execute the commit.
    // Neither observed absence nor a locally visible row is a safe abort/success verdict.
    assert.equal(commands.slice(start).filter(event => event.commandName === 'commitTransaction').length, 1);
    assert.equal(commands.slice(start).filter(event => event.commandName === 'abortTransaction').length, 0);
});

test('real postcommit majority read failure cannot acknowledge or remove committed initialization', async () => {
    const pins = await reset();
    const race = afterCommand(event => event?.commandName === 'commitTransaction',
        () => failCommand('find', { errorCode: 50, errorLabels: [] }));
    try {
        await assert.rejects(assemble(pins, race.authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
    } finally { await disableFailure(); }
    assert.equal(race.fired(), true);
    assert.equal(race.authority.state.retained, true);
    assert.deepEqual(await db.collection('cascadetopologystates').findOne({}), initialState);
});

test('partial additive DDL is retained for audit, never compensated or resumed', async () => {
    const pins = await reset();
    await db.collection('cascadelinks').dropIndex('portalNode_1');
    await db.collection('nodeoperationlocks').dropIndex('node_1');
    const race = afterCommand(event => event?.commandName === 'createIndexes',
        () => failCommand('createIndexes', { errorCode: 50, errorLabels: [] }));
    try {
        await assert.rejects(assemble(pins, race.authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
    } finally { await disableFailure(); }
    assert.equal(race.authority.state.retained, true);
    assert.equal((await db.collection('cascadelinks').listIndexes().toArray()).some(row => row.name === 'portalNode_1'), true);
    assert.equal((await db.collection('nodeoperationlocks').listIndexes().toArray()).some(row => row.name === 'node_1'), false);
    assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
});

test('canonical scope and independently reviewed fields are mandatory before database access', async t => {
    const pins = await reset();
    for (const [label, overrides, code = 'PRODUCTION_INITIALIZATION_INPUT_REFUSED'] of [
        ['no authority', { maintenanceAuthority: undefined }, 'EXTERNAL_MAINTENANCE_AUTHORITY_UNAVAILABLE'],
        ['boolean authority', { maintenanceAuthority: true }, 'EXTERNAL_MAINTENANCE_AUTHORITY_UNAVAILABLE'],
        ['context clone', { serverContext: { ...context } }],
        ['wrong database', { expectedDatabaseName: 'different' }],
        ['missing deployment', { expectedDeployment: undefined }],
        ['array deployment', { expectedDeployment: { ...deployment, replicaSetId: [deployment.replicaSetId] } }],
        ['no maintenance generation', { maintenanceGeneration: undefined }],
        ['array maintenance generation', { maintenanceGeneration: [randomUUID()] }],
        ['unreviewed manifest', { acceptedManifestSha256: '0'.repeat(64) }],
        ['no pins', { acceptedClassicLinks: undefined }],
        ['duplicate pins', { acceptedClassicLinks: [pins[0], ...pins.slice(0, 9)] }],
        ['uppercase ID', { acceptedClassicLinks: [{ ...pins[0], id: pins[0].id.toUpperCase() }, ...pins.slice(1)] }],
        ['missing explicit counter', { initialState: { _id: 'singleton', revision: 0, deployedRevision: 0 } }],
        ['nonzero admission', { initialState: { ...initialState, remoteAdmissionCount: 1 } }],
        ['array counter', { initialState: { ...initialState, topologyAdmissionCount: [0] } }],
        ['drain authority', { initialState: { ...initialState, remoteDrain: null } }],
        ['divergent revision', { initialState: { ...initialState, deployedRevision: 0 } }],
    ]) await t.test(label, async () => {
        const start = commands.length;
        assert.throws(() => assemble(pins, simulatedAuthority(), overrides), { code });
        assert.equal(commands.length, start);
    });
});

test('wrong replica set identity refuses before writes', async () => {
    const pins = await reset();
    const start = commands.length;
    await assert.rejects(assemble(pins, simulatedAuthority(), { expectedDeployment: {
        ...deployment, replicaSetId: String(new mongo.ObjectId()) } }).initialize(),
    { code: 'PRODUCTION_INITIALIZATION_DEPLOYMENT_REFUSED' });
    assert.deepEqual(commands.slice(start).filter(event => ['insert', 'createIndexes'].includes(event.commandName)), []);
});

test('scope completion is an awaited held capability, not a true flag or late callback', async () => {
    const pins = await reset();
    let retained = false;
    await assert.rejects(assemble(pins, { async withHeldMaintenance(challenge, run) {
        return run({ async assertHeld() { return true; }, async retainUnknown() { retained = true; } });
    } }).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
    assert.equal(retained, true);
    let captured;
    const start = commands.length;
    await assert.rejects(assemble(pins, { async withHeldMaintenance(challenge, run) {
        captured = run;
        return true;
    } }).initialize(), { code: 'PRODUCTION_INITIALIZATION_SCOPE_REFUSED' });
    await assert.rejects(captured({}), { code: 'PRODUCTION_INITIALIZATION_SCOPE_REFUSED' });
    assert.equal(commands.length, start);
});

test('transaction rechecks each history winner arriving after the outside baseline', async t => {
    for (const model of models.filter(model => !['cascadelinks', 'cascadetopologystates'].includes(model.collection.name))) {
        await t.test(model.collection.name, async () => {
            const pins = await reset();
            const winner = { _id: new mongo.ObjectId(), status: 'running', owner: 'winner', generation: 99 };
            let hellos = 0;
            const race = afterCommand(event => {
                if (event?.commandName === 'hello') hellos++;
                // Two authority assertions per hello; the second hello starts at count 3.
                return hellos === 3;
            }, () => db.collection(model.collection.name).insertOne(winner));
            const start = commands.length;
            await assert.rejects(assemble(pins, race.authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_HISTORY_PRESENT' });
            assert.equal(race.fired(), true);
            assert.equal(commands.slice(start).filter(event => event.command.startTransaction).length, 1);
            assert.equal(commands.slice(start).filter(event => event.commandName === 'commitTransaction').length, 0);
            assert.deepEqual(await db.collection(model.collection.name).findOne({}), winner);
            assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
        });
    }
});

test('simulated authority violation inserting a snapshot phantom cannot produce success or cleanup', async () => {
    const pins = await reset();
    const winner = { _id: new mongo.ObjectId(), owner: 'foreign', generation: 12 };
    const race = afterCommand(event => event?.commandName === 'find'
        && event.command.find === 'topologyoperations' && event.command.autocommit === false,
    () => db.collection('topologyoperations').insertOne(winner));
    await assert.rejects(assemble(pins, race.authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
    assert.equal(race.authority.state.retained, true);
    assert.deepEqual(await db.collection('topologyoperations').findOne({}), winner);
    assert.deepEqual(await db.collection('cascadetopologystates').findOne({}), initialState);
});

test('postcommit scope loss preserves durable singleton and retains unknown maintenance hold', async () => {
    const pins = await reset();
    const authority = simulatedAuthority(async () => {
        if (commands.at(-1)?.commandName === 'commitTransaction') throw new Error('simulated postcommit loss');
    });
    await assert.rejects(assemble(pins, authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
    assert.equal(authority.state.retained, true);
    assert.deepEqual(await db.collection('cascadetopologystates').findOne({}), initialState);
});

test('authority loses scope during additive DDL: leave indexes, never transact or release', async () => {
    const pins = await reset();
    await db.collection('nodeoperationlocks').dropIndex('node_1');
    const authority = simulatedAuthority(async () => {
        if (commands.at(-1)?.commandName === 'createIndexes') throw new Error('simulated DDL scope loss');
    });
    const start = commands.length;
    await assert.rejects(assemble(pins, authority).initialize(), { code: 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD' });
    assert.equal(authority.state.retained, true);
    assert.equal((await db.collection('nodeoperationlocks').listIndexes().toArray()).some(row => row.name === 'node_1'), true);
    assert.equal(commands.slice(start).filter(event => event.command.startTransaction).length, 0);
    assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
});

test('independent accepted inputs are copied before await and deeply frozen in scope', async () => {
    const pins = await reset();
    const mutableState = { ...initialState }, mutableDeployment = { ...deployment };
    const authority = simulatedAuthority(async challenge => {
        assert.equal(Object.isFrozen(challenge.initialState), true);
        assert.equal(Object.isFrozen(challenge.acceptedClassicLinks[0]), true);
        assert.equal(Object.isFrozen(challenge.deployment), true);
        pins[0].sha256 = '0'.repeat(64);
        mutableState.revision = 100;
        mutableDeployment.replicaSetId = String(new mongo.ObjectId());
    });
    await assemble(pins, authority, { initialState: mutableState, expectedDeployment: mutableDeployment }).initialize();
    assert.deepEqual(await db.collection('cascadetopologystates').findOne({}), initialState);
});

test('adapter errors cannot leak arbitrary prefixed codes or credentials', async () => {
    const pins = await reset();
    const authority = { async withHeldMaintenance() {
        throw Object.assign(new Error('mongodb://synthetic-user:synthetic-secret@host'),
            { code: 'PRODUCTION_INITIALIZATION_synthetic-secret' });
    } };
    await assert.rejects(assemble(pins, authority).initialize(), error => {
        assert.equal(error.code, 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD');
        assert.equal(error.message, error.code);
        assert.equal(error.cause, undefined);
        assert.doesNotMatch(JSON.stringify(error), /synthetic-secret/);
        return true;
    });
});
