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
try { implementation = require('../services/productionAdmissionInitializationPreflight'); }
catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }

const name = `production_init_preflight_${randomUUID().replaceAll('-', '')}`;
let client, child, directory, db;
const sourceModels = [
    require('../../../models/cascadeLinkModel'),
    ...['cascadeTopologyState', 'topologyOperation', 'topologyCreateIntent',
        'topologyIntentQueueState', 'l2tpOperation', 'nodeOperationLock', 'remoteAdmission',
        'topologyExecutionBinding', 'topologyExecutionEnrollment', 'cascadeRouteGroup']
        .map(file => require(`../models/${file}Model`)),
];
const historyNames = sourceModels.map(model => model.collection.name)
    .filter(value => !['cascadelinks', 'cascadetopologystates'].includes(value));
const commands = [];
async function until(work) {
    let error;
    for (let attempt = 0; attempt < 150; attempt++) {
        try { return await work(); } catch (caught) { error = caught; }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw error;
}
function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object') return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, canonical(value[key])]));
    return value;
}
// Independent oracle: full raw BSON Extended JSON, not schema defaults/projections.
function fingerprint(row) {
    return createHash('sha256').update(JSON.stringify(canonical(
        mongo.BSON.EJSON.serialize(row, { relaxed: false })))).digest('hex');
}
async function reset() {
    for (const entry of await db.listCollections({}, { nameOnly: true }).toArray()) {
        await db.collection(entry.name).drop();
    }
    for (const model of sourceModels) {
        await db.createCollection(model.collection.name);
        for (const [key, options] of model.schema.indexes()) {
            const { background, ...rest } = options;
            await db.collection(model.collection.name).createIndex(key, rest);
        }
    }
    // Explicitly synthetic restored-like fixture; never accepted production pins.
    const links = Array.from({ length: 10 }, (_, i) => ({
        _id: new mongo.ObjectId(), name: `classic-fixture-${i}`,
        mode: i < 8 ? 'reverse' : 'forward', active: true, status: 'online',
        portalNode: new mongo.ObjectId(), bridgeNode: new mongo.ObjectId(),
        tunnelUuid: `fixture-secret-${i}`, tunnelPort: 10086 + i,
        arbitraryUnprojectedField: { sentinel: `fixture-${i}` },
    }));
    await db.collection('cascadelinks').insertMany(links);
    return links.map(link => ({ id: String(link._id), sha256: fingerprint(link) }));
}
function inspect(pins, overrides = {}) {
    assert.equal(typeof implementation.inspectProductionAdmissionInitialization, 'function',
        'missing explicit read-only production initialization preflight');
    return implementation.inspectProductionAdmissionInitialization({ db, serverContext: context,
        expectedDatabaseName: name, acceptedClassicLinks: pins, ...overrides });
}

test.before(async () => {
    assert.ok(process.env.C3_MONGOD, 'C3_MONGOD is required; integration tests must not skip');
    assert.ok(process.env.TMPDIR, 'Use the configured scratch directory');
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-prod-init-preflight-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => {
            const selected = server.address().port;
            server.close(() => resolve(selected));
        });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port),
        '--bind_ip', '127.0.0.1', '--replSet', 'productionInitScratch',
        '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    client = new mongo.MongoClient(`mongodb://127.0.0.1:${port}/${name}?directConnection=true`,
        { serverSelectionTimeoutMS: 200, monitorCommands: true });
    client.on('commandStarted', event => commands.push(event));
    await until(() => client.connect());
    await client.db('admin').command({ replSetInitiate: { _id: 'productionInitScratch',
        members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
    await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    db = client.db(name);
});
test.after(async () => {
    try {
        if (db) {
            assert.match(db.databaseName, /^production_init_preflight_[a-f0-9]{32}$/);
            await db.dropDatabase();
        }
    } finally {
        if (client) await client.close();
        if (child && child.exitCode === null) {
            const exited = new Promise(resolve => child.once('exit', resolve));
            child.kill('SIGTERM');
            await exited;
        }
        if (directory) await fs.rm(directory, { recursive: true, force: true });
    }
});

test('missing singleton remains missing, never becomes zero or initialization authority', async () => {
    const pins = await reset();
    const start = commands.length;
    const result = await inspect(pins);
    assert.equal(result.mode, 'preflight-only');
    assert.equal(result.ready, false);
    assert.equal(result.initialized, false);
    assert.deepEqual(result.singleton, { presence: 'missing' });
    assert.equal(result.inventory.matchesAcceptedPins, true);
    assert.equal(result.inventory.reverse, 8);
    assert.equal(result.inventory.forward, 2);
    assert.equal(result.zeroWorkObserved, true);
    assert.ok(Object.values(result.indexes).every(value => value === 'exact-ready'),
        'the frozen index contract must match all actual source-schema indexes');
    assert.ok(result.blockers.includes('EXTERNAL_MAINTENANCE_AUTHORITY_UNAVAILABLE'));
    assert.ok(result.blockers.includes('PRODUCTION_ACCEPTED_PIN_AUTHORITY_UNAVAILABLE'));
    const preflightCommands = commands.slice(start);
    assert.equal(await db.collection('cascadetopologystates').countDocuments(), 0);
    const readCommands = new Set(['find', 'getMore', 'killCursors', 'listCollections', 'listIndexes']);
    assert.deepEqual(preflightCommands.filter(event => !readCommands.has(event.commandName)), []);
});

test('exact immutable server PROD context, database binding and ten accepted pins precede reads', async t => {
    const pins = await reset();
    for (const [label, overrides] of [
        ['missing context', { serverContext: undefined }],
        ['TEST context', { serverContext: { target: 'test', hostIdentity: 'test.infograd.online' } }],
        ['cloned context', { serverContext: { ...context } }],
        ['crossed context', { serverContext: { target: 'production', hostIdentity: 'test.infograd.online' } }],
        ['wrong database', { expectedDatabaseName: 'other' }],
        ['missing database', { expectedDatabaseName: undefined }],
        ['missing pins', { acceptedClassicLinks: undefined }],
        ['nine pins', { acceptedClassicLinks: pins.slice(1) }],
        ['duplicate pins', { acceptedClassicLinks: [pins[0], ...pins.slice(0, 9)] }],
        ['noncanonical ID', { acceptedClassicLinks: [{ ...pins[0], id: pins[0].id.toUpperCase() }, ...pins.slice(1)] }],
        ['malformed fingerprint', { acceptedClassicLinks: [{ ...pins[0], sha256: '0' }, ...pins.slice(1)] }],
        ['extra authority flag', { acceptedClassicLinks: [{ ...pins[0], classicOwned: true }, ...pins.slice(1)] }],
    ]) await t.test(label, async () => {
        const start = commands.length;
        await assert.rejects(inspect(pins, overrides), { code: 'PRODUCTION_INITIALIZATION_INPUT_REFUSED' });
        assert.equal(commands.length, start, 'reject before touching persistence');
    });
});

test('inventory refuses changed, missing, extra or repinned malformed classic links without adoption', async t => {
    for (const [label, mutate, repin = false] of [
        ['unprojected field drift', async () => db.collection('cascadelinks').updateOne({}, { $set: { arbitraryUnprojectedField: 'changed-secret' } })],
        ['missing link', async () => db.collection('cascadelinks').deleteOne({})],
        ['extra active link', async () => db.collection('cascadelinks').insertOne({ active: true, mode: 'reverse', status: 'online' })],
        ['inactive pinned row', async () => db.collection('cascadelinks').updateOne({}, { $set: { active: false } }), true],
        ['missing mode', async () => db.collection('cascadelinks').updateOne({}, { $unset: { mode: '' } }), true],
        ['staged status', async () => db.collection('cascadelinks').updateOne({}, { $set: { status: 'staged' } }), true],
        ['array endpoint', async () => db.collection('cascadelinks').updateOne({}, { $set: { bridgeNode: [new mongo.ObjectId()] } }), true],
        ['changed mix', async () => db.collection('cascadelinks').updateOne({ mode: 'forward' }, { $set: { mode: 'reverse' } }), true],
    ]) await t.test(label, async () => {
        let pins = await reset();
        await mutate();
        if (repin) pins = (await db.collection('cascadelinks').find({}).toArray())
            .map(row => ({ id: String(row._id), sha256: fingerprint(row) }));
        const before = await db.collection('cascadelinks').find({}).sort({ _id: 1 }).toArray();
        const result = await inspect(pins);
        assert.equal(result.inventory.matchesAcceptedPins, false);
        assert.ok(result.blockers.includes('CLASSIC_LINK_INVENTORY_UNRESOLVED'));
        assert.equal(result.ready, false);
        assert.deepEqual(await db.collection('cascadelinks').find({}).sort({ _id: 1 }).toArray(), before);
        assert.doesNotMatch(JSON.stringify(result), /fixture-secret|changed-secret/);
    });
});

test('raw existing or partial singleton is never defaulted, repaired or accepted', async t => {
    for (const row of [
        { _id: 'singleton' },
        { _id: 'singleton', revision: 0, remoteAdmissionCount: 0 },
        { _id: 'singleton', revision: 0, deployedRevision: 0, topologyAdmissionCount: 0, remoteAdmissionCount: 0 },
        { _id: 'singleton', remoteDrain: null },
        { _id: 'singleton', replacementReservation: { ownerToken: 'foreign', epoch: 1 } },
        { _id: 'other', topologyAdmissionCount: [0] },
    ]) await t.test(JSON.stringify(row), async () => {
        const pins = await reset();
        await db.collection('cascadetopologystates').insertOne(row);
        const result = await inspect(pins);
        assert.equal(result.singleton.presence, 'present');
        assert.ok(result.blockers.includes('EXISTING_SINGLETON_REQUIRES_SEPARATE_REVIEW'));
        assert.deepEqual(await db.collection('cascadetopologystates').findOne({}), row);
    });
});

test('every persisted history row including terminal and expired work vetoes a zero-work observation', async t => {
    for (const collection of historyNames) await t.test(collection, async () => {
        const pins = await reset();
        const row = { _id: new mongo.ObjectId(), status: 'succeeded', phase: 'completed',
            leaseUntil: new Date(0), heldTopologyAdmission: true, secret: 'history-secret' };
        await db.collection(collection).insertOne(row);
        const result = await inspect(pins);
        assert.equal(result.zeroWorkObserved, false);
        assert.ok(result.blockers.includes(`HISTORY_REQUIRES_REVIEW:${collection}`));
        assert.deepEqual(await db.collection(collection).findOne({}), row);
        assert.doesNotMatch(JSON.stringify(result), /history-secret/);
    });
});

test('missing history collection is missing, not an empty history or an implicit index creation', async () => {
    const pins = await reset();
    await db.collection('remoteadmissions').drop();
    const result = await inspect(pins);
    assert.equal(result.zeroWorkObserved, false);
    assert.ok(result.blockers.includes('COLLECTION_MISSING:remoteadmissions'));
    assert.equal(result.history.remoteadmissions, 'missing');
    assert.equal((await db.listCollections({ name: 'remoteadmissions' }).toArray()).length, 0);
});

test('exact source-schema indexes are diagnostic only and never created, dropped or reconciled', async t => {
    for (const [label, mutate, expected] of [
        ['all exact', async () => {}, 'exact-ready'],
        ['missing', async () => db.collection('nodeoperationlocks').dropIndex('node_1'), 'missing'],
        ['wrong unique', async () => {
            await db.collection('nodeoperationlocks').dropIndex('node_1');
            await db.collection('nodeoperationlocks').createIndex({ node: 1 }, { unique: false });
        }, 'conflict'],
        ['wrong sparse', async () => {
            await db.collection('nodeoperationlocks').dropIndex('node_1');
            await db.collection('nodeoperationlocks').createIndex({ node: 1 }, { unique: true, sparse: true });
        }, 'conflict'],
        ['hidden', async () => db.command({ collMod: 'nodeoperationlocks', index: { name: 'node_1', hidden: true } }), 'conflict'],
        ['unexpected index', async () => db.collection('nodeoperationlocks').createIndex({ owner: 1 }), 'conflict'],
    ]) await t.test(label, async () => {
        const pins = await reset();
        await mutate();
        const before = await db.collection('nodeoperationlocks').listIndexes().toArray();
        const result = await inspect(pins);
        assert.ok(result.indexes, 'preflight must diagnose exact index readiness');
        assert.equal(result.indexes.nodeoperationlocks, expected);
        if (expected !== 'exact-ready') assert.ok(result.blockers.includes(`INDEX_${expected.toUpperCase()}:nodeoperationlocks`));
        assert.deepEqual(await db.collection('nodeoperationlocks').listIndexes().toArray(), before);
        assert.equal(result.ready, false);
    });
});

function interceptCollectionEnumeration(callback) {
    let reads = 0;
    return new Proxy(db, { get(target, property) {
        if (property === 'listCollections') return (...args) => {
            const cursor = target.listCollections(...args);
            return new Proxy(cursor, { get(inner, key) {
                if (key === 'toArray') return async () => {
                    await callback(++reads);
                    return inner.toArray();
                };
                const value = inner[key];
                return typeof value === 'function' ? value.bind(inner) : value;
            } });
        };
        const value = target[property];
        return typeof value === 'function' ? value.bind(target) : value;
    } });
}

test('actual adversarial commits between observation passes refuse with no repair or ownership release', async t => {
    for (const [label, mutate] of [
        ['new topology operation', async () => db.collection('topologyoperations').insertOne({ status: 'queued' })],
        ['new queued intent', async () => db.collection('topologycreateintents').insertOne({ requestKey: 'race', ordinal: 1 })],
        ['new PPP job', async () => db.collection('l2tpoperations').insertOne({ status: 'queued', idempotencyKey: 'race' })],
        ['new exact node lock', async () => db.collection('nodeoperationlocks').insertOne({ node: new mongo.ObjectId(), owner: 'winner', generation: 'keep' })],
        ['new remote admission', async () => db.collection('remoteadmissions').insertOne({ _id: 'winner', phase: 'running' })],
        ['foreign singleton with drain', async () => db.collection('cascadetopologystates').insertOne({ _id: 'singleton', remoteDrain: { ownerToken: 'winner', epoch: 1 } })],
        ['link drift', async () => db.collection('cascadelinks').updateOne({}, { $set: { tunnelPort: 23456 } })],
        ['index drift', async () => db.collection('nodeoperationlocks').dropIndex('node_1')],
    ]) await t.test(label, async () => {
        const pins = await reset();
        let committed = false;
        let winningState;
        async function capture() {
            const state = {};
            for (const model of sourceModels) state[model.collection.name] = {
                rows: await db.collection(model.collection.name).find({}).sort({ _id: 1 }).toArray(),
                indexes: await db.collection(model.collection.name).listIndexes().toArray(),
            };
            return state;
        }
        const raced = interceptCollectionEnumeration(async pass => {
            if (pass === 2) { await mutate(); committed = true; winningState = await capture(); }
        });
        const result = await inspect(pins, { db: raced });
        assert.equal(committed, true, 'must perform an outside-transaction confirmation pass');
        assert.equal(result.observationStable, false);
        assert.equal(result.zeroWorkObserved, false);
        assert.ok(result.blockers.includes('OBSERVATION_DRIFT'));
        assert.equal(result.ready, false);
        assert.equal(result.initialized, false);
        assert.deepEqual(await capture(), winningState, 'preserve every winning row, owner, generation and index');
    });
});

test('failed observations return only a fixed refusal error without database secrets', async () => {
    const pins = await reset();
    const unavailable = interceptCollectionEnumeration(async () => {
        throw new Error('mongodb://user:fixture-secret@private-host/details');
    });
    await assert.rejects(inspect(pins, { db: unavailable }), error => {
        assert.equal(error.code, 'PRODUCTION_INITIALIZATION_OBSERVATION_UNCONFIRMED');
        assert.equal(error.message, 'PRODUCTION_INITIALIZATION_OBSERVATION_UNCONFIRMED');
        assert.equal(error.cause, undefined);
        return true;
    });
});

test('all document observations request bounded primary-majority reads outside a transaction', async () => {
    const pins = await reset();
    const start = commands.length;
    const result = await inspect(pins);
    const observations = commands.slice(start).filter(event => event.commandName === 'find');
    assert.equal(observations.length, sourceModels.length * 2);
    for (const event of observations) {
        assert.equal(event.command.readConcern.level, 'majority');
        assert.ok(event.command.maxTimeMS > 0 && event.command.maxTimeMS <= 2000,
            'driver CSOT must not enlarge the server read deadline');
        assert.equal(event.command.autocommit, undefined);
    }
    assert.equal(result.observationStable, true);
    assert.equal(result.ready, false, 'two matching scans are not external quiescence proof');
});

test('existing view is unresolved rather than reported as missing or empty history', async () => {
    const pins = await reset();
    await db.collection('remoteadmissions').drop();
    await db.createCollection('remoteadmissions', { viewOn: 'cascadelinks', pipeline: [] });
    const result = await inspect(pins);
    assert.equal(result.history.remoteadmissions, 'unresolved');
    assert.ok(result.blockers.includes('COLLECTION_OPTIONS_UNRESOLVED:remoteadmissions'));
    assert.equal(result.zeroWorkObserved, false);
});
