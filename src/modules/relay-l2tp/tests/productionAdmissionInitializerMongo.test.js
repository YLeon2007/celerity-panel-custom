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
        await assert.rejects(assemble(pins).initialize(), /PRODUCTION_INITIALIZATION_(INDEX_CONFLICT|CATALOG_REFUSED)/);
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
