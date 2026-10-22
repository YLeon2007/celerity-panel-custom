'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');
const { isDeepStrictEqual } = require('node:util');
const { ensureL2tpModelIndexes } = require('../l2tpModelIndexReadiness');
const { createL2tpRootLifecycle } = require('../l2tpRuntimeLifecycleHook');
let directory, child, uri, admin;
let serial = 0;
const databases = new Set();
const evidence = [];
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
async function until(fn) {
    let error;
    for (let i = 0; i < 120; i++) { try { return await fn(); } catch (e) { error = e; } await new Promise(r => setTimeout(r, 50)); }
    throw error;
}
test.before(async () => {
    assert.ok(process.env.C3_MONGOD, 'explicit isolated real Mongo required');
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-index-once-mongo-'));
    const port = await new Promise(resolve => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--setParameter', 'enableTestCommands=1', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    uri = `mongodb://127.0.0.1:${port}`;
    admin = new mongoose.mongo.MongoClient(uri, { serverSelectionTimeoutMS: 100 });
    await until(() => admin.connect());
});
test.after(async () => {
    try {
        if (admin) {
            await admin.db('admin').command({ configureFailPoint: 'failCommand', mode: 'off' });
            const names = (await admin.db('admin').admin().listDatabases()).databases.map(d => d.name);
            assert.ok([...databases].every(name => !names.includes(name)), 'all owned databases removed');
            await admin.close();
        }
    } finally {
        if (child?.exitCode === null) { const exited = new Promise(r => child.once('exit', r)); child.kill('SIGTERM'); await exited; }
        assert.ok(!child || child.exitCode === 0, 'owned mongod exited naturally');
        if (process.env.C3_INDEX_EVIDENCE) await fs.writeFile(process.env.C3_INDEX_EVIDENCE, JSON.stringify({
            evidence, databasesAbsent: true, mongodExit: child.exitCode, physicalAccepted: false, operationalGO: false,
        }, null, 2) + '\n', { flag: 'wx' });
        if (directory) await fs.rm(directory, { recursive: true, force: true });
    }
});
async function isolated(work) {
    const name = `index_once_${process.pid}_${++serial}`; databases.add(name);
    const db = await mongoose.createConnection(`${uri}/${name}`, { monitorCommands: true }).asPromise();
    const commands = [];
    db.getClient().on('commandStarted', e => { if (e.databaseName === name) commands.push({ name: e.commandName, command: JSON.parse(JSON.stringify(e.command, (_, value) => value instanceof Map ? Object.fromEntries(value) : value)) }); });
    try { await work(db, commands); }
    finally { evidence.push({ name, commands }); await db.dropDatabase(); assert.equal((await admin.db('admin').admin().listDatabases()).databases.some(d => d.name === name), false); await db.close(); }
}
function model(db, options = {}) {
    const schema = new mongoose.Schema({ token: String, expireAt: Date, status: String }, options);
    schema.index({ token: 1 }, { name: 'required_token', unique: true, sparse: true });
    schema.index({ expireAt: 1 }, { name: 'required_ttl', expireAfterSeconds: 300 });
    return db.model('Checked', schema);
}
const ready = m => ensureL2tpModelIndexes({ loadModels: () => ({ Checked: m }) });
function prove(m, actual) {
    assert.ok(actual.some(a => isDeepStrictEqual(Object.entries(a.key), [['_id', 1]])));
    for (const [key, opts] of m.schema.indexes()) assert.ok(actual.some(a =>
        isDeepStrictEqual(Object.entries(a.key), Object.entries(key)) &&
        Boolean(a.unique) === Boolean(opts.unique) && Boolean(a.sparse) === Boolean(opts.sparse) &&
        isDeepStrictEqual(a.partialFilterExpression, opts.partialFilterExpression) &&
        isDeepStrictEqual(a.expireAfterSeconds, opts.expireAfterSeconds) && isDeepStrictEqual(a.collation, opts.collation)));
}

test('real Mongo: all 15 public model schemas automatically build each of 27 required indexes only once', async () => isolated(async (db, commands) => {
    const source = require('../relay-l2tp').registerModels();
    const models = Object.fromEntries(Object.entries(source).map(([name, m]) => [name, db.model(name, m.schema.clone())]));
    assert.equal(Object.keys(models).length, 15);
    assert.equal(Object.values(models).reduce((n, m) => n + m.schema.indexes().length, 0), 27);
    await ensureL2tpModelIndexes({ loadModels: () => models });
    const ddl = commands.filter(c => ['create', 'createIndexes'].includes(c.name));
    assert.equal(ddl.filter(c => c.name === 'create').length, 15);
    const built = ddl.filter(c => c.name === 'createIndexes').flatMap(c => c.command.indexes.map(i => `${c.command.createIndexes}:${JSON.stringify(i.key)}`));
    assert.equal(built.length, 27); assert.equal(new Set(built).size, 27);
    assert.equal(commands.filter(c => c.name === 'listIndexes').length, 15, 'complete initial metadata proof for every model');
    for (const m of Object.values(models)) prove(m, await m.collection.indexes());
    const before = commands.length;
    await ensureL2tpModelIndexes({ loadModels: () => models });
    assert.equal(commands.slice(before).filter(c => c.name === 'create' || c.name === 'createIndexes').length, 0);
    assert.equal(commands.slice(before).filter(c => c.name === 'listIndexes').length, 15);
}));

test('real Mongo: disabled automatic DDL and absent namespace still build and reread every required index', async () => isolated(async (db, commands) => {
    const m = model(db, { autoCreate: false, autoIndex: false }); await m.init();
    assert.equal((await db.db.listCollections().toArray()).length, 0);
    await ready(m); prove(m, await m.collection.indexes());
    assert.deepEqual(commands.filter(c => ['create', 'createIndexes', 'listIndexes'].includes(c.name)).map(c => c.name),
        ['listIndexes', 'create', 'createIndexes', 'createIndexes', 'listIndexes', 'listIndexes']);
}));

test('real Mongo: autoCreate alone is not sufficient; disabled autoIndex still builds all indexes', async () => isolated(async (db, commands) => {
    const m = model(db, { autoCreate: true, autoIndex: false }); await ready(m);
    prove(m, await m.collection.indexes());
    assert.equal(commands.filter(c => c.name === 'createIndexes').length, 2);
}));

test('real Mongo: one required index missing triggers additive build and complete proof; operator index retained', async () => isolated(async (db, commands) => {
    const m = model(db, { autoCreate: false, autoIndex: false }); await m.init();
    await db.db.createCollection(m.collection.name);
    await m.collection.createIndex({ token: 1 }, { name: 'required_token', unique: true, sparse: true });
    await m.collection.createIndex({ status: 1 }, { name: 'operator_status' });
    const before = commands.length; await ready(m);
    const actual = await m.collection.indexes(); prove(m, actual);
    assert.ok(actual.some(a => a.name === 'operator_status'));
    assert.equal(commands.slice(before).filter(c => c.name === 'createIndexes').length, 2, 'all declared specs are submitted on fallback');
    assert.equal(commands.slice(before).filter(c => c.name === 'listIndexes').length, 3);
}));

test('real Mongo: weaker/conflicting metadata refuses without dropping or changing the winner', async () => isolated(async (db) => {
    const m = model(db, { autoCreate: false, autoIndex: false }); await m.init();
    await db.db.createCollection(m.collection.name);
    await m.collection.createIndex({ token: 1 }, { name: 'required_token', sparse: true });
    const before = await m.collection.indexes();
    await assert.rejects(ready(m), e => e.code === 85 || e.code === 86);
    const after = await m.collection.indexes();
    for (const winner of before) assert.deepEqual(after.find(a => a.name === winner.name), winner, 'existing metadata must never be replaced or dropped');
}));

async function fault(command, work) {
    await admin.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 }, data: { failCommands: [command], errorCode: 67 } });
    try { await work(); } finally { await admin.db('admin').command({ configureFailPoint: 'failCommand', mode: 'off' }); }
}
for (const stage of ['init', 'read', 'build']) test(`real Mongo: ${stage} error refuses runtime and HTTP, drains admitted sibling, admits no later batch`, async () => isolated(async (db, commands) => {
    const gate = deferred(), entered = deferred(); let runtimeStarts = 0, accepting = false, settled = false, later = false;
    // Only public Mongoose APIs issue the actual commands. The peer's completed
    // real readback is held at delivery to deterministically expose the barrier.
    let m = stage === 'init' ? null : model(db, { autoCreate: false, autoIndex: false });
    if (m) await m.init();
    if (stage === 'read') await db.db.createCollection(m.collection.name);
    const peerSchema = new mongoose.Schema({ token: String }, { autoCreate: false, autoIndex: false });
    const peer = db.model('Peer', peerSchema); await peer.init(); await db.db.createCollection(peer.collection.name);
    const peerRead = peer.collection.indexes.bind(peer.collection);
    peer.collection.indexes = async () => { const actual = await peerRead(); entered.resolve(); await gate.promise; return actual; };
    const root = createL2tpRootLifecycle({ env: { L2TP_EXECUTION_ENABLED: 'false', L2TP_MIGRATIONS_ENABLED: 'false' },
        createMigrationBootstrap: () => ({ async run() {} }),
        ensureModelIndexes: () => ensureL2tpModelIndexes({ loadModels: () => ({ Bad: m, Peer: peer,
            Later: { async init() { later = true; throw new Error('later batch must not start'); } } }) }),
        createRuntimeLifecycleHook: () => { runtimeStarts++; return { async stop() {} }; },
    });
    const command = stage === 'read' ? 'listIndexes' : 'createIndexes';
    // Install the fault before compiling the automatic model, because its
    // public memoized init starts immediately at model construction.
    await fault(command, async () => {
        if (stage === 'init') m = model(db);
        const start = root.startAfterDatabase().then(() => { accepting = true; }).finally(() => { settled = true; });
        const rejected = assert.rejects(start, e => e.code === 67);
        try {
            await entered.promise;
            assert.equal(settled, false); assert.equal(runtimeStarts, 0); assert.equal(accepting, false); assert.equal(later, false);
            const stop = root.stop(); gate.resolve(); await Promise.all([rejected, stop]);
            assert.equal(runtimeStarts, 0); assert.equal(accepting, false); assert.equal(later, false);
            if (stage === 'init') {
                const builds = commands.filter(c => c.name === 'createIndexes' && c.command.createIndexes === m.collection.name);
                assert.equal(builds.length, 2, 'automatic init drains both declared specs, with no explicit second build');
                assert.equal(new Set(builds.map(c => JSON.stringify(c.command.indexes[0].key))).size, 2);
                assert.equal(commands.filter(c => c.name === 'listIndexes' && c.command.listIndexes === m.collection.name).length, 0, 'failed automatic init must not enter metadata fallback');
            }
            if (stage === 'read') assert.equal(commands.filter(c => c.name === 'createIndexes').length, 0, 'read failure must never trigger fallback');
        } finally { gate.resolve(); await rejected; await root.stop(); }
    });
}));
