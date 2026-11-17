'use strict';
// Focused preparation for the named supported-startup schema gap. This is NOT
// an execution-controller or an activation test; ordinary root remains guarded.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { mongo } = require('mongoose');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const { REVIEWED_MANIFEST, REVIEWED_MANIFEST_SHA256 } = require('../services/productionAdmissionInitializer');
const { rawDocumentFingerprint: fingerprint } = require('../services/productionAdmissionInitializationPreflight');
const { testing: adapter } = require('../runtime/productionMaintenanceAuthority');
let verifyInitializedProductionAdmission;
try { ({ verifyInitializedProductionAdmission } = require('../services/productionAdmissionReadiness')); }
catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }
const state = { _id: 'singleton', revision: 7, deployedRevision: 7, stateTransitionRevision: 3,
    replacementEpoch: 2, remoteAdmissionCount: 0, topologyAdmissionCount: 0 };
let child, directory, client, db, accepted, scratchFd;
const originalTmpdir = process.env.TMPDIR;
const commands = [], evidence = { scope: 'LOCAL schema-only; real Mongo and guard OFD; cgroup/remote exclusion MODELED', cases: [] };
async function until(work) {
    const deadline = Date.now() + 15000;
    while (true) { try { return await work(); } catch (error) {
        if (Date.now() >= deadline || child?.exitCode !== null) throw error;
        await new Promise(resolve => setTimeout(resolve, 50));
    } }
}
async function stopOwned(processChild) {
    if (!processChild || processChild.exitCode !== null || processChild.signalCode !== null) return;
    const closed = new Promise(resolve => processChild.once('close', resolve));
    processChild.kill('SIGTERM');
    const timer = setTimeout(() => processChild.kill('SIGKILL'), 5000);
    try { await closed; } finally { clearTimeout(timer); }
}
test.before(async () => {
    // RED must fail on the absent implementation before creating any fixture.
    assert.equal(typeof verifyInitializedProductionAdmission, 'function', 'missing read-only admitted-schema verifier');
    assert.ok(process.env.C3_MONGOD && process.env.TMPDIR);
    // Keep every real fixture file in the caller's OWN scratch. A live parent
    // directory FD gives UDS paths a short spelling without an external symlink
    // or a /tmp directory; trusted_root is still the fresh disposable leaf.
    scratchFd = fs.openSync(process.env.TMPDIR, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    process.env.TMPDIR = `/proc/${process.pid}/fd/${scratchFd}`;
    directory = fs.mkdtempSync(path.join(process.env.TMPDIR, 'admission-schema-'));
    const port = await new Promise(resolve => {
        const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', 'admittedSchemaLocal', '--wiredTigerCacheSizeGB', '0.25', '--oplogSize', '32',
        '--logpath', path.join(directory, 'mongod.log')], { stdio: 'ignore' });
    evidence.mongodPid = child.pid;
    client = new mongo.MongoClient(`mongodb://127.0.0.1:${port}/admin?directConnection=true`, { serverSelectionTimeoutMS: 250 });
    await until(() => client.connect());
    await client.db('admin').command({ replSetInitiate: { _id: 'admittedSchemaLocal', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
    await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    const { config } = await client.db('admin').command({ replSetGetConfig: 1 });
    await client.close();
    client = new mongo.MongoClient(`mongodb://127.0.0.1:${port}/admitted_schema_local?replicaSet=admittedSchemaLocal`,
        { retryWrites: false, monitorCommands: true, serverSelectionTimeoutMS: 2000 });
    await client.connect(); db = client.db('admitted_schema_local');
    for (const entry of REVIEWED_MANIFEST.collections) {
        await db.createCollection(entry.name);
        for (const { key, ...options } of entry.indexes.filter(index => index.name !== '_id_')) {
            await db.collection(entry.name).createIndex(key, options);
        }
    }
    const links = Array.from({ length: 10 }, (_, i) => ({ _id: new mongo.ObjectId((100 + i).toString(16).padStart(24, '0')),
        portalNode: new mongo.ObjectId(), bridgeNode: new mongo.ObjectId(), active: true, status: 'online', mode: i < 8 ? 'reverse' : 'forward' }));
    await db.collection('cascadelinks').insertMany(links);
    await db.collection('cascadetopologystates').insertOne(state);
    accepted = { serverContext: PROD, databaseName: db.databaseName, maintenanceGeneration: randomUUID(),
        deployment: { setName: config._id, replicaSetId: String(config.settings.replicaSetId) },
        acceptedClassicLinks: links.map(link => ({ id: String(link._id), sha256: fingerprint(link) })),
        initialState: state, manifestSha256: REVIEWED_MANIFEST_SHA256, acceptedMissingCollections: [] };
    client.on('commandStarted', event => commands.push(event.commandName));
});
test.after(async () => {
    if (client) await client.close();
    await stopOwned(child);
    if (child) {
        evidence.mongodReaped = !fs.existsSync(`/proc/${child.pid}`);
        assert.equal(evidence.mongodReaped, true);
    }
    if (directory) fs.rmSync(directory, { recursive: true, force: true });
    evidence.directoryRemoved = directory ? !fs.existsSync(directory) : true;
    if (scratchFd !== undefined) fs.closeSync(scratchFd);
    process.env.TMPDIR = originalTmpdir;
    if (process.env.C3_ADMISSION_SCHEMA_EVIDENCE) fs.writeFileSync(process.env.C3_ADMISSION_SCHEMA_EVIDENCE, JSON.stringify(evidence, null, 2));
});
async function heldCase(work, challenge = accepted) {
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR, 'admission-held-'));
    const challengeFile = path.join(root, 'challenge.json');
    fs.writeFileSync(challengeFile, JSON.stringify(challenge));
    const broker = spawn('/usr/bin/python3', ['-I', '-B', 'scripts/prod-maintenance/tests/local_protocol_fixture.py', challengeFile],
        { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
    const authority = adapter.compose({ challenge, child: broker });
    let control, probes = 0;
    try {
        return await authority.withHeldMaintenance(challenge, async scope => {
            control = JSON.parse(fs.readFileSync(path.join(root, 'challenge.control.json')));
            const check = async supplied => {
                const rival = spawnSync('/usr/bin/flock', ['-n', control.lock, '/usr/bin/true']);
                assert.equal(rival.error, undefined); assert.equal(rival.status, 1); probes++;
                return scope.assertHeld(supplied);
            };
            try { return await work({ assertHeld: check }, control); }
            finally { fs.writeFileSync(path.join(root, 'challenge.cleanup'), 'schema observation joined\n'); }
        });
    } finally {
        await stopOwned(broker);
        if (control) {
            await until(async () => assert.equal(fs.existsSync(`/proc/${control.guardPid}`), false));
            evidence.cases.push({ brokerPid: broker.pid, guardPid: control.guardPid, probes,
                brokerReaped: !fs.existsSync(`/proc/${broker.pid}`), guardReaped: !fs.existsSync(`/proc/${control.guardPid}`) });
        }
        fs.rmSync(root, { recursive: true, force: true });
    }
}
function assertReadOnly(start) {
    const forbidden = ['create', 'createIndexes', 'insert', 'update', 'delete', 'findAndModify', 'commitTransaction', 'abortTransaction', 'drop'];
    assert.deepEqual(commands.slice(start).filter(name => forbidden.includes(name)), []);
}
test('accepted initialized admission is observed under actual local held OFD; result does not authorize execution', async () => {
    const start = commands.length;
    await heldCase(async scope => {
        const observed = await verifyInitializedProductionAdmission({ db, accepted, scope });
        assert.deepEqual(observed, { schemaVerified: true, initialized: false, executionEnabled: false,
            stateSha256: fingerprint(state), manifestSha256: REVIEWED_MANIFEST_SHA256 });
    });
    assertReadOnly(start);
});
test('absent or mismatched held authority refuses before the first database command', async () => {
    const start = commands.length;
    await assert.rejects(verifyInitializedProductionAdmission({ db, accepted }), { code: 'PRODUCTION_ADMISSION_SCOPE_REQUIRED' });
    await assert.rejects(heldCase(scope => verifyInitializedProductionAdmission({ db,
        accepted: { ...accepted, maintenanceGeneration: randomUUID() }, scope })),
    { code: 'PRODUCTION_ADMISSION_SCOPE_LOST' });
    assert.equal(commands.length, start);
});
test('altered accepted state or deployment cannot reuse the prior held challenge', async () => {
    const start = commands.length;
    for (const altered of [
        { ...accepted, initialState: { ...state, revision: 8, deployedRevision: 8 } },
        { ...accepted, deployment: { ...accepted.deployment, setName: 'foreign' } },
    ]) await assert.rejects(heldCase(scope => verifyInitializedProductionAdmission({ db, accepted: altered, scope })),
        { code: 'PRODUCTION_ADMISSION_SCOPE_LOST' });
    assert.equal(commands.length, start);
});
test('revoked real local guard refuses before the first database command', async () => {
    const start = commands.length;
    await assert.rejects(heldCase(async (scope, control) => {
        fs.writeFileSync(control.freeze, '0\n'); // MODELED cgroup loss; real guard/channel revocation
        return verifyInitializedProductionAdmission({ db, accepted, scope });
    }), { code: 'PRODUCTION_ADMISSION_SCOPE_LOST' });
    assert.equal(commands.length, start);
});
test('existing partial state is refused and preserved, never repaired from source defaults', async () => {
    await db.collection('cascadetopologystates').updateOne({ _id: 'singleton' }, { $unset: { remoteAdmissionCount: '' } });
    const start = commands.length;
    try {
        await heldCase(scope => assert.rejects(verifyInitializedProductionAdmission({ db, accepted, scope }),
            { code: 'PRODUCTION_ADMISSION_STATE_MISMATCH' }));
        assertReadOnly(start);
        assert.equal(Object.hasOwn(await db.collection('cascadetopologystates').findOne({}), 'remoteAdmissionCount'), false);
    } finally { await db.collection('cascadetopologystates').replaceOne({ _id: 'singleton' }, state); }
});
test('ordinary startup schema verification preserves later revisions, nonzero counters and retained history', async () => {
    const later = { ...state, revision: 12, deployedRevision: 9, remoteAdmissionCount: 2, topologyAdmissionCount: 3 };
    await db.collection('cascadetopologystates').replaceOne({ _id: 'singleton' }, later);
    await db.collection('topologyoperations').insertOne({ _id: 'OWN retained opaque history', status: 'failed', retain: true });
    const schemaAccepted = Object.fromEntries(['serverContext', 'databaseName', 'maintenanceGeneration', 'deployment', 'manifestSha256'].map(k => [k, accepted[k]]));
    const start = commands.length;
    try {
        await heldCase(async scope => {
            const observed = await require('../services/productionAdmissionReadiness').verifyProductionStartupSchema({ db, accepted: schemaAccepted, scope });
            assert.equal(observed.schemaVerified, true); assert.equal(observed.executionEnabled, false); assert.equal(observed.stateSha256, fingerprint(later));
        }, schemaAccepted);
        assertReadOnly(start);
        assert.deepEqual(await db.collection('cascadetopologystates').findOne({}), later);
        assert.equal(await db.collection('topologyoperations').countDocuments(), 1);
    } finally {
        await db.collection('cascadetopologystates').replaceOne({ _id: 'singleton' }, state);
        await db.collection('topologyoperations').deleteOne({ _id: 'OWN retained opaque history' });
    }
});
test('missing required unique index refuses without automatic DDL', async () => {
    const entry = REVIEWED_MANIFEST.collections.find(row => row.name === 'nodeoperationlocks');
    const required = entry.indexes.find(index => index.unique);
    await db.collection(entry.name).dropIndex(required.name);
    const start = commands.length;
    try {
        await heldCase(scope => assert.rejects(verifyInitializedProductionAdmission({ db, accepted, scope }),
            { code: 'PRODUCTION_ADMISSION_INDEX_MISMATCH' }));
        assertReadOnly(start);
        assert.equal((await db.collection(entry.name).listIndexes().toArray()).some(index => index.name === required.name), false);
    } finally { const { key, ...options } = required; await db.collection(entry.name).createIndex(key, options); }
});
