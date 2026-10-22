'use strict';
// Local integration ONLY: real Mongo/transactions, broker, resident guard and
// SCM_RIGHTS/OFD. UID, kernel freeze/systemd, writer completeness and remote
// physical facts are modeled by local_protocol_fixture.py, NOT PROD authority.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { mongo } = require('mongoose');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const { REVIEWED_MANIFEST_SHA256 } = require('../services/productionAdmissionInitializer');
const { rawDocumentFingerprint: fingerprint } = require('../services/productionAdmissionInitializationPreflight');
const { testing: entry } = require('../runtime/productionAdmissionMaintenanceEntry');
const { testing: adapter } = require('../runtime/productionMaintenanceAuthority');
// Existing real-Mongo harness schema source, used only for disposable setup.
const models = [require('../../../models/cascadeLinkModel'),
    ...['cascadeTopologyState', 'topologyOperation', 'topologyCreateIntent', 'topologyIntentQueueState',
        'l2tpOperation', 'nodeOperationLock', 'remoteAdmission', 'topologyExecutionBinding',
        'topologyExecutionEnrollment', 'cascadeRouteGroup'].map(file => require(`../models/${file}Model`))];
const missing = ['cascadetopologystates', 'topologyoperations', 'topologycreateintents',
    'topologyintentqueuestates', 'remoteadmissions', 'topologyexecutionbindings', 'topologyexecutionenrollments'];
const state = { _id: 'singleton', revision: 7, deployedRevision: 7, stateTransitionRevision: 3,
    replacementEpoch: 2, remoteAdmissionCount: 0, topologyAdmissionCount: 0 };
// Independently fixed synthetic source records, never accepted from a DB scan.
const fixedLinks = Array.from({ length: 10 }, (_, i) => ({
    _id: new mongo.ObjectId((0x100 + i).toString(16).padStart(24, '0')),
    portalNode: new mongo.ObjectId((0x200 + i).toString(16).padStart(24, '0')),
    bridgeNode: new mongo.ObjectId((0x300 + i).toString(16).padStart(24, '0')),
    mode: i < 8 ? 'reverse' : 'forward', active: true, status: 'online',
    tunnelPort: 11000 + i, tunnelUuid: `synthetic-local-secret-${i}`, classicOwnership: 'unchanged' }));
const pins = fixedLinks.map(row => ({ id: String(row._id), sha256: fingerprint(row) }));
const name = `prod_authority_mongo_${randomUUID().replaceAll('-', '')}`;
let adminClient, db, mongod, directory, uri, deployment;
const evidence = [];
async function until(fn) {
    let last;
    for (let i = 0; i < 150; i++) {
        try { return await fn(); } catch (error) { last = error; }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw last;
}
function absent(pid) {
    try { process.kill(pid, 0); return false; } catch (error) { if (error.code === 'ESRCH') return true; throw error; }
}
async function stopOwned(child) {
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    const closed = new Promise(resolve => child.once('close', resolve));
    child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    try { await closed; } finally { clearTimeout(timer); }
}
test.before(async () => {
    assert.ok(process.env.C3_MONGOD && process.env.TMPDIR);
    directory = fs.mkdtempSync(path.join(process.env.TMPDIR, 'm-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(() => resolve(port)); });
    });
    mongod = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', 'prodAuthorityScratch', '--setParameter', 'enableTestCommands=1',
        '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    uri = `mongodb://127.0.0.1:${port}/${name}?directConnection=true`;
    adminClient = new mongo.MongoClient(uri, { serverSelectionTimeoutMS: 250, retryWrites: false });
    await until(() => adminClient.connect());
    await adminClient.db('admin').command({ replSetInitiate: { _id: 'prodAuthorityScratch',
        members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
    await until(async () => assert.equal((await adminClient.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    const { config } = await adminClient.db('admin').command({ replSetGetConfig: 1 });
    deployment = { setName: config._id, replicaSetId: String(config.settings.replicaSetId) };
    // The setup client is direct, but the finite entry must use discovery:
    // driver directConnection rewrites primary reads to primaryPreferred.
    uri = `mongodb://127.0.0.1:${port}/${name}?replicaSet=prodAuthorityScratch&appName=prod-authority-entry`;
    db = adminClient.db(name);
});
test.after(async () => {
    try { if (db) { assert.match(name, /^prod_authority_mongo_[a-f0-9]{32}$/); await db.dropDatabase(); } }
    finally {
        if (adminClient) await adminClient.close();
        await stopOwned(mongod);
        if (mongod) assert.ok(absent(mongod.pid), 'owned mongod PID reaped');
        if (process.env.C3_AUTHORITY_MONGO_EVIDENCE) {
            fs.writeFileSync(process.env.C3_AUTHORITY_MONGO_EVIDENCE, JSON.stringify({
                node: process.version, mongoose: require('mongoose/package.json').version,
                mongodb: require(require.resolve('mongodb/package.json', { paths: [path.dirname(require.resolve('mongoose'))] })).version,
                mongodPid: mongod?.pid, mongodReaped: mongod ? absent(mongod.pid) : null, cases: evidence }, null, 2));
            if (directory && fs.existsSync(path.join(directory, 'mongo.log'))) fs.copyFileSync(path.join(directory, 'mongo.log'),
                `${process.env.C3_AUTHORITY_MONGO_EVIDENCE}.mongod.log`);
        }
        if (directory) fs.rmSync(directory, { recursive: true, force: true });
    }
});
async function reset(firstInstall) {
    for (const row of await db.listCollections().toArray()) await db.collection(row.name).drop();
    for (const model of models) {
        if (firstInstall && missing.includes(model.collection.name)) continue;
        await db.createCollection(model.collection.name);
        for (const [key, options] of model.schema.indexes()) {
            const { background, ...rest } = options;
            await db.collection(model.collection.name).createIndex(key, rest);
        }
    }
    await db.collection('cascadelinks').insertMany(fixedLinks);
}
async function runCase(mode) {
    const firstInstall = mode === 'firstInstall';
    await reset(firstInstall);
    const before = await db.listCollections().toArray();
    const accepted = { serverContext: context, databaseName: name, maintenanceGeneration: randomUUID(), deployment,
        acceptedClassicLinks: pins, initialState: state, manifestSha256: REVIEWED_MANIFEST_SHA256,
        acceptedMissingCollections: firstInstall ? missing.map(name => ({ name, options: {} })) : [] };
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR, 'e-'));
    const challengeFile = path.join(root, 'challenge.json');
    fs.writeFileSync(challengeFile, JSON.stringify(accepted));
    const broker = spawn('/usr/bin/python3', ['scripts/prod-maintenance/tests/local_protocol_fixture.py', challengeFile],
        { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', C3_KEEP_AUTHORITY_FIXTURE: '1' } });
    const authority = adapter.compose({ challenge: accepted, child: broker, timeoutMs: 2000 });
    const observed = [], replies = [], failed = [], probeErrors = [];
    let closed = false, brokerEof = false, brokerCloseAck = false, barrierDone = false;
    let guardRoot, control, probes = 0, client, faultArmed = false, singletonInserted = false;
    const record = { mode, brokerPid: broker.pid, commands: observed, replies, failed };
    evidence.push(record);
    function probe() {
        control ||= JSON.parse(fs.readFileSync(path.join(root, 'challenge.control.json')));
        guardRoot = control.root;
        assert.equal(absent(control.guardPid), false, 'independent resident guard remains alive');
        const rival = spawnSync('/usr/bin/flock', ['-n', control.lock, '/usr/bin/true']);
        assert.equal(rival.error, undefined);
        assert.equal(rival.status, 1, 'independent open cannot acquire the guard-owned exclusive OFD');
        if (!record.transferredLock && !brokerEof && !brokerCloseAck) {
            const expected = fs.statSync(control.lock);
            const descriptors = pid => fs.readdirSync(`/proc/${pid}/fd`).filter(fd => {
                try { const st = fs.statSync(`/proc/${pid}/fd/${fd}`); return st.dev === expected.dev && st.ino === expected.ino; }
                catch (error) { if (error.code === 'ENOENT') return false; throw error; }
            });
            assert.notEqual(control.guardPid, broker.pid);
            const guardFds = descriptors(control.guardPid), brokerFds = descriptors(broker.pid);
            assert.equal(guardFds.length, 1);
            assert.equal(brokerFds.length, 1, 'real SCM_RIGHTS recipient holds the pinned lock inode');
            record.transferredLock = { device: expected.dev, inode: expected.ino, guardFds, brokerFds };
        }
        probes++;
    }
    function cleanupBarrier() {
        if (!closed || !(brokerEof || brokerCloseAck) || barrierDone) return;
        barrierDone = true;
        try {
            probe();
            record.guardRetainedAfterBrokerCloseAndClientClose = true;
            record.cleanupBarrier = brokerCloseAck ? 'real close acknowledgement' : 'real broker EOF';
            record.guardJournal = fs.readFileSync(path.join(guardRoot, 'guard.json'), 'utf8');
            record.helperJournal = fs.readFileSync(path.join(guardRoot, 'helper.json'), 'utf8');
        } catch (error) { probeErrors.push(error); }
        // Only the TEST fixture may now terminate its own guard, not the adapter.
        fs.writeFileSync(path.join(root, 'challenge.cleanup'), 'actual native client close completed\n');
    }
    // Observe the actual codec reply; do not hold the successful Python peer
    // waiting for EOF while it waits for our DB-cleanup marker.
    broker.stdout.on('data', bytes => {
        try { if (JSON.parse(bytes.toString()).verb === 'close') { brokerCloseAck = true; cleanupBarrier(); } }
        catch { /* the product codec, not this observer, validates framing */ }
    });
    broker.stdout.once('end', () => { brokerEof = true; cleanupBarrier(); });
    const createClient = (selectedUri, options) => {
        assert.equal(selectedUri, uri);
        assert.equal(options.retryWrites, false);
        probe();
        client = new mongo.MongoClient(selectedUri, { ...options, monitorCommands: true });
        client.on('commandStarted', event => {
            try { probe(); } catch (error) { probeErrors.push(error); }
            observed.push({ requestId: event.requestId, commandName: event.commandName, command: event.command });
            if (event.commandName === 'insert') singletonInserted = true;
            if (mode === 'precommitGuardLoss' && event.commandName === 'listIndexes' && !faultArmed) {
                faultArmed = true;
                fs.writeFileSync(control.freeze, '0\n'); // modeled freeze loss, real guard must poison
            }
        });
        client.on('commandSucceeded', event => replies.push({ requestId: event.requestId, commandName: event.commandName, reply: event.reply }));
        client.on('commandFailed', event => failed.push({ requestId: event.requestId, commandName: event.commandName,
            code: event.failure.code ?? event.failure.cause?.code,
            name: event.failure.name, message: event.failure.message, errorLabels: event.failure.errorLabels }));
        // Fault scheduling ONLY: call the real native method and return its exact
        // server reply. No fabricated Mongo responses or transaction/session shim.
        const nativeDb = client.db.bind(client);
        client.db = (...args) => {
            const selected = nativeDb(...args);
            const command = selected.command.bind(selected);
            selected.command = async (...commandArgs) => {
                const reply = await command(...commandArgs);
                if (mode === 'postcommitReadFailure' && commandArgs[0].commitTransaction && singletonInserted && !faultArmed) {
                    faultArmed = true;
                    await adminClient.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 },
                        data: { failCommands: ['find'], errorCode: 50, errorLabels: [], appName: 'prod-authority-entry' } });
                }
                return reply;
            };
            return selected;
        };
        const close = client.close.bind(client);
        client.close = async (...args) => {
            probe();
            try { await close(...args); probe(); }
            finally { closed = true; cleanupBarrier(); }
        };
        return client;
    };
    try {
        if (mode === 'unknownCommit') {
            await adminClient.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 },
                data: { failCommands: ['commitTransaction'], appName: 'prod-authority-entry',
                    writeConcernError: { code: 64, errmsg: 'local real server WCE' }, errorLabels: ['UnknownTransactionCommitResult'] } });
        }
        const config = { challenge: accepted, mongoUri: uri };
        const operation = entry.runAccepted({ config, authority, createClient });
        if (firstInstall) {
            record.result = await operation;
            assert.deepEqual(record.result, { initialized: true, ready: false, dormant: true, mode: 'insert-only', stateSha256: fingerprint(state) });
            assert.equal(broker.exitCode, 0);
        } else {
            await assert.rejects(operation, error => {
                record.refusal = { code: error.code, message: error.message };
                assert.equal(error.code, 'PRODUCTION_INITIALIZATION_UNKNOWN_HOLD');
                return true;
            });
            assert.equal(broker.exitCode, 1, 'refusal broker exits naturally without adapter signal');
        }
        assert.equal(closed, true);
        assert.deepEqual(probeErrors, []);
        assert.equal(record.guardRetainedAfterBrokerCloseAndClientClose, true);
        assert.ok(probes > 0);
        record.lockProbes = probes;
        assert.equal(absent(broker.pid), true);
        assert.equal(absent(control.guardPid), true, 'fixture reaped only its owned guard after cleanup barrier');
        record.guardPid = control.guardPid;
        record.ownedPidsReaped = true;
        assert.match(record.guardJournal, /unknown-retained/);
        assert.match(record.helperJournal, firstInstall ? /completed-dormant-retained/ : /unknown-retained/);
        const commits = observed.filter(e => e.commandName === 'commitTransaction');
        const inserts = observed.filter(e => e.commandName === 'insert');
        assert.equal(commits.length, firstInstall ? 2 : mode === 'precommitGuardLoss' ? 0 : 1);
        assert.equal(inserts.length, mode === 'precommitGuardLoss' ? 0 : 1);
        assert.equal(observed.filter(e => e.commandName === 'abortTransaction').length, 0);
        for (const event of commits) assert.equal(event.command.writeConcern.w, 'majority');
        if (inserts.length) {
            assert.equal(inserts[0].command.insert, 'cascadetopologystates');
            assert.deepEqual(inserts[0].command.documents, [state]);
        }
        if (firstInstall) {
            assert.deepEqual(observed.filter(e => e.commandName === 'create').map(e => e.command.create), missing);
            const after = await db.listCollections().toArray();
            for (const old of before) assert.deepEqual(after.find(row => row.name === old.name).info.uuid, old.info.uuid);
            const confirmed = observed.filter(e => e.commandName === 'find' && e.command.find === 'cascadetopologystates'
                && e.command.autocommit === undefined);
            assert.ok(confirmed.length >= 1);
            const exact = confirmed.at(-1).command;
            assert.deepEqual(exact.filter, {}, 'bounded full scan rejects foreign/extra singleton rows');
            assert.equal(exact.limit, 2);
            const confirmation = replies.find(reply => reply.requestId === confirmed.at(-1).requestId);
            assert.deepEqual(confirmation.reply.cursor.firstBatch, [state]);
            assert.equal(exact.readConcern.level, 'majority');
            assert.ok(exact.maxTimeMS > 0 && exact.maxTimeMS <= 2000);
            assert.ok(exact.$readPreference === undefined || exact.$readPreference.mode === 'primary');
        }
        if (mode === 'postcommitReadFailure') {
            assert.equal(faultArmed, true);
            assert.ok(failed.some(e => e.commandName === 'find' && e.code === 50));
            assert.ok(replies.some(e => e.commandName === 'commitTransaction' && e.reply.ok === 1));
        }
        if (mode === 'unknownCommit') assert.ok(replies.some(e => e.commandName === 'commitTransaction'
            && e.reply.writeConcernError?.code === 64 && e.reply.errorLabels?.includes('UnknownTransactionCommitResult')));
        await adminClient.db('admin').command({ configureFailPoint: 'failCommand', mode: 'off' });
        const durable = await db.collection('cascadetopologystates').find({ _id: 'singleton' }, { readConcern: { level: 'majority' } }).toArray();
        if (firstInstall || mode === 'postcommitReadFailure') assert.deepEqual(durable, [state]);
        if (mode === 'precommitGuardLoss') assert.deepEqual(durable, []);
        record.durableSingleton = durable;
        assert.deepEqual(await db.collection('cascadelinks').find({}).sort({ _id: 1 }).toArray(), fixedLinks);
        assert.deepEqual(observed.filter(e => ['update', 'delete', 'drop', 'dropIndexes', 'collMod'].includes(e.commandName)), []);
        const count = observed.length;
        await assert.rejects(entry.runAccepted({ config, authority, createClient() { assert.fail('replay must not create a client'); } }),
            { code: 'PROD_MAINTENANCE_ALREADY_ATTEMPTED' });
        assert.equal(observed.length, count);
    } finally {
        await adminClient.db('admin').command({ configureFailPoint: 'failCommand', mode: 'off' });
        if (client && !closed) { await client.close(); }
        fs.writeFileSync(path.join(root, 'challenge.cleanup'), 'owned test cleanup\n');
        await stopOwned(broker);
        // On an assertion failure retain logs/evidence before removing only our roots.
        if (guardRoot && process.env.C3_AUTHORITY_MONGO_EVIDENCE) {
            record.fixtureFiles = Object.fromEntries(['guard.json', 'helper.json'].filter(file => fs.existsSync(path.join(guardRoot, file)))
                .map(file => [file, fs.readFileSync(path.join(guardRoot, file), 'utf8')]));
        }
        if (guardRoot) fs.rmSync(guardRoot, { recursive: true, force: true });
        fs.rmSync(root, { recursive: true, force: true });
    }
}
for (const mode of ['firstInstall', 'precommitGuardLoss', 'unknownCommit', 'postcommitReadFailure']) {
    test(`finite PROD entry + actual broker/guard + disposable replica-set Mongo: ${mode}`, async () => runCase(mode));
}
