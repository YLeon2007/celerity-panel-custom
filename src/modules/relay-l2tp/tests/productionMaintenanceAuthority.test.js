'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
let implementation = {};
try { implementation = require('../runtime/productionMaintenanceAuthority'); }
catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }
const challenge = Object.freeze({ serverContext: { target: 'production', hostIdentity: 'lm1.infograd.online' } });

test('actual fixed Python helper and guard protocol spans successful real initializer plus DB close', async () => entryCase('success'));
for (const mode of ['connectFailure', 'compositionFailure', 'unknownCommit', 'postcommitReadFailure', 'closeFailure', 'precommitGuardLoss', 'postcommitCleanupGuardLoss']) {
    test(`finite entry retains on ${mode} and naturally disposes real helper`, async () => entryCase(mode));
}
async function entryCase(mode) {
    let entry = {};
    try { entry = require('../runtime/productionAdmissionMaintenanceEntry'); }
    catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }
    assert.equal(typeof entry.testing?.runAccepted, 'function', 'missing finite constructor-to-initializer entry');
    const { mongo } = require('mongoose');
    const { REVIEWED_MANIFEST, REVIEWED_MANIFEST_SHA256 } = require('../services/productionAdmissionInitializer');
    const { rawDocumentFingerprint: fingerprint } = require('../services/productionAdmissionInitializationPreflight');
    const fs = require('node:fs');
    const path = require('node:path');
    const { randomUUID } = require('node:crypto');
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR, 'prod-entry-'));
    const links = Array.from({ length: 10 }, (_, i) => ({ _id: new mongo.ObjectId(), portalNode: new mongo.ObjectId(),
        bridgeNode: new mongo.ObjectId(), mode: i < 8 ? 'reverse' : 'forward', active: true, status: 'online' }));
    const accepted = { serverContext: challenge.serverContext, databaseName: 'MODELED_DISPOSABLE_DATABASE',
        maintenanceGeneration: randomUUID(), deployment: { setName: 'modeled', replicaSetId: 'a'.repeat(24) },
        acceptedClassicLinks: links.map(row => ({ id: String(row._id), sha256: fingerprint(row) })),
        initialState: { _id: 'singleton', revision: 7, deployedRevision: 7, stateTransitionRevision: 3,
            replacementEpoch: 2, remoteAdmissionCount: 0, topologyAdmissionCount: 0 },
        manifestSha256: REVIEWED_MANIFEST_SHA256, acceptedMissingCollections: [] };
    if (mode === 'compositionFailure') accepted.manifestSha256 = '0'.repeat(64);
    fs.writeFileSync(path.join(root, 'challenge.json'), JSON.stringify(accepted));
    const child = spawn('/usr/bin/python3', ['scripts/prod-maintenance/tests/local_protocol_fixture.py', path.join(root, 'challenge.json')],
        { stdio: ['pipe', 'pipe', 'pipe'], env: process.env });
    const authority = implementation.testing.compose({ challenge: accepted, child, timeoutMs: 2000 });
    let state, active = false, closed = false;
    const commands = [];
    const control = () => JSON.parse(fs.readFileSync(path.join(root, 'challenge.control.json')));
    const probeLock = () => {
        const { spawnSync } = require('node:child_process');
        const rival = spawnSync('/usr/bin/flock', ['-n', control().lock, '/usr/bin/true']);
        assert.equal(rival.status, 1, 'same actual external guard flock must remain exclusive at each DB boundary');
    };
    const query = rows => ({ sort() { return this; }, limit() { return this; }, async toArray() { probeLock(); return rows; } });
    const command = async cmd => {
        probeLock();
        commands.push(cmd);
        if (mode === 'precommitGuardLoss' && cmd.listIndexes) fs.writeFileSync(control().freeze, '0\n');
        if (cmd.hello) return { setName: 'modeled', isWritablePrimary: true };
        if (cmd.replSetGetConfig) return { config: { _id: 'modeled', settings: { replicaSetId: 'a'.repeat(24) } } };
        if (cmd.listIndexes) return { ok: 1, cursor: { ns: `${accepted.databaseName}.${cmd.listIndexes}`,
            id: mongo.Long.ZERO, firstBatch: REVIEWED_MANIFEST.collections.find(row => row.name === cmd.listIndexes).indexes } };
        if (cmd.commitTransaction || cmd.abortTransaction) return mode === 'unknownCommit' && cmd.commitTransaction
            ? { ok: 1, writeConcernError: { code: 64 } } : { ok: 1 };
        throw new Error('unexpected modeled command');
    };
    const session = () => ({ transaction: { transition() { active = false; } },
        startTransaction() { active = true; }, inTransaction() { return active; }, async endSession() {} });
    const uuids = new Map(REVIEWED_MANIFEST.collections.map(row => [row.name, new mongo.UUID()]));
    const db = { databaseName: accepted.databaseName, command,
        listCollections() { return query(REVIEWED_MANIFEST.collections.map(row => ({ name: row.name, type: 'collection', options: {}, info: { uuid: uuids.get(row.name) } }))); },
        collection(name) { return { find() {
            if (mode === 'postcommitReadFailure' && state && name === 'cascadetopologystates') throw new Error('MODELED_DB_READ_FAILURE');
            return query(name === 'cascadelinks' ? links : name === 'cascadetopologystates' && state ? [state] : []);
        }, async insertOne(row) { probeLock(); commands.push({ insert: name }); state = row; } }; } };
    const client = { db() { return db; }, startSession: session,
        async connect() { probeLock(); if (mode === 'connectFailure') throw new Error('MODELED_CONNECT_FAILURE'); },
        async close() {
            try {
                probeLock(); closed = true;
                if (mode === 'postcommitCleanupGuardLoss') fs.writeFileSync(control().freeze, '0\n');
                if (mode === 'closeFailure') throw new Error('MODELED_CLOSE_FAILURE');
            } finally { fs.writeFileSync(path.join(root, 'challenge.cleanup'), 'DB cleanup attempted\n'); }
        } };
    db.client = client;
    try {
        const operation = entry.testing.runAccepted({ config: { challenge: accepted, mongoUri: 'mongodb://MODELED-NOT-CONNECTED' },
            authority, createClient: () => client });
        if (mode === 'success') {
            const result = await operation;
            assert.equal(result.initialized, true); assert.equal(result.ready, false); assert.equal(result.dormant, true);
            assert.equal(child.exitCode, 0);
        } else {
            await assert.rejects(operation);
            assert.notEqual(child.exitCode, null, 'helper must be reaped naturally');
        }
        assert.equal(closed, true, 'DB disposal runs even when initializer construction refuses');
        if (['success', 'unknownCommit', 'postcommitReadFailure', 'closeFailure', 'postcommitCleanupGuardLoss'].includes(mode)) {
            assert.deepEqual(state, accepted.initialState, 'never compensate uncertain insert');
            assert.equal(commands.filter(cmd => cmd.commitTransaction).length, 1, 'never retry commit');
        } else assert.equal(commands.filter(cmd => cmd.commitTransaction).length, 0);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test('finite public CLI rejects options naturally and emits only redacted dormant status', async () => {
    const { spawnSync } = require('node:child_process');
    const result = spawnSync(process.execPath, ['scripts/production-admission-maintenance.js', '--config=UNTRUSTED_SECRET'],
        { encoding: 'utf8', timeout: 3000, env: process.env });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 1);
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout), { initialized: null, ready: false, dormant: true,
        holdRequired: true, code: 'PROD_ADMISSION_MAINTENANCE_REFUSED' });
    assert.ok(!result.stdout.includes('UNTRUSTED_SECRET'));
});

for (const mode of ['wrongNonce', 'oversized', 'extraField', 'eof', 'partial', 'pipelined', 'deadline', 'closeNonzero']) {
    test(`fixed helper codec refuses ${mode} without a second authority attempt`, async () => {
        const child = spawn(process.execPath, ['-e', `
          const mode=${JSON.stringify(mode)};
          const lines=require('node:readline').createInterface({input:process.stdin});
          lines.on('line', line=>{
            const q=JSON.parse(line), r={version:1,nonce:q.nonce,verb:q.verb,state:q.verb==='close'?'closed-retained':'held-retained'};
            if(mode==='deadline') return;
            if(mode==='eof') { lines.close(); process.stdout.end(); return; }
            if(mode==='partial') { process.stdout.write('{'); lines.close(); process.stdout.end(); return; }
            if(mode==='wrongNonce') r.nonce='0'.repeat(64);
            if(mode==='extraField') r.extra=true;
            if(mode==='oversized') { process.stdout.write('x'.repeat(131073)); return; }
            const out=JSON.stringify(r)+'\\n'; process.stdout.write(mode==='pipelined'?out+out:out);
            if(q.verb==='close') { if(mode==='closeNonzero') process.exitCode=1; lines.close(); }
          });
        `], { stdio: ['pipe', 'pipe', 'pipe'] });
        const authority = implementation.testing.compose({ challenge, child, timeoutMs: 100 });
        let calls = 0;
        await assert.rejects(authority.withHeldMaintenance(challenge, async () => { calls++; return true; }),
            { code: 'PROD_MAINTENANCE_UNKNOWN_RETAINED' });
        assert.equal(calls, mode === 'closeNonzero' ? 1 : 0);
        assert.notEqual(child.exitCode ?? child.signalCode, null);
        await assert.rejects(authority.withHeldMaintenance(challenge, async () => {}), { code: 'PROD_MAINTENANCE_ALREADY_ATTEMPTED' });
    });
}

test('swallowed scope assertion failure cannot be repaired into maintenance success', async () => {
    const child = spawn(process.execPath, ['-e', `
      const lines=require('node:readline').createInterface({input:process.stdin});
      lines.on('line', line=>{ const q=JSON.parse(line);
        process.stdout.write(JSON.stringify({version:1,nonce:q.nonce,verb:q.verb,state:q.verb==='close'?'closed-retained':'held-retained'})+'\\n');
        if(q.verb==='close') lines.close(); });
    `], { stdio: ['pipe', 'pipe', 'pipe'] });
    const authority = implementation.testing.compose({ challenge, child, timeoutMs: 500 });
    await assert.rejects(authority.withHeldMaintenance(challenge, async scope => {
        await assert.rejects(scope.assertHeld({ ...challenge, unexpected: true }));
        // Swallowing the first error MUST NOT revive the same capability.
        await scope.assertHeld(challenge);
        return 'must-not-be-accepted';
    }), { code: 'PROD_MAINTENANCE_UNKNOWN_RETAINED' });
});

test('cleanup after actual stdin disposal preserves callback error, attaches fault and reaps child', async () => {
    const child = spawn(process.execPath, ['-e', `
      const lines=require('node:readline').createInterface({input:process.stdin});
      lines.on('line', line=>{ const q=JSON.parse(line);
        process.stdout.write(JSON.stringify({version:1,nonce:q.nonce,verb:q.verb,state:'held-retained'})+'\\n'); });
    `], { stdio: ['pipe', 'pipe', 'pipe'] });
    const primary = new Error('MODELED_CALLBACK_ERROR');
    const cleanup = new Error('MODELED_AFTER_REAL_STREAM_DISPOSAL_ERROR');
    const end = child.stdin.end.bind(child.stdin);
    child.stdin.end = (...args) => { end(...args); throw cleanup; };
    const authority = implementation.testing.compose({ challenge, child, timeoutMs: 500 });
    await assert.rejects(authority.withHeldMaintenance(challenge, async () => { throw primary; }), error => {
        assert.equal(error, primary);
        assert.ok(error.cleanupErrors.includes(cleanup));
        return true;
    });
    assert.equal(child.exitCode, 0, 'required actual process reap must complete despite stream error');
});

test('real fixed-protocol subprocess holds callback, checks cleanup, revokes escaped scope and exits naturally', async () => {
    assert.equal(typeof implementation.testing?.compose, 'function', 'missing operational PROD authority adapter');
    // Codec peer ONLY; real Python helper + OFD integration is tested separately.
    const child = spawn(process.execPath, ['-e', `
      const readline = require('node:readline');
      const lines = readline.createInterface({input:process.stdin});
      lines.on('line', line => { const q=JSON.parse(line);
        process.stdout.write(JSON.stringify({version:1,nonce:q.nonce,verb:q.verb,state:q.verb==='close'?'closed-retained':'held-retained'})+'\\n');
        if(q.verb==='close') lines.close();
      });
    `], { stdio: ['pipe', 'pipe', 'pipe'] });
    const authority = implementation.testing.compose({ challenge, child, timeoutMs: 500 });
    let escaped;
    const result = await authority.withHeldMaintenance(challenge, async scope => {
        escaped = scope;
        assert.equal(await scope.assertHeld(challenge), undefined);
        return 'initialized-dormant';
    });
    assert.equal(result, 'initialized-dormant');
    await assert.rejects(escaped.assertHeld(challenge), { code: 'PROD_MAINTENANCE_UNKNOWN_RETAINED' });
    await assert.rejects(authority.withHeldMaintenance(challenge, () => {}), { code: 'PROD_MAINTENANCE_ALREADY_ATTEMPTED' });
    assert.equal(child.exitCode, 0);
});
