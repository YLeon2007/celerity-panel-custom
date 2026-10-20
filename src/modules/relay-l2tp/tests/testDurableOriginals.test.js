'use strict';
// Protocol process/files are real; remote/root physical authority SIMULATED.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
let api;
try { api = require('../runtime/testDurableOriginals'); } catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }
const sha = raw => createHash('sha256').update(raw).digest('hex');
const helper = Buffer.from('SIMULATED independently pinned installed helper');
const challenge = Object.freeze({ version: 1, test: 'fixed-fixture' });
const fs = require('node:fs');
const path = require('node:path');
const { once } = require('node:events');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const fixtureScript = path.join(__dirname, '../../../../scripts/test-node-isolation/capture_fixture.py');
const env = { PANEL_DOMAIN: TEST.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
async function actualFixture(t, fault, large = false) {
    const supervisor = spawn('/usr/bin/python3', [fixtureScript, 'supervisor', ...(large ? ['large'] : [])], { env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }, stdio: ['pipe', 'pipe', 'pipe'] });
    let errors = ''; supervisor.stderr.on('data', b => { errors += b; });
    t.after(async () => {
        if (supervisor.exitCode === null && supervisor.signalCode === null) {
            const done = once(supervisor, 'close'); supervisor.kill('SIGINT'); await done;
        }
    });
    const f = await new Promise((resolve, reject) => {
        let text = '';
        supervisor.stdout.on('data', b => { text += b; if (text.includes('\n')) resolve(JSON.parse(text.trim())); });
        supervisor.once('close', code => { if (code) reject(new Error(errors)); });
    });
    const runtime = require('../runtime/testPhysicalController');
    const controller = runtime.createRootTestPhysicalAuthority({ env,
        read(file) {
            if (file === '/etc/celerity/topology-test-physical.json') return Buffer.from(JSON.stringify(f.physical));
            if (file === '/etc/celerity/topology-test-capture.json') return Buffer.from(JSON.stringify({ version: 1, helperSha256: sha(fs.readFileSync(path.join(__dirname, '../../../../scripts/test-node-isolation/coordinated_capture.py'))) }));
            assert.equal(file, '/usr/local/libexec/c3-test-coordinated-capture.py');
            return fs.readFileSync(path.join(__dirname, '../../../../scripts/test-node-isolation/coordinated_capture.py'));
        },
        captureSpawn(command, args, options) {
            assert.equal(command, '/usr/bin/python3');
            assert.deepEqual(args, ['-I', '/usr/local/libexec/c3-test-coordinated-capture.py', 'owner-channel']);
            if (fault === 'challenge') {
                const file = path.join(f.root, 'etc/c3-test-coordinated-capture.json');
                const config = JSON.parse(fs.readFileSync(file)); config.ownerChallenge.host.backend.pid++;
                fs.writeFileSync(file, JSON.stringify(config));
            }
            return spawn('/usr/bin/python3', [fixtureScript, 'owner', f.root, f.socket], { ...options, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
        },
        openChannel: async () => { assert.fail('default same-OFD path must never open a second observer'); },
    });
    t.after(() => controller.close());
    return { ...f, controller, supervisor, errors: () => errors };
}
async function scratchMongo(t) {
    const mongoose = require('mongoose'), net = require('node:net');
    const { randomUUID } = require('node:crypto');
    assert.ok(process.env.TMPDIR.startsWith('/home/leon/.hermes/cache/scratch/'));
    const directory = fs.mkdtempSync(path.join(process.env.TMPDIR, 'capture-mongo-'));
    const port = await new Promise(resolve => {
        const server = net.createServer(); server.listen(0, '127.0.0.1', () => {
            const port = server.address().port; server.close(() => resolve(port));
        });
    });
    const child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', 'captureScratch', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    let connection;
    t.after(async () => {
        try {
            if (connection) {
                const name = connection.name; assert.match(name, /^capture_scratch_[a-f0-9]{32}$/);
                await connection.dropDatabase();
                assert.equal((await connection.getClient().db('admin').admin().listDatabases()).databases.some(d => d.name === name), false);
                await connection.close();
            }
        } finally {
            if (child.exitCode === null) { const done = once(child, 'exit'); child.kill('SIGTERM'); await done; }
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });
    const until = async work => {
        let last;
        for (let n = 0; n < 150; n++) {
            try { return await work(); } catch (error) { last = error; }
            await new Promise(resolve => setTimeout(resolve, 50));
        }
        throw last;
    };
    const uri = `mongodb://127.0.0.1:${port}/capture_scratch_${randomUUID().replaceAll('-', '')}`;
    const client = new mongoose.mongo.MongoClient(`${uri}?directConnection=true`, { serverSelectionTimeoutMS: 100 });
    try {
        await until(() => client.connect());
        await client.db('admin').command({ replSetInitiate: { _id: 'captureScratch', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    } finally { await client.close(); }
    connection = await mongoose.createConnection(`${uri}?replicaSet=captureScratch`, { monitorCommands: true }).asPromise();
    const models = {};
    for (const [name, file] of Object.entries({
        HyNode: '../../../models/hyNodeModel', Owner: '../../../models/topologyConfigOwnerModel',
        Operation: '../models/topologyOperationModel', Lock: '../models/nodeOperationLockModel',
        Enrollment: '../models/topologyExecutionEnrollmentModel', Binding: '../models/topologyExecutionBindingModel',
    })) models[name] = connection.model(name, require(file).schema);
    await Promise.all(Object.values(models).map(m => m.init()));
    return { connection, models };
}
test('default same-OFD actual observer public initializeClassic → adopt → preEnroll all five on real scratch Mongo; loss makes zero DB access',
    { skip: !process.env.C3_MONGOD }, async t => {
    const { connection, models } = await scratchMongo(t);
    const { TopologyExecutionAuthorityLifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
    const { TopologyExecutionBindingStore } = require('../repositories/topologyExecutionBindingStore');
    const entry = require('../../../../scripts/test-topology-owner');
    const make = f => {
        const lifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext: TEST, controller: f.controller });
        const store = new TopologyExecutionBindingStore({ executionContext: TEST, ...models,
            withVerifiedAuthority: lifecycle.withVerifiedAuthority.bind(lifecycle), assertAuthorityHeld: lifecycle.assertHeld.bind(lifecycle) });
        return { lifecycle, store };
    };
    const negative = await actualFixture(t);
    const victim = negative.nodeRoots[negative.physical.nodes.at(-1).nodeId];
    fs.writeFileSync(path.join(victim, 'fixture-live.json'), JSON.stringify({ held: false }));
    const accesses = [], record = e => accesses.push(e.commandName);
    connection.getClient().on('commandStarted', record);
    await assert.rejects(entry.enrollTestOwners({ env, ...make(negative), TopologyConfigOwner: models.Owner }));
    connection.getClient().off('commandStarted', record);
    assert.deepEqual(accesses, [], 'lost retained physical authority must refuse before any candidate DB access');
    negative.controller.close();
    const positive = await actualFixture(t, undefined, true);
    for (const pin of positive.physical.nodes) await models.HyNode.create({ _id: pin.nodeId, name: 'capture-local-only', ip: pin.endpoint.ip,
        type: 'xray', active: true, cascadeRole: pin.targetProfile === 'xray-main' ? 'portal' : 'bridge',
        ssh: { port: 2222, username: pin.endpoint.username, privateKey: 'SIMULATED-unused-private-key' } });
    const { spawnSync } = require('node:child_process');
    let mutations = 0;
    const retained = e => {
        if (!['insert', 'update', 'delete', 'commitTransaction'].includes(e.commandName)) return;
        mutations++;
        for (const root of Object.values(positive.nodeRoots)) {
            const file = path.join(root, 'var/lib/c3-test-node-isolation/lock');
            assert.equal(spawnSync('/usr/bin/flock', ['--exclusive', '--nonblock', file, '/usr/bin/true']).status, 1,
                'every real outer flock must remain held at each candidate DB mutation');
        }
    };
    connection.getClient().on('commandStarted', retained);
    const held = make(positive);
    const result = await entry.enrollTestOwners({ env, ...held, TopologyConfigOwner: models.Owner });
    connection.getClient().off('commandStarted', retained);
    assert.equal(result.status, 'enrolled'); assert.equal(result.nodes.length, 5); assert.ok(mutations > 0);
    const owners = await models.Owner.find().lean(), enrollments = await models.Enrollment.find().lean();
    assert.equal(owners.length, 5); assert.equal(enrollments.length, 5);
    for (const pin of positive.physical.nodes) {
        const owner = owners.find(o => o.node.toString() === pin.nodeId), enrollment = enrollments.find(e => e.nodeId === pin.nodeId);
        const { proofRef, ...snapshot } = pin.originalSnapshot;
        assert.equal(owner.owner, 'topology'); assert.deepEqual(owner.originalSnapshot, snapshot);
        assert.equal(owner.adoptionReceipt.maintenanceId, pin.maintenanceId);
        assert.equal(enrollment.ownerGeneration, owner.generation); assert.equal(enrollment.predecessorGeneration, 'none');
        assert.deepEqual(enrollment.endpoint, pin.endpoint); assert.equal(enrollment.bootId, pin.physical.bootId);
        assert.deepEqual(enrollment.nodeIdentity, { machineId: pin.physical.machineId, sshHostKeySha256: pin.physical.sshHostKeySha256 });
        const bundle = JSON.parse(fs.readFileSync(path.join(positive.nodeRoots[pin.nodeId], 'var/lib/c3-test-node-isolation/originals/originals.json')));
        assert.ok(bundle.profiles[pin.targetProfile]);
    }
    await assert.rejects(held.lifecycle.assertHeld(), 'no escaped authority after final lifecycle assertion');
    assert.equal(await models.Operation.countDocuments(), 0); assert.equal(await models.Lock.countDocuments(), 0);
    assert.equal(await models.Binding.countDocuments(), 0);
});
test('actual observer + Engine + same-OFD capture + default controller reach public owner entry (external facts SIMULATED)', async t => {
    const f = await actualFixture(t);
    const { TopologyExecutionAuthorityLifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
    const lifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext: TEST, controller: f.controller });
    let writes = 0;
    // Stop exactly at first public-model boundary; real Mongo readback remains
    // the parent serial assembled fixture, not this local protocol test.
    const marker = new Error('EXPECTED_FIRST_PUBLIC_MODEL_BOUNDARY');
    await assert.rejects(require('../../../../scripts/test-topology-owner').enrollTestOwners({ env, lifecycle,
        TopologyConfigOwner: { collection: { async indexes() {
            for (const pin of f.physical.nodes) {
                // Each accepted node fixture root is private to its helper. The
                // coordinator journal cannot be used as historical permission:
                // this access occurs only after live root-peer checks succeed.
                assert.ok(pin.originalSnapshot);
            }
            const intent = JSON.parse(fs.readFileSync(path.join(f.root, 'var/lib/c3-test-node-isolation/coordinated-capture.json')));
            assert.equal(intent.phase, 'captured-held'); assert.equal(intent.capturedNodes.length, 5);
            writes++; throw marker;
        } } }, store: { preEnroll() { assert.fail('past first public model boundary'); } },
    }));
    assert.equal(writes, 1, 'actual default root capture must open the public owner entry, not keep refusing');
});
test('large live observations cross the default root UDS through final held assertions without DB', async t => {
    const f = await actualFixture(t, undefined, true);
    const { TopologyExecutionAuthorityLifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
    const lifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext: TEST, controller: f.controller });
    let escaped;
    assert.equal(await lifecycle.run(async () => {
        escaped = () => lifecycle.assertHeld(); await lifecycle.assertHeld(); return 17;
    }), 17);
    await assert.rejects(escaped());
});
test('default retained observer revokes on fresh guard/bytes/helper drift and refuses repaired or escaped authority', async t => {
    for (const fault of ['guard', 'bytes', 'attestor', 'eof']) await t.test(fault, async t => {
        const f = await actualFixture(t);
        const { TopologyExecutionAuthorityLifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
        const lifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext: TEST, controller: f.controller });
        let writes = 0, escaped;
        await assert.rejects(lifecycle.run(async () => {
            await lifecycle.assertHeld(); escaped = () => lifecycle.assertHeld();
            const node = f.physical.nodes.at(-1), root = f.nodeRoots[node.nodeId];
            const file = path.join(root, fault === 'guard' ? 'fixture-live.json' : fault === 'attestor'
                ? 'usr/local/libexec/c3-test-physical-attestor' : 'usr/local/etc/xray/config.json');
            const original = fs.readFileSync(file);
            if (fault === 'eof') { f.supervisor.kill('SIGINT'); await once(f.supervisor, 'close'); }
            else fs.writeFileSync(file, fault === 'guard' ? JSON.stringify({ held: false }) : 'changed fresh bytes');
            await assert.rejects(lifecycle.withCapturedTestOwnerEnrollment(() => { writes++; }));
            if (fault !== 'eof') fs.writeFileSync(file, original);
            await assert.rejects(lifecycle.assertHeld(), 'repair must not resurrect a poisoned scope');
        }));
        assert.equal(writes, 0); await assert.rejects(escaped());
    });
});
test('DEFAULT root and actual owner entry refuse changed independent challenge with zero model/store access', async t => {
    const f = await actualFixture(t, 'challenge');
    const { TopologyExecutionAuthorityLifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
    const lifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext: TEST, controller: f.controller });
    let accesses = 0;
    await assert.rejects(require('../../../../scripts/test-topology-owner').enrollTestOwners({ env, lifecycle,
        TopologyConfigOwner: { collection: { indexes() { accesses++; } }, create() { accesses++; } },
        store: { preEnroll() { accesses++; } },
    }));
    assert.equal(accesses, 0);
});

function setup(mode = '') {
    const children = [];
    return { children, capability: api.createDurableNodeOriginals({
        read(file) {
            if (file === '/etc/celerity/topology-test-capture.json') return Buffer.from(JSON.stringify({ version: 1, helperSha256: sha(helper) }));
            assert.equal(file, '/usr/local/libexec/c3-test-coordinated-capture.py'); return helper;
        },
        spawn(command, args, options) {
            assert.equal(command, '/usr/bin/python3');
            assert.deepEqual(args, ['-I', '/usr/local/libexec/c3-test-coordinated-capture.py', 'owner-channel']);
            assert.equal(options.shell, false);
            const child = spawn(process.execPath, ['-e', `
                let text=''; process.stdin.on('data',b=>{ text+=b; let i; while((i=text.indexOf('\\n'))>=0){
                    const f=JSON.parse(text.slice(0,i)); text=text.slice(i+1);
                    if(f.op==='finish') {process.exit(0);}
                    if(${JSON.stringify(mode)}==='silent') continue;
                    process.stdout.write(JSON.stringify({version:1,op:'capture-held',seq:f.seq,nonce:${JSON.stringify(mode)}==='nonce'?'foreign':f.nonce})+'\\n');
                }});`], { stdio: ['pipe', 'pipe', 'pipe'] });
            children.push(child); return child;
        }, timeoutMs: 100,
    }) };
}
test('fixed installed adapter awaits live challenges across callback and revokes escaped checker', async () => {
    assert.ok(api?.createDurableNodeOriginals, 'actual default durable capture adapter is missing');
    const f = setup(); let escaped, writes = 0;
    const result = await f.capability(challenge, async check => { escaped = check; await check(); writes++; return 17; });
    assert.equal(result, 17); assert.equal(writes, 1);
    await assert.rejects(escaped());
    assert.notEqual(f.children[0].exitCode, null);
});
test('wrong nonce and timeout refuse before callback and permanently revoke adapter', async () => {
    assert.ok(api?.createDurableNodeOriginals);
    for (const mode of ['nonce', 'silent']) {
        const f = setup(mode); let writes = 0;
        await assert.rejects(f.capability(challenge, () => { writes++; }));
        await assert.rejects(f.capability(challenge, () => { writes++; }));
        assert.equal(writes, 0);
        assert.equal(f.children.length, 1);
    }
});
