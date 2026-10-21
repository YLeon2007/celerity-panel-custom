'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const location = path.join(__dirname, '../heldTestOwnerSettlement');
const api = fs.existsSync(location + '.js') ? require(location) : {};
test('explicit held TEST settlement exists; no receipt or boolean substitutes for a restoration scope', () => {
    assert.equal(typeof api.HeldTestOwnerSettlement, 'function', 'held durable owner settlement is missing');
    assert.throws(() => new api.HeldTestOwnerSettlement({ withRestorationScope: true }), /restoration scope/);
});

const fsp = require('node:fs/promises');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID, createHash } = require('node:crypto');
const mongoose = require('mongoose');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../../modules/relay-l2tp/domain/topologyExecutionContext');
const { TopologyConfigTransfer } = require('../topologyConfigTransfer');
const { TopologyExecutionBindingStore } = require('../../modules/relay-l2tp/repositories/topologyExecutionBindingStore');
const { TopologyOperationRepository } = require('../../modules/relay-l2tp/repositories/topologyOperationRepository');
const { NodeOperationLockRepository } = require('../../modules/relay-l2tp/services/nodeOperationLockRepository');
const { freeze } = require('../../modules/relay-l2tp/models/topologyExecutionBindingContract');
let db, child, directory, m;
async function until(fn) {
    let error;
    for (let i = 0; i < 120; i++) { try { return await fn(); } catch (e) { error = e; } await new Promise(r => setTimeout(r, 50)); }
    throw error;
}
test.before(async () => {
    assert.ok(process.env.C3_MONGOD, 'real Mongo proof required');
    directory = await fsp.mkdtemp(path.join(process.env.TMPDIR, 'c3-os-'));
    const port = await new Promise(resolve => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--setParameter', 'enableTestCommands=1', '--replSet', 'ownerSettlement', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const uri = `mongodb://127.0.0.1:${port}/owner_settlement_scratch`;
    const client = new mongoose.mongo.MongoClient(uri + '?directConnection=true', { serverSelectionTimeoutMS: 100 });
    try {
        await until(() => client.connect());
        await client.db('admin').command({ replSetInitiate: { _id: 'ownerSettlement', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    } finally { await client.close(); }
    db = await mongoose.createConnection(uri + '?replicaSet=ownerSettlement', { monitorCommands: true, serverSelectionTimeoutMS: 1000 }).asPromise();
    const bind = (name, location) => db.model(name, require(location).schema);
    m = {
        Owner: bind('TopologyConfigOwner', '../../models/topologyConfigOwnerModel'),
        Enrollment: bind('TopologyExecutionEnrollment', '../../modules/relay-l2tp/models/topologyExecutionEnrollmentModel'),
        Binding: bind('TopologyExecutionBinding', '../../modules/relay-l2tp/models/topologyExecutionBindingModel'),
        Operation: bind('TopologyOperation', '../../modules/relay-l2tp/models/topologyOperationModel'),
        Lock: bind('NodeOperationLock', '../../modules/relay-l2tp/models/nodeOperationLockModel'),
        Topology: bind('CascadeTopologyState', '../../modules/relay-l2tp/models/cascadeTopologyStateModel'),
        Intent: bind('TopologyCreateIntent', '../../modules/relay-l2tp/models/topologyCreateIntentModel'),
        Queue: bind('TopologyIntentQueueState', '../../modules/relay-l2tp/models/topologyIntentQueueStateModel'),
        Link: bind('CascadeLink', '../../models/cascadeLinkModel'),
        L2tpOperation: bind('L2tpOperation', '../../modules/relay-l2tp/models/l2tpOperationModel'),
        HyNode: bind('HyNode', '../../models/hyNodeModel'),
    };
    await Promise.all(Object.values(m).map(model => model.init()));
});
test.after(async () => {
    try { if (db) { await db.dropDatabase(); assert.equal((await db.getClient().db('admin').admin().listDatabases()).databases.some(d => d.name === 'owner_settlement_scratch'), false); await db.close(); } }
    finally { if (child?.exitCode === null) { const exit = new Promise(r => child.once('exit', r)); child.kill('SIGTERM'); await exit; } if (directory) await fsp.rm(directory, { recursive: true, force: true }); }
});
async function fixture(options = {}) {
    // Administrative fixture cleanup is isolated to this owned scratch database.
    for (const model of Object.values(m)) await model.collection.deleteMany({});
    const pins = options.pins || Object.entries(api.NODES).map(([nodeId, targetProfile], i) => ({ nodeId, targetProfile,
        nodeIdentity: { machineId: String(i + 1).repeat(32), sshHostKeySha256: String(i + 1).repeat(64) },
        endpoint: { ip: `192.0.2.${i + 1}`, port: 22, username: 'synthetic' },
        maintenanceId: randomUUID(), bootId: randomUUID(),
        originalSnapshot: { configSha256: 'a'.repeat(64), unitSha256: 'b'.repeat(64), serviceActive: 'active', serviceEnabled: 'enabled' } }));
    let alive = true, checks = 0;
    const check = async () => { checks++; assert.equal(alive, true, 'SIMULATED restoration hold lost'); await options.onCheck?.(checks); };
    const oldBackend = { instanceId: 'SIMULATED-old-test', pid: 42, processStartTime: '1234', processTree: 'stopped', dispatch: 'disabled' };
    const maintenance = async ({ binding }, work) => {
        const pin = pins.find(p => p.nodeId === binding.node);
        await check();
        await work({ status: 'verified', authority: 'external-maintenance-v1', binding: structuredClone(binding), proofId: randomUUID(),
            maintenanceId: pin.maintenanceId, maintenance: 'held', allWriters: 'drained', oldBackend,
            readback: { source: 'node-readback', ...pin.originalSnapshot, ...options.badSnapshot } });
        await check();
    };
    const transfer = new TopologyConfigTransfer({ executionContext: TEST, TopologyConfigOwner: m.Owner, withVerifiedMaintenance: maintenance });
    const store = new TopologyExecutionBindingStore({ executionContext: TEST, ...m, withVerifiedAuthority: async (challenge, work) => {
        const p = pins.find(p => p.nodeId === challenge.enrollment.nodeId);
        return work({ authority: 'external-execution-maintenance-v1', status: 'verified', challenge,
            proofId: randomUUID(), maintenanceId: p.maintenanceId, maintenance: 'held', allWriters: 'drained', bootstrapWriters: 'excluded',
            physicalIdentity: p.nodeIdentity, owner: 'topology', oldBackend,
            connectionAttestation: { authority: 'server-physical-ssh-endpoint-v1', endpoint: p.endpoint, physicalIdentity: p.nodeIdentity,
                maintenanceId: p.maintenanceId, aliases: 'excluded', hostKeyDigest: 'raw-ssh-public-key-sha256', endpointReassignment: 'excluded' },
            predecessor: challenge.action === 'enroll' ? { generation: 'none', bootId: p.bootId, status: 'empty', protocolVersion: 2,
                journal: 'absent', legacyState: 'absent', writers: 'excluded' } : { generation: 'none', bootId: p.bootId, status: 'pre-enrolled' } });
    } });
    const plan = { revision: 7, deployedRevision: 6, nodes: [] };
    for (const p of pins) {
        await m.HyNode.create({ _id: p.nodeId, ip: p.endpoint.ip, name: 'SIMULATED', type: 'xray', active: true,
            cascadeRole: p.targetProfile === 'xray-main' ? 'portal' : 'bridge', ssh: { port: p.endpoint.port, username: p.endpoint.username, privateKey: 'SIMULATED-not-a-key' } });
        const classic = await transfer.initializeClassic({ node: p.nodeId, profile: p.targetProfile, nodeIdentity: p.nodeIdentity });
        const adopted = await transfer.adopt({ node: p.nodeId, profile: p.targetProfile, generation: classic.generation, proofRef: 'SIMULATED-original' });
        const enrollment = await store.preEnroll({ nodeId: p.nodeId, targetProfile: p.targetProfile, endpoint: p.endpoint,
            nodeIdentity: p.nodeIdentity, ownerGeneration: adopted.generation, predecessorGeneration: 'none', bootId: p.bootId });
        plan.nodes.push({ nodeId: p.nodeId, targetProfile: p.targetProfile, enrollmentId: enrollment.enrollmentId, ownerGeneration: adopted.generation });
    }
    const bytes = Buffer.from('{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n');
    const hash = createHash('sha256').update(bytes).digest('hex');
    const nodes = pins.map((p, i) => freeze({ node: p.nodeId, nodeRef: `${p.targetProfile === 'xray-main' ? 'portal' : 'bridge'}-${i + 1}`, role: p.targetProfile === 'xray-main' ? 'portal' : 'bridge', targetProfile: p.targetProfile,
        configPath: p.targetProfile === 'xray-main' ? '/usr/local/etc/xray/config.json' : '/usr/local/etc/xray-bridge/config.json',
        serviceUnit: p.targetProfile === 'xray-main' ? 'xray.service' : 'xray-bridge.service',
        serviceUnitPath: p.targetProfile === 'xray-main' ? '/etc/systemd/system/xray.service' : '/etc/systemd/system/xray-bridge.service', checks: [],
        candidateHash: hash, candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1', bytes: [...bytes], sha256: hash } }));
    const operationId = new mongoose.Types.ObjectId().toString(), owner = 'SIMULATED-worker';
    const repository = new TopologyOperationRepository({ model: m.Operation });
    await db.transaction(async session => repository.createFrozen({ operationId, executionContext: TEST,
        idempotencyKey: `topology:test:revision-7:host-${TEST.hostIdentity}:${randomUUID()}`, topologyRevision: 7,
        priorDeployedRevision: 6, nodes, heldTopologyAdmission: true, admissionFingerprint: 'f'.repeat(64), session }));
    await repository.claim({ operationId, executionContext: TEST, owner, now: new Date(), leaseMs: 120000 });
    const accepted = { operationId, owner, attempt: 1, locks: [] };
    for (const p of pins) {
        const generation = randomUUID(); accepted.locks.push({ nodeId: p.nodeId, generation });
        await new NodeOperationLockRepository({ model: m.Lock }).acquireLease({ node: p.nodeId, operationId, owner, generation, leaseUntil: new Date(Date.now() + 120000) });
        const backupId = `topology-${createHash('sha256').update([operationId, p.nodeId, `sha256:${hash}`, p.targetProfile].join('\0')).digest('hex')}`;
        await store.createBinding(freeze({ executionContext: TEST.hostIdentity, operationId, nodeId: p.nodeId, candidateHash: `sha256:${hash}`,
            backupId, targetProfile: p.targetProfile, topologyRevision: 7, priorDeployedRevision: 6, owner, attempt: 1, generation }));
    }
    await m.Operation.updateOne({ _id: operationId }, { $set: { status: 'failed', heldTopologyAdmission: !!options.retained } }, { runValidators: true });
    // SIMULATED prior terminal reconciliation through public exact-generation
    // lock methods. This is NOT performed by the owner settlement entry.
    if (!options.retained) for (const lock of accepted.locks) {
        assert.equal(await new NodeOperationLockRepository({ model: m.Lock }).deleteVerifiedOwned({
            node: lock.nodeId, operationId, owner, generation: lock.generation }), true);
    }
    await m.Topology.create({ _id: 'singleton', revision: 7, deployedRevision: 6, topologyAdmissionCount: options.retained ? 1 : 0, remoteAdmissionCount: 0 });
    await m.Queue.create({ _id: 'create-v1', outstanding: 0, ordinal: 0 });
    const journalDirectory = await fsp.mkdtemp(path.join(directory, 'journal-'));
    const { HeldOwnerSettlementJournal } = require('../heldOwnerSettlementJournal');
    const journal = new HeldOwnerSettlementJournal({ directory: journalDirectory, uid: process.getuid(), fixtureRoot: directory });
    const verifyEnrollment = async e => { const pin = pins.find(p => p.nodeId === e.nodeId), n = plan.nodes.find(n => n.nodeId === e.nodeId);
        await check(); assert.ok(pin && n); assert.equal(e._id, n.enrollmentId); assert.equal(e.bootId, pin.bootId);
        assert.equal(e.maintenanceId, pin.maintenanceId); assert.deepEqual(e.endpoint, pin.endpoint); assert.deepEqual(e.nodeIdentity, pin.nodeIdentity); };
    const authority = async work => { await check(); const result = await work({ check, verifyEnrollment, withVerifiedMaintenance: maintenance }); await check(); return result; };
    const operationalAuthority = async work => {
        const { withOperationalRestoration } = require('../heldRestorationChannel');
        // Actual JS adapter and finite Python serve() codec. Independent
        // external physical/root facts are SIMULATED; separate Python tests
        // exercise actual RestorationChannel + five-node OFDs over root-UID
        // simulated local UDS fixtures.
        const inputs = { config: { oldBackend: { instanceId: oldBackend.instanceId, pid: oldBackend.pid, processStartTime: oldBackend.processStartTime } },
            pins: pins.map(p => ({ ...p, ...plan.nodes.find(n => n.nodeId === p.nodeId) })),
            assertPins() { assert.equal(alive, true, 'SIMULATED accepted pins/hold revoked'); } };
        return withOperationalRestoration(inputs, work, { openBridge: () => spawn('/usr/bin/python3', ['-c',
            'import owner_restoration_channel as b\nclass SIMULATED:\n def check(self): pass\nb.serve(SIMULATED(), lifetime=30)'],
            { cwd: path.join(__dirname, '../../../scripts/test-node-isolation'), stdio: ['pipe', 'pipe', 'pipe'],
                env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } }) });
    };
    return { plan, pins, store, authority, operationalAuthority, journal, journalDirectory, revoke() { alive = false; }, held: () => alive, checks: () => checks };
}

async function sameHeldFreshFixture(fault = '') {
    const here = path.join(__dirname, '../../../scripts/test-node-isolation');
    const process = spawn('/usr/bin/python3', ['-B', 'fresh_owner_fixture.py', fault],
        { cwd: here, env: { ...global.process.env, PYTHONDONTWRITEBYTECODE: '1' }, stdio: ['pipe','pipe','pipe'] });
    let stderr = ''; process.stderr.on('data', raw => { stderr += raw; });
    const exited = new Promise(resolve => process.once('close', (code, signal) => resolve({ code, signal })));
    const lines = require('node:readline').createInterface({ input: process.stdout })[Symbol.asyncIterator]();
    const next = async () => { const r = await lines.next(); assert.equal(r.done, false, stderr); return JSON.parse(r.value); };
    try {
        const meta = await next();
        const source = await fsp.readFile(path.join(here, 'fresh_owner_fixture.py'), 'utf8');
        const quote = String.fromCharCode(39).repeat(3);
        const bridge = source.split('BRIDGE_CODE = ' + quote)[1].split(quote)[0];
        const f = await fixture({ pins: meta.pins });
        const { withFreshOperationalRestoration } = require('../heldRestorationChannel');
        const inputs = { pins: meta.pins.map(p => ({ ...p, ...f.plan.nodes.find(n => n.nodeId === p.nodeId) })),
            config: { oldBackend: { instanceId: 'SIMULATED-old-test', pid: 42, processStartTime: '1234' } }, assertPins() {} };
        return { ...f, next, meta, authority: work => withFreshOperationalRestoration(inputs, work,
            { openBridge: () => spawn('/usr/bin/python3', ['-B','-c',bridge,meta.root,meta.socket],
                { cwd: here, env: global.process.env, stdio: ['pipe','pipe','pipe'] }) }),
            async close() { process.stdin.end(); const status = await exited; if (!fault) assert.deepEqual(status, {code:0,signal:null}, stderr); } };
    } catch (error) { process.kill(); await exited; throw error; }
}

test('fresh same-held JS/Python/FreshLaunch actual exec follows public five-owner Mongo CAS/readbacks', {timeout:90000}, async () => {
    const f = await sameHeldFreshFixture();
    try {
        let opens = 0;
        const service = new api.HeldTestOwnerSettlement({ withRestorationScope:work => { opens++; return f.authority(work); }, models:m, journal:f.journal });
        const result = await service.freshHandback(f.plan);
        assert.equal(result.code, 'COMMITTED_FRESH_ACTIVATION_CONFIRMED');
        const physical = await f.next();
        assert.equal(physical.count,1); assert.equal(physical.completed,true); assert.equal(physical.candidateFrozen,true);
        assert.equal(physical.active,false);
        assert.equal(await m.Owner.countDocuments({owner:'classic'}),5);
        for (const n of physical.commit.settlement.nodes) {
            assert.deepEqual(n.owner, JSON.parse(JSON.stringify(await m.Owner.findOne({node:n.nodeId}).lean())));
            assert.equal(n.priorOwnerGeneration,f.plan.nodes.find(p=>p.nodeId===n.nodeId).ownerGeneration);
        }
        await assert.rejects(service.freshHandback(f.plan));
        assert.equal(opens,1,'terminal fresh service must not reopen a restoration channel');
    } finally { await f.close(); }
});

test('fresh terminal ack loss, timeout and required cleanup remain unknown with exactly one actual exec', {timeout:180000}, async t => {
    for (const fault of ['ack-loss','terminal-timeout','cleanup']) await t.test(fault, async () => {
        const f = await sameHeldFreshFixture(fault);
        try {
            let opens=0;
            const service=new api.HeldTestOwnerSettlement({withRestorationScope:work=>{opens++;return f.authority(work);},models:m,journal:f.journal});
            await assert.rejects(service.freshHandback(f.plan), {code:'COMMITTED_ACTIVATION_UNKNOWN'});
            const physical=await f.next();
            assert.equal(physical.count,1);assert.equal(physical.candidateFrozen,true);
            assert.equal(await m.Owner.countDocuments({owner:'classic'}),5);
            await assert.rejects(service.freshHandback(f.plan));assert.equal(opens,1);
        } finally { await f.close(); }
    });
});

test('fresh all-five guardloss and stale generations refuse before terminal exec or owner CAS', {timeout:220000}, async t => {
    for (const node of Object.keys(api.NODES)) for (const kind of ['guardloss','generation']) await t.test(kind+':'+node,async()=>{
        const f=await sameHeldFreshFixture(kind+':'+node);
        try {
            if(kind==='generation') f.plan.nodes.find(n=>n.nodeId===node).ownerGeneration=randomUUID();
            const owners=await m.Owner.find().lean();
            const service=new api.HeldTestOwnerSettlement({withRestorationScope:f.authority,models:m,journal:f.journal});
            await assert.rejects(service.freshHandback(f.plan));
            assert.deepEqual(await m.Owner.find().lean(),owners);
            const physical=await f.next();assert.equal(physical.count,0);assert.equal(physical.candidateFrozen,true);
        } finally {await f.close();}
    });
});

test('SIMULATED physical restoration: actual JS/Python bridge and public five-node handback prove zero locks/admissions without thaw', async () => {
    const f = await fixture(); f.authority = f.operationalAuthority;
    const before = await m.Operation.findOne().lean(), enrollments = await m.Enrollment.find().lean(), bindings = await m.Binding.find().lean();
    const commands = []; const monitor = e => commands.push(e.commandName);
    db.getClient().on('commandStarted', monitor);
    let result;
    try { result = await new api.HeldTestOwnerSettlement({ withRestorationScope: f.authority, models: m, journal: f.journal }).settle(f.plan); }
    finally { db.getClient().off('commandStarted', monitor); }
    assert.equal(result.handbackAllowed, false); assert.equal(result.externalAdmission, 'closed');
    assert.equal(result.outstandingLocks, 0); assert.equal(result.topologyAdmissionCount, 0); assert.equal(f.held(), true);
    assert.equal(commands.filter(c => c === 'commitTransaction').length, 5);
    assert.equal(commands.includes('abortTransaction'), false);
    const owners = await m.Owner.find().lean(); assert.equal(owners.length, 5);
    for (const owner of owners) { assert.equal(owner.owner, 'classic'); assert.equal(owner.handbackReceipt.fromGeneration, f.plan.nodes.find(n => n.nodeId === String(owner.node)).ownerGeneration); }
    assert.equal(await m.Lock.countDocuments(), 0); assert.equal((await m.Topology.findById('singleton')).topologyAdmissionCount, 0);
    const after = await m.Operation.findOne().lean(); assert.equal(after.status, before.status); assert.deepEqual(after.nodes, before.nodes);
    assert.deepEqual(after.executionContext, before.executionContext); assert.equal(after.heldTopologyAdmission, false);
    assert.deepEqual(await m.Enrollment.find().lean(), enrollments); assert.deepEqual(await m.Binding.find().lean(), bindings);
    await assert.rejects(new api.HeldTestOwnerSettlement({ withRestorationScope: f.authority, models: m, journal: f.journal }).settle(f.plan));
    const progress = JSON.parse(await fsp.readFile(path.join(f.journalDirectory, 'owner-settlement.json')));
    assert.equal(progress.phase, 'settled-held'); assert.equal(progress.settled.length, 5); assert.equal(progress.inFlightNode, null);
});
test('combined TEST handback commits exact all-five readbacks before its bounded activation', async () => {
    const f = await fixture(); const events = [];
    const authority = work => f.authority(async scope => work({ ...scope,
        async commitHandoff(proof) {
            events.push('commit');
            assert.equal(await m.Owner.countDocuments({ owner: 'classic' }), 5);
            assert.equal(proof.nodes.length, 5); assert.equal(proof.context, TEST.hostIdentity);
            for (const n of proof.nodes) {
                assert.deepEqual(n.owner, JSON.parse(JSON.stringify(await m.Owner.findOne({ node: n.nodeId }).lean())));
                assert.equal(n.enrollmentSha256.length, 64);
            }
            assert.equal(proof.quietSha256.length, 64);
            return 'a'.repeat(64);
        },
        async activateClassic() { events.push('activate'); },
        async completeHandoff() { events.push('complete'); },
    }));
    assert.equal(typeof api.HeldTestOwnerSettlement.prototype.handback, 'function', 'actual combined handback missing');
    const result = await new api.HeldTestOwnerSettlement({ withRestorationScope: authority, models: m, journal: f.journal }).handback(f.plan);
    assert.deepEqual(events, ['commit', 'activate', 'complete']);
    assert.equal(result.code, 'COMMITTED_BOUNDED_ACTIVATION_CONFIRMED');
    assert.equal(result.externalAdmission, 'closed');
    assert.deepEqual(result.activationSet, ['existing-classic-backend']);
    await assert.rejects(new api.HeldTestOwnerSettlement({ withRestorationScope: authority, models: m, journal: f.journal }).handback(f.plan));
    assert.deepEqual(events, ['commit', 'activate', 'complete']);
});

test('combined postcommit fsync, activation EOF and completion EOF never rollback or retry', async () => {
    for (const fault of ['commit-ack', 'journal-fsync', 'activation-EOF', 'completion-EOF']) {
        const f = await fixture(); const events = [];
        if (fault === 'journal-fsync') {
            const committed = f.journal.committed.bind(f.journal);
            f.journal.committed = digest => {
                const sync = fs.fsyncSync;
                fs.fsyncSync = () => { throw new Error('SIMULATED fsync syscall refusal'); };
                try { return committed(digest); } finally { fs.fsyncSync = sync; }
            };
        }
        const authority = work => f.authority(scope => work({ ...scope,
            async commitHandoff() { events.push('commit'); if (fault === 'commit-ack') throw new Error('EOF'); return 'a'.repeat(64); },
            async activateClassic() { events.push('activate'); if (fault === 'activation-EOF') throw new Error('EOF'); },
            async completeHandoff() { events.push('complete'); throw new Error('EOF'); },
        }));
        const service = new api.HeldTestOwnerSettlement({ withRestorationScope: authority, models: m, journal: f.journal });
        await assert.rejects(service.handback(f.plan), { code: fault === 'commit-ack' ? 'COMMIT_UNKNOWN_NO_ACTIVATION' : 'COMMITTED_ACTIVATION_UNKNOWN' });
        assert.deepEqual(events, fault === 'commit-ack' || fault === 'journal-fsync' ? ['commit'] : fault === 'activation-EOF' ? ['commit','activate'] : ['commit','activate','complete']);
        assert.equal(await m.Owner.countDocuments({ owner: 'classic' }), 5);
        assert.equal(await m.Enrollment.countDocuments(), 5); assert.equal(await m.Binding.countDocuments(), 5);
        await assert.rejects(service.handback(f.plan));
        assert.equal(events.filter(e => e === 'commit').length, 1);
        if (fault === 'journal-fsync') assert.equal(fs.existsSync(path.join(f.journalDirectory,'owner-settlement.json.next')),true);
    }
});

test('SIMULATED root/physical: actual finite operator CLI, real Mongo and Python codec exit naturally', async t => {
    for (const closeFailure of [false, true]) await t.test(closeFailure ? 'postcommit Mongo cleanup EOF is unknown' : 'confirmed natural exit', async () => {
    const f = await fixture();
    const inputs = { config: { mongoUri: `mongodb://${db.getClient().options.hosts[0]}/${db.name}?replicaSet=ownerSettlement`, plan: f.plan,
            oldBackend: { instanceId: 'SIMULATED-old-test', pid: 42, processStartTime: '1234' } },
        pins: f.pins.map(p => ({ ...p, ...f.plan.nodes.find(n => n.nodeId === p.nodeId) })) };
    const file = path.join(directory,'cli-input.json'); await fsp.writeFile(file,JSON.stringify(inputs));
    const python = `import hashlib,json,os\nimport owner_restoration_channel as b\nclass SIMULATED:\n def check(self): pass\n def handoff(self,op,proof=None):\n  if op=='commit-handoff':\n   raw=json.dumps(proof).encode()\n   self.digest=hashlib.sha256(raw).hexdigest()\n  return self.digest\nb.serve(SIMULATED(),lifetime=30)`;
    const code = `const fs=require('fs'),path=require('path'),Module=require('module');
const inputs=JSON.parse(fs.readFileSync(${JSON.stringify(file)}));inputs.assertPins=()=>{};
const channel=require('./src/services/heldRestorationChannel');
const Journal=require('./src/services/heldOwnerSettlementJournal').HeldOwnerSettlementJournal;
const journal=new Journal({directory:${JSON.stringify(f.journalDirectory)},uid:process.getuid(),fixtureRoot:${JSON.stringify(directory)}});
const load=Module._load;
Module._load=function(request,parent,isMain){
 if(request.endsWith('/heldRestorationChannel'))return {...channel,operationalInputs:()=>inputs,
  withOperationalRestoration:(i,work)=>channel.withOperationalRestoration(i,work,{openBridge:()=>require('child_process').spawn('/usr/bin/python3',['-B','-c',${JSON.stringify(python)}],
  {cwd:path.resolve('scripts/test-node-isolation'),stdio:['pipe','pipe','pipe'],env:process.env})})};
 if(request.endsWith('/heldOwnerSettlementJournal'))return {HeldOwnerSettlementJournal:function(){return journal}};
 return load.call(this,request,parent,isMain);
};
if(${closeFailure}){
 const mongo=require('mongoose'),connect=mongo.createConnection.bind(mongo);
 mongo.createConnection=(...args)=>{const conn=connect(...args),close=conn.close.bind(conn);
  conn.close=async()=>{await close();throw new Error('SIMULATED postcommit Mongo cleanup EOF')};return conn;};
}
process.getuid=()=>0; // SIMULATED root only, never a CLI switch
process.argv=[process.execPath,path.resolve('scripts/test-node-isolation/settle-held-owner.js')];
require('./scripts/test-node-isolation/settle-held-owner').main().catch(e=>{console.error(e);process.exitCode=75});`;
    const { execFile } = require('node:child_process');
    const result = await new Promise(resolve => execFile(process.execPath,['-e',code],{cwd:path.join(__dirname,'../../..'),env:process.env,timeout:20000},
        (error,stdout,stderr)=>resolve({error,stdout,stderr})));
    if (closeFailure) {
        assert.equal(result.error?.code,75); assert.match(result.stderr,/COMMITTED_ACTIVATION_UNKNOWN/);
        assert.equal(result.stdout,'');
    } else {
        assert.equal(result.error,null,result.stderr); assert.equal(result.stderr,'');
        assert.equal(JSON.parse(result.stdout).code,'COMMITTED_BOUNDED_ACTIVATION_CONFIRMED');
    }
    assert.equal(await m.Owner.countDocuments({owner:'classic'}),5);
    });
});

const run = f => new api.HeldTestOwnerSettlement({ withRestorationScope: f.authority, models: m, journal: f.journal }).settle(f.plan);
async function unchangedRefusal(f) {
    const owners = await m.Owner.find().lean(), locks = await m.Lock.find().lean(), topology = await m.Topology.find().lean();
    await assert.rejects(run(f));
    assert.deepEqual(await m.Owner.find().lean(), owners); assert.deepEqual(await m.Lock.find().lean(), locks);
    assert.deepEqual(await m.Topology.find().lean(), topology); assert.equal(f.held(), true);
}
test('retained terminal admission and uncertain locks are NOT erased by restoration handback', async () => {
    const f = await fixture({ retained: true }); await unchangedRefusal(f);
    assert.equal(await m.Lock.countDocuments(), 5); assert.equal((await m.Topology.findById('singleton')).topologyAdmissionCount, 1);
    assert.equal(fs.existsSync(path.join(f.journalDirectory, 'owner-settlement.json')), false);
});
test('an expired foreign generation lock refuses before ANY owner CAS, despite zero admission counters', async () => {
    const f = await fixture();
    await m.Lock.create({ node: f.plan.nodes[0].nodeId, owner: 'foreign', operationId: new mongoose.Types.ObjectId().toString(),
        generation: randomUUID(), leaseUntil: new Date(0), remoteUncertain: true });
    await unchangedRefusal(f);
});
test('active operation, unknown counter, pending intent and candidate each refuse without owner changes', async () => {
    for (const variant of ['operation', 'counter', 'queue', 'candidate']) {
        const f = await fixture();
        if (variant === 'operation') await m.Operation.updateOne({}, { $set: { status: 'preparing' } }, { runValidators: true });
        if (variant === 'counter') await m.Topology.updateOne({}, { $unset: { remoteAdmissionCount: 1 } });
        if (variant === 'queue') await m.Queue.updateOne({}, { $set: { outstanding: 1 } });
        if (variant === 'candidate') await m.Link.create({ portalNode: f.plan.nodes[0].nodeId, bridgeNode: f.plan.nodes[2].nodeId,
            active: true, status: 'pending', name: 'SIMULATED-candidate', tunnelUuid: randomUUID() });
        await unchangedRefusal(f);
    }
});
test('stale enrollment, stale owner generation and changed original snapshot cannot obtain public handback', async () => {
    for (const variant of ['enrollment', 'generation', 'snapshot']) {
        const f = await fixture();
        if (variant === 'enrollment') f.plan.nodes[0].enrollmentId = randomUUID();
        if (variant === 'generation') f.plan.nodes[0].ownerGeneration = randomUUID();
        if (variant === 'snapshot') f.pins[0].originalSnapshot.configSha256 = 'c'.repeat(64);
        await unchangedRefusal(f);
    }
});
test('guard loss after first real Mongo commit retains durable in-flight progress and never transfers later owners', async () => {
    const f = await fixture(); let commits = 0;
    const monitor = e => { if (e.commandName === 'commitTransaction' && ++commits === 1) f.revoke(); };
    db.getClient().on('commandSucceeded', monitor);
    try { await assert.rejects(run(f)); } finally { db.getClient().off('commandSucceeded', monitor); }
    assert.equal(commits, 1); assert.equal(await m.Owner.countDocuments({ owner: 'classic' }), 1);
    assert.equal(await m.Owner.countDocuments({ owner: 'topology' }), 4);
    const progress = JSON.parse(await fsp.readFile(path.join(f.journalDirectory, 'owner-settlement.json')));
    assert.equal(progress.inFlightNode, f.plan.nodes[0].nodeId); assert.deepEqual(progress.settled, []);
    assert.equal(progress.phase, 'settling-held'); assert.equal(await m.Lock.countDocuments(), 0);
});
test('public handback transaction abort preserves every owner and leaves durable unknown intent', async () => {
    const f = await fixture();
    await db.getClient().db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 },
        data: { failCommands: ['findAndModify'], errorCode: 2 } });
    try { await unchangedRefusal(f); } finally { await db.getClient().db('admin').command({ configureFailPoint: 'failCommand', mode: 'off' }); }
    const progress = JSON.parse(await fsp.readFile(path.join(f.journalDirectory, 'owner-settlement.json')));
    assert.equal(progress.inFlightNode, f.plan.nodes[0].nodeId); assert.equal(progress.settled.length, 0);
});
test('failed postcommit owner confirmation keeps the exact durable in-flight node and does not advance', async () => {
    const f = await fixture(); let failRead = false, commits = 0;
    const original = m.Owner.findOne;
    m.Owner.findOne = function (...args) {
        const query = original.apply(this, args), lean = query.lean;
        query.lean = function (...args) {
            if (failRead) { failRead = false; throw new Error('SIMULATED failed primary-majority read delivery after real commit'); }
            return lean.apply(this, args);
        };
        return query;
    };
    const monitor = e => { if (e.commandName === 'commitTransaction' && ++commits === 1) failRead = true; };
    db.getClient().on('commandSucceeded', monitor);
    try { await assert.rejects(run(f)); }
    finally { db.getClient().off('commandSucceeded', monitor); m.Owner.findOne = original; }
    assert.equal(commits, 1); assert.equal(f.held(), true); assert.equal(await m.Owner.countDocuments({ owner: 'classic' }), 1);
    const progress = JSON.parse(await fsp.readFile(path.join(f.journalDirectory, 'owner-settlement.json')));
    assert.equal(progress.inFlightNode, f.plan.nodes[0].nodeId); assert.deepEqual(progress.settled, []);
});
test('historical enrollment/binding rows cannot dispatch after original owner generation is retired', async () => {
    const f = await fixture();
    const b = await m.Binding.findOne().lean();
    await run(f);
    const { EXPECTED_KEYS } = require('../../modules/relay-l2tp/models/topologyExecutionBindingContract');
    const expected = freeze(Object.fromEntries(EXPECTED_KEYS.map(k => [k, b[k]])));
    // Give the stale reader an otherwise valid original claim/lock again in
    // this scratch fixture: refusal must be the retired OWNER generation, not
    // merely the already absent lock or terminal operation.
    await m.Operation.updateOne({ _id: b.operationId }, { $set: { status: 'preparing', heldTopologyAdmission: true,
        leaseUntil: new Date(Date.now() + 120000) } }, { runValidators: true });
    await new NodeOperationLockRepository({ model: m.Lock }).acquireLease({ node: b.nodeId, operationId: b.operationId,
        owner: b.owner, generation: b.generation, leaseUntil: new Date(Date.now() + 120000) });
    let dispatched = false; const ownerQueries = [];
    const monitor = e => { if (e.commandName === 'find' && e.command.find === m.Owner.collection.collectionName) ownerQueries.push(e.command.filter); };
    db.getClient().on('commandStarted', monitor);
    try { await assert.rejects(f.store.withReadOnlyVerifiedBinding(expected, () => { dispatched = true; })); }
    finally { db.getClient().off('commandStarted', monitor); }
    assert.equal(dispatched, false); assert.ok(ownerQueries.some(q => q.owner === 'topology' && q.generation === b.ownerGeneration));
    assert.equal(await m.Enrollment.countDocuments(), 5); assert.equal(await m.Binding.countDocuments(), 5);
});
test('static receipts, returned booleans, early authority return and escaped callbacks never transfer owners', async () => {
    const f = await fixture(); const owners = await m.Owner.find().lean(); let escaped;
    for (const authority of [async () => true, async () => ({ status: 'verified', held: true }),
        async callback => { escaped = callback; }, async callback => { callback({ check: async () => {}, withVerifiedMaintenance: async () => {} }); }]) {
        await assert.rejects(new api.HeldTestOwnerSettlement({ withRestorationScope: authority, models: m, journal: f.journal }).settle(f.plan));
    }
    await assert.rejects(async () => escaped({ check: async () => {}, withVerifiedMaintenance: async () => {} }));
    assert.deepEqual(await m.Owner.find().lean(), owners);
});
test('actual held adapter latches a swallowed enrollment failure and revokes escaped checks after exit', async () => {
    const f = await fixture(); let escaped;
    await assert.rejects(f.operationalAuthority(async scope => {
        escaped = scope.check;
        await assert.rejects(scope.verifyEnrollment({ nodeId: f.plan.nodes[0].nodeId, _id: randomUUID() }));
        await assert.rejects(scope.check());
    }));
    await assert.rejects(escaped());
    assert.equal(await m.Owner.countDocuments({ owner: 'topology' }), 5);
});
test('real process bridge rejects wrong nonce/EOF and cannot revive after a repaired response', async () => {
    const { RestorationPipe } = require('../heldRestorationChannel');
    const child = spawn('/usr/bin/python3', ['-c',
        'import json,sys\nr=json.loads(sys.stdin.readline())\nprint(json.dumps({**r,"op":"checked","nonce":"b"*64}),flush=True)'],
        { stdio: ['pipe', 'pipe', 'pipe'] });
    const pipe = new RestorationPipe(child);
    try { await assert.rejects(pipe.check()); await assert.rejects(pipe.check()); }
    finally { pipe.close(); if (child.exitCode === null && child.signalCode === null) await new Promise(resolve => child.once('exit', resolve)); }
});
test('fixed operational CLI refuses non-root before Mongo, files or network', async () => {
    if (process.getuid() === 0) return;
    const { execFile } = require('node:child_process');
    const result = await new Promise(resolve => execFile(process.execPath, [path.join(__dirname, '../../../scripts/test-node-isolation/settle-held-owner.js')],
        { env: process.env }, (error, stdout, stderr) => resolve({ error, stdout, stderr })));
    assert.equal(result.error.code, 75); assert.equal(result.stdout, ''); assert.match(result.stderr, /UNKNOWN_RETAINED; no automatic retry or ownership rollback/);
});
