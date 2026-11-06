'use strict';
// MODELED replica-set queries/transactions + independent physical/UID facts.
// Most terminal fixtures use a modeled journal facade, explicitly distinguished
// from the real durable journal in the v1/v2 public-settlement positives below.
// Actual public initializeClassic/adopt/handback, Python originals, flocks,
// NodeServers, root-peer channel, durable COMMIT and natural process cleanup.
// This does NOT prove Mongo atomicity, operational enrollment, or deployment.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const { spawn } = require('node:child_process');
const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const { HeldTestOwnerSettlement, NODES } = require('../heldTestOwnerSettlement');
const { TopologyConfigTransfer } = require('../topologyConfigTransfer');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../../modules/relay-l2tp/domain/topologyExecutionContext');
const HERE = path.resolve(__dirname, '../../../scripts/test-node-isolation');
const sha = raw => createHash('sha256').update(raw).digest('hex');
const canonical = value => JSON.stringify(value, (_k, v) => v && typeof v === 'object' && !Array.isArray(v)
    ? Object.fromEntries(Object.keys(v).sort().map(k => [k, v[k]])) : v);
const COORD = '/usr/local/libexec/c3-test-coordinated-restore.py';
const BRIDGE = '/usr/local/libexec/c3-test-owner-restoration-channel.py';
const FRESH_BRIDGE = '/usr/local/libexec/c3-test-fresh-owner-restoration-channel.py';
const CONFIG = '/etc/celerity/topology-test-owner-settlement.json';
const FRESH_CONFIG = '/etc/celerity/topology-test-fresh-owner-settlement.json';
const RESTORE = '/etc/c3-test-coordinated-restore.json';
const INVENTORY = '/etc/celerity/topology-test-inventory.json';
let meta, legacyMeta;
test.before(async () => {
    const { execFile } = require('node:child_process');
    const result = await require('node:util').promisify(execFile)('/usr/bin/python3', ['-B', 'test_v2_terminal_restore.py', 'meta-js'],
        { cwd: HERE, env: process.env, timeout: 10000 });
    assert.equal(result.stderr, ''); meta = JSON.parse(result.stdout);
    const legacy = await require('node:util').promisify(execFile)('/usr/bin/python3', ['-B', 'test_v2_terminal_restore.py', 'meta-v1-js'],
        { cwd: HERE, env: process.env, timeout: 10000 });
    assert.equal(legacy.stderr, ''); legacyMeta = JSON.parse(legacy.stdout);
});

function parser(files) {
    // Private source-loader fixture, never a product flag/path/read override.
    // Only root/private-file authority is MODELED; the entire real parser runs.
    const file = path.resolve(__dirname, '../heldRestorationChannel.js');
    const m = new Module(file, module); m.filename = file; m.paths = module.paths;
    m.fixtureRead = name => { assert.ok(files.has(name), name); return files.get(name); };
    const source = fs.readFileSync(file, 'utf8');
    m._compile('const __fixtureRead = module.fixtureRead;\n' + source.replace('function trustedRead(file) {',
        'function trustedRead(file) { return __fixtureRead(file);'), file);
    const uid = process.getuid;
    return { api: m.exports, read(fresh = false) {
        process.getuid = () => 0;
        try { return fresh ? m.exports.freshOperationalInputs() : m.exports.operationalInputs(); }
        finally { process.getuid = uid; }
    } };
}
function modelFixture() {
    const events = [], models = {};
    const db = { getClient: () => ({ options: {}, topology: { description: { type: 'ReplicaSetWithPrimary' } } }),
        async transaction(work) {
            events.push('transaction');
            const before = Object.fromEntries(Object.entries(models).map(([k, m]) => [k, structuredClone(m.rows)]));
            try { await work({ modeledSession: true }); }
            catch (error) { for (const [k, rows] of Object.entries(before)) models[k].rows = rows; throw error; }
        } };
    for (const name of ['Owner', 'Enrollment', 'Binding', 'Operation', 'Lock', 'Topology', 'Intent', 'Queue', 'Link', 'L2tpOperation']) {
        const matches = (row, filter) => Object.entries(filter).every(([k, v]) => same(row[k], v));
        const m = models[name] = { db, rows: [], collection: { indexes: async () => [{ key: { node: 1, profile: 1 }, unique: true }] },
            async create(rows) { for (const row of rows) { assert.equal(m.rows.some(r => r.node === row.node && r.profile === row.profile), false); m.rows.push(structuredClone(row)); } },
            find(filter = {}) { return query(() => m.rows.filter(r => matches(r, filter))); },
            findOne(filter = {}) { return query(() => m.rows.find(r => matches(r, filter)) || null); },
            async findOneAndUpdate(filter, update, options) {
                assert.equal(options.runValidators, true); assert.equal(options.session.modeledSession, true);
                const row = m.rows.find(r => matches(r, filter)); if (!row) return null;
                Object.assign(row, structuredClone(update.$set));
                for (const k of Object.keys(update.$unset || {})) delete row[k];
                events.push(update.$set.owner); return structuredClone(row);
            } };
    }
    function query(read) {
        const q = { read(value) { assert.equal(value, 'primary'); return q; }, readConcern(value) { assert.equal(value, 'majority'); return q; },
            setOptions(value) { assert.ok(value.maxTimeMS > 0 && value.timeoutMS > 0); return q; },
            limit(value) { assert.equal(value, 1001); return q; }, maxTimeMS(value) { assert.equal(value, 5000); return q; },
            lean: async () => structuredClone(read()) };
        return q;
    }
    return { models, events };
}
async function prepare(meta, version = 2) {
    const f = modelFixture();
    const config = { version, mongoUri: 'mongodb://MODELED/never-connected', bridgeSha256: sha(fs.readFileSync(path.join(HERE, 'owner_restoration_channel.py'))),
        coordinatorSha256: sha(fs.readFileSync(path.join(HERE, 'coordinated_restore.py'))),
        plan: { revision: 7, deployedRevision: 6, nodes: [] }, acceptedOriginalsBase64: meta.acceptedOriginalsBase64,
        oldBackend: { instanceId: 'MODELED-original', pid: 42, processStartTime: '123' },
        ...(version === 2 ? { inventorySha256: sha(canonical(meta.inventory)) } : {}) };
    const pins = [];
    for (const [nodeId, pin] of Object.entries(meta.restore.nodes)) {
        const accepted = JSON.parse(Buffer.from(meta.acceptedOriginalsBase64[nodeId], 'base64'));
        const p = accepted.profiles[pin.identity.targetProfile];
        pins.push({ nodeId, targetProfile: pin.identity.targetProfile, endpoint: { ip: pin.identity.endpointIp, port: 2222, username: 'c3-test-runner' },
            nodeIdentity: { machineId: pin.identity.machineId, sshHostKeySha256: pin.identity.sshHostKeySha256 }, bootId: pin.identity.bootId,
            maintenanceId: randomUUID(), originalSnapshot: { configSha256: p.files.config.sha256, unitSha256: p.files.unit.sha256,
                serviceActive: p.service.ActiveState, serviceEnabled: p.service.UnitFileState } });
    }
    const maintenance = async ({ binding }, work) => {
        const pin = pins.find(p => p.nodeId === binding.node);
        await work({ status: 'verified', authority: 'external-maintenance-v1', binding, proofId: randomUUID(), maintenanceId: pin.maintenanceId,
            maintenance: 'held', allWriters: 'drained', oldBackend: { ...config.oldBackend, processTree: 'stopped', dispatch: 'disabled' },
            readback: { source: 'node-readback', ...pin.originalSnapshot } });
    };
    const transfer = new TopologyConfigTransfer({ executionContext: TEST, TopologyConfigOwner: f.models.Owner, withVerifiedMaintenance: maintenance });
    for (const p of pins) {
        const classic = await transfer.initializeClassic({ node: p.nodeId, profile: p.targetProfile, nodeIdentity: p.nodeIdentity });
        const adopted = await transfer.adopt({ node: p.nodeId, profile: p.targetProfile, generation: classic.generation, proofRef: 'MODELED-originals' });
        const enrollmentId = randomUUID();
        config.plan.nodes.push({ nodeId: p.nodeId, targetProfile: p.targetProfile, enrollmentId, ownerGeneration: adopted.generation });
        // Enrollment/history is an explicit modeled persistence seam, not a
        // claim that the real binding store publicly provisioned a live node.
        f.models.Enrollment.rows.push({ _id: enrollmentId, executionContext: TEST.hostIdentity, nodeId: p.nodeId, targetProfile: p.targetProfile,
            ownerGeneration: adopted.generation, nodeIdentity: p.nodeIdentity, endpoint: p.endpoint,
            bootId: p.bootId, maintenanceId: meta.restore.nodes[p.nodeId].identity.maintenanceId });
    }
    f.models.Topology.rows.push({ _id: 'singleton', revision: 7, deployedRevision: 6, topologyAdmissionCount: 0, remoteAdmissionCount: 0 });
    f.models.Queue.rows.push({ _id: 'create-v1', outstanding: 0 });
    f.journal = { events: [], async start(plan) { this.events.push(['start', structuredClone(plan)]); },
        async beforeNode(id) { this.events.push(['before', id]); }, async afterNode(id, generation) { this.events.push(['after', id, generation]); },
        async complete() { this.events.push(['complete']); }, async committed(hash) { this.events.push(['commit', hash]); } };
    const files = new Map([[COORD, fs.readFileSync(path.join(HERE, 'coordinated_restore.py'))], [BRIDGE, fs.readFileSync(path.join(HERE, 'owner_restoration_channel.py'))],
        [FRESH_BRIDGE, fs.readFileSync(path.join(HERE, 'fresh_owner_restoration_channel.py'))], [RESTORE, Buffer.from(JSON.stringify(meta.restore))],
        [INVENTORY, Buffer.from(JSON.stringify(meta.inventory))], [CONFIG, Buffer.from(JSON.stringify(config))]]);
    const fresh = { ...config, freshBridgeSha256: sha(files.get(FRESH_BRIDGE)) };
    files.set(FRESH_CONFIG, Buffer.from(JSON.stringify(fresh)));
    return { ...f, config, files, pins };
}
function modeledScope(f, { terminalFault, checkFault } = {}) {
    const events = []; let checks = 0;
    const inputs = parser(f.files).read();
    const scope = { async check() { checks++; if (checkFault?.(checks)) throw new Error('MODELED guard lost'); },
        async verifyEnrollment() {}, async withVerifiedMaintenance({ binding }, work) {
            const n = inputs.pins.find(p => p.nodeId === binding.node);
            await work({ binding, status: 'verified', authority: 'external-maintenance-v1', proofId: randomUUID(), maintenanceId: n.maintenanceId,
                maintenance: 'held', allWriters: 'drained', oldBackend: { ...inputs.config.oldBackend, processTree: 'stopped', dispatch: 'disabled' },
                readback: { source: 'node-readback', ...n.originalSnapshot } });
        } };
    for (const [method, op] of [['commitHandoff', 'commit'], ['activateClassic', 'activate'], ['completeHandoff', 'complete'], ['freshHandback', 'fresh']])
        scope[method] = async proof => { events.push(op); if (proof) assert.equal(proof.nodes.length, inputs.pins.length);
            if (terminalFault === op) throw new Error('MODELED lost terminal reply'); return 'a'.repeat(64); };
    const service = () => new HeldTestOwnerSettlement({ models: f.models, journal: f.journal, inventory: inputs.inventory,
        inventorySha256: inputs.config.inventorySha256, withRestorationScope: work => work(scope) });
    return { service, events };
}
async function rootFixture(t) {
    const child = spawn('/usr/bin/python3', ['-B', 'test_v2_terminal_restore.py', 'serve-js'], { cwd: HERE, env: process.env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stderr = ''; child.stderr.on('data', b => { stderr += b; });
    const exit = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
    const lines = require('node:readline').createInterface({ input: child.stdout })[Symbol.asyncIterator]();
    const next = async () => { const line = await lines.next(); assert.equal(line.done, false, stderr); return JSON.parse(line.value); };
    t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill(); await exit; });
    return { meta: await next(), child, next, exit, stderr: () => stderr };
}
const BRIDGE_CODE = `import os,sys
from pathlib import Path
import test_node_originals as t
import coordinated_restore as c
import owner_restoration_channel as b
fs=t.n.Files(t.n.Fixture(Path(sys.argv[1]),os.getuid(),os.getgid(),None))
c.trusted_read=lambda path:fs.read(path)[0]
channel=c.RestorationChannel(fs,fixture_socket=sys.argv[2])
try:
 channel.__enter__()
 b.serve(channel,lifetime=30)
finally: channel.close()
`;

test('v2 modeled DB/journal + actual parser/channel completes the same live Coordinator terminal', { timeout: 30000 }, async t => {
    const root = await rootFixture(t), f = await prepare(root.meta), p = parser(f.files);
    const inputs = p.read();
    const service = new HeldTestOwnerSettlement({ models: f.models, journal: f.journal,
        inventory: inputs.inventory, inventorySha256: inputs.config.inventorySha256,
        withRestorationScope: work => p.api.withOperationalRestoration(inputs, work, { openBridge: () => spawn('/usr/bin/python3',
            ['-B', '-c', BRIDGE_CODE, root.meta.root, root.meta.socket], { cwd: HERE, env: process.env, stdio: ['pipe', 'pipe', 'pipe'] }) }) });
    const result = await service.handback(inputs.config.plan);
    assert.equal(result.code, 'COMMITTED_BOUNDED_ACTIVATION_CONFIRMED'); assert.equal(result.ownerCount, 2);
    assert.equal(f.events.filter(e => e === 'classic').length, 2);
    const physical = await root.next(); assert.equal(physical.intent.phase, 'handoff-completed');
    assert.equal(sha(canonical(physical.commit)), result.commitSha256);
    for (const n of physical.commit.settlement.nodes) {
        assert.deepEqual(n.owner, JSON.parse(JSON.stringify(f.models.Owner.rows.find(o => o.node === n.nodeId))));
        assert.equal(n.enrollmentSha256, sha(JSON.stringify(f.models.Enrollment.rows.find(e => e._id === n.enrollmentId))));
    }
    assert.deepEqual(await root.exit, { code: 0, signal: null }, root.stderr());
});

test('both fixed root CLI callers forward accepted inventory before public owner settlement', async () => {
    for (const fresh of [false, true]) {
        const f = await prepare(meta), p = parser(f.files), inputs = p.read(fresh);
        const events = [];
        const scope = { async check() {}, async verifyEnrollment() {},
            async withVerifiedMaintenance({ binding }, work) {
                const n = inputs.pins.find(p => p.nodeId === binding.node);
                await work({ binding, status: 'verified', authority: 'external-maintenance-v1', proofId: randomUUID(), maintenanceId: n.maintenanceId,
                    maintenance: 'held', allWriters: 'drained', oldBackend: { ...inputs.config.oldBackend, processTree: 'stopped', dispatch: 'disabled' },
                    readback: { source: 'node-readback', ...n.originalSnapshot } });
            },
            async freshHandback(proof) { events.push('fresh'); assert.equal(proof.nodes.length, 2); return 'a'.repeat(64); },
            async commitHandoff(proof) { events.push('commit'); assert.equal(proof.nodes.length, 2); return 'a'.repeat(64); },
            async activateClassic() { events.push('activate'); }, async completeHandoff() { events.push('complete'); } };
        const entry = path.join(HERE, fresh ? 'settle-fresh-held-owner.js' : 'settle-held-owner.js');
        const mod = new Module(entry, module); mod.filename = entry; mod.paths = module.paths;
        const names = { TopologyConfigOwner: 'Owner', TopologyExecutionEnrollment: 'Enrollment', TopologyExecutionBinding: 'Binding',
            TopologyOperation: 'Operation', NodeOperationLock: 'Lock', CascadeTopologyState: 'Topology', TopologyCreateIntent: 'Intent',
            TopologyIntentQueueState: 'Queue', CascadeLink: 'Link', L2tpOperation: 'L2tpOperation' };
        const connection = { model: name => f.models[names[name]], async close() { events.push('db-close'); } };
        mod.require = request => request === 'mongoose' ? { createConnection(uri, options) {
            assert.equal(uri, inputs.config.mongoUri); assert.equal(options.autoIndex, false); return { asPromise: async () => connection };
        } } : request.endsWith('/heldRestorationChannel') ? { ...p.api, operationalInputs: () => inputs, freshOperationalInputs: () => inputs,
            withOperationalRestoration: (_i, work) => work(scope), withFreshOperationalRestoration: (_i, work) => work(scope) }
            : request.endsWith('/heldOwnerSettlementJournal') ? { HeldOwnerSettlementJournal: function () { return f.journal; } }
            : Module.prototype.require.call(mod, request);
        mod._compile(fs.readFileSync(entry, 'utf8'), entry);
        const uid = process.getuid, argv = process.argv, write = process.stdout.write;
        let output = '';
        try {
            process.getuid = () => 0; process.argv = [process.execPath, entry]; process.stdout.write = raw => { output += raw; return true; };
            await mod.exports.main();
        } finally { process.getuid = uid; process.argv = argv; process.stdout.write = write; }
        assert.equal(JSON.parse(output).ownerCount, 2);
        assert.deepEqual(events, fresh ? ['fresh', 'db-close'] : ['commit', 'activate', 'complete', 'db-close']);
        assert.equal(f.events.filter(e => e === 'classic').length, 2);
    }
});

test('both v2 private parsers refuse inventory/identity/profile/original membership drift', async () => {
    for (const fresh of [false, true]) for (const kind of ['digest', 'physical', 'profiles', 'endpoint', 'origin', 'missing', 'duplicate', 'foreign', 'originals', 'mixed-version']) {
        const f = await prepare(meta), p = parser(f.files), configPath = fresh ? FRESH_CONFIG : CONFIG;
        const config = JSON.parse(f.files.get(configPath)), restore = JSON.parse(f.files.get(RESTORE));
        const first = config.plan.nodes[0], pin = restore.nodes[first.nodeId];
        if (kind === 'digest') config.inventorySha256 = 'f'.repeat(64);
        if (kind === 'physical') pin.identity.machineId = 'f'.repeat(32);
        if (kind === 'profiles') pin.profiles = ['xray-main', 'xray-bridge'];
        if (kind === 'endpoint') pin.identity.endpointIp = '104.143.201.72';
        if (kind === 'origin') restore.origin.machineId = 'f'.repeat(32);
        if (kind === 'missing') config.plan.nodes.pop();
        if (kind === 'duplicate') config.plan.nodes[1] = structuredClone(first);
        if (kind === 'foreign') first.nodeId = 'f'.repeat(24);
        if (kind === 'originals') delete config.acceptedOriginalsBase64[first.nodeId];
        if (kind === 'mixed-version') restore.version = 1;
        f.files.set(configPath, Buffer.from(JSON.stringify(config))); f.files.set(RESTORE, Buffer.from(JSON.stringify(restore)));
        assert.throws(() => p.read(fresh), undefined, `${fresh}:${kind}`);
    }
    const f = await prepare(meta), p = parser(f.files), inputs = p.read();
    f.files.set(INVENTORY, Buffer.from(JSON.stringify(meta.inventory) + '\n'));
    assert.throws(inputs.assertPins, /RETAINED/, 'accepted raw inventory drift during scope');
});

test('v2 missing singleton/counters/queue, retained locks/jobs, and enrollment drift preserve every owner', async () => {
    for (const kind of ['singleton', 'counter', 'queue-missing', 'queue-busy', 'lock', 'operation', 'retained', 'intent', 'link', 'enrollment', 'physical', 'generation']) {
        const f = await prepare(meta), owners = structuredClone(f.models.Owner.rows), beforeCas = f.events.length;
        const x = modeledScope(f);
        if (kind === 'singleton') f.models.Topology.rows = [];
        if (kind === 'counter') delete f.models.Topology.rows[0].remoteAdmissionCount;
        if (kind === 'queue-missing') f.models.Queue.rows = [];
        if (kind === 'queue-busy') f.models.Queue.rows[0].outstanding = 1;
        if (kind === 'lock') f.models.Lock.rows.push({ node: f.config.plan.nodes[0].nodeId, generation: randomUUID(), remoteUncertain: true, leaseUntil: new Date(0) });
        if (kind === 'operation') f.models.Operation.rows.push({ status: 'preparing', heldTopologyAdmission: false });
        if (kind === 'retained') f.models.Operation.rows.push({ status: 'succeeded', heldTopologyAdmission: true });
        if (kind === 'intent') f.models.Intent.rows.push({ status: 'pending' });
        if (kind === 'link') f.models.Link.rows.push({ active: true, status: 'pending' });
        if (kind === 'enrollment') f.models.Enrollment.rows = [];
        if (kind === 'physical') f.models.Enrollment.rows[0].bootId = randomUUID();
        if (kind === 'generation') f.config.plan.nodes[0].ownerGeneration = randomUUID();
        await assert.rejects(x.service().handback(f.config.plan), undefined, kind);
        assert.deepEqual(f.models.Owner.rows, owners, kind); assert.equal(f.events.length, beforeCas, kind);
        assert.deepEqual(x.events, []); assert.deepEqual(f.journal.events, []);
    }
});

test('v2 owner partial/unknown confirmation retains actual durable in-flight row without later CAS/terminal', async t => {
    const { HeldOwnerSettlementJournal } = require('../heldOwnerSettlementJournal');
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR, 'v2-partial-journal-'));
    const directory = path.join(root, 'journal'); fs.mkdirSync(directory, { mode: 0o700 });
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const f = await prepare(meta);
    f.journal = new HeldOwnerSettlementJournal({ directory, uid: process.getuid(), fixtureRoot: root });
    const x = modeledScope(f), original = f.models.Owner.findOne;
    f.models.Owner.findOne = function (filter) {
        const q = original.call(this, filter);
        if (filter.owner === 'classic') q.lean = async () => { throw new Error('MODELED postcommit majority read lost'); };
        return q;
    };
    await assert.rejects(x.service().handback(f.config.plan), /majority read lost/);
    assert.equal(f.events.filter(e => e === 'classic').length, 1); assert.deepEqual(x.events, []);
    const row = JSON.parse(fs.readFileSync(path.join(directory, 'owner-settlement.json')));
    assert.equal(row.inFlightNode, f.config.plan.nodes[0].nodeId); assert.equal(row.settled.length, 0);
    await assert.rejects(x.service().handback(f.config.plan)); assert.equal(f.events.filter(e => e === 'classic').length, 1);
});

test('legacy v1 parser/public settlement/real durable journal still complete exactly five owners', async t => {
    const { HeldOwnerSettlementJournal } = require('../heldOwnerSettlementJournal');
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR, 'v1-terminal-journal-'));
    const directory = path.join(root, 'journal'); fs.mkdirSync(directory, { mode: 0o700 });
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const f = await prepare(legacyMeta, 1), p = parser(f.files);
    assert.equal(p.read().pins.length, 5); assert.equal(p.read(true).pins.length, 5); assert.equal(p.read().inventory, undefined);
    assert.deepEqual(Object.keys(legacyMeta.restore.nodes).sort(), Object.keys(NODES).sort());
    f.journal = new HeldOwnerSettlementJournal({ directory, uid: process.getuid(), fixtureRoot: root });
    const x = modeledScope(f), result = await x.service().handback(f.config.plan);
    assert.equal(result.code, 'COMMITTED_BOUNDED_ACTIVATION_CONFIRMED'); assert.equal(result.ownerCount, 5);
    assert.deepEqual(x.events, ['commit', 'activate', 'complete']);
    const row = JSON.parse(fs.readFileSync(path.join(directory, 'owner-settlement.json')));
    assert.equal(row.phase, 'irreversibly-committed'); assert.equal(row.settled.length, 5);
});

test('plans cannot select two-node membership without root accepted inventory', async () => {
    const f = await prepare(meta), owners = structuredClone(f.models.Owner.rows); let called = false;
    const service = new HeldTestOwnerSettlement({ models: f.models, journal: f.journal,
        withRestorationScope: async () => { called = true; } });
    await assert.rejects(service.handback(f.config.plan)); assert.equal(called, false); assert.deepEqual(f.models.Owner.rows, owners);
    assert.throws(() => new HeldTestOwnerSettlement({ models: f.models, journal: f.journal,
        withRestorationScope: async () => {}, inventory: meta.inventory, inventorySha256: 'f'.repeat(64) }));
});

test('v2 public settlement with the real durable journal commits exactly the two saved-plan owners', async t => {
    const { HeldOwnerSettlementJournal } = require('../heldOwnerSettlementJournal');
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR, 'v2-terminal-journal-'));
    const directory = path.join(root, 'journal'); fs.mkdirSync(directory, { mode: 0o700 });
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const f = await prepare(meta);
    f.journal = new HeldOwnerSettlementJournal({ directory, uid: process.getuid(), fixtureRoot: root });
    const x = modeledScope(f), enrollments = structuredClone(f.models.Enrollment.rows);
    // Genuine public initializeClassic/adopt/handback and real journal/fs IO;
    // persistence and the terminal physical authority remain explicitly modeled.
    const result = await x.service().handback(f.config.plan);
    assert.equal(result.code, 'COMMITTED_BOUNDED_ACTIVATION_CONFIRMED'); assert.equal(result.ownerCount, 2);
    const row = JSON.parse(fs.readFileSync(path.join(directory, 'owner-settlement.json')));
    assert.equal(row.phase, 'irreversibly-committed'); assert.equal(row.inFlightNode, null);
    assert.deepEqual(row.plan, f.config.plan); assert.equal(row.settled.length, 2);
    assert.deepEqual(row.settled, f.config.plan.nodes.map(n => {
        const owner = f.models.Owner.rows.find(o => o.node === n.nodeId);
        assert.equal(owner.owner, 'classic'); assert.equal(owner.handbackReceipt.fromGeneration, n.ownerGeneration);
        return { nodeId: n.nodeId, generation: owner.generation };
    }));
    assert.equal(row.commitSha256, result.commitSha256);
    assert.deepEqual(x.events, ['commit', 'activate', 'complete']); assert.equal(f.events.filter(e => e === 'classic').length, 2);
    assert.deepEqual(f.models.Enrollment.rows, enrollments);
    const bytes = fs.readFileSync(path.join(directory, 'owner-settlement.json'));
    await assert.rejects(x.service().handback(f.config.plan));
    assert.deepEqual(x.events, ['commit', 'activate', 'complete']); assert.equal(f.events.filter(e => e === 'classic').length, 2);
    assert.deepEqual(fs.readFileSync(path.join(directory, 'owner-settlement.json')), bytes);
});

test('v2 terminal unknown results retain real durable journal and owner history; fresh invocation cannot reopen', async t => {
    const { HeldOwnerSettlementJournal } = require('../heldOwnerSettlementJournal');
    for (const fault of ['commit', 'activate', 'complete', 'fresh']) {
        const root = fs.mkdtempSync(path.join(process.env.TMPDIR, 'v2-unknown-journal-'));
        const directory = path.join(root, 'journal'); fs.mkdirSync(directory, { mode: 0o700 });
        t.after(() => fs.rmSync(root, { recursive: true, force: true }));
        const f = await prepare(meta);
        f.journal = new HeldOwnerSettlementJournal({ directory, uid: process.getuid(), fixtureRoot: root });
        const x = modeledScope(f, { terminalFault: fault }), service = x.service();
        const enrollments = structuredClone(f.models.Enrollment.rows);
        const method = fault === 'fresh' ? 'freshHandback' : 'handback';
        await assert.rejects(service[method](f.config.plan), { code: fault === 'commit' ? 'COMMIT_UNKNOWN_NO_ACTIVATION' : 'COMMITTED_ACTIVATION_UNKNOWN' });
        assert.equal(f.events.filter(e => e === 'classic').length, 2);
        assert.deepEqual(f.models.Enrollment.rows, enrollments);
        const file = path.join(directory, 'owner-settlement.json'), bytes = fs.readFileSync(file), row = JSON.parse(bytes);
        assert.equal(row.phase, ['commit', 'fresh'].includes(fault) ? 'settled-held' : 'irreversibly-committed');
        assert.equal(row.inFlightNode, null); assert.equal(row.settled.length, 2);
        const events = [...x.events];
        await assert.rejects(service[method](f.config.plan));
        await assert.rejects(x.service()[method](f.config.plan));
        assert.deepEqual(x.events, events); assert.deepEqual(fs.readFileSync(file), bytes);
    }
});
