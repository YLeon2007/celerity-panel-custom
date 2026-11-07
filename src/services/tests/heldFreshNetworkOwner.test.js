'use strict';
// Source-only consumer evidence. Real JS private parser, public transfer CAS and
// journal, plus actual parent/child stdio and natural exit. Persistence/root IO
// and the transport PRODUCER are modeled; no Python ordinary owner is exercised.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const { spawn } = require('node:child_process');
const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const { HeldTestOwnerSettlement } = require('../heldTestOwnerSettlement');
const { HeldOwnerSettlementJournal } = require('../heldOwnerSettlementJournal');
const { TopologyConfigTransfer } = require('../topologyConfigTransfer');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../../modules/relay-l2tp/domain/topologyExecutionContext');
const sha = raw => createHash('sha256').update(raw).digest('hex');
const canonical = value => JSON.stringify(value, (_k, v) => v && typeof v === 'object' && !Array.isArray(v)
    ? Object.fromEntries(Object.keys(v).sort().map(k => [k, v[k]])) : v);
const FIXED = {
    config: '/etc/celerity/topology-test-fresh-owner-settlement.json',
    legacy: '/etc/celerity/topology-test-owner-settlement.json',
    restore: '/etc/c3-test-coordinated-restore.json', inventory: '/etc/celerity/topology-test-inventory.json',
    network: '/etc/c3-test-fresh-network.json', shared: '/etc/c3-test-node-isolation.json', policy: '/etc/c3-test-fresh-classic.json',
    bridge: '/usr/local/libexec/c3-test-owner-restoration-channel.py', freshBridge: '/usr/local/libexec/c3-test-fresh-owner-restoration-channel.py',
    coordinator: '/usr/local/libexec/c3-test-coordinated-restore.py', sharedSource: '/usr/local/libexec/c3-test-shared-host.py',
    isolation: '/usr/local/libexec/c3-test-node-isolation', freezer: '/usr/local/libexec/c3-panel-host-freezer.py',
    fresh: '/usr/local/libexec/c3-test-fresh-classic.py',
};
const encode = value => Buffer.from(JSON.stringify(value));
function parser(files) {
    // Model ONLY independent root/private filesystem authority. No operational
    // path/reader override is exported by product code.
    const file = path.resolve(__dirname, '../heldRestorationChannel.js');
    const m = new Module(file, module); m.filename = file; m.paths = module.paths;
    m.fixtureRead = name => { assert.ok(files.has(name), name); return files.get(name); };
    m._compile('const __fixtureRead = module.fixtureRead;\n' + fs.readFileSync(file, 'utf8').replace('function trustedRead(file) {',
        'function trustedRead(file) { return __fixtureRead(file);'), file);
    return { api: m.exports, read(fresh = true) {
        const uid = process.getuid; process.getuid = () => 0;
        try { return fresh ? m.exports.freshOperationalInputs() : m.exports.operationalInputs(); }
        finally { process.getuid = uid; }
    } };
}
function modelFixture() {
    // Same modeled per-node transaction/query seam as heldTestOwnerSettlementV2.
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
async function fixture(t, { network = true } = {}) {
    const f = modelFixture(), files = new Map();
    for (const name of ['bridge', 'freshBridge', 'coordinator', 'sharedSource', 'isolation', 'freezer', 'fresh'])
        files.set(FIXED[name], Buffer.from('MODELED installed source: ' + name));
    const nodes = ['1'.repeat(24), '2'.repeat(24)].map((nodeId, i) => ({ nodeId, targetProfile: i ? 'xray-bridge' : 'xray-main',
        endpoint: { ip: '10.203.61.' + (i + 1), port: 2222, username: 'c3-test-runner' },
        physical: { machineId: String(i + 1).repeat(32), bootId: randomUUID(), sshHostKeySha256: String(i + 1).repeat(64) },
        profiles: i ? ['xray-main', 'xray-bridge'] : ['xray-main'] }));
    const inventory = { version: 1, profile: 'accepted-test-v1', executionContext: TEST, nodes, sharedNodeId: nodes[1].nodeId };
    const inventorySha256 = sha(canonical(inventory)), sharedNode = nodes[1];
    const networkPlan = { version: 1, context: TEST.hostIdentity, machine: sharedNode.physical.machineId, boot: sharedNode.physical.bootId,
        ordinaryOwner: { version: 1, stopConfigSha256: 'b'.repeat(64) } };
    files.set(FIXED.network, encode(networkPlan));
    const networkPlanSha256 = sha(files.get(FIXED.network));
    const shared = { version: 2, mode: 'shared-test', inventorySha256, nodeId: sharedNode.nodeId, targetProfile: sharedNode.targetProfile,
        endpointIp: sharedNode.endpoint.ip, ...sharedNode.physical,
        hostHold: { owner: randomUUID(), freezerSha256: sha(files.get(FIXED.freezer)),
            expected: { host: { machineId: networkPlan.machine, bootId: networkPlan.boot } }, networkPlanSha256 } };
    files.set(FIXED.shared, encode(shared));
    const config = { version: 2, mongoUri: 'mongodb://MODELED/never-connected', bridgeSha256: sha(files.get(FIXED.bridge)),
        freshBridgeSha256: sha(files.get(FIXED.freshBridge)), coordinatorSha256: sha(files.get(FIXED.coordinator)), inventorySha256,
        plan: { revision: 7, deployedRevision: 6, nodes: [] }, acceptedOriginalsBase64: {},
        oldBackend: { instanceId: 'MODELED-original', pid: 42, processStartTime: '123' }, ...(network ? { networkPlanSha256 } : {}) };
    const restore = { version: 2, context: TEST.hostIdentity, inventorySha256,
        origin: { machineId: networkPlan.machine, bootId: networkPlan.boot }, nodes: {} };
    for (const n of nodes) {
        const identity = { context: TEST.hostIdentity, nodeId: n.nodeId, endpointIp: n.endpoint.ip, targetProfile: n.targetProfile,
            ...n.physical, inventorySha256, maintenanceId: randomUUID(), planHash: n === sharedNode ? sha(canonical(shared)) : 'c'.repeat(64) };
        const pin = restore.nodes[n.nodeId] = { identity, profiles: n.profiles, files: { self: config.coordinatorSha256,
            ...(n === sharedNode ? { shared: sha(files.get(FIXED.sharedSource)), isolation: sha(files.get(FIXED.isolation)), freezer: sha(files.get(FIXED.freezer)) } : {}) } };
        const profile = { files: { config: { sha256: 'a'.repeat(64) }, unit: { sha256: 'b'.repeat(64) } }, service: { ActiveState: 'active', UnitFileState: 'enabled' } };
        const acceptedRaw = encode({ ...identity, profiles: Object.fromEntries(n.profiles.map(p => [p, profile])) });
        config.acceptedOriginalsBase64[n.nodeId] = acceptedRaw.toString('base64'); pin.files.accepted = sha(acceptedRaw);
    }
    const maintenance = async ({ binding }, work) => work({ status: 'verified', authority: 'external-maintenance-v1', binding,
        proofId: randomUUID(), maintenanceId: restore.nodes[binding.node].identity.maintenanceId, maintenance: 'held', allWriters: 'drained',
        oldBackend: { ...config.oldBackend, processTree: 'stopped', dispatch: 'disabled' },
        readback: { source: 'node-readback', configSha256: 'a'.repeat(64), unitSha256: 'b'.repeat(64), serviceActive: 'active', serviceEnabled: 'enabled' } });
    const transfer = new TopologyConfigTransfer({ executionContext: TEST, TopologyConfigOwner: f.models.Owner, withVerifiedMaintenance: maintenance });
    for (const n of nodes) {
        const nodeIdentity = { machineId: n.physical.machineId, sshHostKeySha256: n.physical.sshHostKeySha256 };
        const classic = await transfer.initializeClassic({ node: n.nodeId, profile: n.targetProfile, nodeIdentity });
        const adopted = await transfer.adopt({ node: n.nodeId, profile: n.targetProfile, generation: classic.generation, proofRef: 'MODELED-originals' });
        const enrollmentId = randomUUID();
        config.plan.nodes.push({ nodeId: n.nodeId, targetProfile: n.targetProfile, enrollmentId, ownerGeneration: adopted.generation });
        f.models.Enrollment.rows.push({ _id: enrollmentId, executionContext: TEST.hostIdentity, nodeId: n.nodeId, targetProfile: n.targetProfile,
            ownerGeneration: adopted.generation, nodeIdentity, endpoint: n.endpoint, bootId: n.physical.bootId,
            maintenanceId: restore.nodes[n.nodeId].identity.maintenanceId });
    }
    f.models.Topology.rows.push({ _id: 'singleton', revision: 7, deployedRevision: 6, topologyAdmissionCount: 0, remoteAdmissionCount: 0 });
    f.models.Queue.rows.push({ _id: 'create-v1', outstanding: 0 });
    // Existing fresh_classic_launch semantics: coordinatorSha256 is the
    // canonical RESTORE CONFIG, sourceSha256 is the coordinator SOURCE, while
    // files[FRESH] independently pins the fresh implementation (not an alias).
    files.set(FIXED.policy, encode({ version: 1, context: TEST.hostIdentity,
        files: { [FIXED.fresh]: sha(files.get(FIXED.fresh)), [FIXED.coordinator]: config.coordinatorSha256 },
        inventory: { networkPlanSha256, coordinatorSha256: sha(canonical(restore)), sourceSha256: config.coordinatorSha256 } }));
    for (const [file, value] of [[FIXED.inventory, inventory], [FIXED.restore, restore], [FIXED.config, config]]) files.set(file, encode(value));
    const { freshBridgeSha256, networkPlanSha256: _network, ...legacy } = config;
    files.set(FIXED.legacy, encode(legacy));
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR, 'js-network-owner-')), directory = path.join(root, 'journal');
    fs.mkdirSync(directory, { mode: 0o700 }); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const journal = new HeldOwnerSettlementJournal({ directory, uid: process.getuid(), fixtureRoot: root });
    return { ...f, files, config, parser: parser(files), journal, journalFile: path.join(directory, 'owner-settlement.json') };
}

test('new receipt grammar is selected only by pinned v2 fresh root inputs', async t => {
    const f = await fixture(t), inputs = f.parser.read();
    assert.equal(inputs.config.networkPlanSha256, sha(f.files.get(FIXED.network)));
    assert.doesNotThrow(inputs.assertPins);
    f.files.set(FIXED.network, Buffer.concat([f.files.get(FIXED.network), Buffer.from('\n')]));
    assert.throws(inputs.assertPins, /RETAINED/);
});

// Explicit modeled TRANSPORT PRODUCER, not the pending Python ordinary owner.
// Receipt bytes are produced only after reading the actual public proof on stdio.
const PRODUCER = String.raw`
const readline = require('node:readline'), {createHash} = require('node:crypto');
const [mode, fault] = process.argv.slice(1), rl = readline.createInterface({input:process.stdin});
if (['late-data','late-stderr'].includes(fault)) process.on('SIGTERM',()=>{});
const sha = x => createHash('sha256').update(JSON.stringify(x)).digest('hex');
let terminal = false;
rl.on('line', line => {
 const r = JSON.parse(line);
 if (terminal || r.version !== 1 || !/^[a-f0-9]{64}$/.test(r.nonce)) throw Error('bad request');
 if (r.op === 'check') {
  if (Object.keys(r).sort().join() !== 'nonce,op,version') throw Error('check grammar changed');
  process.stdout.write(JSON.stringify({version:1,op:'checked',nonce:r.nonce,
   ...(fault === 'check-extra' ? {networkOwnershipSha256:'a'.repeat(64)}:{})})+'\n'); return;
 }
 if (r.op !== 'fresh-handback' || Object.keys(r).sort().join() !== 'nonce,op,proof,version' ||
     Object.keys(r.proof).sort().join() !== 'context,deployedRevision,nodes,quietSha256,revision') throw Error('public proof widened');
 terminal = true;
 const commitSha256 = sha(r.proof);
 const reply = {version:1,op:'fresh-handback-ack',nonce:r.nonce,commitSha256,
  ...(mode === 'new' ? {networkOwnershipSha256:sha({phase:'ordinary-owned',commitSha256})}: {})};
 if (fault === 'missing') delete reply.networkOwnershipSha256;
 if (fault === 'extra-network') reply.networkOwnershipSha256 = 'a'.repeat(64);
 if (fault === 'network-malformed') reply.networkOwnershipSha256 = 'A'.repeat(64);
 if (fault === 'network-type') reply.networkOwnershipSha256 = [reply.networkOwnershipSha256];
 if (fault === 'commit-type') reply.commitSha256 = [commitSha256];
 if (fault === 'commit-malformed') reply.commitSha256 = 'f'.repeat(63);
 if (fault === 'nonce') reply.nonce = '0'.repeat(64);
 if (fault === 'nonce-type') reply.nonce = [reply.nonce];
 if (fault === 'version-type') reply.version = true;
 if (fault === 'op') reply.op = 'complete-handoff-ack';
 if (fault === 'extra') reply.unknown = true;
 if (fault === 'eof') { rl.close(); process.stdin.destroy(); return; }
 let raw = JSON.stringify(reply);
 if (fault === 'duplicate') raw = raw.replace('{','{"networkOwnershipSha256":"'+'0'.repeat(64)+'",');
 process.stdout.write((fault === 'parse' ? '{' : raw)+'\n');
 if (fault === 'late-data') setTimeout(()=>process.stdout.write('{}\n'),5);
 if (fault === 'late-partial') setTimeout(()=>process.stdout.write('{'),5);
 if (fault === 'late-stderr') setTimeout(()=>process.stderr.write('modeled cleanup fault'),5);
 rl.close(); process.stdin.destroy();
 setTimeout(()=>{process.exitCode = fault === 'exit' ? 9 : 0;},fault === 'late-exit' ? 5100 : 30);
});
`;
function bridge(t, mode, fault = '') {
    const child = spawn(process.execPath, ['-e', PRODUCER, mode, fault], { stdio: ['pipe', 'pipe', 'pipe'] });
    const requests = [], signals = []; let stderr = '';
    const write = child.stdin.write.bind(child.stdin), kill = child.kill.bind(child);
    child.stdin.write = (...args) => { requests.push(JSON.parse(args[0])); return write(...args); };
    child.kill = signal => { if (child.exitCode === null && child.signalCode === null) signals.push(signal); return kill(signal); };
    child.stderr.on('data', raw => { stderr += raw; });
    const exit = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
    t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await exit; });
    return { child, requests, signals, exit, stderr: () => stderr };
}
function service(f, inputs, b) {
    return new HeldTestOwnerSettlement({ models: f.models, journal: f.journal, inventory: inputs.inventory,
        inventorySha256: inputs.config.inventorySha256,
        withRestorationScope: work => f.parser.api.withFreshOperationalRestoration(inputs, work, { openBridge: () => b.child }) });
}
for (const mode of ['legacy', 'new']) test(mode + ' public fresh handback consumes real wire reply after genuine per-node CAS and natural exit', async t => {
    const f = await fixture(t, { network: mode === 'new' }), inputs = f.parser.read(), b = bridge(t, mode);
    const enrollment = structuredClone(f.models.Enrollment.rows), svc = service(f, inputs, b);
    const result = await svc.freshHandback(inputs.config.plan);
    assert.equal(result.code, mode === 'new' ? 'COMMITTED_FRESH_NETWORK_OWNED' : 'COMMITTED_FRESH_ACTIVATION_CONFIRMED');
    assert.deepEqual(await b.exit, { code: 0, signal: null }, b.stderr()); assert.deepEqual(b.signals, []);
    assert.equal(f.events.filter(e => e === 'classic').length, 2);
    assert.deepEqual(f.models.Enrollment.rows, enrollment); assert.deepEqual(f.models.Binding.rows, []);
    const terminal = b.requests.filter(r => r.op === 'fresh-handback'); assert.equal(terminal.length, 1);
    const proof = terminal[0].proof;
    assert.deepEqual(Object.keys(proof).sort(), ['context', 'deployedRevision', 'nodes', 'quietSha256', 'revision']);
    assert.deepEqual(proof.nodes.map(n => n.owner), JSON.parse(JSON.stringify(f.models.Owner.rows)));
    assert.equal(result.commitSha256, sha(JSON.stringify(proof)));
    if (mode === 'new') assert.equal(result.networkOwnershipSha256, sha(JSON.stringify({ phase: 'ordinary-owned', commitSha256: result.commitSha256 })));
    else assert.equal(Object.hasOwn(result, 'networkOwnershipSha256'), false);
    const row = JSON.parse(fs.readFileSync(f.journalFile));
    assert.equal(row.phase, 'irreversibly-committed'); assert.equal(row.commitSha256, result.commitSha256); assert.equal(row.settled.length, 2);
    await assert.rejects(svc.freshHandback(inputs.config.plan), { code: 'FRESH_REPLAY_FORBIDDEN' });
    assert.equal(b.requests.filter(r => r.op === 'fresh-handback').length, 1);
});

for (const fault of ['late-data', 'late-partial', 'late-stderr']) test('valid ACK followed by ' + fault + ' cannot become success on exit zero', async t => {
    const f = await fixture(t), inputs = f.parser.read(), b = bridge(t, 'new', fault), svc = service(f, inputs, b);
    await assert.rejects(svc.freshHandback(inputs.config.plan), { code: 'COMMITTED_ACTIVATION_UNKNOWN' });
    assert.deepEqual(await b.exit, { code: 0, signal: null });
    assert.equal(f.events.filter(e => e === 'classic').length, 2);
    const row = JSON.parse(fs.readFileSync(f.journalFile)); assert.equal(row.phase, 'settled-held');
    await assert.rejects(svc.freshHandback(inputs.config.plan), { code: 'FRESH_REPLAY_FORBIDDEN' });
});

for (const fault of ['missing', 'network-malformed', 'network-type', 'commit-malformed', 'commit-type', 'nonce', 'nonce-type',
    'version-type', 'op', 'extra', 'duplicate', 'parse', 'eof', 'exit']) test('new public receipt refuses ' + fault + ' with committed uncertainty and no rollback/replay', async t => {
    const f = await fixture(t), inputs = f.parser.read(), b = bridge(t, 'new', fault), svc = service(f, inputs, b);
    const enrollment = structuredClone(f.models.Enrollment.rows);
    await assert.rejects(svc.freshHandback(inputs.config.plan), { code: 'COMMITTED_ACTIVATION_UNKNOWN' });
    await b.exit;
    assert.equal(f.events.filter(e => e === 'classic').length, 2);
    assert.ok(f.models.Owner.rows.every(o => o.owner === 'classic' && o.handbackReceipt));
    assert.deepEqual(f.models.Enrollment.rows, enrollment);
    assert.equal(JSON.parse(fs.readFileSync(f.journalFile)).phase, 'settled-held');
    await assert.rejects(svc.freshHandback(inputs.config.plan), { code: 'FRESH_REPLAY_FORBIDDEN' });
    assert.equal(b.requests.filter(r => r.op === 'fresh-handback').length, 1);
});

test('legacy reply grammar is not widened to accept a network receipt', async t => {
    const f = await fixture(t, { network: false }), inputs = f.parser.read(), b = bridge(t, 'legacy', 'extra-network');
    await assert.rejects(service(f, inputs, b).freshHandback(inputs.config.plan), { code: 'COMMITTED_ACTIVATION_UNKNOWN' });
    assert.equal(f.events.filter(e => e === 'classic').length, 2);
});

for (const bad of [null, true, ['a'.repeat(64)], 'A'.repeat(64), 'a'.repeat(63), 1]) test('private network selector refuses type/value ' + JSON.stringify(bad), async t => {
    const f = await fixture(t); f.config.networkPlanSha256 = bad; f.files.set(FIXED.config, encode(f.config));
    assert.throws(() => f.parser.read(), /RETAINED/);
});
for (const kind of ['v1-fresh', 'v2-nonfresh', 'v1-nonfresh']) test(kind + ' forbids the new private selector', async t => {
    const f = await fixture(t), fresh = kind === 'v1-fresh', file = fresh ? FIXED.config : FIXED.legacy;
    const config = JSON.parse(f.files.get(file)); config.networkPlanSha256 = f.config.networkPlanSha256;
    if (kind.startsWith('v1')) config.version = 1;
    f.files.set(file, encode(config)); assert.throws(() => f.parser.read(fresh), /RETAINED/);
});
for (const [name, file, mutate] of [
    ['missing ordinaryOwner', FIXED.network, x => { delete x.ordinaryOwner; }],
    ['ordinaryOwner extra key', FIXED.network, x => { x.ordinaryOwner.flag = true; }],
    ['ordinaryOwner bool version', FIXED.network, x => { x.ordinaryOwner.version = true; }],
    ['stop hash type', FIXED.network, x => { x.ordinaryOwner.stopConfigSha256 = ['b'.repeat(64)]; }],
    ['network context', FIXED.network, x => { x.context = 'foreign'; }],
    ['network machine', FIXED.network, x => { x.machine = 'f'.repeat(32); }],
    ['network boot', FIXED.network, x => { x.boot = randomUUID(); }],
    ['shared digest', FIXED.shared, x => { x.hostHold.networkPlanSha256 = 'f'.repeat(64); }],
    ['shared inventory', FIXED.shared, x => { x.inventorySha256 = 'f'.repeat(64); }],
    ['shared node', FIXED.shared, x => { x.nodeId = 'f'.repeat(24); }],
    ['shared host identity', FIXED.shared, x => { x.hostHold.expected.host.machineId = 'f'.repeat(32); }],
    ['policy digest', FIXED.policy, x => { x.inventory.networkPlanSha256 = 'f'.repeat(64); }],
    ['policy coordinator', FIXED.policy, x => { x.inventory.coordinatorSha256 = 'f'.repeat(64); }],
    ['policy source', FIXED.policy, x => { x.inventory.sourceSha256 = 'f'.repeat(64); }],
]) test('new root crossbinding refuses ' + name, async t => {
    const f = await fixture(t), value = JSON.parse(f.files.get(file)); mutate(value); f.files.set(file, encode(value));
    if (file === FIXED.network) { f.config.networkPlanSha256 = sha(f.files.get(file)); f.files.set(FIXED.config, encode(f.config)); }
    assert.throws(() => f.parser.read(), /RETAINED/);
});
for (const file of [FIXED.network, FIXED.shared, FIXED.policy, FIXED.sharedSource, FIXED.isolation, FIXED.freezer, FIXED.fresh])
    test('assertPins retains raw bound input/source ' + file, async t => {
        const f = await fixture(t), inputs = f.parser.read();
        f.files.set(file, Buffer.concat([f.files.get(file), Buffer.from('\n')])); assert.throws(inputs.assertPins, /RETAINED/);
        // A fresh trusted load may accept equivalent shared/policy JSON; only
        // the current scope is bound to their exact opening raw bytes.
        if (![FIXED.shared, FIXED.policy].includes(file)) assert.throws(() => f.parser.read(), /RETAINED/);
    });
test('duplicate and escaped duplicate root selectors refuse before selection', async t => {
    const f = await fixture(t);
    for (const key of ['networkPlanSha256', 'networkPlanSha\\u003256']) {
        f.files.set(FIXED.config, Buffer.from(JSON.stringify(f.config).replace('{', '{"' + key + '":"' + 'f'.repeat(64) + '",')));
        assert.throws(() => f.parser.read(), /RETAINED/);
    }
});
test('absent selector remains legacy even if other fixed files or environment suggest new mode', async t => {
    const f = await fixture(t, { network: false });
    // No read of optional network/policy/shared files is permitted on legacy.
    for (const file of [FIXED.network, FIXED.shared, FIXED.policy]) f.files.delete(file);
    const prior = process.env.C3_FRESH_NETWORK_OWNED; process.env.C3_FRESH_NETWORK_OWNED = 'true';
    try { const inputs = f.parser.read(); assert.equal(Object.hasOwn(inputs.config, 'networkPlanSha256'), false); inputs.assertPins(); }
    finally { if (prior === undefined) delete process.env.C3_FRESH_NETWORK_OWNED; else process.env.C3_FRESH_NETWORK_OWNED = prior; }
});
test('public plan cannot choose network mode or extend the five-field proof', async t => {
    const f = await fixture(t), inputs = f.parser.read(); let opened = false;
    const svc = new HeldTestOwnerSettlement({ models: f.models, journal: f.journal, inventory: inputs.inventory,
        inventorySha256: inputs.config.inventorySha256, withRestorationScope: () => { opened = true; } });
    const owners = structuredClone(f.models.Owner.rows);
    await assert.rejects(svc.freshHandback({ ...inputs.config.plan, networkPlanSha256: f.config.networkPlanSha256 }));
    assert.equal(opened, false); assert.deepEqual(f.models.Owner.rows, owners);
});
test('checked pipe disposal failure after accepted new receipt stays committed-unknown', async t => {
    const f = await fixture(t), inputs = f.parser.read(), b = bridge(t, 'new'), svc = service(f, inputs, b);
    const proto = f.parser.api.RestorationPipe.prototype, dispose = proto.dispose, fault = new Error('MODELED disposal ACK lost after actual cleanup');
    proto.dispose = async function () { await dispose.call(this); throw fault; };
    try { await assert.rejects(svc.freshHandback(inputs.config.plan), error => error === fault && error.code === 'COMMITTED_ACTIVATION_UNKNOWN'); }
    finally { proto.dispose = dispose; }
    assert.deepEqual(await b.exit, { code: 0, signal: null });
    assert.equal(JSON.parse(fs.readFileSync(f.journalFile)).phase, 'irreversibly-committed');
    assert.equal(f.events.filter(e => e === 'classic').length, 2);
    await assert.rejects(svc.freshHandback(inputs.config.plan), { code: 'FRESH_REPLAY_FORBIDDEN' });
});

async function runEntry(f, inputs, b, closeFailure = false) {
    const entry = path.resolve(__dirname, '../../../scripts/test-node-isolation/settle-fresh-held-owner.js');
    const mod = new Module(entry, module); mod.filename = entry; mod.paths = module.paths;
    const names = { TopologyConfigOwner: 'Owner', TopologyExecutionEnrollment: 'Enrollment', TopologyExecutionBinding: 'Binding',
        TopologyOperation: 'Operation', NodeOperationLock: 'Lock', CascadeTopologyState: 'Topology', TopologyCreateIntent: 'Intent',
        TopologyIntentQueueState: 'Queue', CascadeLink: 'Link', L2tpOperation: 'L2tpOperation' };
    const connection = { model: name => f.models[names[name]], async close() { if (closeFailure) throw new Error('MODELED DB disposal fault'); } };
    mod.require = request => request === 'mongoose' ? { createConnection(uri, options) {
        assert.equal(uri, inputs.config.mongoUri); assert.equal(options.autoIndex, false); assert.equal(options.retryWrites, false);
        return { asPromise: async () => connection };
    } } : request.endsWith('/heldRestorationChannel') ? { ...f.parser.api, freshOperationalInputs: () => inputs,
        withFreshOperationalRestoration: (i, work) => f.parser.api.withFreshOperationalRestoration(i, work, { openBridge: () => b.child }) }
        : request.endsWith('/heldOwnerSettlementJournal') ? { HeldOwnerSettlementJournal: function () { return f.journal; } }
        : Module.prototype.require.call(mod, request);
    let output = '', failure;
    mod.fixtureWrite = raw => { output += raw; };
    // Redirect only this entry's final report, never process.stdout: node:test
    // uses that stream for its binary child protocol while the async entry runs.
    mod._compile(fs.readFileSync(entry, 'utf8').replace("process.stdout.write(JSON.stringify(result) + '\\n');",
        "module.fixtureWrite(JSON.stringify(result) + '\\n');"), entry);
    const uid = process.getuid, argv = process.argv;
    try {
        process.getuid = () => 0; process.argv = [process.execPath, entry];
        try { await mod.exports.main(); } catch (error) { failure = error; }
    } finally { process.getuid = uid; process.argv = argv; }
    return { output, failure };
}
for (const mode of ['legacy', 'new']) for (const closeFailure of [false, true])
    test('fixed fresh CLI actual public service and wire: ' + mode + (closeFailure ? ' DB disposal unknown' : ' natural success'), async t => {
        const f = await fixture(t, { network: mode === 'new' }), inputs = f.parser.read(), b = bridge(t, mode);
        const { output, failure } = await runEntry(f, inputs, b, closeFailure);
        if (closeFailure) { assert.equal(output, ''); assert.equal(failure?.code, 'COMMITTED_ACTIVATION_UNKNOWN'); }
        else { assert.ifError(failure); assert.equal(JSON.parse(output).code, mode === 'new' ? 'COMMITTED_FRESH_NETWORK_OWNED' : 'COMMITTED_FRESH_ACTIVATION_CONFIRMED'); }
        assert.deepEqual(await b.exit, { code: 0, signal: null });
        assert.equal(f.events.filter(e => e === 'classic').length, 2);
    });

test('new selection does not widen the exact check-reply grammar', async t => {
    const f = await fixture(t), inputs = f.parser.read(), b = bridge(t, 'new', 'check-extra');
    const owners = structuredClone(f.models.Owner.rows);
    await assert.rejects(service(f, inputs, b).freshHandback(inputs.config.plan), error => error.code !== 'COMMITTED_ACTIVATION_UNKNOWN');
    assert.deepEqual(f.models.Owner.rows, owners); assert.equal(fs.existsSync(f.journalFile), false);
    assert.equal(b.requests.some(r => r.op === 'fresh-handback'), false);
});
test('arbitrary class constructor keys cannot select ordinary network grammar', async t => {
    const f = await fixture(t, { network: false }), inputs = f.parser.read(), b = bridge(t, 'new');
    const svc = new HeldTestOwnerSettlement({ models: f.models, journal: f.journal, inventory: inputs.inventory,
        inventorySha256: inputs.config.inventorySha256, networkPlanSha256: 'a'.repeat(64), freshNetworkOwnershipRequired: true,
        withRestorationScope: work => f.parser.api.withFreshOperationalRestoration(inputs, work, { openBridge: () => b.child }) });
    await assert.rejects(svc.freshHandback(inputs.config.plan), { code: 'COMMITTED_ACTIVATION_UNKNOWN' });
    assert.equal(f.events.filter(e => e === 'classic').length, 2);
});
test('late natural bridge exit is unknown within the unchanged five-second cleanup ceiling', { timeout: 15000 }, async t => {
    const f = await fixture(t), inputs = f.parser.read(), b = bridge(t, 'new', 'late-exit');
    await assert.rejects(service(f, inputs, b).freshHandback(inputs.config.plan), { code: 'COMMITTED_ACTIVATION_UNKNOWN' });
    assert.ok((await b.exit).signal); assert.ok(b.signals.includes('SIGTERM'));
    assert.equal(JSON.parse(fs.readFileSync(f.journalFile)).phase, 'settled-held');
});
test('terminal parse error is primary when required disposal also fails', async t => {
    const f = await fixture(t), inputs = f.parser.read(), b = bridge(t, 'new', 'missing');
    const proto = f.parser.api.RestorationPipe.prototype, dispose = proto.dispose, secondary = new Error('MODELED secondary disposal fault');
    proto.dispose = async function () { await dispose.call(this); throw secondary; };
    try { await assert.rejects(service(f, inputs, b).freshHandback(inputs.config.plan), error =>
        error.message === 'RESTORATION_PIPE_REVOKED' && error.code === 'COMMITTED_ACTIVATION_UNKNOWN' && error.cleanupErrors?.[0] === secondary); }
    finally { proto.dispose = dispose; }
    assert.equal(f.events.filter(e => e === 'classic').length, 2);
});
