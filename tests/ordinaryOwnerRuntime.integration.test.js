'use strict';
// Invoked by the genuine Python integration fixture, not a transport producer.
// Root acceptance/replica-set persistence/physical maintenance are modeled. The
// public initialize/adopt/handback, journal, bridge pipe, COMMIT and exits are real.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const { HeldTestOwnerSettlement } = require('../src/services/heldTestOwnerSettlement');
const { HeldOwnerSettlementJournal } = require('../src/services/heldOwnerSettlementJournal');
const { TopologyConfigTransfer } = require('../src/services/topologyConfigTransfer');
const { withFreshOperationalRestoration } = require('../src/services/heldRestorationChannel');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../src/modules/relay-l2tp/domain/topologyExecutionContext');
const sha = raw => createHash('sha256').update(raw).digest('hex');
function noatime(file) {
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NOATIME);
    try { return fs.readFileSync(fd); } finally { fs.closeSync(fd); }
}
function persistence() {
    const models = {}, events = [];
    const db = { getClient: () => ({ options: {}, topology: { description: { type: 'ReplicaSetWithPrimary' } } }),
        async transaction(work) {
            const before = Object.fromEntries(Object.entries(models).map(([k, m]) => [k, structuredClone(m.rows)]));
            try { return await work({ modeledSession: true }); }
            catch (error) { for (const [k, rows] of Object.entries(before)) models[k].rows = rows; throw error; }
        } };
    function query(read) {
        const q = { read(v) { assert.equal(v, 'primary'); return q; }, readConcern(v) { assert.equal(v, 'majority'); return q; },
            setOptions(v) { assert.ok(v.maxTimeMS > 0 && v.timeoutMS > 0); return q; },
            limit(v) { assert.equal(v, 1001); return q; }, maxTimeMS(v) { assert.equal(v, 5000); return q; },
            lean: async () => structuredClone(read()) };
        return q;
    }
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
                for (const key of Object.keys(update.$unset || {})) delete row[key];
                events.push(update.$set.owner); return structuredClone(row);
            } };
    }
    return { models, events };
}
async function main(file) {
    const description = JSON.parse(noatime(file)), f = persistence();
    const config = { version: 2, inventorySha256: description.inventorySha256,
        oldBackend: { instanceId: 'MODELED-original', pid: 42, processStartTime: '123' },
        plan: { revision: 7, deployedRevision: 6, nodes: [] },
        ...(description.ordinary ? { networkPlanSha256: description.networkPlanSha256 } : {}) };
    const pins = [];
    const maintenance = async ({ binding }, work) => {
        const n = description.nodes.find(n => n.nodeId === binding.node);
        return work({ status: 'verified', authority: 'external-maintenance-v1', binding, proofId: randomUUID(),
            maintenanceId: n.maintenanceId, maintenance: 'held', allWriters: 'drained',
            oldBackend: { ...config.oldBackend, processTree: 'stopped', dispatch: 'disabled' },
            readback: { source: 'node-readback', ...n.originalSnapshot } });
    };
    const transfer = new TopologyConfigTransfer({ executionContext: TEST, TopologyConfigOwner: f.models.Owner, withVerifiedMaintenance: maintenance });
    for (const n of description.nodes) {
        const nodeIdentity = { machineId: n.physical.machineId, sshHostKeySha256: n.physical.sshHostKeySha256 };
        const classic = await transfer.initializeClassic({ node: n.nodeId, profile: n.targetProfile, nodeIdentity });
        const adopted = await transfer.adopt({ node: n.nodeId, profile: n.targetProfile, generation: classic.generation, proofRef: 'MODELED-originals' });
        const enrollmentId = randomUUID();
        config.plan.nodes.push({ nodeId: n.nodeId, targetProfile: n.targetProfile, enrollmentId, ownerGeneration: adopted.generation });
        const enrollment = { _id: enrollmentId, executionContext: TEST.hostIdentity, nodeId: n.nodeId, targetProfile: n.targetProfile,
            ownerGeneration: adopted.generation, nodeIdentity, endpoint: n.endpoint, bootId: n.physical.bootId, maintenanceId: n.maintenanceId };
        f.models.Enrollment.rows.push(enrollment); // explicit modeled enrollment persistence, not a grant/COMMIT
        pins.push({ ...n, ...enrollment, enrollmentId });
    }
    f.models.Topology.rows.push({ _id: 'singleton', revision: 7, deployedRevision: 6, topologyAdmissionCount: 0, remoteAdmissionCount: 0 });
    f.models.Queue.rows.push({ _id: 'create-v1', outstanding: 0 });
    const directory = path.join(description.root, 'public-owner-journal'); fs.mkdirSync(directory, { mode: 0o700 });
    const journal = new HeldOwnerSettlementJournal({ directory, uid: process.getuid(), fixtureRoot: description.root });
    // Supported internal openBridge seam. No product module rewriting/loader hook,
    // fabricated terminal producer, manually returned receipt or seeded COMMIT.
    const inputs = { config, pins, inventory: description.inventory,
        assertPins() { for (const [file, expected] of Object.entries(description.bridgeSources)) assert.equal(sha(noatime(file)), expected); } };
    const children = [], requests = [];
    const service = new HeldTestOwnerSettlement({ models: f.models, journal, inventory: inputs.inventory,
        inventorySha256: config.inventorySha256,
        withRestorationScope: work => withFreshOperationalRestoration(inputs, work, { openBridge() {
            const child = spawn(description.python, ['-B', '-c', description.bridgeSource, description.root, description.socket],
                { cwd: description.cwd, stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
            child.stderr.on('data', raw => fs.appendFileSync(path.join(description.root, 'bridge-stderr.log'), raw));
            const write = child.stdin.write.bind(child.stdin), kills = [];
            child.stdin.write = (...args) => { requests.push(JSON.parse(args[0])); return write(...args); };
            const kill = child.kill.bind(child); child.kill = signal => {
                if (child.exitCode === null && child.signalCode === null) kills.push(signal);
                return kill(signal);
            };
            const closed = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
            children.push({ child, closed, kills }); return child;
        } }) });
    try {
        const result = await service.freshHandback(config.plan);
        assert.equal(result.code, description.ordinary ? 'COMMITTED_FRESH_NETWORK_OWNED' : 'COMMITTED_FRESH_ACTIVATION_CONFIRMED');
        assert.equal(children.length, 1);
        assert.deepEqual(await children[0].closed, { code: 0, signal: null });
        assert.deepEqual(children[0].kills, []);
        const terminal = requests.filter(r => r.op === 'fresh-handback'); assert.equal(terminal.length, 1);
        assert.deepEqual(Object.keys(terminal[0].proof).sort(), ['context', 'deployedRevision', 'nodes', 'quietSha256', 'revision']);
        const commit = noatime(path.join(description.root, 'var/lib/c3-test-node-isolation/handoff-commit.json'));
        assert.equal(sha(commit), result.commitSha256);
        assert.deepEqual(JSON.parse(commit).settlement, terminal[0].proof);
        assert.equal(f.events.filter(e => e === 'classic').length, description.nodes.length);
        const row = JSON.parse(noatime(path.join(directory, 'owner-settlement.json')));
        assert.equal(row.phase, 'irreversibly-committed'); assert.equal(row.commitSha256, result.commitSha256);
        assert.equal(row.settled.length, description.nodes.length);
        if (description.ordinary) assert.deepEqual(Object.keys(result).filter(k => k.endsWith('Sha256')).sort(), ['commitSha256', 'networkOwnershipSha256']);
        else assert.equal(Object.hasOwn(result, 'networkOwnershipSha256'), false);
        process.stdout.write(JSON.stringify(result)+'\n');
    } finally {
        for (const { child, closed } of children) {
            if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
            await closed;
        }
    }
}
if (require.main === module) {
    if (process.argv.length !== 3) throw Error('Python integration fixture descriptor required');
    main(process.argv[2]).catch(error => { console.error(error); process.exitCode = 1; });
}
