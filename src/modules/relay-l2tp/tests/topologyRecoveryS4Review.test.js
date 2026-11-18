'use strict';

// Offline characterizations, not Mongo/SSH/guard acceptance. No filesystem fixtures.
const assert = require('node:assert/strict');
const { isDeepStrictEqual: same } = require('node:util');
const { randomUUID, createHash } = require('node:crypto');
const { test } = require('node:test');
const noIO = () => assert.fail('unexpected I/O');
require('node:net').Socket.prototype.connect = noIO;
require('node:net').Server.prototype.listen = noIO;
function stub(request, exports) {
    const filename = require.resolve(request);
    require.cache[filename] = { id: filename, filename, loaded: true, exports };
}
stub('../../../utils/logger', { error() {}, warn() {}, info() {} });
// The recovery module imports the full runtime; its unrelated config generator
// requires root config at module load. Never evaluate settings/dotenv here.
stub('../../../../config', {});
stub('dotenv', { config: noIO });
const diagnostics = [];
stub('../../../routes/topologyTestDiagnostics', { logTopologyTestFailure({ phase, error }) { diagnostics.push({ phase, error }); } });

const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const { matchesTopologyOperationClaimBinding } = require('../domain/topologyOperationClaimBinding');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const settlement = require('../repositories/topologyV2Settlement');
const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
const { TopologyOperationExecutor, verifiedClosingOriginal } = require('../services/topologyOperationExecutor');
const { TopologyUserResync } = require('../services/topologyUserResync');
const { createTopologyOperationRecoveryLifecycle } = require('../runtime/createTopologyOperationRecoveryLifecycle');
const { freeze, runnerRequest, v2Receipt, SIMULATED_TRUSTED_CONNECTION } = require('./helpers/topologyV2Fixture');

const id = '110000000000000000000000';
const P = '110000000000000000000001', B = '110000000000000000000002';
const leaseMs = 60_000;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const clone = structuredClone;
const timer = { setInterval: () => ({}), clearInterval() {} };
const env = { PANEL_DOMAIN: PROD.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' };
const nodes = [[P, 'portal', 'xray-main'], [B, 'bridge', 'xray-bridge']].map(([node, role, targetProfile]) => {
    const text = JSON.stringify({ inbounds: [{ tag: `local-${role}` }], outbounds: [{ tag: 'direct' }], routing: { rules: [] } }) + '\n';
    const candidateHash = sha(text);
    return { node, role, nodeRef: role, targetProfile, candidateHash, checks: [], state: 'pending', backupId: '',
        candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1', bytes: [...Buffer.from(text)], sha256: candidateHash } };
});

// Only the query subset exercised here, with exact predicates around expiry and owner.
function matches(row, query, now) {
    return Object.entries(query).every(([key, value]) => {
        if (key === '$or') return value.some(filter => matches(row, filter, now));
        if (key === '$expr') {
            if (value.$and) return matchesTopologyOperationClaimBinding(row, PROD); // no native BSON/casting claim
            assert.deepEqual(value, { $lte: ['$leaseUntil', '$$NOW'] });
            return row.leaseUntil instanceof Date && row.leaseUntil <= now;
        }
        if (key === 'nodes.node') return row.nodes.some(n => n.node === value);
        const field = key.split('.').reduce((o, k) => o?.[k], row);
        if (!value || typeof value !== 'object' || value instanceof Date || !Object.keys(value).some(k => k.startsWith('$'))) return same(field, value);
        return Object.entries(value).every(([op, arg]) => {
            if (op === '$in') return arg.includes(field ?? null);
            if (op === '$exists') return (field !== undefined) === arg;
            if (op === '$eq') return same(field, arg);
            if (op === '$ne') return !same(field, arg);
            if (op === '$gte') return field >= arg;
            if (op === '$lte') return field <= arg;
            if (op === '$gt') return field > arg;
            if (op === '$not') return !matches(row, { [key]: arg }, now);
            if (op === '$elemMatch') return field.some(item => matches(item, arg, now));
            if (op === '$type') return arg === 'date' ? field instanceof Date : arg.includes('int') && Number.isSafeInteger(field);
            assert.fail(`unhandled predicate ${op}`);
        });
    });
}
function memory(initial, clock, rejectWrite) {
    let data = clone(initial);
    const writes = [], commits = [], aborts = [];
    const db = {
        async startSession() {
            return { startTransaction() { this.rows = clone(data); this.active = true; }, inTransaction() { return this.active; },
                transaction: { transition(next) { assert.equal(next, 'TRANSACTION_COMMITTED'); } },
                async abortTransaction() { this.active = false; aborts.push(true); }, async endSession() {} };
        },
        getClient: () => ({ db: name => ({ async command(c, { session }) {
            assert.equal(name, 'admin'); assert.equal(c.commitTransaction, 1); assert.ok(session.active);
            data = session.rows; session.active = false; commits.push(true); return { ok: 1 };
        } }) }),
    };
    const backing = (name, session) => (session?.rows ?? data)[name];
    const query = (read, opts = {}) => {
        let session = opts.session, limit = Infinity;
        const q = { select: () => q, sort: () => q, limit: n => { limit = n; return q; }, read: () => q, readConcern: () => q,
            session: s => { session = s; return q; }, setOptions: o => { session = o.session ?? session; return q; },
            then: (ok, no) => Promise.resolve().then(() => read(session, limit)).then(ok, no), lean: () => q };
        return q;
    };
    const model = name => {
        const find = (filter, session) => backing(name, session).filter(row => matches(row, filter, clock.now()));
        function update(filter, u, opts = {}) {
            const row = find(filter, opts.session)[0];
            if (!row || rejectWrite(name, filter, u)) return null;
            for (const [path, value] of Object.entries(u.$set ?? {})) {
                if (path.startsWith('nodes.$.')) row.nodes.find(n => n.node === filter['nodes.node'])[path.slice(8)] = clone(value);
                else row[path] = clone(value);
            }
            for (const [k, value] of Object.entries(u.$inc ?? {})) row[k] += value;
            writes.push([name, clone(u), !!opts.session]);
            return clone(row);
        }
        return { db, create: noIO, find: filter => query((s, l) => clone(find(filter, s).slice(0, l))),
            findOne: filter => query(s => clone(find(filter, s)[0] ?? null)),
            findById: _id => query(s => clone(find({ _id }, s)[0] ?? null)),
            findOneAndUpdate: async (...args) => update(...args),
            updateOne: async (...args) => ({ matchedCount: update(...args) ? 1 : 0 }),
            countDocuments: filter => query(s => find(filter, s).length),
            async deleteOne(filter, { session } = {}) {
                const rows = backing(name, session), row = find(filter, session)[0];
                if (!row) return { deletedCount: 0 };
                rows.splice(rows.indexOf(row), 1); writes.push([name, 'delete', !!session]); return { deletedCount: 1 };
            } };
    };
    return { model, get: () => data, snapshot: () => clone(data), writes, commits, aborts };
}

function fixture({ cut, nonempty = false, successor = false } = {}) {
    let offset = 0;
    const clock = { now: () => new Date(Date.now() + offset) };
    const s = memory({ op: [{ _id: id, kind: 'link.apply', admissionScope: 'selected', executionContext: PROD,
        resourceNodeIds: [P, B], selectedOwnerPins: [], linkId: '110000000000000000000003',
        topologyRevision: 17, priorDeployedRevision: 16, attempts: 0,
        idempotencyKey: `topology:production:revision-17:host-${PROD.hostIdentity}:${randomUUID()}`,
        nodes, status: 'queued', heldTopologyAdmission: true, leaseOwner: '', leaseUntil: null }],
    topology: [{ _id: 'singleton', revision: 17, deployedRevision: 16, topologyAdmissionCount: 1 }], lock: [], binding: [], owner: [], alias: [] },
    clock, (name, filter, update) => name === 'op' && ((filter['nodes.node'] === P
        && cut === `db-${update.$set?.['nodes.$.state']}`)
        || (cut === 'verified-before-closing' && update.$set?.v2Terminal?.state === 'closing')
        || (cut === 'both-closed' && update.$set?.v2Terminal?.state === 'proven')));
    const op = () => s.get().op[0];
    const expire = () => { offset += 2 * leaseMs; };
    const journals = new Map();
    const events = [], proof = [], bindings = new Map();
    const user = { xrayUuid: randomUUID(), userId: 'local-fixture' };
    let legacyCalls = 0;
    const repository = {
        TopologyOperation: s.model('op'), CascadeTopologyState: s.model('topology'), NodeOperationLock: s.model('lock'),
        TopologyExecutionBinding: s.model('binding'), TopologyConfigOwner: s.model('owner'), TopologyExecutionEnrollment: s.model('alias'),
        selectedTopologyRepository: { async verifySelected(row) { assert.deepEqual(row.resourceNodeIds, [P, B]); } },
    };
    let stopAfterTakeover = false;
    function build(owner, { recovering = false } = {}) {
        const check = async expected => {
            const b = bindings.get(expected.nodeId), lock = s.get().lock.find(l => l.node === expected.nodeId);
            assert.ok(b && lock && lock.remoteUncertain && lock.owner === expected.owner && lock.generation === expected.generation
                && lock.leaseUntil > clock.now() && op().leaseUntil > clock.now() && op().leaseOwner === expected.owner, 'fixture exact live ownership');
            if (expected.owner !== b.owner) assert.deepEqual(verifiedClosingOriginal(expected), b);
            return b;
        };
        const reader = { readVerified: check,
            async readVerifiedConnection(expected) { return freeze({ binding: await check(expected), connection: SIMULATED_TRUSTED_CONNECTION }); },
            async withVerifiedBinding(expected, work) { return work(await check(expected), () => check(expected)); } };
        reader.withReadOnlyVerifiedBinding = reader.withVerifiedBinding;
        const executor = new TopologyOperationExecutor({ ...PROD, executionBindingReader: reader,
            RunnerBootstrapper: class { async ensureRunner() { assert.equal(recovering, false); }
                async verifyExisting() { assert.equal(recovering, true); } }, nodeExecutionResolver: { async resolve({ nodeId }) {
                return { async exec(command) {
                    const request = runnerRequest(command), { checks, ...fields } = request;
                    assert.equal(request.nodeId, nodeId);
                    const { command: label, commandId, ...wireBinding } = fields;
                    events.push([nodeId, label, commandId]);
                    const b = bindings.get(nodeId);
                    let j = journals.get(nodeId);
                    if (!j) {
                        assert.equal(label, 'prepare');
                        j = { version: 2, nodeId, head: b.generation, bootId: b.bootId,
                            executionContext: b.executionContext, generations: { [b.generation]: { binding: wireBinding, phase: 'new', commands: {} } } };
                        journals.set(nodeId, j);
                    }
                    const g = j.generations[b.generation];
                    assert.deepEqual(g.binding, wireBinding);
                    const stdout = receipt => ({ code: 0, stderr: '', stdout: JSON.stringify(receipt) + '\n' });
                    if (label === 'status') return stdout({ ...g.commands[commandId].receipt, command: 'status' });
                    assert.equal(g.commands[commandId], undefined, 'fixture models runner COMMAND_REUSE');
                    assert.equal(g.phase, { prepare: 'new', commit: 'prepared', verify: 'committed', close: 'verified', 'restore-users': 'verified' }[label]);
                    const receipt = label === 'restore-users' ? { ...fields, protocolVersion: 2, completion: 'completed', phase: 'verified', ownershipRetained: true,
                        bootId: b.bootId, checksSha256: sha(JSON.stringify(checks)), result: { ok: true, code: 'XRAY_USERS_RESTORED', userCount: 1, inboundCount: 1 } }
                        : v2Receipt(fields, { bootId: b.bootId, ...(label === 'close' ? { phase: 'closed', terminal: true, terminalOutcome: 'verified' } : {}) });
                    g.commands[commandId] = { state: 'completed', command: label, receipt };
                    g.phase = receipt.phase; g.serviceState = receipt.serviceState ?? g.serviceState;
                    if (cut === 'first-close' && label === 'close' && nodeId === P) throw new Error('modeled lost close reply');
                    if ((cut === 'late-commit' || cut === 'timeout-commit') && label === 'commit' && nodeId === P) {
                        if (cut === 'late-commit') { pauseAcknowledged(); await reply; }
                        else { lateReceipt = receipt; throw new Error('modeled transport timeout'); }
                    }
                    return stdout(receipt);
                } };
            } } });
        const bindingLifecycle = { executionContext: PROD, run: work => work(), async assertHeld() {},
            async readUnclosedPair(bs) { proof.push(bs.map(b => b.nodeId)); return bs.map(b => ({
                nodeId: b.nodeId, targetProfile: b.targetProfile, runnerIdle: true,
                physical: { bootId: b.bootId }, journal: clone(journals.get(b.nodeId)),
                current: { source: 'node-readback', serviceActive: 'active', configSha256: b.candidateHash.slice(7) },
            })); } };
        const bindingProvisioner = { executionContext: PROD, async reserveBinding(expected) {
            if (recovering) noIO();
            const b = freeze({ ...expected, predecessorGeneration: successor ? randomUUID() : 'none', attemptId: randomUUID(), bootId: randomUUID(), maintenanceId: randomUUID(),
                commandIds: Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close'].map(c => [c, randomUUID()])) });
            bindings.set(b.nodeId, b);
            const join = { nodeId: b.nodeId, targetProfile: b.targetProfile, executionContext: b.executionContext, bootId: b.bootId,
                maintenanceId: b.maintenanceId, ownerGeneration: randomUUID(), nodeIdentity: { machineId: '4'.repeat(32), sshHostKeySha256: '5'.repeat(64) },
                endpoint: SIMULATED_TRUSTED_CONNECTION.expectedEndpoint };
            const enrollmentId = randomUUID();
            s.get().alias.push({ _id: enrollmentId, ...join });
            s.get().binding.push({ ...b, ...join, enrollmentId });
            s.get().owner.push({ node: b.nodeId, profile: b.targetProfile, executionContext: PROD, owner: 'topology', generation: join.ownerGeneration,
                nodeIdentity: join.nodeIdentity, originalSnapshot: { proofRef: 'modeled-original' }, adoptionReceipt: { toGeneration: join.ownerGeneration } });
            op().selectedOwnerPins.push({ node: b.nodeId, profile: b.targetProfile, generation: join.ownerGeneration });
            if (cut === 'first-binding' && b.nodeId === P) throw new Error('modeled lost response after first binding persisted');
            return b;
        } };
        const finalizer = {
            finalizeSucceeded: noIO, probeV2Settlement: ({ operationId }) => settlement.probe(repository, operationId),
            beginV2Closure: request => settlement.begin(repository, request),
            async persistV2TerminalProofs(request) { return settlement.persist(repository, request); },
            async finalizeV2Succeeded(request) {
                return settlement.settle(repository, request, async session => {
                    if (cut === 'proven') return null; // refusal in publish; abort all uncommitted settlement writes
                    const rows = session.rows;
                    rows.op[0].status = 'succeeded'; rows.op[0].heldTopologyAdmission = false;
                    rows.topology[0].topologyAdmissionCount--;
                    return { deployedRevision: 17 };
                });
            },
            async reclaimUnclosedPair(request, terminal) {
                const row = await settlement.reclaimUnclosedPair(repository, request, terminal);
                if (stopAfterTakeover) { stopAfterTakeover=false; throw new Error('modeled crash at confirmed takeover before rehydration'); }
                return row;
            },
        };
        return new TopologyOperationWorker({ executionContext: PROD, workerId: owner, leaseMs, clock, timer, executor, finalizer,
            operationRepository: new TopologyOperationRepository({ model: repository.TopologyOperation }),
            selectedTopologyRepository: repository.selectedTopologyRepository, bindingLifecycle, bindingProvisioner,
            lockService: { async acquire({ node, operationId }) {
                if (recovering) noIO();
                const lock = { node, operationId, generation: randomUUID(), owner, remoteUncertain: true, leaseUntil: new Date(+clock.now() + leaseMs) };
                s.get().lock.push(lock); return { ok: true, lock: clone(lock) };
            }, async renew({ node, generation }) {
                const lock = s.get().lock.find(l => l.node === node && l.generation === generation && l.owner === owner);
                if (!lock || lock.leaseUntil <= clock.now()) return { ok: false };
                lock.leaseUntil = new Date(+clock.now() + leaseMs); return { ok: true };
            }, release: noIO },
            userResync: new TopologyUserResync({ preferBoundRunner: true,
                HyNode: { findById: _id => ({ async lean() { return { _id, type: 'xray' }; } }) },
                syncService: { async _getUsersForNode(n) { return nonempty && n._id === P ? [user] : []; },
                    addXrayUser() { legacyCalls++; return noIO(); } },
            }),
            pppReadinessGate: { async verifyPlan() {
                return { ok: cut !== 'restored' && (recovering || cut !== 'closing'), relayRevisions: [] };
            } },
        });
    }
    let releaseReply, pauseAcknowledged, lateReceipt;
    const reply = new Promise(resolve => { releaseReply = resolve; });
    const paused = new Promise(resolve => { pauseAcknowledged = resolve; });
    async function restart(owner) {
        const worker = build(owner, { recovering: true }), outcomes = [];
        const lifecycle = createTopologyOperationRecoveryLifecycle({ executionContext: PROD, env, clock, timer,
            operationModel: repository.TopologyOperation, worker: { async run(discovered) {
                const result = await worker.run(discovered); outcomes.push(result); return result;
            } } });
        assert.equal(lifecycle.start().enabled, true);
        return { state: await lifecycle.stop(), outcomes };
    }
    return { s, op, journals, proof, events, bindings, clock, expire, start: () => build('worker-A').run(id), restart, releaseReply, paused,
        legacyCalls: () => legacyCalls,
        late: () => lateReceipt, stopAfterTakeover: () => { stopAfterTakeover = true; } };
}

async function unchangedAfterScan(f, expected, owner = 'worker-B') {
    const before = f.s.snapshot(), journals = clone(f.journals), commands = f.events.length, writes = f.s.writes.length;
    const { outcomes, state } = await f.restart(owner);
    assert.deepEqual(outcomes, expected);
    assert.equal(state.drainUncertain === true, expected.some(outcome => outcome.drainUncertain));
    assert.deepEqual(f.s.snapshot(), before); assert.deepEqual(f.journals, journals);
    assert.equal(f.events.length, commands); assert.equal(f.s.writes.length, writes);
    assert.equal(f.op().heldTopologyAdmission, true); assert.equal(f.s.get().topology[0].topologyAdmissionCount, 1);
    assert.equal(f.s.get().lock.length, 2); assert.ok(f.s.get().lock.every(l => l.remoteUncertain));
}
const review = claimed => ({ operationId: id, claimed, status: 'committing', stopped: true, drainUncertain: true,
    errorCode: 'TOPOLOGY_V2_RECOVERY_REQUIRES_SETTLEMENT_REVIEW' });

test('S4 first binding persisted, no runner command, expired restart cannot claim', async () => {
    const f = fixture({ cut: 'first-binding' });
    assert.equal((await f.start()).errorCode, 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN');
    assert.equal(f.op().status, 'preparing'); assert.equal(f.op().attempts, 1);
    assert.deepEqual(f.op().nodes.map(n => n.state), ['pending', 'pending']);
    assert.deepEqual(f.s.get().binding.map(b => b.nodeId), [P]);
    assert.equal(f.events.length, 0);
    await unchangedAfterScan(f, []);
    f.expire(); await unchangedAfterScan(f, [{ claimed: false, operationId: id }]);
});

test('S4 prepare / commit receipt stored, before matching DB node row', async t => {
    for (const [command, phase, db] of [['prepare', 'prepared', 'pending'], ['commit', 'committed', 'prepared']]) await t.test(command, async () => {
        const f = fixture({ cut: `db-${phase}` });
        assert.equal((await f.start()).errorCode, 'TOPOLOGY_OPERATION_LEASE_LOST');
        const b = f.bindings.get(P);
        assert.equal(f.journals.get(P).generations[b.generation].commands[b.commandIds[command]].state, 'completed');
        assert.equal(f.op().nodes[0].state, db); assert.equal(f.op().attempts, 1);
        f.expire(); await unchangedAfterScan(f, [{ claimed: false, operationId: id }]);
    });
});

test('S4 both verify receipts stored, before closure intent reaches DB', async () => {
    const f = fixture({ cut: 'verified-before-closing' });
    assert.equal((await f.start()).errorCode, 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED');
    assert.equal(f.op().status, 'committing'); assert.equal(f.op().v2Terminal, undefined);
    assert.deepEqual(f.op().nodes.map(n => n.state), ['committed', 'committed']);
    assert.deepEqual([...f.bindings.values()].map(b => f.journals.get(b.nodeId).generations[b.generation].phase), ['verified', 'verified']);
    f.expire(); await unchangedAfterScan(f, [{ claimed: false, operationId: id }]);
});

test('S4 stored close receipts with empty DB proofs fail the unclosed check', async t => {
    for (const [cut, phases] of [['first-close', ['closed', 'verified']], ['both-closed', ['closed', 'closed']]]) await t.test(cut, async () => {
        const f = fixture({ cut });
        assert.equal((await f.start()).errorCode, 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED');
        assert.deepEqual(f.op().v2Terminal.proofs, []); assert.equal(f.op().v2Terminal.state, 'closing');
        assert.deepEqual([...f.bindings.values()].map(b => f.journals.get(b.nodeId).generations[b.generation].phase), phases);
        f.expire(); await unchangedAfterScan(f, [review(false)]);
        assert.deepEqual(f.proof, [[P, B]]);
    });
});

test('S4 terminal proofs stored, no publication, later scan is read-only', async () => {
    const f = fixture({ cut: 'proven' });
    assert.equal((await f.start()).errorCode, 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED');
    assert.equal(f.op().v2Terminal.state, 'proven');
    assert.equal(f.op().v2Terminal.proofs.length, 2); assert.ok(f.op().v2Terminal.sideEffects.usersVerified);
    assert.equal(f.s.aborts.length, 1);
    f.expire(); await unchangedAfterScan(f, [review(false)]);
});

test('S4 persisted restore-users receipt prevents closing recovery before any close', async () => {
    const f = fixture({ cut: 'restored', nonempty: true });
    assert.equal((await f.start()).errorCode, 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED');
    assert.equal(f.op().v2Terminal.state, 'closing');
    assert.deepEqual(f.op().v2Terminal.proofs, []);
    assert.equal(f.events.at(-1)[1], 'restore-users');
    assert.equal(f.legacyCalls(), 0);
    f.expire(); await unchangedAfterScan(f, [review(false)]);
    assert.deepEqual(f.proof, [[P, B]]);
});

test('S4 late successful commit reply cannot advance a dead lease', async () => {
    const f = fixture({ cut: 'late-commit' });
    const first = f.start();
    try {
        await Promise.race([f.paused, first.then(outcome => assert.fail(`commit was not paused: ${JSON.stringify(outcome)}`))]);
        assert.equal(f.events.at(-1)?.[1], 'commit');
        assert.equal(f.op().nodes[0].state, 'prepared');
        f.expire(); await unchangedAfterScan(f, [{ claimed: false, operationId: id }]);
    } finally { f.releaseReply(); }
    assert.equal((await first).errorCode, 'TOPOLOGY_OPERATION_LEASE_LOST');
    assert.equal(f.op().nodes[0].state, 'prepared');
    assert.equal(f.events.at(-1)?.[1], 'commit');
});

test('S4 timeout with completed remote commit leaves failed retained outside scan', async () => {
    const f = fixture({ cut: 'timeout-commit' });
    assert.equal((await f.start()).errorCode, 'REMOTE_COMMAND_OUTCOME_UNCERTAIN');
    assert.equal(f.late().phase, 'committed'); assert.equal(f.op().status, 'failed');
    f.expire(); await unchangedAfterScan(f, []);
});

test('S4 closing takeover publishes once, including a second restart before any close', async t => {
    for (const crash of [false, true]) await t.test(crash ? 'second restart' : 'first restart', async () => {
        const f = fixture({ cut: 'closing' });
        assert.equal((await f.start()).errorCode, 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED');
        const before = f.s.snapshot(), commands = f.events.length;
        f.expire();
        const diagnosticStart = diagnostics.length;
        const result = crash ? (f.stopAfterTakeover(), await f.restart('worker-B')) : await f.restart('worker-B');
        assert.deepEqual(f.s.get().binding, before.binding);
        if (!crash) {
            assert.deepEqual(result.outcomes, [{ claimed: true, operationId: id, status: 'succeeded' }],
                diagnostics.slice(diagnosticStart).map(({phase, error}) => `${phase}: ${error?.cause?.stack ?? error?.stack}`).join('\n'));
            assert.deepEqual(f.events.slice(commands).map(([node, action]) => [node, action]), [[P, 'close'], [P, 'status'], [B, 'close'], [B, 'status']]);
            assert.equal(f.s.get().lock.length, 0); assert.equal(f.s.get().topology[0].topologyAdmissionCount, 0);
            const after = f.s.snapshot(), eventCount = f.events.length, commitCount = f.s.commits.length;
            assert.deepEqual((await f.restart('worker-C')).outcomes, []);
            assert.deepEqual(f.s.get(), after); assert.equal(f.events.length, eventCount); assert.equal(f.s.commits.length, commitCount);
            return;
        }
        assert.deepEqual(result.outcomes, [review(false)]); // commit succeeded; return/claimed flag was lost
        assert.equal(f.op().leaseOwner, 'worker-B');
        assert.deepEqual(f.s.get().lock.map(l => [l.owner, l.generation]), before.lock.map(l => ['worker-B', l.generation]));
        assert.equal(f.events.length, commands); assert.deepEqual(f.proof, [[P, B]]);
        f.expire();
        assert.deepEqual((await f.restart('worker-C')).outcomes, [{claimed:true, operationId:id, status:'succeeded'}]);
        assert.deepEqual(f.s.get().binding,before.binding);assert.equal(f.op().attempts,1);
        assert.deepEqual(f.events.slice(commands).map(([node,action])=>[node,action]),[[P,'close'],[P,'status'],[B,'close'],[B,'status']]);
        assert.equal(f.op().v2Terminal.proofs.length,2);assert.equal(f.s.get().lock.length,0);assert.equal(f.s.get().topology[0].topologyAdmissionCount,0);
        const done=f.s.snapshot(), count=f.events.length;
        assert.deepEqual((await f.restart('worker-D')).outcomes,[]);assert.deepEqual(f.s.get(),done);assert.equal(f.events.length,count);
    });
});

test('S4 closing cannot transfer with any one original lease live', async t => {
    for (const live of ['operation', P, B]) await t.test(live, async () => {
        const f = fixture({ cut: 'closing' });
        assert.equal((await f.start()).errorCode, 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED');
        f.expire();
        const field = live === 'operation' ? f.op() : f.s.get().lock.find(l => l.node === live);
        field.leaseUntil = new Date(+f.clock.now() + leaseMs);
        // Pre-commit writes in the modeled transaction are allowed; no durable change.
        const before = f.s.snapshot(), commits = f.s.commits.length, aborts = f.s.aborts.length, commands = f.events.length;
        const result = await f.restart('worker-B');
        assert.deepEqual(result.outcomes, live === 'operation' ? [] : [review(false)]);
        assert.deepEqual(f.s.snapshot(), before); assert.equal(f.events.length, commands);
        assert.equal(f.s.commits.length, commits); assert.equal(f.s.aborts.length, aborts + (live === 'operation' ? 0 : 1));
        assert.deepEqual(f.proof, live === 'operation' ? [] : [[P, B]]);
        f.expire();
        assert.deepEqual((await f.restart('worker-B')).outcomes, [{ claimed: true, operationId: id, status: 'succeeded' }]);
    });
});

test('S4 successor closing is outside the first-generation recovery route', async () => {
    const f = fixture({ cut: 'closing', successor: true });
    assert.equal((await f.start()).errorCode, 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED');
    assert.equal(f.op().v2Terminal.state, 'closing');
    assert.ok(f.op().v2Terminal.bindings.every(b => b.predecessorGeneration !== 'none'));
    f.expire(); await unchangedAfterScan(f, [review(false)]);
    assert.deepEqual(f.proof, []);
});
