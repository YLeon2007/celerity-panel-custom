'use strict';
// Local persistence/transaction fixtures, not Mongo or remote execution proof.
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const LinkModel = require('../../../models/cascadeLinkModel');
const { TopologyIntentService } = require('../services/topologyIntentService');
const context = Object.freeze({ target: 'test', hostIdentity: 'test.infograd.online' });
const ids = Array.from({ length: 8 }, (_, i) => `507f1f77bcf86cd7994390${String(i).padStart(2, '0')}`);
const copy = value => value === undefined ? undefined : structuredClone(value);
function equal(a, b) { return String(a) === String(b); }
function matches(row, filter) {
    return Object.entries(filter).every(([key, value]) => {
        if (key === '$or') return value.some(part => matches(row, part));
        const actual = key.split('.').reduce((v, part) => v?.[part], row);
        if (value && typeof value === 'object' && !(value instanceof Date)) {
            return Object.entries(value).every(([op, expected]) => {
                if (op === '$in') return expected.some(v => equal(actual, v));
                if (op === '$nin') return expected.every(v => !equal(actual, v));
                if (op === '$exists') return (actual !== undefined) === expected;
                if (op === '$gt') return actual > expected;
                if (op === '$lt') return actual < expected;
                if (op === '$ne') return !equal(actual, expected);
                if (op === '$eq') return equal(actual, expected);
                throw Error(`Unsupported fixture predicate ${op}`);
            });
        }
        return equal(actual, value);
    });
}
function apply(row, update) {
    for (const [key, value] of Object.entries(update.$set || {})) row[key] = copy(value);
    for (const [key, value] of Object.entries(update.$inc || {})) row[key] = (row[key] || 0) + value;
    for (const key of Object.keys(update.$unset || {})) delete row[key];
}
function fixture() {
    const db = {};
    let data = {
        CascadeTopologyState: [{ _id: 'singleton', revision: 7, deployedRevision: 5, topologyAdmissionCount: 0, remoteAdmissionCount: 0 }],
        HyNode: ids.map((_id, i) => ({ _id, active: true, type: 'xray', cascadeRole: i % 2 ? 'bridge' : 'portal' })),
        CascadeLink: [], CascadeRouteGroup: [], RelayL2tpState: [], TopologyCreateIntent: [], TopologyIntentQueueState: [], TopologyOperation: [],
    };
    const trace = [];
    function model(name) {
        class Model {
            constructor(input) { return new LinkModel(input); }
            static db = db;
            static query(work) {
                let session, sort, limit;
                return {
                    session(value) { session = value; return this; }, select() { return this; },
                    sort(value) { sort = value; return this; }, limit(value) { limit = value; return this; },
                    readConcern(value) { trace.push(['readConcern', value]); return this; },
                    read(value) { trace.push(['read', value]); return this; },
                    maxTimeMS(value) { trace.push(['maxTimeMS', value]); return this; },
                    async lean() {
                        const result = work(session?.data || data);
                        if (Array.isArray(result)) {
                            if (sort) result.sort((a, b) => a[Object.keys(sort)[0]] - b[Object.keys(sort)[0]]);
                            return copy(limit ? result.slice(0, limit) : result);
                        }
                        return copy(result);
                    },
                    then(resolve, reject) { return this.lean().then(resolve, reject); },
                };
            }
            static find(filter) { return this.query(state => state[name].filter(row => matches(row, filter))); }
            static findOne(filter) { return this.query(state => state[name].find(row => matches(row, filter)) || null); }
            static findById(_id) { return this.findOne({ _id }); }
            static exists(filter) { return this.findOne(filter); }
            static findOneAndUpdate(filter, update, options = {}) {
                return this.query(state => {
                    const row = state[name].find(candidate => matches(candidate, filter));
                    if (!row) return null;
                    apply(row, update); return row;
                }).session(options.session);
            }
            static async create(rows, { session } = {}) {
                trace.push(['create', name, session]);
                const state = session?.data || data;
                return rows.map(input => {
                    const row = JSON.parse(JSON.stringify({ _id: new mongoose.Types.ObjectId(), ...input }));
                    state[name].push(row); return row;
                });
            }
            static async updateOne(filter, update, { session } = {}) {
                const row = (session?.data || data)[name].find(candidate => matches(candidate, filter));
                if (row) apply(row, update);
                return { matchedCount: row ? 1 : 0 };
            }
            static async deleteOne(filter, { session } = {}) {
                const rows = (session?.data || data)[name];
                const index = rows.findIndex(row => matches(row, filter));
                if (index >= 0) rows.splice(index, 1);
                return { deletedCount: index >= 0 ? 1 : 0 };
            }
        }
        return Model;
    }
    const dependencies = Object.fromEntries(Object.keys(data).map(name => [name, model(name)]));
    Object.assign(dependencies, { executionContext: context,
        async transactionRunner(work) {
            const session = { data: copy(data) };
            const result = await work(session);
            data = session.data;
            return result;
        },
        async resolveIntentResources({ link }) { return [String(link.portalNode), String(link.bridgeNode)].sort(); },
    });
    const link = (pair = 0) => ({ name: `link-${pair}`, portalNode: ids[pair * 2], bridgeNode: ids[pair * 2 + 1], tunnelPort: 10086 });
    return { dependencies, link, trace, get data() { return data; } };
}

test('v2 auto-create atomically saves one desired link and its intent; replay precedes credentials', async () => {
    const f = fixture(); let generated = 0;
    f.dependencies.prepareLink = async link => ({ ...link, tunnelUuid: `generated-${++generated}` });
    const input = { version: 2, kind: 'link.create', expectedTopologyRevision: 7, requestKey: 'create-one', link: f.link() };
    const first = await new TopologyIntentService(f.dependencies).accept(input);
    assert.equal(first.kind, 'link.create');
    assert.equal(first.desiredSaved, true);
    assert.equal(first.linkId, first.createdLinkId);
    assert.match(first.desiredVersion, /^[a-f0-9]{64}$/);
    assert.equal(f.data.CascadeLink.length, 1);
    assert.equal(f.data.TopologyCreateIntent.length, 1);
    assert.equal(f.data.CascadeTopologyState[0].revision, 8);
    assert.equal(f.data.TopologyCreateIntent[0].version, 2);
    assert.equal(String(f.data.CascadeLink[0]._id), first.linkId);
    const replay = await new TopologyIntentService(f.dependencies).accept({ ...input, expectedTopologyRevision: 1 });
    assert.deepEqual(replay, first);
    assert.equal(generated, 1);
    await assert.rejects(new TopologyIntentService(f.dependencies).accept({ ...input, link: { ...input.link, tunnelPort: 10087 } }), { code: 'TOPOLOGY_INTENT_KEY_CONFLICT' });
    assert.equal(generated, 1);
    const writes = f.trace.filter(entry => entry[0] === 'create' && ['CascadeLink', 'TopologyCreateIntent'].includes(entry[1]));
    assert.equal(writes.length, 2);
    assert.ok(writes[0][2] === writes[1][2], 'actual draft repository and intent insert join the exact session');
});

function withAdmission(f) {
    const queued = [];
    f.dependencies.intentOperationAdmission = {
        db: f.dependencies.CascadeLink.db,
        async queue({ session, mutation, expectedTopologyRevision, resourceNodeIds }) {
            queued.push({ mutation, expectedTopologyRevision, resourceNodeIds });
            const [operation] = await f.dependencies.TopologyOperation.create([{
                executionContext: context, status: 'queued', topologyRevision: expectedTopologyRevision,
                priorDeployedRevision: 5, heldTopologyAdmission: true, admissionFingerprint: 'a'.repeat(64),
                idempotencyKey: `topology:test:revision-${expectedTopologyRevision}:host-${context.hostIdentity}:00000000-0000-0000-0000-000000000000`,
                admissionScope: 'selected', resourceNodeIds, kind: mutation.kind, linkId: mutation.linkId,
                desiredVersion: mutation.desiredVersion,
            }], { session });
            return { operationId: operation._id };
        },
    };
    return queued;
}
test('v2 consumer materializes the stored create as one apply, pinned to its desired version', async () => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const f = fixture(); const queued = withAdmission(f);
    const job = await new TopologyIntentService(f.dependencies).accept({ version: 2, kind: 'link.create',
        expectedTopologyRevision: 7, requestKey: 'consume-created', link: f.link() });
    f.data.CascadeTopologyState[0].revision = 31; // An independent desired change.
    const consumer = new TopologyIntentConsumer(f.dependencies);
    assert.equal(typeof consumer.consumeVersioned, 'function', 'versioned intents need a non-create materialization path');
    await consumer.runOnce();
    assert.equal(f.data.TopologyCreateIntent[0].status, 'admitted');
    assert.equal(f.data.CascadeLink.length, 1, 'consumer must not create another desired link');
    assert.deepEqual(queued, [{ mutation: { kind: 'link.apply', linkId: job.linkId, desiredVersion: job.desiredVersion },
        expectedTopologyRevision: 31, resourceNodeIds: [ids[0], ids[1]] }]);
    assert.equal(f.data.TopologyOperation.length, 1);
    assert.equal(f.data.TopologyCreateIntent[0].attempts, 1);
});

test('a retained uncertain predecessor orders overlaps but does not block independent jobs', async () => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const f = fixture(); const queued = withAdmission(f);
    const service = new TopologyIntentService(f.dependencies);
    const first = await service.accept({ version: 2, kind: 'link.create', expectedTopologyRevision: 7, requestKey: 'head', link: f.link() });
    const overlap = await service.accept({ version: 2, kind: 'link.apply', expectedTopologyRevision: 8,
        requestKey: 'overlap', linkId: first.linkId, desiredVersion: first.desiredVersion });
    const independent = await service.accept({ version: 2, kind: 'link.create', expectedTopologyRevision: 8,
        requestKey: 'independent', link: f.link(1) });
    const consumer = new TopologyIntentConsumer(f.dependencies);
    await consumer.runOnce();
    f.data.TopologyOperation[0].status = 'failed'; // Terminal label is not release proof.
    await consumer.runOnce();
    assert.equal(queued.length, 2);
    assert.equal(queued[1].mutation.linkId, independent.linkId);
    const rows = new Map(f.data.TopologyCreateIntent.map(row => [String(row._id), row]));
    assert.equal(rows.get(first.jobId).status, 'blocked');
    assert.equal(rows.get(overlap.jobId).status, 'waiting');
    assert.equal(rows.get(overlap.jobId).attempts, 0);
    assert.equal(rows.get(overlap.jobId).waitingReason, 'TOPOLOGY_INTENT_RESOURCE_BUSY');
    assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 3);
});

test('busy admission consumes no attempt and the same tick can admit independent work', async () => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const f = fixture(); const calls = withAdmission(f);
    const queue = f.dependencies.intentOperationAdmission.queue;
    let busyCalls = 0;
    f.dependencies.intentOperationAdmission.queue = async input => {
        if (input.resourceNodeIds.includes(ids[0])) { busyCalls++; throw Object.assign(Error('busy'), { code: 'TOPOLOGY_DEPLOY_BUSY' }); }
        return queue(input);
    };
    const service = new TopologyIntentService(f.dependencies);
    await service.accept({ version: 2, kind: 'link.create', expectedTopologyRevision: 7, requestKey: 'busy-head', link: f.link() });
    const independent = await service.accept({ version: 2, kind: 'link.create', expectedTopologyRevision: 8, requestKey: 'free-tail', link: f.link(1) });
    await new TopologyIntentConsumer({ ...f.dependencies, backoffMs: 0 }).runOnce();
    assert.equal(calls.length, 1);
    assert.equal(calls[0].mutation.linkId, independent.linkId);
    assert.equal(busyCalls, 1);
    assert.equal(f.data.TopologyCreateIntent[0].attempts, 0);
    assert.equal(f.data.TopologyCreateIntent[0].status, 'waiting');
    assert.equal(f.data.TopologyCreateIntent[0].waitingReason, 'TOPOLOGY_INTENT_RESOURCE_BUSY');
});

test('an undispatched successor refreshes its selected union after a predecessor settles', async () => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const f = fixture(); const queued = withAdmission(f); const service = new TopologyIntentService(f.dependencies);
    const created = await service.accept({ version: 2, kind: 'link.create', expectedTopologyRevision: 7, requestKey: 'before', link: f.link() });
    const successor = await service.accept({ version: 2, kind: 'link.apply', expectedTopologyRevision: 8,
        requestKey: 'after', linkId: created.linkId, desiredVersion: created.desiredVersion });
    let expanded = false;
    f.dependencies.resolveIntentResources = async () => expanded ? [ids[0], ids[1], ids[2]] : [ids[0], ids[1]];
    const consumer = new TopologyIntentConsumer(f.dependencies);
    await consumer.runOnce();
    f.data.TopologyOperation[0].status = 'succeeded'; f.data.TopologyOperation[0].heldTopologyAdmission = false;
    expanded = true;
    f.data.CascadeTopologyState[0].topologyAdmissionCount = 99; // Unrelated selected/legacy metadata is never cleared.
    f.data.CascadeTopologyState[0].revision = 43;
    await consumer.runOnce();
    const row = f.data.TopologyCreateIntent.find(intent => String(intent._id) === successor.jobId);
    assert.equal(row.status, 'admitted');
    assert.deepEqual(queued[1].resourceNodeIds, [ids[0], ids[1], ids[2]]);
    assert.equal(queued[1].expectedTopologyRevision, 43);
    assert.equal(f.data.CascadeTopologyState[0].topologyAdmissionCount, 99);
    assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 1);
});

test('an uncertain preparation error is retained rather than blanket-retried', async () => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const f = fixture(); let calls = 0;
    f.dependencies.intentOperationAdmission = { db: f.dependencies.CascadeLink.db, async queue() { calls++; throw Error('unclassified outcome'); } };
    await new TopologyIntentService(f.dependencies).accept({ version: 2, kind: 'link.create', expectedTopologyRevision: 7, requestKey: 'uncertain', link: f.link() });
    const consumer = new TopologyIntentConsumer({ ...f.dependencies, backoffMs: 0 });
    await consumer.runOnce(); await consumer.runOnce();
    assert.equal(calls, 1);
    assert.equal(f.data.TopologyCreateIntent[0].status, 'blocked');
    assert.equal(f.data.TopologyCreateIntent[0].errorCode, 'TOPOLOGY_INTENT_PREPARE_UNCERTAIN');
    assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 1);
});

test('manual and delete persist the requested version; delete requires a joined tombstone writer', async () => {
    const { linkDesiredVersion } = require('../services/topologyIntentService');
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const f = fixture(); const queued = withAdmission(f);
    const stored = JSON.parse(JSON.stringify(new LinkModel({ ...f.link(), tunnelUuid: 'retained-secret' }).toObject()));
    f.data.CascadeLink.push(stored);
    const desiredVersion = linkDesiredVersion(stored);
    const service = new TopologyIntentService(f.dependencies);
    const manual = await service.accept({ version: 2, kind: 'link.apply', expectedTopologyRevision: 7,
        requestKey: 'manual', linkId: stored._id, desiredVersion });
    assert.equal(manual.createdLinkId, undefined);
    await assert.rejects(service.accept({ version: 2, kind: 'link.delete', expectedTopologyRevision: 7,
        requestKey: 'delete', linkId: stored._id, desiredVersion }), { code: 'TOPOLOGY_INTENT_DELETE_WRITER_UNAVAILABLE' });
    assert.equal(f.data.TopologyCreateIntent.length, 1);
    assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 1);
    let markerSession;
    f.dependencies.deleteIntentWriter = { db: f.dependencies.CascadeLink.db,
        async markDeleting({ session, linkId, jobId }) {
            markerSession = session;
            return f.dependencies.CascadeLink.updateOne({ _id: linkId }, { $set: { deleteIntentJobId: jobId } }, { session });
        } };
    const deleteService = new TopologyIntentService(f.dependencies);
    const deleted = await deleteService.accept({ version: 2, kind: 'link.delete', expectedTopologyRevision: 7,
        requestKey: 'delete', linkId: stored._id, desiredVersion });
    assert.equal(f.data.CascadeLink.length, 1, 'desired descriptor survives until operation-owned cleanup');
    assert.equal(f.data.CascadeLink[0].deleteIntentJobId, deleted.jobId);
    assert.ok(f.trace.some(([action, name, session]) => action === 'create' && name === 'TopologyCreateIntent' && session === markerSession));
    const consumer = new TopologyIntentConsumer(f.dependencies);
    await consumer.runOnce();
    f.data.TopologyOperation[0].status = 'succeeded'; f.data.TopologyOperation[0].heldTopologyAdmission = false;
    await consumer.runOnce();
    assert.deepEqual(queued.map(call => call.mutation.kind), ['link.apply', 'link.delete']);
    assert.ok(queued.every(call => call.mutation.desiredVersion === desiredVersion));
});

test('a changed requested desired version fails visibly without materialization', async () => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const f = fixture(); const queued = withAdmission(f);
    await new TopologyIntentService(f.dependencies).accept({ version: 2, kind: 'link.create',
        expectedTopologyRevision: 7, requestKey: 'old-version', link: f.link() });
    f.data.CascadeLink[0].tunnelPort++;
    await new TopologyIntentConsumer(f.dependencies).runOnce();
    assert.equal(queued.length, 0);
    assert.equal(f.data.TopologyCreateIntent[0].status, 'failed');
    assert.equal(f.data.TopologyCreateIntent[0].errorCode, 'TOPOLOGY_INTENT_DESIRED_VERSION_CONFLICT');
    assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 0);
});

test('link, revision and capacity roll back when intent insertion fails', async () => {
    const f = fixture();
    f.dependencies.TopologyCreateIntent.create = async () => { throw Error('fixture insert refusal'); };
    await assert.rejects(new TopologyIntentService(f.dependencies).accept({ version: 2, kind: 'link.create',
        expectedTopologyRevision: 7, requestKey: 'atomic-refusal', link: f.link() }), /fixture insert refusal/);
    assert.equal(f.data.CascadeLink.length, 0);
    assert.equal(f.data.TopologyCreateIntent.length, 0);
    assert.equal(f.data.TopologyIntentQueueState.length, 0);
    assert.equal(f.data.CascadeTopologyState[0].revision, 7);
});

test('unknown v2 acceptance commit confirms the exact persisted job without regenerating credentials', async () => {
    const f = fixture(); let generated = 0; let transactions = 0;
    const run = f.dependencies.transactionRunner;
    f.dependencies.prepareLink = async link => ({ ...link, tunnelUuid: `generated-${++generated}` });
    f.dependencies.transactionRunner = async work => {
        transactions++; await run(work);
        throw { hasErrorLabel: label => label === 'UnknownTransactionCommitResult' };
    };
    const job = await new TopologyIntentService(f.dependencies).accept({ version: 2, kind: 'link.create',
        expectedTopologyRevision: 7, requestKey: 'unknown-accept', link: f.link() });
    assert.equal(job.linkId, f.data.CascadeLink[0]._id);
    assert.equal(transactions, 1); assert.equal(generated, 1);
    assert.deepEqual(f.trace.filter(([name]) => ['readConcern', 'read', 'maxTimeMS'].includes(name)),
        [['readConcern', 'majority'], ['read', 'primary'], ['maxTimeMS', 5000]]);
});

test('legacy version-one acceptance is still create-only and never saves a desired link early', async () => {
    const f = fixture(); const service = new TopologyIntentService(f.dependencies);
    const legacy = { expectedTopologyRevision: 7, requestKey: 'legacy', link: { ...f.link(), tunnelUuid: 'legacy-secret' } };
    const accepted = await service.accept(legacy);
    assert.equal(f.data.TopologyCreateIntent[0].version, 1);
    assert.equal(f.data.CascadeLink.length, 0);
    assert.equal(accepted.kind, undefined);
    assert.deepEqual(await service.accept(legacy), accepted);
    assert.equal(f.data.TopologyCreateIntent.length, 1);
    await assert.rejects(service.accept({ ...legacy, kind: 'link.delete' }), { code: 'INVALID_TOPOLOGY_INTENT' });
});

test('real intent schemas validate v2 pins and preserve legacy rows without invented defaults', async () => {
    const Model = require('../models/topologyCreateIntentModel');
    const Queue = require('../models/topologyIntentQueueStateModel');
    const base = { executionContext: context, requestKey: 'schema', payloadHash: 'a'.repeat(64), payload: {},
        ordinal: 1, acceptanceRevision: 7, status: 'waiting' };
    const legacy = new Model({ ...base, version: 1 }); await legacy.validate();
    assert.equal(legacy.kind, undefined); assert.equal(legacy.resourceNodeIds, undefined);
    await assert.rejects(new Model({ ...base, version: 2 }).validate(), /linkId|desiredVersion|kind|resourceNodeIds/);
    await assert.rejects(new Model({ ...base, version: 2, kind: 'link.create', linkId: ids[0],
        desiredVersion: 'b'.repeat(64), resourceNodeIds: [ids[0]] }).validate(), /createdLinkId/);
    for (const kind of ['link.create', 'link.apply', 'link.delete']) {
        await new Model({ ...base, version: 2, kind, linkId: ids[0],
            ...(kind === 'link.create' ? { createdLinkId: ids[0] } : {}),
            desiredVersion: 'b'.repeat(64), resourceNodeIds: [ids[0], ids[1]] }).validate();
    }
    await assert.rejects(new Queue({ _id: 'create-v1', outstanding: 1.5, ordinal: 1 }).validate(), /outstanding/);
});

test('capacity and stale-form refusals leave no second job or desired row', async () => {
    const f = fixture(); const service = new TopologyIntentService({ ...f.dependencies, capacity: 1 });
    await service.accept({ version: 2, kind: 'link.create', expectedTopologyRevision: 7, requestKey: 'capacity-one', link: f.link() });
    await assert.rejects(service.accept({ version: 2, kind: 'link.create', expectedTopologyRevision: 7,
        requestKey: 'stale', link: f.link(1) }), { code: 'STALE_TOPOLOGY_REVISION' });
    await assert.rejects(service.accept({ version: 2, kind: 'link.create', expectedTopologyRevision: 8,
        requestKey: 'overflow', link: f.link(1) }), { code: 'TOPOLOGY_INTENT_BACKLOG_FULL' });
    assert.equal(f.data.CascadeLink.length, 1); assert.equal(f.data.TopologyCreateIntent.length, 1);
    assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 1);
    assert.equal(f.data.CascadeTopologyState[0].revision, 8);
});

test('known predispatch transaction abort retries are bounded by maxAttempts', async () => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const f = fixture(); let calls = 0;
    f.dependencies.intentOperationAdmission = { db: f.dependencies.CascadeLink.db, async queue() {
        calls++; throw { hasErrorLabel: label => label === 'TransientTransactionError' };
    } };
    await new TopologyIntentService(f.dependencies).accept({ version: 2, kind: 'link.create',
        expectedTopologyRevision: 7, requestKey: 'bounded-abort', link: f.link() });
    const consumer = new TopologyIntentConsumer({ ...f.dependencies, maxAttempts: 2, backoffMs: 0 });
    await consumer.runOnce(); await consumer.runOnce(); await consumer.runOnce();
    assert.equal(calls, 2); assert.equal(f.data.TopologyCreateIntent[0].attempts, 2);
    assert.equal(f.data.TopologyCreateIntent[0].status, 'failed');
    assert.equal(f.data.TopologyCreateIntent[0].errorCode, 'TOPOLOGY_INTENT_ATTEMPTS_EXHAUSTED');
    assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 0);
});

test('unknown consume commit resumes from the persisted binding instead of creating another operation', async () => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const f = fixture(); const calls = withAdmission(f);
    await new TopologyIntentService(f.dependencies).accept({ version: 2, kind: 'link.create',
        expectedTopologyRevision: 7, requestKey: 'consume-unknown', link: f.link() });
    const run = f.dependencies.transactionRunner; let transactions = 0;
    const consumer = new TopologyIntentConsumer({ ...f.dependencies, transactionRunner: async work => {
        transactions++; const result = await run(work);
        if (transactions === 2) throw { hasErrorLabel: label => label === 'UnknownTransactionCommitResult' };
        return result;
    } });
    await consumer.runOnce();
    assert.equal(f.data.TopologyCreateIntent[0].status, 'admitted');
    await new TopologyIntentConsumer(f.dependencies).runOnce();
    assert.equal(calls.length, 1); assert.equal(f.data.TopologyOperation.length, 1);
    assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 1);
});

test('a scoped draft wrapper cannot acknowledge or release an outer intent transaction early', async () => {
    const f = fixture(); let locks = 0;
    f.dependencies.withScopedNodeLocks = async () => { locks++; };
    await assert.rejects(new TopologyIntentService(f.dependencies).accept({ version: 2, kind: 'link.create',
        expectedTopologyRevision: 7, requestKey: 'requires-joined-writer', link: f.link() }), { code: 'TOPOLOGY_INTENT_DRAFT_TRANSACTION_UNAVAILABLE' });
    assert.equal(locks, 0); assert.equal(f.data.CascadeLink.length, 0); assert.equal(f.data.TopologyCreateIntent.length, 0);
});

module.exports = { fixture, ids, context };
