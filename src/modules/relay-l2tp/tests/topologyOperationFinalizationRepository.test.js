'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    TopologyOperationFinalizationRepository,
} = require('../repositories/topologyOperationFinalizationRepository');
const { TopologyOperationFinalizer } = require('../services/topologyOperationFinalizer');

const NOW = new Date('2026-09-22T10:00:00.000Z');
const LEASE_UNTIL = new Date('2026-09-22T10:00:30.000Z');
const SESSION = Object.freeze({ id: 'topology-finalization-transaction' });

function clone(value) {
    return structuredClone(value);
}

function equalValue(left, right) {
    if (left instanceof Date && right instanceof Date) {
        return left.getTime() === right.getTime();
    }
    return left === right;
}

function matches(document, filter) {
    return Object.entries(filter).every(([key, expected]) => {
        const actual = key.split('.').reduce((value, segment) => value?.[segment], document);
        if (expected && typeof expected === 'object' && !(expected instanceof Date)) {
            if (Object.hasOwn(expected, '$eq') && !equalValue(actual, expected.$eq)) return false;
            if (Object.hasOwn(expected, '$gt') && !(actual > expected.$gt)) return false;
            if (Object.hasOwn(expected, '$exists')
                && (actual !== undefined) !== expected.$exists) return false;
            return true;
        }
        return equalValue(actual, expected);
    });
}

function applySet(document, update) {
    Object.assign(document, clone(update.$set || {}));
    for (const field of Object.keys(update.$unset || {})) delete document[field];
    for (const [field, increment] of Object.entries(update.$inc || {})) {
        document[field] += increment;
    }
}

function createHarness(overrides = {}) {
    const store = {
        operation: {
            _id: 'operation-7',
            topologyRevision: 7,
            priorDeployedRevision: 5,
            status: 'committing',
            leaseOwner: 'worker-1',
            leaseUntil: LEASE_UNTIL,
            finishedAt: null,
            nodes: [{ candidate: { bytes: [1, 2, 3] }, secret: 'must-stay-untouched' }],
            ...(overrides.operation || {}),
        },
        topology: {
            _id: 'singleton',
            revision: 7,
            deployedRevision: 5,
            ...(overrides.topology || {}),
        },
    };
    const calls = [];
    const TopologyOperation = {
        findById(id) {
            return {
                select() { return this; },
                session(value) { assert.strictEqual(value, SESSION); return this; },
                async lean() { return id === store.operation._id
                    ? { heldTopologyAdmission: store.operation.heldTopologyAdmission,
                        ...(store.operation.pppWait ? { pppWait: clone(store.operation.pppWait),
                            nodes: clone(store.operation.nodes) } : {}) } : null; },
            };
        },
        updateOne(filter, update, options) {
            calls.push({ model: 'TopologyOperation', filter, update, options });
            if (!matches(store.operation, filter)) return Promise.resolve({ matchedCount: 0 });
            applySet(store.operation, update);
            return Promise.resolve({ matchedCount: 1, modifiedCount: 1 });
        },
    };
    const CascadeTopologyState = {
        updateOne(filter, update, options) {
            calls.push({ model: 'CascadeTopologyState', filter, update, options });
            if (!matches(store.topology, filter)) return Promise.resolve({ matchedCount: 0 });
            applySet(store.topology, update);
            return Promise.resolve({ matchedCount: 1, modifiedCount: 1 });
        },
    };
    const transactionRunner = async work => {
        const before = clone(store);
        calls.push({ transaction: 'begin', session: SESSION });
        try {
            const result = await work(SESSION);
            if (overrides.transactionError) throw overrides.transactionError;
            calls.push({ transaction: 'commit', session: SESSION });
            return result;
        } catch (error) {
            store.operation = before.operation;
            store.topology = before.topology;
            calls.push({ transaction: 'abort', session: SESSION });
            throw error;
        }
    };
    const repository = new TopologyOperationFinalizationRepository({
        TopologyOperation,
        CascadeTopologyState,
        transactionRunner,
    });
    return { calls, repository, store };
}

function request(overrides = {}) {
    return {
        operationId: 'operation-7',
        owner: 'worker-1',
        leaseUntil: LEASE_UNTIL,
        topologyRevision: 7,
        priorDeployedRevision: 5,
        now: NOW,
        ...overrides,
    };
}

test('finalizeSucceeded marks active cascade links deployed in the same transaction', async () => {
    const harness = createHarness();
    const linkCalls = [];
    const CascadeLink = {
        updateMany(filter, update, options) {
            linkCalls.push({ filter, update, options });
            return Promise.resolve({ matchedCount: 2, modifiedCount: 2 });
        },
    };
    const repository = new TopologyOperationFinalizationRepository({
        TopologyOperation: harness.repository.TopologyOperation,
        CascadeTopologyState: harness.repository.CascadeTopologyState,
        CascadeLink,
        transactionRunner: async work => work(SESSION),
    });

    const finalized = await repository.finalizeSucceeded(request());

    assert.equal(finalized?.deployedRevision, 7);
    assert.deepEqual(linkCalls, [{
        filter: { active: true },
        update: { $set: { status: 'deployed' } },
        options: { runValidators: true, session: SESSION },
    }]);
});

test('successful finalization records execution success without implying client readiness', async () => {
    const harness = createHarness(); // legacy document has no readiness field
    const result = await harness.repository.finalizeSucceeded(request());
    assert.equal(result?.operationId, 'operation-7');
    assert.equal(harness.store.operation.status, 'succeeded');
    assert.equal(harness.store.operation.clientReadiness, 'unverified');
    assert.equal(harness.calls.at(-1).transaction, 'commit');
});

test('atomically marks the leased committing operation succeeded and advances deployedRevision', async () => {
    const harness = createHarness();

    const finalized = await harness.repository.finalizeSucceeded(request());

    assert.deepEqual(finalized, {
        operationId: 'operation-7',
        topologyRevision: 7,
        deployedRevision: 7,
        finishedAt: NOW,
    });
    assert.deepEqual(harness.store.operation, {
        _id: 'operation-7',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        status: 'succeeded',
        clientReadiness: 'unverified',
        leaseOwner: 'worker-1',
        leaseUntil: null,
        finishedAt: NOW,
        nodes: [{ candidate: { bytes: [1, 2, 3] }, secret: 'must-stay-untouched' }],
    });
    assert.deepEqual(harness.store.topology, {
        _id: 'singleton',
        revision: 7,
        deployedRevision: 7,
    });
    assert.deepEqual(harness.calls, [
        { transaction: 'begin', session: SESSION },
        {
            model: 'TopologyOperation',
            filter: {
                _id: 'operation-7',
                topologyRevision: 7,
                priorDeployedRevision: 5,
                status: 'committing',
                leaseOwner: 'worker-1',
                leaseUntil: { $eq: LEASE_UNTIL, $gt: NOW },
            },
            update: {
                $set: {
                    status: 'succeeded',
                    clientReadiness: 'unverified',
                    finishedAt: NOW,
                    leaseUntil: null,
                },
            },
            options: { runValidators: true, session: SESSION },
        },
        {
            model: 'CascadeTopologyState',
            filter: {
                _id: 'singleton',
                revision: 7,
                deployedRevision: 5,
            },
            update: { $set: { deployedRevision: 7 } },
            options: {
                runValidators: true,
                session: SESSION,
                timestamps: false,
            },
        },
        { transaction: 'commit', session: SESSION },
    ]);
    assert.doesNotMatch(JSON.stringify(harness.calls), /candidate|bytes|secret/i);
});

test('fresh PPP proof fences relay revision and releases admission on success', async () => {
    const relayNode = 'aaaaaaaaaaaaaaaaaaaaaaaa';
    const wait = { lockOwner: 'worker-1', relayNode, credentialRevision: 7,
        locks: [{ node: relayNode, generation: 'old-generation' }],
        releasedNodes: [relayNode] };
    const harness = createHarness({ operation: {
        heldTopologyAdmission: true, pppWait: wait,
        nodes: [{ node: relayNode, role: 'relay' }],
    }, topology: { topologyAdmissionCount: 1 } });
    const stateWrites = [];
    const db = {};
    harness.repository.CascadeTopologyState.db = db;
    harness.repository.RelayL2tpState = { db, async updateOne(filter, update, options) {
        stateWrites.push({ filter, update, options });
        return { matchedCount: 1 };
    } };
    const proof = [{ relayNode, credentialRevision: 8 }];
    assert.equal((await harness.repository.finalizeSucceeded(request({ pppProof: proof })))?.operationId,
        'operation-7');
    assert.equal(harness.store.operation.status, 'succeeded');
    assert.equal(harness.store.operation.pppWait, undefined);
    assert.equal(harness.store.operation.heldTopologyAdmission, false);
    assert.equal(harness.store.topology.topologyAdmissionCount, 0);
    assert.deepEqual(stateWrites, [{ filter: { node: relayNode, status: 'installed',
        desiredState: 'installed', secretRevision: 8 },
    update: { $inc: { replacementFence: 1 } }, options: { session: SESSION } }]);
});

test('PPP wait with unreleased fresh probe generation cannot finalize', async () => {
    const relayNode = 'aaaaaaaaaaaaaaaaaaaaaaaa';
    const harness = createHarness({ operation: { heldTopologyAdmission: true,
        nodes: [{ node: relayNode, role: 'relay' }],
        pppWait: { lockOwner: 'worker-1', relayNode, credentialRevision: 7,
            locks: [{ node: relayNode, generation: 'old' }], releasedNodes: [relayNode],
            probeLocks: [{ node: relayNode, owner: 'worker-2', generation: 'fresh' }] },
    }, topology: { topologyAdmissionCount: 1 } });
    let writes = 0;
    harness.repository.RelayL2tpState = { async updateOne() { writes += 1; return { matchedCount: 1 }; } };
    const before = clone(harness.store);
    assert.equal(await harness.repository.finalizeSucceeded(request({
        pppProof: [{ relayNode, credentialRevision: 8 }],
    })), null);
    assert.deepEqual(harness.store, before);
    assert.equal(writes, 0);
});

test('PPP wait finalization fences a concurrent user edit and preserves topology admission', async () => {
    const relayNode = 'aaaaaaaaaaaaaaaaaaaaaaaa';
    const wait = { relayNode, credentialRevision: 7, locks: [
        { node: relayNode, generation: 'prior-generation' }], releasedNodes: [relayNode] };
    const harness = createHarness({
        operation: { heldTopologyAdmission: true, pppWait: wait,
            nodes: [{ node: relayNode, role: 'relay' }] },
        topology: { topologyAdmissionCount: 1 },
    });
    const stateWrites = [];
    harness.repository.RelayL2tpState = {
        db: harness.repository.CascadeTopologyState.db,
        async updateOne(filter, update, options) {
            stateWrites.push({ filter, update, options });
            return { matchedCount: 0 }; // concurrent user edit incremented secretRevision
        },
    };
    const before = clone(harness.store);
    const proof = [{ relayNode, credentialRevision: 7 }];
    assert.equal(await harness.repository.finalizeSucceeded(request({ pppProof: proof })), null);
    assert.deepEqual(harness.store, before);
    assert.equal(harness.calls.at(-1).transaction, 'abort');
    assert.equal(stateWrites.length, 1);
    assert.equal(stateWrites[0].filter.secretRevision, 7);
    assert.equal(stateWrites[0].options.session, SESSION);
});

test('successful admitted operation releases its slot in the same transaction so a second link can queue', async () => {
    const harness = createHarness({
        operation: { heldTopologyAdmission: true },
        topology: { topologyAdmissionCount: 1 },
    });
    const finalized = await harness.repository.finalizeSucceeded(request());
    assert.equal(finalized?.operationId, 'operation-7');
    assert.equal(harness.store.operation.status, 'succeeded');
    assert.equal(harness.store.operation.heldTopologyAdmission, false);
    assert.equal(harness.store.topology.topologyAdmissionCount, 0);
    const singletonWrite = harness.calls.find(call => call.model === 'CascadeTopologyState');
    assert.equal(singletonWrite.filter.topologyAdmissionCount, 1);
    assert.deepEqual(singletonWrite.update.$inc, { topologyAdmissionCount: -1 });
});

test('an unavailable admission slot aborts both success and release', async () => {
    const harness = createHarness({
        operation: { heldTopologyAdmission: true },
        topology: { topologyAdmissionCount: 0 },
    });
    await assertRejectedWithoutChanges(harness);
});

async function assertRejectedWithoutChanges(harness, candidateRequest = request()) {
    const before = clone(harness.store);

    const finalized = await harness.repository.finalizeSucceeded(candidateRequest);

    assert.equal(finalized, null);
    assert.deepEqual(harness.store, before);
    assert.equal(harness.calls.at(-1).transaction, 'abort');
}

test('rejects a stale lease owner without changing either document', async () => {
    const harness = createHarness({
        operation: { leaseOwner: 'worker-2' },
    });

    await assertRejectedWithoutChanges(harness);

    assert.deepEqual(
        harness.calls.filter(call => call.model).map(call => call.model),
        ['TopologyOperation'],
    );
});

test('rejects an expired lease without changing either document', async () => {
    const expiredLease = new Date('2026-09-22T09:59:59.999Z');
    const harness = createHarness({
        operation: { leaseUntil: expiredLease },
    });

    await assertRejectedWithoutChanges(harness, request({ leaseUntil: expiredLease }));

    assert.deepEqual(
        harness.calls.filter(call => call.model).map(call => call.model),
        ['TopologyOperation'],
    );
});

test('rolls back the operation when the topology revision changed', async () => {
    const harness = createHarness({ topology: { revision: 8 } });

    await assertRejectedWithoutChanges(harness);

    assert.deepEqual(
        harness.calls.filter(call => call.model).map(call => call.model),
        ['TopologyOperation', 'CascadeTopologyState'],
    );
});

test('rolls back the operation when the prior deployed revision changed', async () => {
    const harness = createHarness({ topology: { deployedRevision: 6 } });

    await assertRejectedWithoutChanges(harness);

    assert.deepEqual(
        harness.calls.filter(call => call.model).map(call => call.model),
        ['TopologyOperation', 'CascadeTopologyState'],
    );
});

test('rolls back both document updates when the transaction fails', async () => {
    const transactionError = new Error('transaction commit failed');
    const harness = createHarness({ transactionError });
    const before = clone(harness.store);

    await assert.rejects(
        harness.repository.finalizeSucceeded(request()),
        error => error === transactionError,
    );

    assert.deepEqual(harness.store, before);
    assert.deepEqual(
        harness.calls.filter(call => call.model).map(call => call.model),
        ['TopologyOperation', 'CascadeTopologyState'],
    );
    assert.equal(harness.calls.at(-1).transaction, 'abort');
});

// ---------------------------------------------------------------------------
// Scoped operation kinds (link.apply / domain.reconcile): an explicit per-link
// autoDeploy event must mark only its own links deployed and must NOT advance
// the global deployedRevision — otherwise a preexisting pending link would be
// silently reported as deployed by an operation that never touched it.
// ---------------------------------------------------------------------------

function scopedHarness({ kind = 'domain.reconcile', linkIds = ['link-a', 'link-b'], linkId = linkIds[0], staged = kind === 'link.apply' ? true : undefined, missingStaged = false, topology = {}, includeLinks = true, heldAdmission = false } = {}) {
    const harness = createHarness({
        topology: { ...topology, ...(heldAdmission ? { topologyAdmissionCount: 1 } : {}) },
        ...(heldAdmission ? { operation: { heldTopologyAdmission: true } } : {}),
    });
    const linkCalls = [];
    const TopologyOperation = {
        ...harness.repository.TopologyOperation,
        findById(id) {
            return {
                select() { return this; },
                session() { return this; },
                async lean() {
                    return id === 'operation-7'
                        ? kind === 'domain.sync' ? { kind,
                            ...(heldAdmission ? { heldTopologyAdmission: harness.store.operation.heldTopologyAdmission } : {}) }
                            : { kind, linkId, linkIds, ...(missingStaged ? {} : { staged }),
                                ...(heldAdmission ? { heldTopologyAdmission: harness.store.operation.heldTopologyAdmission } : {}) }
                        : null;
                },
            };
        },
    };
    const CascadeLink = {
        updateMany(filter, update, options) {
            linkCalls.push({ filter, update, options });
            const count = Array.isArray(filter._id?.$in) ? filter._id.$in.length : linkIds.length;
            return Promise.resolve({ matchedCount: count, modifiedCount: count });
        },
    };
    const repository = new TopologyOperationFinalizationRepository({
        TopologyOperation,
        CascadeTopologyState: harness.repository.CascadeTopologyState,
        CascadeLink: includeLinks ? CascadeLink : null,
        transactionRunner: harness.repository.transactionRunner,
    });
    return { harness, repository, linkCalls };
}

test('each successful scoped auto-deploy releases its own admission without advancing unrelated draft baseline', async t => {
    for (const kind of ['link.apply', 'domain.reconcile']) {
        await t.test(kind, async () => {
            const { harness, repository } = scopedHarness({ kind, heldAdmission: true });
            const result = await repository.finalizeSucceeded(request());
            assert.equal(result?.scopeKind, kind);
            assert.equal(harness.store.topology.deployedRevision, 5);
            assert.equal(harness.store.topology.topologyAdmissionCount, 0);
            assert.equal(harness.store.operation.heldTopologyAdmission, false);
            assert.equal(await repository.finalizeSucceeded(request()), null,
                'a replay cannot release a second slot');
        });
    }
});

test('scoped domain.reconcile commit marks only its own links and keeps the global revision', async () => {
    const { harness, repository, linkCalls } = scopedHarness();

    const finalized = await repository.finalizeSucceeded(request());

    assert.deepEqual(finalized, {
        operationId: 'operation-7',
        topologyRevision: 7,
        deployedRevision: 5,
        scopeKind: 'domain.reconcile',
        finishedAt: NOW,
    });
    assert.equal(harness.store.operation.status, 'succeeded');
    assert.equal(harness.store.topology.deployedRevision, 5,
        'a scoped reconcile must not claim the whole revision is deployed');
    assert.equal(harness.calls.filter(call => call.model === 'CascadeTopologyState').length, 1,
        'a scoped commit must still fence the pinned revision and prior deployed revision');
    assert.deepEqual(linkCalls, [{
        filter: { _id: { $in: ['link-a', 'link-b'] } },
        update: { $set: { status: 'deployed' } },
        options: { runValidators: true, session: SESSION },
    }]);
});

test('real scoped repository and finalizer agree without advancing global deployedRevision', async () => {
    const { harness, repository } = scopedHarness({ kind: 'link.apply', staged: false });
    const finalizer = new TopologyOperationFinalizer({
        repository,
        clock: { now: () => NOW },
    });
    assert.deepEqual(await finalizer.finalizeSucceeded({
        operationId: 'operation-7', owner: 'worker-1', leaseUntil: LEASE_UNTIL,
        topologyRevision: 7, priorDeployedRevision: 5,
    }), {
        operationId: 'operation-7', topologyRevision: 7,
        deployedRevision: 5, finishedAt: NOW,
    });
    assert.equal(harness.store.operation.status, 'succeeded');
    assert.equal(harness.store.topology.deployedRevision, 5);
});

test('scoped link.apply commit is likewise confined to its own links', async () => {
    const { harness, repository, linkCalls } = scopedHarness({
        kind: 'link.apply',
        linkIds: ['link-only'],
    });

    const finalized = await repository.finalizeSucceeded(request());

    assert.equal(finalized?.topologyRevision, 7);
    assert.equal(harness.store.topology.deployedRevision, 5);
    assert.deepEqual(linkCalls.map(call => call.filter), [{ _id: { $in: ['link-only'] } }]);
    assert.deepEqual(linkCalls.map(call => call.update), [{ $set: { status: 'staged' } }]);
});

test('scoped link.apply stages only its requested link, not its deployed baseline', async () => {
    const { harness, repository, linkCalls } = scopedHarness({
        kind: 'link.apply', linkId: 'link-new',
        linkIds: ['link-old', 'link-new'],
    });
    const finalized = await repository.finalizeSucceeded(request());
    assert.equal(finalized?.topologyRevision, 7);
    assert.equal(harness.store.topology.deployedRevision, 5);
    assert.deepEqual(linkCalls, [{
        filter: { _id: { $in: ['link-new'] } },
        update: { $set: { status: 'staged' } },
        options: { runValidators: true, session: SESSION },
    }]);
});

test('scoped finalization rejects a requested link outside its declared links', async () => {
    const { harness, repository, linkCalls } = scopedHarness({
        kind: 'link.apply', linkId: 'link-outsider', linkIds: ['link-old'],
    });
    assert.equal(await repository.finalizeSucceeded(request()), null);
    assert.equal(harness.store.operation.status, 'committing');
    assert.deepEqual(linkCalls, []);
});

test('complete scoped link.apply activates every staged baseline link without global Sync', async () => {
    const { harness, repository, linkCalls } = scopedHarness({
        kind: 'link.apply', linkId: 'link-b', linkIds: ['link-a', 'link-b'], staged: false,
    });
    const finalized = await repository.finalizeSucceeded(request());
    assert.equal(finalized?.topologyRevision, 7);
    assert.equal(harness.store.topology.deployedRevision, 5);
    assert.deepEqual(linkCalls.map(call => call.filter), [{ _id: { $in: ['link-a', 'link-b'] } }]);
    assert.deepEqual(linkCalls.map(call => call.update), [{ $set: { status: 'deployed' } }]);
});

test('scoped link.apply without durable staged bit cannot finalize as ready', async () => {
    const { harness, repository, linkCalls } = scopedHarness({
        kind: 'link.apply', linkId: 'link-a', linkIds: ['link-a'], missingStaged: true,
    });
    assert.equal(await repository.finalizeSucceeded(request()), null);
    assert.equal(harness.store.operation.status, 'committing');
    assert.equal(harness.store.topology.deployedRevision, 5);
    assert.deepEqual(linkCalls, []);
});

test('malformed scoped operation cannot fall back to global deployment', async () => {
    const { harness, repository, linkCalls } = scopedHarness({ kind: 'link.apply', linkIds: [] });
    const finalized = await repository.finalizeSucceeded(request());

    assert.equal(finalized, null);
    assert.equal(harness.store.operation.status, 'committing');
    assert.equal(harness.store.topology.deployedRevision, 5);
    assert.deepEqual(linkCalls, []);
    assert.equal(harness.calls.at(-1).transaction, 'abort');
});

test('scoped finalization refuses a stale topology revision before marking links', async () => {
    const { harness, repository, linkCalls } = scopedHarness({ topology: { revision: 8 } });
    const finalized = await repository.finalizeSucceeded(request());

    assert.equal(finalized, null);
    assert.equal(harness.store.operation.status, 'committing');
    assert.equal(harness.store.topology.deployedRevision, 5);
    assert.deepEqual(linkCalls, []);
    assert.equal(harness.calls.at(-1).transaction, 'abort');
});

test('scoped finalization requires a cascade-link updater', async () => {
    const { harness, repository } = scopedHarness({ includeLinks: false });
    const finalized = await repository.finalizeSucceeded(request());
    assert.equal(finalized, null);
    assert.equal(harness.store.operation.status, 'committing');
    assert.equal(harness.store.topology.deployedRevision, 5);
});

test('an explicit domain.sync keeps the legacy global commit semantics', async () => {
    const { harness, repository, linkCalls } = scopedHarness({ kind: 'domain.sync' });

    const finalized = await repository.finalizeSucceeded(request());

    assert.equal(finalized?.deployedRevision, 7);
    assert.equal(harness.store.topology.deployedRevision, 7,
        'the optional full Sync must still advance the global deployed revision');
    assert.deepEqual(linkCalls.map(call => call.filter), [{ active: true }]);
});

function replacementHarness({ revision = 7, pathIds = ['upstream', 'old'],
    newStatus = 'pending', relayStatus = 'installed', relayNode = 'owner',
    activePathKey = 'main' } = {}) {
    const h = createHarness({ operation: { heldTopologyAdmission: true },
        topology: { topologyAdmissionCount: 1, revision } });
    const group = { paths: [{ pathKey: 'main', linkIds: [...pathIds], enabled: true }] };
    const links = [{ _id: 'upstream', active: true, status: 'deployed' },
        { _id: 'old', active: true, status: 'online' },
        { _id: 'new', active: true, status: newStatus },
        { _id: 'unrelated', active: true, status: 'pending' }];
    h.repository.TopologyOperation.findById = () => ({
        select() { return this; }, session() { return this; },
        async lean() { return { heldTopologyAdmission: h.store.operation.heldTopologyAdmission,
            kind: 'link.replace', linkId: 'new', linkIds: ['new', 'upstream'],
            oldLinkId: 'old', groupId: 'group', pathKey: 'main',
            ownerNodeId: 'owner', oldPathLinkIds: ['upstream', 'old'] }; },
    });
    h.repository.CascadeRouteGroup = {
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, SESSION);
            if (filter._id !== 'group' || JSON.stringify(filter.paths.$elemMatch.linkIds)
                !== JSON.stringify(group.paths[0].linkIds)
                || filter.paths.$elemMatch.pathKey !== 'main') return { matchedCount: 0 };
            group.paths[0].linkIds = clone(update.$set['paths.$.linkIds']);
            return { matchedCount: 1 };
        },
    };
    h.repository.RelayL2tpState = {
        async updateOne(filter, update, options) {
            assert.equal(filter.routeGroup, 'group');
            assert.equal(filter.status, 'installed');
            assert.equal(filter.desiredState, 'installed');
            assert.deepEqual(update, { $inc: { replacementFence: 1 } });
            assert.strictEqual(options.session, SESSION);
            return { matchedCount: relayStatus === 'installed'
                && (filter.node === undefined || filter.node === relayNode)
                && (filter.activePathKey === undefined || filter.activePathKey === activePathKey)
                ? 1 : 0 };
        },
    };
    h.repository.CascadeLink = {
        async updateMany(filter, update, options) {
            assert.strictEqual(options.session, SESSION);
            const selected = links.filter(link => filter._id.$in.includes(link._id)
                && filter.active === link.active && filter.status.$in.includes(link.status));
            for (const link of selected) Object.assign(link, update.$set);
            return { matchedCount: selected.length };
        },
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, SESSION);
            const selected = links.find(link => link._id === filter._id
                && link.active === filter.active && filter.status.$in.includes(link.status));
            if (!selected) return { matchedCount: 0 };
            Object.assign(selected, update.$set);
            return { matchedCount: 1 };
        },
    };
    const repository = h.repository;
    const run = repository.transactionRunner;
    repository.transactionRunner = async work => {
        const before = clone({ group, links });
        try { return await run(work); }
        catch (error) {
            Object.assign(group, before.group);
            links.splice(0, links.length, ...before.links);
            throw error;
        }
    };
    return { h, group, links, repository };
}

test('verified replacement atomically swaps its path and retires only the old link', async () => {
    const { h, group, links, repository } = replacementHarness();
    // Neither the operation nor its transaction has a PPP/state writer.
    const pppSnapshot = { relay: { status: 'installed', routeGroupId: 'group',
        pskFingerprint: 'stable', clientCidr: '198.51.100.0/24' },
    users: [{ login: 'existing', desiredRevision: 41, appliedRevision: 41,
        encryptedPassword: 'unchanged' }] };
    const pppBefore = clone(pppSnapshot);
    const result = await repository.finalizeSucceeded(request());
    assert.equal(result?.scopeKind, 'link.replace');
    assert.deepEqual(group.paths[0].linkIds, ['upstream', 'new']);
    assert.deepEqual(links.map(link => [link.active, link.status]), [
        [true, 'deployed'], [false, 'offline'], [true, 'deployed'], [true, 'pending'],
    ]);
    assert.equal(h.store.topology.deployedRevision, 5);
    assert.equal(h.store.topology.topologyAdmissionCount, 0);
    assert.equal(h.store.operation.status, 'succeeded');
    assert.deepEqual(pppSnapshot, pppBefore);
    assert.equal(await repository.finalizeSucceeded(request()), null);
});

for (const scenario of [
    { name: 'L2TP group no longer installed', options: { relayStatus: 'queued' } },
    { name: 'different L2TP owner took over the same group', options: { relayNode: 'other-owner' } },
    { name: 'installed L2TP owner changed its active path', options: { activePathKey: 'other-path' } },
    { name: 'stale topology revision', options: { revision: 8 } },
    { name: 'changed installed path', options: { pathIds: ['upstream', 'unrelated'] } },
    { name: 'new link already changed', options: { newStatus: 'offline' } },
]) {
    test(`replacement rejects ${scenario.name} and rolls back the operation/admission`, async () => {
        const { h, group, links, repository } = replacementHarness(scenario.options);
        const before = clone({ store: h.store, group, links });
        assert.equal(await repository.finalizeSucceeded(request()), null);
        assert.deepEqual({ store: h.store, group, links }, before);
    });
}

function emptyMainAttachHarness(paths, { terminalStatus = 'pending' } = {}) {
    const h = createHarness({ operation: { heldTopologyAdmission: true },
        topology: { topologyAdmissionCount: 1 } });
    const group = { _id: 'group', paths: clone(paths) };
    const owner = { routeGroup: 'group', node: 'relay', activePathKey: 'main',
        status: 'installed', desiredState: 'installed', appliedTopologyRevision: 5,
        secretRevision: 11, replacementFence: 0 };
    const links = [
        { _id: 'portal-relay', portalNode: 'portal', bridgeNode: 'relay', active: true, status: 'staged' },
        { _id: 'relay-next', portalNode: 'relay', bridgeNode: 'next', active: true, status: 'staged' },
        { _id: 'next-bridge', portalNode: 'next', bridgeNode: 'bridge', active: true, status: terminalStatus },
        { _id: 'foreign', portalNode: 'other', bridgeNode: 'elsewhere', active: true, status: 'pending' },
    ];
    const groupWrites = [];
    h.repository.TopologyOperation.findById = () => ({
        select() { return this; }, session(session) { assert.strictEqual(session, SESSION); return this; },
        async lean() { return { heldTopologyAdmission: h.store.operation.heldTopologyAdmission,
            kind: 'link.attach', linkId: 'next-bridge',
            linkIds: ['next-bridge', 'portal-relay', 'relay-next'],
            newPathLinkIds: ['relay-next', 'next-bridge'],
            groupId: 'group', pathKey: 'main', ownerNodeId: 'relay',
            ownerTopologyRevision: 5, ownerCredentialRevision: 11 }; },
    });
    h.repository.RelayL2tpState = {
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, SESSION);
            if (!matches(owner, filter)) return { matchedCount: 0 };
            applySet(owner, update);
            return { matchedCount: 1 };
        },
    };
    h.repository.CascadeRouteGroup = {
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, SESSION);
            groupWrites.push({ filter, update, options });
            if (filter._id !== group._id) return { matchedCount: 0 };
            if (Array.isArray(filter.paths) && filter.paths.length === 0) {
                if (group.paths.length !== 0) return { matchedCount: 0 };
                group.paths = clone(update.$set.paths);
                return { matchedCount: 1 };
            }
            assert.deepEqual(filter, { _id: 'group', paths: { $size: 1 },
                'paths.0.pathKey': 'main', 'paths.0.linkIds': [],
                'paths.0.enabled': { $ne: false } });
            if (group.paths.length !== 1 || group.paths[0].pathKey !== 'main'
                || group.paths[0].enabled === false || group.paths[0].linkIds.length !== 0) {
                return { matchedCount: 0 };
            }
            assert.deepEqual(Object.keys(update.$set), ['paths.0.linkIds']);
            group.paths[0].linkIds = clone(update.$set['paths.0.linkIds']);
            return { matchedCount: 1 };
        },
    };
    h.repository.CascadeLink = {
        find(filter) { return {
            select() { return this; }, session(session) { assert.strictEqual(session, SESSION); return this; },
            async lean() { return clone(links.filter(link => filter._id.$in.includes(link._id))); },
        }; },
        async updateMany(filter, update, options) {
            assert.strictEqual(options.session, SESSION);
            const selected = links.filter(link => filter._id.$in.includes(link._id)
                && link.active === filter.active && filter.status.$in.includes(link.status));
            for (const link of selected) Object.assign(link, clone(update.$set));
            return { matchedCount: selected.length };
        },
    };
    const run = h.repository.transactionRunner;
    h.repository.transactionRunner = async work => {
        const before = clone({ group, owner, links });
        try { return await run(work); }
        catch (error) {
            Object.assign(group, before.group);
            Object.assign(owner, before.owner);
            links.splice(0, links.length, ...before.links);
            throw error;
        }
    };
    return { h, group, owner, links, groupWrites };
}

test('attach atomically fills the sole enabled empty main path without replacing its metadata or unrelated state', async () => {
    const original = { pathKey: 'main', linkIds: [], priority: 4, enabled: true };
    const { h, group, owner, links, groupWrites } = emptyMainAttachHarness([original]);
    const result = await h.repository.finalizeSucceeded(request());
    assert.equal(result?.scopeKind, 'link.attach');
    assert.deepEqual(group.paths, [{ ...original, linkIds: ['relay-next', 'next-bridge'] }]);
    assert.equal(owner.replacementFence, 1);
    assert.deepEqual(links.map(link => link.status), ['deployed', 'deployed', 'deployed', 'pending']);
    assert.equal(h.store.operation.status, 'succeeded');
    assert.equal(h.store.operation.heldTopologyAdmission, false);
    assert.equal(h.store.topology.topologyAdmissionCount, 0);
    assert.equal(h.store.topology.deployedRevision, 5);
    assert.equal(groupWrites.length, 2, 'CAS must try only the empty group and the sole empty main path');
    assert.equal(await h.repository.finalizeSucceeded(request()), null, 'replay cannot publish twice');
});

test('attach rolls back filling an empty main path if the terminal link changes', async () => {
    const { h, group, owner, links, groupWrites } = emptyMainAttachHarness(
        [{ pathKey: 'main', linkIds: [], priority: 4, enabled: true }],
        { terminalStatus: 'offline' },
    );
    const before = clone({ store: h.store, group, owner, links });
    assert.equal(await h.repository.finalizeSucceeded(request()), null);
    assert.equal(groupWrites.length, 2, 'the path was filled before link CAS failed');
    assert.deepEqual({ store: h.store, group, owner, links }, before);
});

for (const [name, paths] of [
    ['nonempty main path', [{ pathKey: 'main', linkIds: ['foreign'], priority: 4, enabled: true }]],
    ['extra path', [{ pathKey: 'main', linkIds: [], priority: 4, enabled: true },
        { pathKey: 'other', linkIds: ['foreign'], priority: 5, enabled: true }]],
    ['disabled main path', [{ pathKey: 'main', linkIds: [], priority: 4, enabled: false }]],
    ['different empty path', [{ pathKey: 'other', linkIds: [], priority: 4, enabled: true }]],
]) {
    test(`attach rejects ${name} without partial publication`, async () => {
        const { h, group, owner, links } = emptyMainAttachHarness(paths);
        const before = clone({ store: h.store, group, owner, links });
        assert.equal(await h.repository.finalizeSucceeded(request()), null);
        assert.deepEqual({ store: h.store, group, owner, links }, before);
    });
}
