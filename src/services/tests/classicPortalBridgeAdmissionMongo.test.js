'use strict';
// Real private Mongo replica set and production lock/repository implementations.
// SSH preview and the remote core are explicitly modeled; no physical claims.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const fixturePath = path.resolve(__dirname, 'classicScopedCascadeDeploymentMongo.test.js');
const text = fs.readFileSync(fixturePath, 'utf8');
const boundary = "test('real Mongo occupied source port";
assert.equal(text.split(boundary).length, 2);
const fixture = new Module(fixturePath, module);
fixture.filename = fixturePath; fixture.paths = Module._nodeModulePaths(path.dirname(fixturePath));
fixture._compile(text.split(boundary)[0] + `\nmodule.exports = { get models(){return models}, reset, state, receipt, input, source, bridge, otherPortal, linkId, oldId, env, mongoose, HyNode, CascadeLink };`, fixturePath);
const f = fixture.exports;
const { createClassicScopedCascadeDeploymentService } = require('../classicScopedCascadeDeploymentService');
const { createClassicPortalBridgePhase } = require('../classicPortalBridgePhase');
const { AsyncResource } = require('node:async_hooks');
const { createTopologyDraftWriteService } = require('../../modules/relay-l2tp/services/topologyDraftWriteService');
const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to a private disposable MongoDB binary' };
const { TopologyDraftRepository, isStandaloneClassicMutation, NODE_FILTER } = require('../../modules/relay-l2tp/repositories/topologyDraftRepository');
const { withScopedClassicNodeLocks } = require('../classicPortalBridgeAdmission');

// REAL transaction writes and separately held real commit. Only the timing of
// an UnknownTransactionCommitResult delivery is modeled, not a server failpoint.
function delayedCommit() {
    let session;
    return {
        async run(work) {
            assert.equal(session, undefined, 'one owned transaction');
            session = await f.mongoose.connection.startSession();
            session.startTransaction({ readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
            await work(session);
            throw Object.assign(new Error('modeled transport unknown commit before held real commit'), {
                errorLabels: ['UnknownTransactionCommitResult'],
            });
        },
        async commit() { await session.commitTransaction(); },
        async close() {
            if (!session) return;
            try { if (session.inTransaction()) await session.abortTransaction(); }
            finally { await session.endSession(); }
        },
    };
}
function removalReceipt() {
    const result = f.receipt();
    result.receipt.kind = 'classic-scoped-reverse-removal';
    delete result.receipt.tunnelEstablished;
    result.receipt.targetAbsent = true;
    for (const p of result.receipt.profiles) p.changed = true;
    for (const p of result.receipt.preservedProfiles) { p.beforeSha256 = p.sha256; p.changed = false; }
    return result;
}

test('native Mongo draft unknown commit retains exact fences before a late real config update commit', local, async () => {
    await setup(); const delayed = delayedCommit(); let coreCalls = 0;
    // Standalone draft classification requires no relay reference inventory.
    await f.models.RelayL2tpState.deleteMany({ node: f.source });
    const repository = new TopologyDraftRepository({ ...f.models, transactionRunner: delayed.run,
        withScopedNodeLocks: withScopedClassicNodeLocks, allowStandaloneClassicDrafts: true });
    try {
        await assert.rejects(repository.commitDraft({ expectedRevision: 4,
            prepare: async () => ({ mutation: { kind: 'link.update', id: f.linkId, changes: { tunnelPort: 11096 } } }),
        }), /modeled transport unknown commit/);
        const locks = await f.models.NodeOperationLock.find().sort({ node: 1 }).lean();
        assert.equal(locks.length, 3, 'selected pair plus unrelated fence retained');
        assert.equal((await f.CascadeLink.findById(f.linkId).lean()).tunnelPort, 10096);
        await assert.rejects(service(async () => { coreCalls++; return f.receipt(); }).queue(f.input()), { code: 'CLASSIC_DEPLOY_NODE_BUSY' });
        assert.equal(coreCalls, 0);
        await delayed.commit();
        assert.equal((await f.CascadeLink.findById(f.linkId).lean()).tunnelPort, 11096);
        assert.equal((await f.state()).revision, 5);
        assert.deepEqual(await f.models.NodeOperationLock.find().sort({ node: 1 }).lean(), locks);
    } finally { await delayed.close(); }
});

test('native Mongo draft validation remains retryable and a known commit releases exact selected locks', local, async () => {
    await setup(); await f.models.RelayL2tpState.deleteMany({ node: f.source });
    const repository = new TopologyDraftRepository({ ...f.models,
        withScopedNodeLocks: withScopedClassicNodeLocks, allowStandaloneClassicDrafts: true });
    let reads = 0;
    const mutation = { kind: 'link.update', id: f.linkId, changes: { tunnelPort: 11096 } };
    await assert.rejects(repository.commitDraft({ expectedRevision: 4, prepare: async () => {
        if (++reads === 2) {
            assert.equal(await f.models.NodeOperationLock.countDocuments(), 3);
            throw new Error('read-only fresh validation refusal');
        }
        return { mutation };
    } }), /read-only fresh validation refusal/);
    assert.equal((await f.CascadeLink.findById(f.linkId).lean()).tunnelPort, 10096);
    assert.equal((await f.state()).revision, 4);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
    assert.deepEqual(await repository.commitDraft({ expectedRevision: 4, prepare: async () => ({ mutation }) }),
        { revision: 5, deployedRevision: 0, standaloneClassicDraft: true });
    assert.equal((await f.CascadeLink.findById(f.linkId).lean()).tunnelPort, 11096);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
});

test('native Mongo swallowed nested draft unknown commit keeps parent generation poisoned', local, async () => {
    await setup(); await f.models.RelayL2tpState.deleteMany({ node: f.source });
    const delayed = delayedCommit();
    const repository = new TopologyDraftRepository({ ...f.models, transactionRunner: delayed.run,
        withScopedNodeLocks: withScopedClassicNodeLocks, allowStandaloneClassicDrafts: true });
    try {
        await withScopedClassicNodeLocks({ nodeIds: [f.source, f.bridge], operationId: 'fixture-parent-db' }, async held => {
            await held.beforeRemoteMutation({ nodeId: f.source, phase: 'modeled-previous-write' });
            await held.settleVerified();
            await assert.rejects(repository.commitDraft({ expectedRevision: 4,
                prepare: async () => ({ mutation: { kind: 'link.update', id: f.linkId, changes: { tunnelPort: 11096 } } }),
            }), /modeled transport unknown commit/);
            // A later known successful nested DB capability cannot clear it.
            const anotherCommitted = await held.beforeDatabaseMutation();
            await anotherCommitted();
            await assert.rejects(held.settleVerified(), { code: 'CLASSIC_CONFIG_WRITE_DATABASE_UNCERTAIN' });
        });
        assert.equal(await f.models.NodeOperationLock.countDocuments(), 3);
    } finally { await delayed.close(); }
});

test('native Mongo independent DELETE releases only after known commit and bounded primary-majority absence', local, async () => {
    for (const failRead of [false, true]) {
        await setup(); let absenceReads = 0;
        const exists = f.CascadeLink.exists;
        f.CascadeLink.exists = function(filter) {
            const query = exists.call(this, filter), setOptions = query.setOptions;
            query.setOptions = function(options) {
                assert.deepEqual(options, { readPreference: 'primary', readConcern: { level: 'majority' }, maxTimeMS: 5000 });
                absenceReads++;
                if (failRead) throw new Error('modeled postcommit majority absence read failure');
                return setOptions.call(this, options);
            };
            return query;
        };
        try {
            const selected = createClassicScopedCascadeDeploymentService({ ...f.models, env: f.env, NodeSSH: Preview,
                cascadeService: { async removeScopedClassicLink(args) {
                    await args.beforeRemoteMutation({ nodeId: f.source, phase: 'modeled-physical-remove' });
                    return removalReceipt();
                } } });
            const deletion = selected.deleteLink({ expectedTopologyRevision: 4, linkId: f.linkId });
            if (failRead) await assert.rejects(deletion, { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
            else assert.deepEqual(await deletion, { revision: 5, deployedRevision: 0 });
            assert.equal(absenceReads, 1);
            assert.equal(await f.CascadeLink.collection.findOne({ _id: new f.mongoose.Types.ObjectId(f.linkId) }), null);
            assert.equal((await f.state()).revision, 5);
            assert.equal(await f.models.NodeOperationLock.countDocuments(), failRead ? 4 : 1);
        } finally { f.CascadeLink.exists = exists; }
    }
});

test('native Mongo checked DELETE unknown commit rearms settled removal before a late real delete commit', local, async () => {
    await setup(); const delayed = delayedCommit(); let coreCalls = 0;
    const connection = f.mongoose.connection, transaction = connection.transaction;
    let transactions = 0;
    connection.transaction = function(work, options) {
        return ++transactions === 2 ? delayed.run(work) : transaction.call(this, work, options);
    };
    try {
        const selected = createClassicScopedCascadeDeploymentService({ ...f.models, env: f.env, NodeSSH: Preview,
            cascadeService: { async removeScopedClassicLink(args) {
                coreCalls++;
                await args.beforeRemoteMutation({ nodeId: f.source, phase: 'modeled-physical-remove' });
                return removalReceipt();
            } } });
        await assert.rejects(selected.deleteLink({ expectedTopologyRevision: 4, linkId: f.linkId }), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
        const locks = await f.models.NodeOperationLock.find().sort({ node: 1 }).lean();
        assert.equal(locks.length, 4, 'whole preservation component plus unrelated fence retained');
        assert.ok(await f.CascadeLink.exists({ _id: f.linkId }));
        await assert.rejects(service(async () => { coreCalls++; return f.receipt(); }).queue(f.input()), { code: 'CLASSIC_DEPLOY_NODE_BUSY' });
        assert.equal(coreCalls, 1, 'second independent apply never calls the core');
        await delayed.commit();
        assert.equal(await f.CascadeLink.exists({ _id: f.linkId }), null);
        assert.equal((await f.state()).revision, 5);
        assert.deepEqual(await f.models.NodeOperationLock.find().sort({ node: 1 }).lean(), locks);
    } finally { connection.transaction = transaction; await delayed.close(); }
});

const outside = '507f1f77bcf86cd799439040';
class Preview {
    async connect() { assert.equal(await f.models.NodeOperationLock.countDocuments({ node: { $in: [f.source, f.bridge, f.otherPortal] } }), 3); }
    disconnect() {}
    async exec(command) {
        assert.doesNotMatch(command, /\.stage|restart|ufw|firewall-cmd|\bmv\b/);
        const marker = command.match(/C3_PORT_READ_[a-f0-9]+/)[0];
        const value = command.includes('C3_READ_CONFIG') ? JSON.stringify({ inbounds: [] }) : '';
        return { code: 0, stdout: `${value}\n${marker}\n`, stderr: '' };
    }
}
async function setup() {
    await f.reset();
    await f.HyNode.updateMany({ _id: { $in: [f.source, f.otherPortal] } }, { $set: { cascadeRole: 'portal' } });
    await f.HyNode.collection.insertOne({ _id: new f.mongoose.Types.ObjectId(outside), name: 'disjoint-private-fixture', type: 'xray', active: true, cascadeRole: 'relay', ip: '192.0.2.40', ssh: { password: 'fixture-only' } });
    await f.models.NodeOperationLock.collection.insertOne({ node: new f.mongoose.Types.ObjectId(outside), owner: 'fixture-unrelated', operationId: 'fixture-unrelated-op', generation: 'fixture-unrelated-generation', remoteUncertain: true, leaseUntil: new Date(Date.now() + 120000) });
    await f.models.CascadeTopologyState.collection.updateOne({ _id: 'singleton' }, { $set: { replacementEpoch: 9, topologyAdmissionCount: 2, remoteAdmissionCount: 7, replacementReservation: { ownerToken: 'fixture-unrelated', epoch: 9 } } });
}
function service(work) {
    return createClassicScopedCascadeDeploymentService({ ...f.models, env: f.env, NodeSSH: Preview,
        cascadeService: { async deployScopedClassicLink(args) { return work(args); } } });
}
async function foreign() { return f.models.NodeOperationLock.findOne({ node: outside }).lean(); }

test('native Mongo default draft factory admits Hysteria terminal Bridge create and update under unrelated busy state', local, async () => {
    await setup();
    await f.HyNode.updateOne({ _id: f.bridge }, { $set: { type: 'hysteria' } });
    await f.models.RelayL2tpState.deleteMany({ node: f.source });
    const before = await f.state(), lock = await foreign(), nodes = await f.HyNode.find().sort({ _id: 1 }).lean();
    const drafts = createTopologyDraftWriteService({ ...f.models, deploymentEnv: f.env });
    const newId = '507f1f77bcf86cd799439023';
    assert.deepEqual(await drafts.createLink({ expectedTopologyRevision: 4, link: {
        _id: newId, name: 'Hysteria terminal draft', portalNode: f.source, bridgeNode: f.bridge,
        mode: 'reverse', active: true, status: 'pending', tunnelPort: 11096, tunnelUuid: 'fixture-hysteria',
    } }), { revision: 5, deployedRevision: 0, standaloneClassicDraft: true });
    assert.deepEqual(await drafts.updateLink({ expectedTopologyRevision: 5, linkId: newId,
        changes: { name: 'edited Hysteria terminal draft' },
    }), { revision: 6, deployedRevision: 0, standaloneClassicDraft: true });
    assert.equal((await f.CascadeLink.findById(newId).lean()).name, 'edited Hysteria terminal draft');
    const after = await f.state();
    assert.ok(after.updatedAt >= before.updatedAt, 'ordinary revision write updates its timestamp');
    assert.deepEqual(after, { ...before, revision: 6, updatedAt: after.updatedAt });
    assert.deepEqual(await foreign(), lock);
    assert.deepEqual(await f.HyNode.find().sort({ _id: 1 }).lean(), nodes);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
});
test('native Mongo classic endpoint inventory uses the same session and leaves native nodes xray-only', local, async () => {
    await setup();
    await f.HyNode.updateOne({ _id: f.bridge }, { $set: { type: 'hysteria' } });
    const native = await new TopologyDraftRepository(f.models).readDraft();
    assert.equal(Object.hasOwn(native, 'classicEndpointNodes'), false, 'native reads stay dormant');
    assert.deepEqual(native.nodes.map(row => String(row._id)).sort(), [f.source, f.otherPortal, outside].sort());
    assert.deepEqual(NODE_FILTER, { type: 'xray', active: true, cascadeRole: { $in: ['portal', 'relay', 'bridge'] } });
    const find = f.HyNode.find, reads = [];
    f.HyNode.find = function(filter) {
        const query = find.call(this, filter), lean = query.lean;
        query.lean = function(...args) {
            reads.push({ filter: this.getFilter(), session: this.getOptions().session, fields: this._fields });
            return lean.apply(this, args);
        };
        return query;
    };
    try {
        await f.mongoose.connection.transaction(async session => {
            const snapshot = await new TopologyDraftRepository({ ...f.models, allowStandaloneClassicDrafts: true }).readDraft(session);
            assert.deepEqual(snapshot.nodes, native.nodes);
            assert.deepEqual(snapshot.classicEndpointNodes.map(row => String(row._id)).sort(), [f.source, f.bridge, f.otherPortal].sort());
            assert.equal(reads.length, 2);
            for (const read of reads) {
                assert.ok(read.session === session, 'fresh role queries join the transaction');
                assert.deepEqual(read.fields, { _id: 1, cascadeRole: 1 });
            }
            assert.deepEqual(reads[0].filter, NODE_FILTER);
            assert.deepEqual(reads[1].filter, { active: true, $or: [
                { type: 'xray', cascadeRole: { $in: ['portal', 'bridge'] } },
                { type: 'hysteria', cascadeRole: 'bridge' },
            ] });
        });
    } finally { f.HyNode.find = find; }
});

test('native Mongo unsupported endpoints and forward group relay chain dependencies remain strict', local, async () => {
    for (const scenario of ['unsupported', 'case', 'whitespace', 'inactive', 'source-hysteria', 'nonterminal',
        'forward', 'geo', 'group', 'relay-reference', 'chain']) {
        await setup();
        await f.HyNode.updateOne({ _id: f.bridge }, { $set: { type: 'hysteria' } });
        await f.models.RelayL2tpState.deleteMany({ node: f.source });
        const link = { _id: '507f1f77bcf86cd799439023', portalNode: f.source, bridgeNode: f.bridge, mode: 'reverse' };
        if (['unsupported', 'case', 'whitespace'].includes(scenario)) {
            await f.HyNode.collection.updateOne({ _id: new f.mongoose.Types.ObjectId(f.bridge) },
                { $set: { type: { unsupported: 'unsupported', case: 'Hysteria', whitespace: 'hysteria ' }[scenario] } });
        }
        if (scenario === 'inactive') await f.HyNode.updateOne({ _id: f.bridge }, { $set: { active: false } });
        if (scenario === 'source-hysteria') await f.HyNode.updateOne({ _id: f.source }, { $set: { type: 'hysteria' } });
        if (scenario === 'nonterminal') await f.HyNode.updateOne({ _id: f.bridge }, { $set: { cascadeRole: 'relay' } });
        if (scenario === 'forward') link.mode = 'forward';
        if (scenario === 'geo') link.geoRouting = { enabled: true };
        if (scenario === 'group') await f.models.CascadeRouteGroup.collection.insertOne({ paths: [{ linkIds: [new f.mongoose.Types.ObjectId(f.oldId)] }] });
        if (scenario === 'relay-reference') await f.models.RelayL2tpState.collection.insertOne({ node: new f.mongoose.Types.ObjectId(f.bridge), status: 'not_installed' });
        if (scenario === 'chain') await f.CascadeLink.collection.insertOne({ portalNode: new f.mongoose.Types.ObjectId(f.bridge), bridgeNode: new f.mongoose.Types.ObjectId(outside), mode: 'reverse', active: false });
        // Test the counted-busy refusal separately from replacement ownership.
        await f.models.CascadeTopologyState.collection.updateOne({ _id: 'singleton' }, { $unset: { replacementReservation: '' } });
        const before = await f.state(), locks = await f.models.NodeOperationLock.find().lean();
        const links = await f.CascadeLink.find().sort({ _id: 1 }).lean();
        const repository = new TopologyDraftRepository({ ...f.models,
            withScopedNodeLocks: withScopedClassicNodeLocks, allowStandaloneClassicDrafts: true });
        const mutation = { kind: 'link.create', document: link };
        assert.equal(isStandaloneClassicMutation(await repository.readDraft(), mutation), false, scenario);
        await assert.rejects(repository.commitDraft({ expectedRevision: 4, prepare: async () => ({ mutation }) }),
            { code: 'TOPOLOGY_DEPLOY_BUSY' }, scenario);
        assert.deepEqual(await f.state(), before, scenario);
        assert.deepEqual(await f.CascadeLink.find().sort({ _id: 1 }).lean(), links, scenario);
        assert.deepEqual(await f.models.NodeOperationLock.find().lean(), locks, scenario);
    }
});

test('native Mongo default factory rechecks Hysteria endpoint eligibility inside the locked transaction', local, async () => {
    for (const change of [{ type: 'unsupported' }, { active: false }, { cascadeRole: 'relay' }]) {
        await setup();
        await f.HyNode.updateOne({ _id: f.bridge }, { $set: { type: 'hysteria' } });
        await f.models.RelayL2tpState.deleteMany({ node: f.source });
        const before = await f.state();
        const drafts = createTopologyDraftWriteService({ ...f.models, deploymentEnv: f.env,
            transactionRunner: async work => {
                assert.equal(await f.models.NodeOperationLock.countDocuments(), 3, 'selected old/new pair is locked');
                await f.HyNode.updateOne({ _id: f.bridge }, { $set: change });
                return f.mongoose.connection.transaction(work);
            },
        });
        await assert.rejects(drafts.updateLink({ expectedTopologyRevision: 4, linkId: f.linkId,
            changes: { name: 'must not commit' } }), { code: 'TOPOLOGY_REPLACEMENT_RESERVED' });
        assert.equal((await f.CascadeLink.findById(f.linkId).lean()).name, 'selected');
        assert.deepEqual(await f.state(), before);
        assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
    }
});

test('native Mongo default checked DELETE returns trusted standalone metadata for Hysteria terminal Bridge', local, async () => {
    await setup();
    await f.HyNode.updateOne({ _id: f.bridge }, { $set: { type: 'hysteria' } });
    await f.models.RelayL2tpState.deleteMany({ node: f.source });
    const before = await f.state(), lock = await foreign();
    const preserved = await f.CascadeLink.findById(f.oldId).lean();
    const nodes = await f.HyNode.find().sort({ _id: 1 }).lean();
    let removals = 0;
    const selected = createClassicScopedCascadeDeploymentService({ ...f.models, env: f.env, NodeSSH: Preview,
        cascadeService: { async removeScopedClassicLink(args) {
            removals++;
            await args.beforeRemoteMutation({ nodeId: f.source, phase: 'modeled-physical-remove' });
            return removalReceipt();
        } } });
    assert.deepEqual(await selected.deleteLink({ expectedTopologyRevision: 4, linkId: f.linkId }),
        { revision: 5, deployedRevision: 0, standaloneClassicDraft: true });
    assert.equal(removals, 1);
    assert.equal(await f.CascadeLink.exists({ _id: f.linkId }), null);
    assert.deepEqual(await f.CascadeLink.findById(f.oldId).lean(), preserved);
    const after = await f.state();
    assert.deepEqual(after, { ...before, revision: 5, updatedAt: after.updatedAt });
    assert.deepEqual(await foreign(), lock);
    assert.deepEqual(await f.HyNode.find().sort({ _id: 1 }).lean(), nodes);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
});

test('native Mongo independent apply preserves unrelated busy state and locks across an unrelated revision change', local, async () => {
    await setup(); const before = await f.state(), lock = await foreign();
    const result = await service(async args => {
        await args.scopedExecutionContext.verify();
        assert.equal(await f.models.NodeOperationLock.countDocuments(), 4);
        await f.models.CascadeTopologyState.updateOne({ _id: 'singleton' }, { $inc: { revision: 1 } }, { timestamps: false });
        await args.scopedExecutionContext.verify();
        return f.receipt();
    }).queue(f.input());
    assert.deepEqual(result, { status: 'succeeded', executionMode: 'classic', topologyRevision: 4 });
    assert.deepEqual(await f.state(), { ...before, revision: 5 });
    assert.deepEqual(await foreign(), lock);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
});
test('native Mongo same-component conflict leaves the competing and disjoint generations intact', local, async () => {
    await setup(); const state = await f.state(), lock = await foreign(); let called = false;
    await f.models.NodeOperationLock.collection.insertOne({ node: new f.mongoose.Types.ObjectId(f.bridge), owner: 'fixture-other-writer', operationId: 'fixture-same-node', generation: 'fixture-same-generation', remoteUncertain: true, leaseUntil: new Date(Date.now() + 120000) });
    const other = await f.models.NodeOperationLock.findOne({ node: f.bridge }).lean();
    await assert.rejects(service(async () => { called = true; return f.receipt(); }).queue(f.input()), { code: 'CLASSIC_DEPLOY_NODE_BUSY' });
    assert.equal(called, false); assert.deepEqual(await f.state(), state);
    assert.deepEqual(await foreign(), lock);
    assert.deepEqual(await f.models.NodeOperationLock.findOne({ node: f.bridge }).lean(), other);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 2);
});
test('native Mongo private core no-write provenance releases only this component, allowing retry', local, async () => {
    await setup(); const state = await f.state(), lock = await foreign();
    await assert.rejects(service(async args => {
        throw createClassicPortalBridgePhase({ beforeRemoteMutation: args.beforeRemoteMutation }).failure(Object.assign(new Error('modeled private preview failure'), { code: 'CLASSIC_SCOPED_SERVICE_LAYOUT_UNSUPPORTED' }));
    }).queue(f.input()), { code: 'CLASSIC_DEPLOY_PREFLIGHT_FAILED' });
    assert.deepEqual(await f.state(), state); assert.deepEqual(await foreign(), lock);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
    assert.equal((await service(async () => f.receipt()).queue(f.input())).status, 'succeeded');
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
});
test('native Mongo independent request cannot edit a deployment-held component and receives a safe busy code', local, async () => {
    await setup(); const original = await f.CascadeLink.findById(f.linkId).lean();
    // Represents a separately accepted HTTP request, not trusted reentrant work.
    const request = new AsyncResource('private-independent-draft-request');
    const drafts = createTopologyDraftWriteService({ ...f.models, deploymentEnv: f.env,
        // This case isolates real admission/DB serialization; domain validity is
        // exercised separately by route/physical acceptance, not by these stubs.
        validator: () => ({ valid: true }), compiler: () => ({ valid: true }),
    });
    let draftError;
    try {
        const result = await service(async () => {
            try {
                await request.runInAsyncScope(() => drafts.updateLink({ expectedTopologyRevision: 4,
                    linkId: f.linkId, changes: { name: 'racing edit must not persist' } }));
            } catch (error) { draftError = error; }
            return f.receipt();
        }).queue(f.input());
        assert.equal(result.status, 'succeeded');
        assert.equal(draftError?.code, 'CLASSIC_DEPLOY_NODE_BUSY', draftError?.message);
        assert.deepEqual((await f.CascadeLink.findById(f.linkId).lean()).name, original.name);
        assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
    } finally { request.emitDestroy(); }
});
test('native Mongo possible remote mutation retains only this component and never the unrelated singleton slot', local, async () => {
    await setup(); const state = await f.state(), lock = await foreign();
    await assert.rejects(service(async args => {
        await args.beforeRemoteMutation({ nodeId: f.source, phase: 'modeled-stage-dispatch' });
        throw new Error('modeled unknown remote outcome');
    }).queue(f.input()), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
    assert.deepEqual(await f.state(), state); assert.deepEqual(await foreign(), lock);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 4);
    const own = await f.models.NodeOperationLock.find({ node: { $in: [f.source, f.bridge, f.otherPortal] } }).lean();
    assert.equal(own.length, 3); assert.ok(own.every(row => row.remoteUncertain === true));
});
