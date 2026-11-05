'use strict';
// Fresh real Mongo replica set: actual schemas, public producers, admission,
// binding store, worker, readiness and finalizer transactions. Physical IO modeled.
const test = require('node:test');
const assert = require('node:assert/strict');
const { lifecycleFixture, mongoFixture, id, sha, evidence } = require('./helpers/cascadeLegacyInstalledGroupMongoFixture');
const mongo = mongoFixture();
test.before(() => mongo.start());
test.after(() => mongo.stop());

async function succeeded(f, request) {
    const job = await f.accept(request);
    const operation = await f.consume(job);
    assert.equal(operation.status, 'succeeded', `worker ${operation.status}/${operation.errorCode || 'none'} at ${f.stage}`);
    await f.assertPreserved();
    assert.ok(f.options.gateCalls.includes('MAIN') && f.options.gateCalls.includes('PPP'));
    assert.ok(f.options.userPushes > 0, 'actual user resync consumed independent existing client inventory');
    assert.equal(operation.v2Terminal.state, 'proven');
    assert.equal(operation.heldTopologyAdmission, false);
    assert.ok(operation.nodes.every(node => node.state === 'committed'));
    assert.ok(f.dispatches.some(call => call.command === 'close') && f.dispatches.some(call => call.command === 'status'));
    return { job, operation };
}

test('Mongo existing G2 import -> unchanged APPLY d -> durable replay -> revised byte-noop -> DELETE d kept-empty -> new-ID recreate -> fresh reader', { timeout: 180000 }, async t => {
    const f = await lifecycleFixture(t, mongo);
    await f.adoptAndEnroll();
    await f.assertInitial();
    const firstRequest = await f.request('link.apply', id(11), 'C-d-initial');
    const first = await succeeded(f, firstRequest);
    await f.assertFresh(id(11), [id(10), id(11)], [id(11)]);
    const dispatches = f.dispatches.length, operations = (await f.data()).TopologyOperation.length;
    const replay = await f.freshIntentService().accept(firstRequest);
    assert.equal(replay.jobId, first.job.jobId);
    assert.equal(replay.status, 'succeeded');
    assert.equal(await f.consumer.claim(), null);
    assert.equal(f.dispatches.length, dispatches);
    assert.equal((await f.data()).TopologyOperation.length, operations);
    const physical = f.physicalFingerprint();
    await f.advanceRevision();
    const noop = await succeeded(f, await f.request('link.apply', id(11), 'C-d-noop'));
    assert.notEqual(String(noop.operation._id), String(first.operation._id));
    assert.equal(f.physicalFingerprint(), physical, 'genuine byte-noop retains config bytes/inode/modeled PID/start/restart counts');
    const deleted = await succeeded(f, await f.request('link.delete', id(11), 'C-d-delete'));
    assert.equal(await f.models.CascadeLink.findById(id(11)).lean(), null);
    await f.assertFresh(id(10), [id(10)], []);
    f.assertBlocked();
    assert.equal(deleted.operation.v2Terminal.sideEffects.installedIngressProof.pppInternetProof, 'not_applicable');
    const recreated = await succeeded(f, await f.createRequest(id(11), 'C-d-recreate'));
    assert.notEqual(recreated.job.createdLinkId, id(11));
    await f.assertFresh(recreated.job.createdLinkId, [id(10), recreated.job.createdLinkId], [recreated.job.createdLinkId]);
    f.assertRetired(id(11), 25001);
    assert.equal((await f.data()).NodeOperationLock.length, 0);
});

test('Mongo fresh existing G2 import -> DELETE u preserves installed R-to-B PPP suffix/disconnected portal -> new-ID u recreate -> fresh reader', { timeout: 180000 }, async t => {
    const f = await lifecycleFixture(t, mongo);
    await f.adoptAndEnroll();
    await f.assertInitial();
    const deleted = await succeeded(f, await f.request('link.delete', id(10), 'C-u-delete'));
    assert.equal(await f.models.CascadeLink.findById(id(10)).lean(), null);
    await f.assertFresh(id(11), [id(11)], [id(11)]);
    assert.equal(deleted.operation.routeState, 'no_portal_input');
    assert.equal(deleted.operation.v2Terminal.sideEffects.installedIngressProof.pppInternetProof, 'unverified');
    f.assertSuffix();
    const recreated = await succeeded(f, await f.createRequest(id(10), 'C-u-recreate'));
    assert.notEqual(recreated.job.createdLinkId, id(10));
    await f.assertFresh(recreated.job.createdLinkId, [recreated.job.createdLinkId, id(11)], [id(11)]);
    f.assertRetired(id(10), 25000);
    assert.equal((await f.data()).NodeOperationLock.length, 0);
});

// Bounded one-field controls at the two real installed-readiness boundaries;
// deletion makes premature path publication observable (old [d] versus new []).
const refusals = [
    ['MAIN wrong SOCKS port', f => f.corruptMain(config => { config.outbounds.find(o => o.tag === 'cascade-legacy-main').settings.servers[0].port++; }), 'INGRESS_UNVERIFIED'],
    ['MAIN wrong group inbound tag', f => f.corruptMain(config => { config.inbounds.find(i => i.tag.startsWith('relay-l2tp-')).tag = 'relay-l2tp-wrong-group'; }), 'INGRESS_UNVERIFIED'],
    ['MAIN unreadable', f => { f.options.unreadableMain = true; }, 'INGRESS_UNVERIFIED'],
    ['MAIN inactive', f => f.deactivateMain(), 'INGRESS_UNVERIFIED'],
    ['PPP wrong credential readback', f => { f.options.wrongCredential = true; }, 'INGRESS_PPP_UNVERIFIED'],
    ['PPP wrong managed-user readback', f => { f.options.wrongUsers = true; }, 'INGRESS_PPP_UNVERIFIED'],
    ['PPP unreadable', f => { f.options.unreadablePpp = true; }, 'INGRESS_PPP_UNVERIFIED'],
    ['PPP user desired-applied mismatch', async f => { await f.models.L2tpUser.updateOne({ _id: id(80) }, { $inc: { appliedRevision: -1 } }, { runValidators: true }); }, 'INGRESS_PPP_UNVERIFIED'],
];
async function retained(f, label) {
    const job = await f.accept(await f.request('link.delete', id(11), label));
    const operation = await f.consume(job);
    assert.equal(operation.status, 'committing');
    assert.equal(f.lastResult.errorCode, 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED');
    assert.equal(operation.heldTopologyAdmission, true);
    assert.deepEqual((await f.data()).CascadeRouteGroup[0].paths[0].linkIds.map(String), [id(11)], 'failed delete must not publish empty path');
    assert.equal((await f.data()).RelayL2tpState[0].appliedTopologyRevision, 7, 'failed gate/final CAS must not publish revision');
    assert.equal((await f.data()).CascadeTopologyState[0].topologyAdmissionCount, 1);
    assert.equal((await f.data()).NodeOperationLock.length, 3);
    for (const node of operation.nodes) {
        const lock = (await f.data()).NodeOperationLock.find(row => String(row.node) === String(node.node));
        const binding = (await f.data()).TopologyExecutionBinding.find(row => row.nodeId === String(node.node) && row.operationId === String(operation._id));
        assert.ok(lock && binding);
        assert.equal(lock.operationId, String(operation._id)); assert.equal(lock.generation, binding.generation);
        assert.equal(lock.remoteUncertain, true);
    }
    assert.ok((await f.data()).TopologyConfigOwner.every(row => row.lastSettledOperation === undefined));
    assert.equal((await f.models.CascadeLink.findById(id(11)).lean()).lifecycle.state, 'deleting');
    assert.equal(await f.consumer.settle(await f.models.TopologyCreateIntent.findById(job.jobId).lean()), false);
    assert.equal((await f.freshIntentService().get(job.jobId)).status, 'admitted');
    assert.equal((await f.data()).L2tpOperation.length, 1, 'no PPP repair-sync is allowed to mask refusal');
    return operation;
}
for (const [name, change, innerCode] of refusals) test(`Mongo actual installed refusal: ${name} retains exact ownership and old path`, { timeout: 60000 }, async t => {
    const f = await lifecycleFixture(t, mongo); await f.adoptAndEnroll(); await f.assertInitial(); await change(f);
    await retained(f, `C-negative-${name.replaceAll(' ', '-')}`);
    assert.deepEqual(f.options.prepareErrors, [innerCode]);
    assert.ok(f.options.gateCalls.includes('MAIN'));
    assert.equal(f.dispatches.some(call => call.command === 'close'), false);
});

for (const drift of ['owner', 'group', 'credential-epoch']) test(`Mongo after readiness ${drift} drift refuses final publication without releasing the admitted generation`, { timeout: 60000 }, async t => {
    const f = await lifecycleFixture(t, mongo); await f.adoptAndEnroll(); await f.assertInitial();
    f.options.afterPrepare = async () => {
        // Intentional adversarial competing row changes, ONLY after public
        // producers and actual successful readiness; never seeded success.
        if (drift === 'owner') await f.models.TopologyConfigOwner.collection.updateOne({ node: new (require('mongoose').Types.ObjectId)(id(1)) }, { $set: { generation: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' } });
        else if (drift === 'group') await f.models.CascadeRouteGroup.updateOne({ _id: id(60) }, { $inc: { 'paths.0.priority': 1 } }, { runValidators: true });
        else await f.models.RelayL2tpState.updateOne({ node: id(2) }, { $inc: { secretRevision: 1 } }, { runValidators: true });
    };
    await retained(f, `C-final-${drift}`);
    assert.equal(f.options.prepares.length, 1, 'actual MAIN and PPP producer succeeded before the drift');
    assert.deepEqual(f.options.prepareErrors, []);
    assert.ok(f.options.gateCalls.includes('PPP'));
    if (drift === 'owner') assert.equal((await f.data()).TopologyConfigOwner[0].generation, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
    if (drift === 'group') assert.equal((await f.data()).CascadeRouteGroup[0].paths[0].priority, 5);
    if (drift === 'credential-epoch') assert.equal((await f.data()).RelayL2tpState[0].secretRevision, 42);
});


function joinEvidence(commands, models, terminal) {
    const joins = commands.filter(row => row.name === 'find' && row.collection === models.RelayL2tpState.collection.name
        && row.filterFields.length === 1 && row.filterFields[0] === 'routeGroup');
    assert.ok(joins.length > 0, 'real initial-import owner join must reach Mongo');
    const safe = Object.fromEntries('node routeGroup status desiredState activePathKey appliedTopologyRevision secretRevision'.split(' ').map(k => [k, 1]));
    for (const row of joins) {
        assert.deepEqual(row.projection, safe, 'exact explicit safe field projection');
        assert.equal(row.autocommit, false); assert.ok(row.lsid && row.txnNumber !== undefined);
        const tx = commands.filter(other => other.lsid === row.lsid && other.txnNumber === row.txnNumber && other.autocommit === false);
        assert.ok(tx.some(other => other.collection === models.CascadeRouteGroup.collection.name && other.name === 'find'));
        assert.ok(tx.some(other => other.collection === models.TopologyConfigOwner.collection.name && other.name === 'find'));
        assert.ok(tx.some(other => other.name === terminal), 'same actual session/transaction completes with expected terminal');
        assert.equal(tx.find(other => other.startTransaction)?.readConcern?.level, 'snapshot');
    }
    return joins.length;
}

test('Mongo initial imported private projection and explicit safe owner join use genuine same-session native queries', { timeout: 60000 }, async t => {
    const f = await lifecycleFixture(t, mongo); await f.adoptAndEnroll(); await f.assertInitial();
    const visible = await f.models.TopologyConfigOwner.find({}).sort({ node: 1 }).lean();
    const privateRows = await f.models.TopologyConfigOwner.find({}).select('+legacyAppliedTopology').sort({ node: 1 }).lean();
    assert.equal(visible.length, 3); assert.equal(privateRows.length, 3);
    assert.ok(visible.every(row => row.legacyAppliedTopology === undefined));
    assert.ok(privateRows.every(row => row.legacyAppliedTopology.groups.length === 1));
    const start = mongo.commands.length;
    await mongo.connection.transaction(async session => {
        assert.ok(session.client === mongo.connection.getClient()); assert.equal(session.inTransaction(), true);
        const snapshot = await f.draft.readDraft(session);
        const selected = await f.deployment.readSelected({ snapshot, session, scope: { kind: 'link.apply', linkId: id(11) }, executionContext: f.context });
        assert.deepEqual(selected.installedPath.oldPathLinkIds, [id(11)]);
    }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
    const joins = joinEvidence(mongo.commands.slice(start), f.models, 'commitTransaction');
    assert.equal((await f.data()).TopologyOperation.length, 0); assert.equal(f.dispatches.length, 0);
    evidence({ fixtureId: f.fixtureId, stage: 'private-projection-and-safe-session-verified', joins, defaultPrivateAbsent: true, explicitPrivatePresent: true });
});

const initialRefusals = [
    ['group-priority', 'TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED', async f => {
        await f.models.CascadeRouteGroup.updateOne({ _id: id(60) }, { $inc: { 'paths.0.priority': 1 } }, { runValidators: true });
    }],
    ['missing-installed', 'TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED', async f => {
        await f.models.RelayL2tpState.deleteOne({ node: id(2) });
    }],
    ['configured-peer', 'TOPOLOGY_INSTALLED_ROUTE_OWNER_AMBIGUOUS', async f => {
        const { _id, __v, createdAt, updatedAt, ...state } = (await f.data()).RelayL2tpState[0];
        await f.models.RelayL2tpState.create({ ...state, _id: id(71), node: id(4), status: 'queued' });
    }],
    ['missing-peer-descriptor', 'APPLIED_BASELINE_REQUIRED', async f => {
        await f.models.TopologyConfigOwner.collection.updateOne({ node: new (require('mongoose').Types.ObjectId)(id(3)) }, { $unset: { legacyAppliedTopology: 1 } });
    }],
    ['corrupt-peer-descriptor', 'TOPOLOGY_LEGACY_IMPORT_MISMATCH', async f => {
        await f.models.TopologyConfigOwner.collection.updateOne({ node: new (require('mongoose').Types.ObjectId)(id(3)) },
            { $inc: { 'legacyAppliedTopology.groups.0.paths.0.priority': 1 } });
    }],
];
for (const [name, code, change] of initialRefusals) test(`Mongo initial admission refuses ${name} before operation, locks or dispatch`, { timeout: 60000 }, async t => {
    const f = await lifecycleFixture(t, mongo); await f.adoptAndEnroll(); await f.assertInitial(); await change(f);
    const before = sha(JSON.stringify(await f.data())), physical = f.physicalFingerprint(), start = mongo.commands.length;
    await assert.rejects(f.accept(await f.request('link.apply', id(11), `Mongo-refusal-${name}`)), { code });
    assert.equal(sha(JSON.stringify(await f.data())), before, 'actual outer transaction rolls all attempted admission/queue writes back');
    assert.equal(f.physicalFingerprint(), physical); assert.equal(f.dispatches.length, 0);
    const rows = await f.data(); assert.equal(rows.TopologyOperation.length, 0); assert.equal(rows.NodeOperationLock.length, 0);
    assert.equal(rows.TopologyCreateIntent.length, 0); assert.equal(rows.CascadeTopologyState[0].topologyAdmissionCount, 0);
    const joins = name.includes('descriptor') ? 0 : joinEvidence(mongo.commands.slice(start), f.models, 'abortTransaction');
    evidence({ fixtureId: f.fixtureId, stage: 'initial-admission-refused', name, code, joins, inventoryUnchangedSha256: before, dispatchCount: 0 });
});

test('Mongo actual V2 finalizer aborts immediately AFTER validated group publication write without partial owner/epoch/operation/lock commit', { timeout: 90000 }, async t => {
    const f = await lifecycleFixture(t, mongo); await f.adoptAndEnroll(); await f.assertInitial();
    const Group = f.models.CascadeRouteGroup, original = f.finalization.CascadeRouteGroup;
    let injected = 0, outside, transactionId;
    // Dedicated finalizer-only model seam; every query/update is the unmodified
    // real schema/native driver. No transaction runner, CAS or validator bypass.
    f.finalization.CascadeRouteGroup = { db: Group.db, findById: (...args) => Group.findById(...args),
        async updateOne(filter, update, options) {
            assert.equal(options.runValidators, true); assert.equal(options.session.inTransaction(), true);
            assert.ok(options.session.client === mongo.connection.getClient());
            const result = await Group.updateOne(filter, update, options);
            assert.equal(result.matchedCount, 1, 'injection only AFTER successful valid group write');
            injected++;
            const inside = await Group.findById(id(60)).session(options.session).lean();
            assert.deepEqual(inside.paths[0].linkIds, []);
            outside = await f.data();
            assert.deepEqual(outside.CascadeRouteGroup[0].paths[0].linkIds.map(String), [id(11)]);
            assert.equal(await f.models.NodeOperationLock.countDocuments({}).session(options.session), 0, 'same transaction already deleted exact locks');
            assert.equal(outside.NodeOperationLock.length, 3);
            const owners = await f.models.TopologyConfigOwner.find({}).session(options.session).lean();
            assert.ok(owners.every(row => row.lastSettledOperation !== undefined));
            assert.ok(outside.TopologyConfigOwner.every(row => row.lastSettledOperation === undefined));
            const state = await f.models.RelayL2tpState.findOne({ node: id(2) }).session(options.session).lean();
            assert.ok(state.replacementFence > outside.RelayL2tpState[0].replacementFence);
            transactionId = mongo.commands.findLast(row => row.name === 'update' && row.collection === Group.collection.name && row.autocommit === false);
            throw Object.assign(Error('INJECTED_AFTER_VALID_GROUP_WRITE'), { code: 'FIXTURE_PUBLICATION_ABORT' });
        } };
    const start = mongo.commands.length;
    try { await retained(f, 'Mongo-rollback-after-valid-group'); }
    finally { f.finalization.CascadeRouteGroup = original; }
    assert.equal(injected, 1, 'owning guard must not refuse before the causal rollback hook');
    const after = await f.data();
    for (const name of ['CascadeRouteGroup', 'RelayL2tpState', 'TopologyConfigOwner', 'NodeOperationLock', 'TopologyOperation', 'CascadeTopologyState', 'L2tpUser']) {
        assert.deepEqual(after[name], outside[name], `${name} cannot partially commit after injected abort`);
    }
    const tx = mongo.commands.slice(start).filter(row => row.lsid === transactionId.lsid && row.txnNumber === transactionId.txnNumber && row.autocommit === false);
    assert.equal(tx.filter(row => row.name === 'abortTransaction').length, 1);
    assert.equal(tx.filter(row => row.name === 'commitTransaction').length, 0);
    for (const [name, collection] of [['update', Group.collection.name], ['update', f.models.TopologyConfigOwner.collection.name],
        ['update', f.models.RelayL2tpState.collection.name], ['delete', f.models.NodeOperationLock.collection.name]]) {
        assert.ok(tx.some(row => row.name === name && row.collection === collection));
    }
    evidence({ fixtureId: f.fixtureId, stage: 'actual-publication-transaction-aborted', injected, lsid: transactionId.lsid,
        txnNumber: transactionId.txnNumber, abortCommands: 1, commitCommands: 0,
        unchangedPublicationSha256: sha(JSON.stringify(Object.fromEntries(['CascadeRouteGroup','RelayL2tpState','TopologyConfigOwner','NodeOperationLock','TopologyOperation','CascadeTopologyState'].map(n => [n, after[n]])))) });
});
