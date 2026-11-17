'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, id } = require('./cascadeAnyOrderSelectedApply.test');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const { linkDesiredVersion } = require('../services/topologyIntentService');
async function apply(f, linkId) {
    const result = await f.coordinator.queue({ expectedTopologyRevision: f.CascadeTopologyState.rows[0].revision,
        scope: { kind: 'link.apply', linkId, linkIds: [linkId] } });
    assert.equal((await f.worker.run(result.operationId)).status, 'succeeded');
    return result;
}
async function remove(f, linkId, jobId = id(90)) {
    const link = f.CascadeLink.rows.find(row => row._id === linkId);
    const desiredVersion = linkDesiredVersion(link);
    const resources = await f.coordinator.resolveIntentResourcesForQueue({ kind: 'link.delete', link, desiredVersion, session: f.session });
    link.lifecycle = { state: 'deleting', deleteJobId: jobId, desiredVersion };
    return f.coordinator.queueIntent({ session: f.session, executionContext: context, intentId: jobId,
        mutation: { kind: 'link.delete', linkId, desiredVersion }, expectedTopologyRevision: f.CascadeTopologyState.rows[0].revision,
        resourceNodeIds: resources });
}
test('selected delete cleans the last edge before removing the exact tombstone, then recreates on the same port', async () => {
    const f = fixture();
    await apply(f, id(10));
    const original = structuredClone(f.CascadeLink.rows[0]);
    const neighbor = structuredClone(f.CascadeLink.rows[1]);
    const queued = await remove(f, id(10));
    const operation = f.TopologyOperation.rows.find(row => row._id === queued.operationId);
    assert.equal(operation.deleteJobId, id(90));
    assert.deepEqual(operation.linkIds, []);
    assert.deepEqual(operation.effectiveTopology.links, []);
    assert.deepEqual(operation.resourceNodeIds, [id(1), id(2)]);
    let verifications = 0;
    f.executor.verify = async () => { assert.ok(f.CascadeLink.rows.some(row => row._id === id(10))); verifications++; return { ok: true }; };
    assert.equal((await f.worker.run(queued.operationId)).status, 'succeeded');
    assert.equal(verifications, 2);
    assert.equal(f.CascadeLink.rows.some(row => row._id === id(10)), false);
    assert.deepEqual(f.CascadeLink.rows[0], neighbor);
    assert.equal(f.NodeOperationLock.rows.length, 0);
    assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 0);
    f.executor.verify = async () => ({ ok: true });
    f.CascadeLink.rows.push({ ...original, _id: id(12), status: 'pending' });
    f.CascadeTopologyState.rows[0].revision++;
    await apply(f, id(12));
});
const permutations = values => values.length ? values.flatMap((value, index) =>
    permutations(values.filter((_, i) => i !== index)).map(rest => [value, ...rest])) : [[]];
let cases = 0;
for (const [graph, edges] of [['G1', [[11, 3, 4]]], ['G2', [[12, 3, 1], [10, 1, 2]]],
    ['G3', [[12, 3, 1], [10, 1, 2], [13, 1, 4]]]]) {
    for (let bits = 0; bits < 2 ** edges.length; bits++) for (const order of permutations(edges.map(edge => edge[0]))) for (const deleteOrder of permutations(order)) {
        cases++;
        test(`${graph} modes=${bits} create=${order.join(',')} delete=${deleteOrder.join(',')} then recreate`, async () => {
            const f = fixture();
            const sample = f.CascadeLink.rows[0];
            f.CascadeLink.rows.splice(0, f.CascadeLink.rows.length, ...edges.map(([n, source, target], i) => ({ ...sample,
                _id: id(n), portalNode: id(source), bridgeNode: id(target), tunnelPort: 23000 + n,
                mode: bits & 2 ** i ? 'forward' : 'reverse',
                ...(n === 13 ? { geoRouting: { enabled: true, geoip: ['ru'], domains: ['category-ru'] } } : {}) })));
            for (const n of order) { f.CascadeTopologyState.rows[0].revision++; await apply(f, id(n)); }
            const originals = structuredClone(f.CascadeLink.rows);
            for (const n of deleteOrder) {
                const neighbors = structuredClone(f.CascadeLink.rows.filter(row => row._id !== id(n)));
                const queued = await remove(f, id(n), id(100 + n));
                const outcome = await f.worker.run(queued.operationId);
                assert.equal(outcome.status, 'succeeded', JSON.stringify(outcome));
                assert.deepEqual(f.CascadeLink.rows, neighbors);
            }
            assert.equal(f.CascadeLink.rows.length, 0);
            for (const n of order) {
                const old = originals.find(row => row._id === id(n));
                f.CascadeLink.rows.push({ ...old, status: 'pending', tunnelPort: old.tunnelPort + (bits % 2 ? 100 : 0) });
                f.CascadeTopologyState.rows[0].revision++;
                await apply(f, id(n));
            }
            assert.equal(f.CascadeLink.rows.length, edges.length);
            assert.equal(f.NodeOperationLock.rows.length, 0);
            assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 0);
        });
    }
}
test('matrix cardinality is generated, not hand counted', t => {
    const expected = [1, 2, 3].reduce((sum, n) => sum + 2 ** n * permutations(Array.from({ length: n }, (_, i) => i)).length ** 2, 0);
    t.diagnostic(JSON.stringify({ cases, expected })); assert.equal(cases, expected);
});
test('unknown cleanup retains exact tombstone/locks and blocks same-resource recreate while independent work runs', async () => {
    const f = fixture(); await apply(f, id(10));
    const queued = await remove(f, id(10));
    const originalPrepare = f.executor.prepare;
    f.executor.prepare = async () => { throw new Error('cleanup unknown'); };
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.errorCode, 'REMOTE_COMMAND_OUTCOME_UNCERTAIN');
    assert.equal(f.CascadeLink.rows[0].lifecycle.deleteJobId, id(90));
    const retained = structuredClone(f.NodeOperationLock.rows);
    f.CascadeLink.rows.push({ ...f.CascadeLink.rows[0], _id: id(12), tunnelPort: 29900, lifecycle: undefined });
    f.CascadeTopologyState.rows[0].revision++;
    await assert.rejects(apply(f, id(12)), { code: 'TOPOLOGY_DEPLOY_BUSY' });
    f.executor.prepare = originalPrepare; await apply(f, id(11));
    assert.deepEqual(f.NodeOperationLock.rows, retained);
});
test('draft update/delete reject an accepted tombstone in the exact session', async () => {
    const f = fixture(); await apply(f, id(10)); await remove(f, id(10));
    const repository = new (require('../repositories/topologyDraftRepository').TopologyDraftRepository)({ ...f, transactionRunner: work => work(f.session) });
    for (const kind of ['link.update', 'link.delete']) await assert.rejects(repository.persistMutation({ kind, id: id(10), changes: { tunnelPort: 29999 } }, f.session), { code: 'CASCADE_LINK_DELETING' });
});
test('delete identity survives strict schema and malformed tombstone fails before dispatch', async () => {
    const f = fixture(); await apply(f, id(10));
    const queued = await remove(f, id(10));
    const source = f.TopologyOperation.rows.find(row => row._id === queued.operationId);
    const document = new (require('../models/topologyOperationModel'))(source); await document.validate();
    assert.equal(document.deleteJobId, id(90));
    f.CascadeLink.rows[0].lifecycle.deleteJobId = id(91);
    f.calls.length = 0;
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.status, 'failed'); assert.equal(f.calls.length, 0);
    assert.equal(f.NodeOperationLock.rows.length, 0);
});
test('verified absent-applied pending delete is DB-only and preserves ownership/history without an invented operation', async () => {
    const f = fixture(); const neighbor = structuredClone(f.CascadeLink.rows[1]);
    const owners = structuredClone(f.TopologyConfigOwner.rows), history = structuredClone(f.TopologyOperation.rows);
    const queued = await remove(f, id(10));
    assert.equal(queued.status, 'succeeded'); assert.equal(queued.desiredOnly, true);
    assert.equal(queued.operationId, undefined);
    assert.deepEqual(f.CascadeLink.rows, [neighbor]);
    assert.deepEqual(f.calls, []);
    assert.deepEqual(f.TopologyConfigOwner.rows, owners); assert.deepEqual(f.TopologyOperation.rows, history);
});
test('same delete job replays after row removal, changed job content is rejected', async () => {
    const f = fixture(); await apply(f, id(10));
    const desiredVersion = linkDesiredVersion(f.CascadeLink.rows[0]);
    const queued = await remove(f, id(10)); assert.equal((await f.worker.run(queued.operationId)).status, 'succeeded');
    const operation = f.TopologyOperation.rows.find(row => row._id === queued.operationId);
    const input = { session: f.session, executionContext: context, intentId: id(90),
        mutation: { kind: 'link.delete', linkId: id(10), desiredVersion }, expectedTopologyRevision: 7,
        resourceNodeIds: operation.resourceNodeIds };
    const replay = await f.coordinator.queueIntent(input);
    assert.equal(replay.operationId, queued.operationId); assert.equal(replay.status, 'succeeded');
    await assert.rejects(f.coordinator.queueIntent({ ...input, mutation: { ...input.mutation, desiredVersion: '0'.repeat(64) } }), { code: 'TOPOLOGY_INTENT_BINDING_INVALID' });
    const count = f.TopologyOperation.rows.length;
    assert.equal((await f.worker.run(replay.operationId)).claimed, false);
    assert.equal(f.TopologyOperation.rows.length, count);
});
module.exports = { fixture, id, apply, remove };
for (const hasHistory of [false, true]) test(`disabled pending delete uses verified history=${hasHistory}, never the pending-only shortcut`, async () => {
    const f = fixture(); if (hasHistory) await apply(f, id(10));
    f.CascadeLink.rows[0].active = false; f.CascadeLink.rows[0].status = 'pending';
    const queued = await remove(f, id(10));
    let reads = 0; f.executor.verify = async () => { reads++; return { ok: true }; };
    if (hasHistory) {
        assert.equal((await f.worker.run(queued.operationId)).status, 'succeeded');
        assert.equal(reads, 2, 'pending/disabled does not override verified applied history');
    } else {
        assert.equal(queued.desiredOnly, true); assert.equal(queued.operationId, undefined);
        assert.equal(reads, 0); assert.deepEqual(f.calls, []);
    }
    assert.equal(f.CascadeLink.rows.some(row => row._id === id(10)), false);
});
test('executor-owner absent-listener handoff survives admission, strict schema and actual worker', async () => {
    const f = fixture(); await apply(f, id(10));
    // Explicit composer handoff until the executor-owner commit is integrated.
    // Its actual runner/listener proof belongs to cascadeAnyOrderCleanupExecution.
    const materialize = f.coordinator.planMaterializer.materialize.bind(f.coordinator.planMaterializer);
    f.coordinator.planMaterializer.materialize = async input => {
        const plan = await materialize(input);
        return { ...plan, nodes: plan.nodes.map(node => node.node === id(1) ? { ...node,
            checks: [...node.checks, { type: 'port', protocol: 'tcp', port: 23451, expectedState: 'absent' }] } : node) };
    };
    const queued = await remove(f, id(10)); const operation = f.TopologyOperation.rows.find(row => row._id === queued.operationId);
    await new (require('../models/topologyOperationModel'))(operation).validate();
    let observed = false;
    f.executor.prepare = async input => { observed ||= input.node.checks.some(check => check.expectedState === 'absent'); return { backupId: 'backup', prepared: {} }; };
    assert.equal((await f.worker.run(queued.operationId)).status, 'succeeded'); assert.equal(observed, true);
});
test('actual CascadeLink ObjectId tombstone is accepted by selected delete, not mistaken for a different job', async t => {
    const f = fixture();
    const Model = require('../../../models/cascadeLinkModel');
    const doc = new Model({ ...f.CascadeLink.rows[0], lifecycle: { state: 'deleting', deleteJobId: id(90), desiredVersion: '0'.repeat(64) } });
    doc.lifecycle.desiredVersion = linkDesiredVersion(doc.toObject());
    assert.equal(typeof doc.toObject().lifecycle.deleteJobId, 'object');
    const find = Model.collection.find; t.after(() => { Model.collection.find = find; });
    Model.collection.find = () => ({ async toArray() { return [doc.toObject()]; } });
    f.deployment.snapshotReader.CascadeLink = Model;
    const selected = await f.deployment.readSelected({ snapshot: await f.deployment.snapshotReader.readDraft(),
        scope: { kind: 'link.delete', linkId: id(10) }, executionContext: context, session: f.session,
        desiredVersion: doc.lifecycle.desiredVersion, deleteJobId: id(90) });
    assert.deepEqual(selected.effectiveTopology.links, []);
});
