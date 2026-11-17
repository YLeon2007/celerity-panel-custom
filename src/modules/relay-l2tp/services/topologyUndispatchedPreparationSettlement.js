'use strict';
// Explicit dedicated TEST disposition, not continuation/replay: a failed first
// node followed only by pending nodes is retained until ALL original bindings
// are physically absent under the existing held authority. The failed history,
// attempt, generations, plan, owner heads and original finish time never change.
const { isDeepStrictEqual: same } = require('node:util');
const { randomUUID, createHash } = require('node:crypto');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const { UUID, validTerminalReceipt } = require('../models/topologyExecutionBindingContract');
const { enrollmentRuntimeBootId } = require('../repositories/topologyExecutionBindingStore');
const { validateUndispatchedPhysical } = require('../repositories/topologyUndispatchedPreparationContinuation');
const ISSUED = new WeakSet();
const OPTIONS = { maxTimeMS: 5000, timeoutMS: 5000 };
const PRIVATE = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +installedPath +undispatchedPreparationSettlement +undispatchedPreparationContinuation +closedSettlementContinuation +preparedCommitContinuation';
function refuse() { throw Object.assign(Error('TEST_UNDISPATCHED_SETTLEMENT_UNPROVEN'), { code: 'TEST_UNDISPATCHED_SETTLEMENT_UNPROVEN' }); }
function eligible(op) {
    if (!op || !same(op.executionContext, TEST) || op.kind !== 'link.apply' || op.admissionScope !== 'selected'
        || op.status !== 'failed' || op.attempts !== 1 || op.heldTopologyAdmission !== true || op.leaseUntil !== null
        || typeof op.leaseOwner !== 'string' || !op.leaseOwner || !(op.finishedAt instanceof Date)
        || ['v2Terminal', 'pppWait', 'bootstrapContinuation', 'bootstrapCancellation', 'bindingReservationContinuation',
            'retainedVerifyContinuation', 'undispatchedPreparationContinuation', 'closedSettlementContinuation',
            'preparedCommitContinuation', 'undispatchedPreparationSettlement'].some(k => op[k] !== undefined)
        || !op.nodes?.length || op.nodes.length > 8 || op.resourceNodeIds?.length !== op.nodes.length
        || new Set(op.resourceNodeIds).size !== op.nodes.length
        || op.nodes.some((n, i) => n.state !== (i === 0 ? 'failed' : 'pending')
            || (i === 0 ? !n.backupId : n.backupId !== '')
            || !['xray-main', 'xray-bridge'].includes(n.targetProfile) || !op.resourceNodeIds.includes(String(n.node)))) refuse();
}
function query(Model, q, session, select) {
    let r = Model.findOne(q);
    if (select) r = r.select(select);
    return (session ? r.session(session) : r.read('primary').readConcern('majority')).setOptions(OPTIONS).lean();
}
async function roots(models, op, session) {
    const operationId = String(op._id);
    let qb = models.TopologyExecutionBinding.find({ operationId }), ql = models.NodeOperationLock.find({ operationId });
    const all = await (session ? qb.session(session) : qb.read('primary').readConcern('majority')).setOptions(OPTIONS).lean();
    const locks = await (session ? ql.session(session) : ql.read('primary').readConcern('majority')).setOptions(OPTIONS).lean();
    if (all.length !== op.nodes.length || locks.length !== op.nodes.length) refuse();
    const result = [];
    for (const n of op.nodes) {
        const id = String(n.node), b = all.find(b => b.nodeId === id), l = locks.find(l => String(l.node) === id);
        const e = await query(models.TopologyExecutionEnrollment, { nodeId: id, targetProfile: n.targetProfile }, session);
        const o = await query(models.TopologyConfigOwner, { node: id, profile: n.targetProfile }, session, '+legacyAppliedTopology +profileTargetPin');
        if (!b || !l || !e || !o || b.operationId !== operationId || b.attempt !== 1 || b.owner !== op.leaseOwner
            || b.generation !== l.generation || !UUID.test(b.generation) || l.owner !== b.owner || l.remoteUncertain !== true
            || b.executionContext !== TEST.hostIdentity || b.targetProfile !== n.targetProfile || b.candidateHash !== 'sha256:' + n.candidateHash
            || (n.state === 'failed' && b.backupId !== n.backupId)
            || b.topologyRevision !== op.topologyRevision || b.priorDeployedRevision !== op.priorDeployedRevision
            || b.backupId !== 'topology-' + createHash('sha256').update([operationId, id, b.candidateHash, n.targetProfile].join('\0')).digest('hex')
            || o.owner !== 'topology' || !same(o.executionContext, TEST) || o.handbackReceipt !== undefined
            || b.ownerGeneration !== o.generation || e.ownerGeneration !== o.generation || b.enrollmentId !== e._id
            || b.bootId !== enrollmentRuntimeBootId(e) || !same(b.nodeIdentity, e.nodeIdentity) || !same(o.nodeIdentity, e.nodeIdentity)
            || !same(b.endpoint, e.endpoint) || o.lastSettledGeneration !== b.predecessorGeneration) refuse();
        const prior = await query(models.TopologyExecutionBinding, { _id: b.predecessorBindingId,
            operationId: o.lastSettledOperation, generation: o.lastSettledGeneration, 'commandIds.close': o.lastSettledCloseId }, session);
        const settled = prior && await query(models.TopologyOperation, { _id: prior.operationId, status: 'succeeded', heldTopologyAdmission: false, 'v2Terminal.state': 'proven' }, session);
        if (!prior || !settled || !validTerminalReceipt(b.predecessorReceipt, prior) || b.predecessorReceipt.terminalOutcome !== 'verified'
            || !settled.v2Terminal.proofs.some(p => same(p, b.predecessorReceipt))) refuse();
        result.push({ b, l, e, o, prior });
    }
    return result;
}
async function settleUndispatchedPreparation({ models, selected, lifecycle, finalizer, operationId, onSettled }) {
    return lifecycle.run(async () => {
        await lifecycle.assertHeld();
        const op = await query(models.TopologyOperation, { _id: operationId }, undefined, PRIVATE); eligible(op);
        const r = await roots(models, op);
        return lifecycle.withTestUndispatchedPreparation(r.map(x => x.b), async (physical, check) => {
            const observed = validateUndispatchedPhysical(r.map(x => x.b), r.map(x => x.prior), physical);
            await check();
            const state = await query(models.CascadeTopologyState, { _id: 'singleton' });
            const evidence = Object.freeze({ op, roots: r, observed, state, check });
            ISSUED.add(evidence);
            const result = await finalizer.finalizeUndispatchedPreparation({ operationId, evidence });
            await check();
            if (onSettled) await onSettled(result);
            return result;
        });
    });
}
async function finalizeUndispatchedPreparation(repo, { operationId, evidence, now }) {
    if (!ISSUED.has(evidence)) refuse();
    ISSUED.delete(evidence); // One transaction only, including ambiguous commit.
    if (!(now instanceof Date) || String(evidence.op._id) !== operationId) refuse();
    const models = repo, selected = repo.selectedTopologyRepository, db = models.TopologyOperation.db;
    const s = await db.startSession(); let attempted = false, audit;
    try {
        s.startTransaction({ readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
        const op = await query(models.TopologyOperation, { _id: operationId }, s, PRIVATE); eligible(op);
        if (!same(op, evidence.op) || !same(await roots(models, op, s), evidence.roots)) refuse();
        if (await query(models.TopologyOperation, { _id: { $ne: operationId }, heldTopologyAdmission: true }, s)) refuse();
        await selected.verifySelected(op, s);
        const state = await query(models.CascadeTopologyState, { _id: 'singleton' }, s);
        if (!same(state, evidence.state) || state?.topologyAdmissionCount !== 1 || state.remoteAdmissionCount !== 0
            || state.remoteDrain || state.replacementReservation) refuse();
        await evidence.check();
        const nonce = randomUUID();
        for (let i = 0; i < evidence.roots.length; i++) {
            const { b, l, o } = evidence.roots[i], { updatedAt: ignored, ...owner } = o;
            for (const [M, f] of [[models.TopologyConfigOwner, owner], [models.HyNode, { _id: b.nodeId, active: true, type: 'xray',
                cascadeRole: op.nodes[i].role, ip: b.endpoint.ip, 'ssh.port': b.endpoint.port, 'ssh.username': b.endpoint.username }]]) {
                if ((await M.updateOne(f, { $set: { executionBindingCheck: nonce } }, { session: s, ...OPTIONS, runValidators: true })).matchedCount !== 1) refuse();
            }
            if ((await models.NodeOperationLock.deleteOne(l, { session: s, ...OPTIONS })).deletedCount !== 1) refuse();
        }
        audit = { kind: 'failed-first-prepare-all-bindings-absent-v1', settledAt: now, originalFinishedAt: op.finishedAt,
            originalAttempts: op.attempts, originalNodes: op.nodes.map(n => ({ node: String(n.node), state: n.state, backupId: n.backupId })),
            stateEpoch: { revision: state.revision, replacementEpoch: state.replacementEpoch, stateTransitionRevision: state.stateTransitionRevision },
            bindings: evidence.roots.map(({ b }) => ({ id: b._id, nodeId: b.nodeId, generation: b.generation, attemptId: b.attemptId, commandIds: b.commandIds })),
            observed: evidence.observed.map(p => ({ nodeId: p.nodeId, bootId: p.bootId, generation: p.generation,
                noDispatch: p.noDispatch, journalSha256: p.journalSha256,
                current: Object.fromEntries(Object.entries(p.current).map(([k, v]) => [k, { configSha256: v.configSha256, serviceActive: v.serviceActive }])) })) };
        if ((await models.TopologyOperation.updateOne({ _id: operationId, status: 'failed', attempts: 1, heldTopologyAdmission: true,
            leaseOwner: op.leaseOwner, leaseUntil: null, finishedAt: op.finishedAt, nodes: op.nodes, undispatchedPreparationSettlement: { $exists: false } },
        { $set: { heldTopologyAdmission: false, undispatchedPreparationSettlement: audit } }, { session: s, ...OPTIONS, runValidators: true })).matchedCount !== 1) refuse();
        if ((await models.CascadeTopologyState.updateOne(state, { $inc: { topologyAdmissionCount: -1, stateTransitionRevision: 1 } },
            { session: s, ...OPTIONS, runValidators: true })).matchedCount !== 1) refuse();
        await evidence.check(); attempted = true;
        try {
            const r = await db.getClient().db('admin').command({ commitTransaction: 1, writeConcern: { w: 'majority', wtimeout: 5000 }, maxTimeMS: 5000 }, { session: s, ...OPTIONS });
            if (r.ok !== 1 || r.writeConcernError || r.errorLabels?.length) refuse();
        } finally { s.transaction.transition('TRANSACTION_COMMITTED'); }
    } catch (e) { if (!attempted && s.inTransaction()) await s.abortTransaction().catch(() => {}); throw e; }
    finally { await s.endSession(); }
    const fresh = await query(models.TopologyOperation, { _id: operationId }, undefined, PRIVATE);
    if (fresh?.status !== 'failed' || fresh.heldTopologyAdmission !== false || !same(fresh.undispatchedPreparationSettlement, audit)
        || !same(fresh.nodes, evidence.op.nodes) || !same(fresh.finishedAt, evidence.op.finishedAt)) refuse();
    for (const { b, o } of evidence.roots) {
        if (await query(models.NodeOperationLock, { node: b.nodeId, generation: b.generation })) refuse();
        const owner = await query(models.TopologyConfigOwner, { node: b.nodeId, profile: b.targetProfile });
        if (owner?.lastSettledOperation !== o.lastSettledOperation || owner.lastSettledGeneration !== o.lastSettledGeneration
            || owner.lastSettledCloseId !== o.lastSettledCloseId) refuse();
    }
    await evidence.check();
    return { operationId, status: 'failed', reconciled: true, businessSuccess: false, noDispatchProven: true };
}
module.exports = { settleUndispatchedPreparation, finalizeUndispatchedPreparation, assertFailedUndispatchedEligible: eligible };
