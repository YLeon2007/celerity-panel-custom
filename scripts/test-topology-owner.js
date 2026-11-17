#!/usr/bin/env node
'use strict';
// Explicit internal maintenance entry, never imported/called by normal startup.
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../src/modules/relay-l2tp/domain/topologyExecutionContext');
const { freeze } = require('../src/modules/relay-l2tp/models/topologyExecutionBindingContract');
function failure(code) { return Object.assign(new Error(code), { code }); }
function assertTestContext(env) {
    if (env?.PANEL_DOMAIN !== TEST.hostIdentity || env.L2TP_EXECUTION_ENABLED !== 'true'
        || env.L2TP_MIGRATIONS_ENABLED !== 'true' || env.TOPOLOGY_TEST_EXECUTION_ENABLED !== 'true'
        || env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'true' || env.L2TP_PRODUCTION_EXECUTION_ENABLED === 'true') {
        throw failure('TEST_OWNER_CONTEXT_REQUIRED');
    }
}
async function initializeDedicatedTestState(models, check, physicalPlan) {
    const State = models.CascadeTopologyState;
    const absentRelays = [];
    await check();
    await State.db.transaction(async session => {
        absentRelays.length = 0;
        const state = await State.findById('singleton').session(session).setOptions({ maxTimeMS: 5000 }).lean();
        if (state) {
            if (!['revision','deployedRevision','remoteAdmissionCount','topologyAdmissionCount'].every(k => Number.isSafeInteger(state[k]) && state[k] >= 0)
                || state.remoteDrain || state.replacementReservation) throw failure('TEST_ADMISSION_STATE_RECONCILE_REQUIRED');
            return; // Never reset/repair existing counters or desired state.
        }
        for (const name of ['CascadeLink','CascadeRouteGroup','RelayL2tpState','TopologyOperation','TopologyExecutionBinding',
            'NodeOperationLock','RemoteAdmission','L2tpOperation','TopologyCreateIntent','TopologyIntentQueueState']) {
            if (await models[name].findOne({}).session(session).setOptions({ maxTimeMS: 5000 }).lean()) throw failure('TEST_ADMISSION_STATE_NOT_EMPTY');
        }
        if (physicalPlan !== undefined) {
            if (!Array.isArray(physicalPlan.nodes) || !physicalPlan.nodes.length
                || ['HyNode','L2tpUser','L2tpOperation','RelayL2tpState'].some(name => models[name]?.db !== State.db)) {
                throw failure('TEST_PPP_ABSENCE_UNPROVEN');
            }
            for (const pin of physicalPlan.nodes) {
                const node = await models.HyNode.findById(pin.nodeId).select('_id cascadeRole')
                    .session(session).setOptions({ maxTimeMS: 5000 }).lean();
                if (!node || String(node._id) !== pin.nodeId) throw failure('TEST_PPP_ABSENCE_UNPROVEN');
                if (node.cascadeRole !== 'relay') continue;
                if (pin.l2tpUnconfigured !== true
                    || await models.L2tpUser.findOne({ relayNode: pin.nodeId }).session(session).setOptions({ maxTimeMS: 5000 }).lean()
                    || await models.L2tpOperation.findOne({ node: pin.nodeId }).session(session).setOptions({ maxTimeMS: 5000 }).lean()) {
                    throw failure('TEST_PPP_ABSENCE_UNPROVEN');
                }
                absentRelays.push(pin.nodeId);
            }
            await check();
            if (absentRelays.length) await models.RelayL2tpState.insertMany(absentRelays.map(node => ({
                node, desiredState: 'absent', status: 'not_installed', secretRevision: 0,
            })), { session });
        }
        await State.create([{ _id: 'singleton', revision: 0, deployedRevision: 0, stateTransitionRevision: 0,
            replacementEpoch: 0, remoteAdmissionCount: 0, topologyAdmissionCount: 0 }], { session });
    }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
    await check();
    const confirmed = await State.findById('singleton').read('primary').readConcern('majority').maxTimeMS(5000).lean();
    if (!confirmed || !['revision','deployedRevision','remoteAdmissionCount','topologyAdmissionCount'].every(k => Number.isSafeInteger(confirmed[k]) && confirmed[k] >= 0)) throw failure('TEST_ADMISSION_STATE_UNCONFIRMED');
    for (const node of absentRelays) {
        const state = await models.RelayL2tpState.findOne({ node }).read('primary').readConcern('majority').maxTimeMS(5000).lean();
        if (state?.status !== 'not_installed' || state.desiredState !== 'absent' || state.secretRevision !== 0) throw failure('TEST_PPP_ABSENCE_UNCONFIRMED');
    }
    await check();
}
async function enrollTestOwners({ env, lifecycle, store, TopologyConfigOwner, TopologyExecutionEnrollment, dedicatedModels, resumeOnly = false, onReconciled } = {}) {
    assertTestContext(env);
    if (typeof lifecycle?.withCapturedTestOwnerEnrollment !== 'function') {
        throw failure('TEST_DURABLE_ORIGINALS_CAPTURE_REQUIRED');
    }
    // No caller-provided node inventory, owner generation, receipt or flag can
    // supply the plan: only the actual held controller's private accepted pins.
    return lifecycle.run(() => lifecycle.withCapturedTestOwnerEnrollment(async (plan, check) => {
        const { TopologyConfigTransfer } = require('../src/services/topologyConfigTransfer');
        const transfer = new TopologyConfigTransfer({ executionContext: TEST, TopologyConfigOwner,
            withVerifiedMaintenance: lifecycle.withVerifiedMaintenance.bind(lifecycle) });
        const enrolled = [];
        for (const pin of plan.nodes) {
            await check();
            if (env.TOPOLOGY_TEST_STARTUP_MODE === 'dedicated-runtime-v1') {
                const owner = await TopologyConfigOwner.findOne({ node: pin.nodeId, profile: pin.targetProfile }).read('primary').readConcern('majority').maxTimeMS(5000).lean();
                const existing = await TopologyExecutionEnrollment.findOne({ nodeId: pin.nodeId, targetProfile: pin.targetProfile }).read('primary').readConcern('majority').maxTimeMS(5000).lean();
                if (owner || existing || resumeOnly) {
                    if (!owner || !existing || owner.owner !== 'topology') throw failure('TEST_ENROLLMENT_RECONCILE_REQUIRED');
                    const { proofRef, ...snapshot } = pin.originalSnapshot;
                    const result = await store.verifyPristineEnrollment(freeze({ nodeId: pin.nodeId, targetProfile: pin.targetProfile,
                        endpoint: pin.endpoint, nodeIdentity: pin.nodeIdentity, bootId: pin.bootId,
                        predecessorGeneration: 'none', ownerGeneration: owner.generation }), snapshot);
                    await check();
                    enrolled.push({ nodeId: pin.nodeId, targetProfile: pin.targetProfile, enrollmentId: result.enrollmentId, ownerGeneration: owner.generation,
                        enrollmentBootId: existing.bootId, runtimeBootId: result.bootId });
                    continue;
                }
            }
            const classic = await transfer.initializeClassic({ node: pin.nodeId, profile: pin.targetProfile, nodeIdentity: pin.nodeIdentity });
            await check();
            const adopted = await transfer.adopt({ node: pin.nodeId, profile: pin.targetProfile,
                generation: classic.generation, proofRef: pin.originalSnapshot.proofRef });
            await check();
            const result = await store.preEnroll(freeze({ nodeId: pin.nodeId, targetProfile: pin.targetProfile,
                endpoint: pin.endpoint, nodeIdentity: pin.nodeIdentity, bootId: pin.bootId,
                predecessorGeneration: 'none', ownerGeneration: adopted.generation }));
            await check();
            enrolled.push({ nodeId: pin.nodeId, targetProfile: pin.targetProfile, enrollmentId: result.enrollmentId,
                ownerGeneration: adopted.generation });
        }
        if (env.TOPOLOGY_TEST_STARTUP_MODE === 'dedicated-runtime-v1') await initializeDedicatedTestState(dedicatedModels, check, plan);
        const result = freeze({ status: 'enrolled', executionContext: TEST, nodes: enrolled });
        if (onReconciled) { await check(); await onReconciled(result); }
        return result;
    }));
}
async function main(argv = process.argv.slice(2)) {
    if (argv.length !== 1 || argv[0] !== 'enroll') {
        process.stderr.write('Usage: node scripts/test-topology-owner.js enroll\n'); return 2;
    }
    // Reuse existing private dotenv/config and database credentials, never print
    // their values. No argv/env path, node selector, shell, upload or live probe.
    require('dotenv').config({ quiet: true });
    assertTestContext(process.env);
    const config = require('../config');
    const mongoose = require('mongoose');
    let root;
    try {
        const { createL2tpRootLifecycle } = require('../src/modules/l2tpRuntimeLifecycleHook');
        root = createL2tpRootLifecycle();
        // Enrollment never installs schema or starts background consumers.
        await mongoose.connect(config.MONGO_URI, { autoCreate: false, autoIndex: false, serverSelectionTimeoutMS: 5000 });
        const result = await root.enrollTestOwnersAfterDatabase();
        process.stdout.write(JSON.stringify(result) + '\n'); return 0;
    } finally {
        try { await root?.stop(); }
        finally {
            // A finite maintenance CLI owns this process. Drain the root first,
            // then close only a pool already imported by its dependency graph;
            // never instantiate a fresh pool during cleanup or force process.exit.
            try {
                const pool = require.cache[require.resolve('../src/services/sshPoolService')]?.exports;
                if (pool) await pool.closeAll();
            } finally { await mongoose.disconnect(); }
        }
    }
}
if (require.main === module) main().then(code => { process.exitCode = code; }, () => {
    // Driver/controller exceptions can contain credentials or secret file bytes.
    process.stderr.write('TEST_OWNER_ENROLLMENT_REFUSED_RETAINED\n'); process.exitCode = 1;
});
// Late-added, still-pristine dedicated relay. This is the same explicit absent
// PPP epoch as first startup, not installation or missing-row recovery. No
// operation may be active, and the original enrolled runtime must remain exact.
async function initializePristineDedicatedRelayAbsence({ env, models, lifecycle, nodeId }) {
    assertTestContext(env);
    const { isDeepStrictEqual: same } = require('node:util');
    const { randomUUID } = require('node:crypto');
    const { enrollmentRuntimeBootId } = require('../src/modules/relay-l2tp/repositories/topologyExecutionBindingStore');
    const refuse = () => { throw failure('TEST_PRISTINE_RELAY_ABSENCE_UNPROVEN'); };
    if (env.TOPOLOGY_TEST_STARTUP_MODE !== 'dedicated-runtime-v1' || !/^[a-f0-9]{24}$/.test(nodeId || '')
        || typeof lifecycle?.run !== 'function' || typeof lifecycle.withTestRetainedVerifyObservation !== 'function') refuse();
    const options = { maxTimeMS: 5000, timeoutMS: 5000 }, db = models.CascadeTopologyState.db;
    if (['HyNode','TopologyConfigOwner','TopologyExecutionEnrollment','TopologyExecutionBinding','TopologyOperation','NodeOperationLock','RelayL2tpState','L2tpUser','L2tpOperation'].some(k => models[k]?.db !== db)) refuse();
    const q = (M, f, s, select) => { let r = M.findOne(f); if (select) r = r.select(select); return (s ? r.session(s) : r.read('primary').readConcern('majority')).setOptions(options).lean(); };
    return lifecycle.run(async () => {
        const load = async session => {
            const state = await q(models.CascadeTopologyState, { _id:'singleton' }, session);
            const e = await q(models.TopologyExecutionEnrollment, { nodeId, targetProfile:'xray-bridge' }, session);
            const o = await q(models.TopologyConfigOwner, { node:nodeId, profile:'xray-bridge' }, session, '+legacyAppliedTopology +profileTargetPin');
            const n = await q(models.HyNode, { _id:nodeId }, session, '_id active type cascadeRole ip ssh.port ssh.username');
            if (!state || state.topologyAdmissionCount !== 0 || state.remoteAdmissionCount !== 0 || state.remoteDrain || state.replacementReservation
                || !e || e.executionContext !== TEST.hostIdentity || e.predecessorGeneration !== 'none'
                || !o || !same(o.executionContext,TEST) || o.owner !== 'topology' || o.generation !== e.ownerGeneration
                || !same(o.nodeIdentity,e.nodeIdentity) || !o.originalSnapshot || o.adoptionReceipt?.toGeneration !== o.generation
                || ['lastSettledOperation','lastSettledGeneration','lastSettledCloseId','legacyAppliedTopology','profileTargetPin','handbackReceipt'].some(k => o[k] !== undefined)
                || !n || n.type !== 'xray' || n.active !== true || n.cascadeRole !== 'relay' || n.ip !== e.endpoint.ip
                || n.ssh.port !== e.endpoint.port || n.ssh.username !== e.endpoint.username) refuse();
            for (const [M,f] of [[models.TopologyExecutionBinding,{nodeId}],[models.TopologyOperation,{heldTopologyAdmission:true}],
                [models.NodeOperationLock,{}],[models.RelayL2tpState,{node:nodeId}],[models.L2tpUser,{relayNode:nodeId}],[models.L2tpOperation,{node:nodeId}]]) if (await q(M,f,session)) refuse();
            return {state,e,o,n};
        };
        const root = await load();
        const enrolled = { ...root.e, bootId:enrollmentRuntimeBootId(root.e) };
        return lifecycle.withTestRetainedVerifyObservation([enrolled], async (physical, check) => {
            const p = physical.nodes?.[0], current = p?.current?.['xray-bridge'];
            const { source, ...snapshot } = current || {};
            if (physical.nodes.length !== 1 || p.nodeId !== nodeId || p.bootId !== enrolled.bootId || p.runnerIdle !== true
                || p.journal !== null || p.l2tpUnconfigured !== true || source !== 'node-readback' || !same(snapshot,root.o.originalSnapshot)) refuse();
            await check(); const s = await db.startSession(), nonce = randomUUID(); let attempted = false;
            try {
                s.startTransaction({readConcern:{level:'snapshot'},writeConcern:{w:'majority'},readPreference:'primary'});
                if (!same(await load(s),root)) refuse();
                const {updatedAt:ignored,...owner}=root.o;
                const nodeFence={_id:root.n._id,active:true,type:'xray',cascadeRole:'relay',ip:root.e.endpoint.ip,'ssh.port':root.e.endpoint.port,'ssh.username':root.e.endpoint.username};
                for (const [M,f] of [[models.TopologyConfigOwner,owner],[models.HyNode,nodeFence]])
                    if ((await M.updateOne(f,{$set:{executionBindingCheck:nonce}},{session:s,...options,runValidators:true})).matchedCount !== 1) refuse();
                await models.RelayL2tpState.insertMany([{node:nodeId,desiredState:'absent',status:'not_installed',secretRevision:0}],{session:s,...options});
                if ((await models.CascadeTopologyState.updateOne(root.state,{$inc:{stateTransitionRevision:1}},{session:s,...options,runValidators:true})).matchedCount !== 1) refuse();
                await check(); attempted=true;
                try { const r=await db.getClient().db('admin').command({commitTransaction:1,writeConcern:{w:'majority',wtimeout:5000},maxTimeMS:5000},{session:s,...options});if(r.ok!==1||r.writeConcernError||r.errorLabels?.length)refuse(); }
                finally { s.transaction.transition('TRANSACTION_COMMITTED'); }
            } catch (e) { if(!attempted&&s.inTransaction())await s.abortTransaction().catch(()=>{});throw e; }
            finally { await s.endSession(); }
            const state = await q(models.RelayL2tpState,{node:nodeId});
            if(state?.status !== 'not_installed' || state.desiredState !== 'absent' || state.secretRevision !== 0)refuse();
            for(const[M,f]of[[models.TopologyConfigOwner,{_id:root.o._id,generation:root.o.generation,executionBindingCheck:nonce}],[models.HyNode,{_id:nodeId,executionBindingCheck:nonce}]])if(!await q(M,f))refuse();
            await check();return {nodeId,status:'not_installed',desiredState:'absent',credentialRevision:0,installed:false,physicalPristineAbsence:true};
        });
    });
}
async function inspectTestOwnerHandback({ env, models }) {
    assertTestContext(env);
    if (env.TOPOLOGY_TEST_STARTUP_MODE !== 'dedicated-runtime-v1') throw failure('TEST_OWNER_HANDBACK_UNPROVEN');
    const read = query => query.read('primary').readConcern('majority').maxTimeMS(5000).lean();
    const owners = await read(models.TopologyConfigOwner.find({ executionContext: TEST, owner: 'topology' }));
    const aliases = await read(models.TopologyExecutionEnrollment.find({ executionContext: TEST.hostIdentity }));
    if (!owners.length || owners.length !== aliases.length) throw failure('TEST_OWNER_HANDBACK_UNPROVEN');
    const ids = owners.map(row => String(row.node));
    const state = await read(models.CascadeTopologyState.findById('singleton'));
    if (!state || state.remoteAdmissionCount !== 0 || state.topologyAdmissionCount !== 0
        || state.remoteDrain || state.replacementReservation || state.classicLifecycleAttempt
        || await read(models.NodeOperationLock.findOne({ node: { $in: ids } }))
        || await read(models.RemoteAdmission.findOne({ nodeId: { $in: ids }, phase: { $ne: 'completed' } }))
        || await read(models.TopologyOperation.findOne({ heldTopologyAdmission: true }))
        || await read(models.TopologyCreateIntent.findOne({ status: { $nin: ['succeeded','failed','cancelled'] } }))) {
        throw failure('TEST_OWNER_HANDBACK_BUSY');
    }
    return freeze(owners.map(owner => {
        const alias = aliases.find(row => row.nodeId === String(owner.node) && row.targetProfile === owner.profile);
        if (!alias || alias.ownerGeneration !== owner.generation || owner.handbackReceipt !== undefined
            || alias.maintenanceId !== owner.adoptionReceipt?.maintenanceId) throw failure('TEST_OWNER_HANDBACK_UNPROVEN');
        return { nodeId: String(owner.node), targetProfile: owner.profile, ownerGeneration: owner.generation,
            proofRef: 'dedicated-' + alias.maintenanceId };
    }));
}
async function handbackTestOwners({ env, models, lifecycle, authority, expected }) {
    const { isDeepStrictEqual: same } = require('node:util');
    const nodes = await inspectTestOwnerHandback({ env, models });
    if (!same(lifecycle.executionContext, TEST) || !same(nodes, expected)) throw failure('TEST_OWNER_HANDBACK_UNPROVEN');
    // Existing sole controller: drain, fresh actual journal/profile CURRENT,
    // all-participant prepare, exact original restoration, verified transfer.
    authority.drainOriginals();
    const current = await authority.readOriginalRestoreCurrent();
    if (!same(Object.keys(current).sort(), nodes.map(row => row.nodeId).sort())) throw failure('TEST_OWNER_HANDBACK_UNPROVEN');
    await authority.restoreOriginals(current);
    const transfer = new (require('../src/services/topologyConfigTransfer').TopologyConfigTransfer)({
        executionContext: TEST, TopologyConfigOwner: models.TopologyConfigOwner,
        withVerifiedMaintenance: lifecycle.withVerifiedMaintenance.bind(lifecycle) });
    for (const row of nodes) await lifecycle.run(() => transfer.handback({ node: row.nodeId, profile: row.targetProfile,
        generation: row.ownerGeneration, proofRef: row.proofRef }));
    for (const row of nodes) {
        const owner = await models.TopologyConfigOwner.findOne({ node: row.nodeId, profile: row.targetProfile })
            .read('primary').readConcern('majority').maxTimeMS(5000).lean();
        if (owner?.owner !== 'classic' || owner.handbackReceipt?.fromGeneration !== row.ownerGeneration) throw failure('TEST_OWNER_HANDBACK_UNPROVEN');
    }
    await authority.releaseOriginals();
    return freeze({ status: 'handed-back', nodes: nodes.map(({ nodeId, targetProfile }) => ({ nodeId, targetProfile })) });
}
module.exports = { enrollTestOwners, initializeDedicatedTestState, initializePristineDedicatedRelayAbsence,
    inspectTestOwnerHandback, handbackTestOwners, assertTestContext, main };
