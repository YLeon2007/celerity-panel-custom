'use strict';
// Explicit dedicated TEST continuation only. No new operation/attempt/generation,
// no deletion/release, and no replay of predecessor commands (including UNKNOWN).
const { isDeepStrictEqual: same } = require('node:util');
const { randomUUID, createHash } = require('node:crypto');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const { enrollmentRuntimeBootId } = require('./topologyExecutionBindingStore');
const { validTerminalReceipt, UUID } = require('../models/topologyExecutionBindingContract');
const PRIVATE = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +deleteJobId +installedPath';
const OPTIONS = { maxTimeMS: 5000, timeoutMS: 5000 };
function refuse() { throw Object.assign(Error('TEST_BINDING_RESERVATION_CONTINUATION_UNPROVEN'), { code:'TEST_BINDING_RESERVATION_CONTINUATION_UNPROVEN' }); }
function eligible(op, owner) {
    if (!op || !same(op.executionContext, TEST) || op.kind !== 'link.apply' || op.admissionScope !== 'selected'
        || op.status !== 'queued' || op.attempts !== 1 || op.leaseOwner !== '' || op.leaseUntil !== null
        || op.heldTopologyAdmission !== true || op.finishedAt !== null || op.v2Terminal !== undefined
        || op.pppWait !== undefined || op.bindingReservationContinuation !== undefined
        || op.bootstrapContinuation !== undefined || op.bootstrapCancellation !== undefined
        || !Array.isArray(op.nodes) || !op.nodes.length || op.nodes.length > 8 || op.resourceNodeIds?.length !== op.nodes.length
        || new Set(op.resourceNodeIds).size !== op.nodes.length
        || op.nodes.some(n => n.state !== 'pending' || n.backupId !== '' || !['xray-main','xray-bridge'].includes(n.targetProfile)
            || !op.resourceNodeIds.includes(String(n.node))) || typeof owner !== 'string' || !owner) refuse();
}
// Reached six-profile DELETE only: one immutable reservation was committed,
// then its readVerified CAS conflicted with the heartbeat before any prepare.
// Complete only absent reservations after the existing held physical observer
// proves every original generation/operation/backup absent and predecessor live.
function pendingDeleteEligible(op, owner, now) {
    if (!op || !same(op.executionContext, TEST) || op.kind !== 'link.delete' || op.admissionScope !== 'selected'
        || op.status !== 'preparing' || op.attempts !== 1 || op.leaseOwner !== owner
        || !(op.leaseUntil instanceof Date) || op.leaseUntil > now || op.finishedAt !== null
        || op.heldTopologyAdmission !== true || typeof op.deleteJobId !== 'string'
        || op.nodes?.length !== 6 || op.resourceNodeIds?.length !== 6 || new Set(op.resourceNodeIds).size !== 6
        || op.nodes.some(n => n.state !== 'pending' || n.backupId !== '' || !op.resourceNodeIds.includes(String(n.node)))
        || ['v2Terminal','pppWait','bootstrapContinuation','bootstrapCancellation','bindingReservationContinuation',
            'retainedVerifyContinuation','undispatchedPreparationContinuation','closedSettlementContinuation','preparedCommitContinuation']
            .some(k => op[k] !== undefined)) refuse();
}
async function claimPendingDeleteReservations(models, selected, lifecycle, input, op) {
    const { operationId, owner, leaseMs, now } = input, M = models.TopologyOperation, db = M.db;
    pendingDeleteEligible(op, owner, now);
    if ([models.TopologyExecutionBinding,models.TopologyExecutionEnrollment,models.TopologyConfigOwner,
        models.NodeOperationLock,models.HyNode,models.CascadeTopologyState].some(Model => Model?.db !== db)) refuse();
    const majority = (Model,q,select) => { let r=Model.findOne(q);if(select)r=r.select(select);return r.read('primary').readConcern('majority').setOptions(OPTIONS).lean(); };
    const all = await models.TopologyExecutionBinding.find({operationId}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
    const locks = await models.NodeOperationLock.find({operationId}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
    if (all.length !== 1 || locks.length !== 6) refuse();
    const roots=[], reservations=[], priors=[];
    for (const n of op.nodes) {
        const id=String(n.node), l=locks.find(l=>String(l.node)===id);
        const e=await majority(models.TopologyExecutionEnrollment,{nodeId:id,targetProfile:n.targetProfile});
        const o=await majority(models.TopologyConfigOwner,{node:id,profile:n.targetProfile},'+legacyAppliedTopology +profileTargetPin');
        if (!l || l.owner!==owner || l.remoteUncertain!==true || !UUID.test(l.generation)
            || !(l.leaseUntil instanceof Date) || l.leaseUntil>now || !e || !o || o.owner!=='topology'
            || !same(o.executionContext,TEST) || o.handbackReceipt!==undefined || e.ownerGeneration!==o.generation
            || !same(e.nodeIdentity,o.nodeIdentity) || Object.hasOwn(e,'profileTargetPin') || Object.hasOwn(o,'profileTargetPin')) refuse();
        const prior=await majority(models.TopologyExecutionBinding,{enrollmentId:e._id,operationId:o.lastSettledOperation,
            generation:o.lastSettledGeneration,'commandIds.close':o.lastSettledCloseId});
        const settled=prior&&await majority(M,{_id:prior.operationId,status:'succeeded',heldTopologyAdmission:false,'v2Terminal.state':'proven'});
        const proof=settled?.v2Terminal?.proofs?.find(p=>p.nodeId===id);
        if (!prior || !proof || prior.nodeId!==id || prior.targetProfile!==n.targetProfile || prior.ownerGeneration!==o.generation
            || prior.bootId!==enrollmentRuntimeBootId(e) || !same(prior.endpoint,e.endpoint) || !same(prior.nodeIdentity,e.nodeIdentity)
            || !validTerminalReceipt(proof,prior) || proof.terminalOutcome!=='verified') refuse();
        const candidateHash='sha256:'+n.candidateHash;
        // These are observation requests, not invented durable bindings/IDs.
        const r={executionContext:TEST.hostIdentity,operationId,nodeId:id,targetProfile:n.targetProfile,
            generation:l.generation,candidateHash,backupId:'topology-'+createHash('sha256').update([operationId,id,candidateHash,n.targetProfile].join('\0')).digest('hex'),
            bootId:prior.bootId,maintenanceId:e.maintenanceId,endpoint:e.endpoint,nodeIdentity:e.nodeIdentity,
            predecessorGeneration:prior.generation,predecessorReceipt:proof};
        const b=all.find(b=>b.nodeId===id);
        if (b && (b.attempt!==1 || b.owner!==owner || b.enrollmentId!==e._id || b.ownerGeneration!==o.generation
            || b.topologyRevision!==op.topologyRevision || b.priorDeployedRevision!==op.priorDeployedRevision
            || b.predecessorBindingId!==prior._id || !UUID.test(b._id) || !UUID.test(b.attemptId)
            || ['prepare','commit','verify','rollback','close'].some(c=>!UUID.test(b.commandIds?.[c]))
            || Object.entries(r).some(([k,v])=>!same(b[k],v)))) refuse();
        reservations.push(r);priors.push(prior);roots.push({e,o,l,prior,settled,b});
    }
    if (new Set(priors.map(b=>b.operationId)).size!==1 || !roots.some(r=>r.b)) refuse();
    return lifecycle.withTestUndispatchedPreparation(reservations,async(physical,check)=>{
        const observed=require('./topologyUndispatchedPreparationContinuation').validateUndispatchedPhysical(reservations,priors,physical);
        await check();const session=await db.startSession(),nonce=randomUUID();let attempted=false,lease,audit;
        try {
            session.startTransaction({readConcern:{level:'snapshot'},writeConcern:{w:'majority'},readPreference:'primary'});
            const current=await M.findById(operationId).select(PRIVATE).session(session).setOptions(OPTIONS).lean();
            pendingDeleteEligible(current,owner,now);if(!same(current,op))refuse();
            if (!same(await models.TopologyExecutionBinding.find({operationId}).session(session).setOptions(OPTIONS).lean(),all)
                || await M.findOne({_id:{$ne:operationId},heldTopologyAdmission:true}).session(session).setOptions(OPTIONS).lean()) refuse();
            await selected.verifySelected(current,session);
            const state=await models.CascadeTopologyState.findById('singleton').session(session).setOptions(OPTIONS).lean();
            if(state?.topologyAdmissionCount!==1||state.remoteAdmissionCount!==0||state.remoteDrain||state.replacementReservation)refuse();
            await check();lease=new Date(Date.now()+leaseMs);
            for(const {e,o,l,prior,settled,b}of roots){
                for(const [Model,row]of [[models.TopologyExecutionEnrollment,e],[models.TopologyExecutionBinding,prior],...(b?[[models.TopologyExecutionBinding,b]]:[])])
                    if(!await Model.findOne(row).session(session).setOptions(OPTIONS).lean())refuse();
                if(!await M.findOne({_id:settled._id,status:'succeeded',heldTopologyAdmission:false,v2Terminal:settled.v2Terminal}).session(session).setOptions(OPTIONS).lean())refuse();
                const {updatedAt:ignored,...ownerFence}=o;
                for(const [Model,row]of [[models.TopologyConfigOwner,ownerFence],[models.HyNode,{_id:e.nodeId,active:true,type:'xray',
                    cascadeRole:op.nodes.find(n=>String(n.node)===e.nodeId).role,ip:e.endpoint.ip,'ssh.port':e.endpoint.port,'ssh.username':e.endpoint.username}]])
                    if((await Model.updateOne(row,{$set:{executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
                if((await models.NodeOperationLock.updateOne(l,{$set:{leaseUntil:lease,executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
            }
            audit={kind:'partial-delete-reservations-all-native-dispatch-absent-v1',observedAt:new Date(),nonce,
                originalStatus:op.status,originalAttempts:op.attempts,originalLeaseUntil:op.leaseUntil,
                locks:locks.map(l=>({node:String(l.node),generation:l.generation})),preservedBindingIds:all.map(b=>b._id),
                predecessorOperation:priors[0].operationId,observed};
            if((await M.updateOne({_id:operationId,status:'preparing',attempts:1,leaseOwner:owner,leaseUntil:op.leaseUntil,
                heldTopologyAdmission:true,finishedAt:null,nodes:op.nodes,bindingReservationContinuation:{$exists:false}},
                {$set:{leaseUntil:lease,bindingReservationContinuation:audit,executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
            if((await models.CascadeTopologyState.updateOne(state,{$inc:{stateTransitionRevision:1}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
            await check();attempted=true;
            try{const result=await db.getClient().db('admin').command({commitTransaction:1,writeConcern:{w:'majority',wtimeout:5000},maxTimeMS:5000},{session,...OPTIONS});if(result.ok!==1||result.writeConcernError||result.errorLabels?.length)refuse();}
            finally{session.transaction.transition('TRANSACTION_COMMITTED');}
        }catch(error){if(!attempted&&session.inTransaction())await session.abortTransaction().catch(()=>{});throw error;}
        finally{await session.endSession();}
        const confirmed=await M.findById(operationId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
        if(confirmed?.status!=='preparing'||confirmed.attempts!==1||confirmed.leaseUntil?.getTime()!==lease.getTime()
            ||!same(confirmed.bindingReservationContinuation,audit)
            ||!same(await models.TopologyExecutionBinding.find({operationId}).read('primary').readConcern('majority').setOptions(OPTIONS).lean(),all))refuse();
        for(const {l,o}of roots)if(!await majority(models.NodeOperationLock,{_id:l._id,operationId,owner,generation:l.generation,
            remoteUncertain:true,leaseUntil:lease,executionBindingCheck:nonce})||!await majority(models.TopologyConfigOwner,
            {_id:o._id,generation:o.generation,lastSettledOperation:o.lastSettledOperation,lastSettledGeneration:o.lastSettledGeneration,
                lastSettledCloseId:o.lastSettledCloseId,executionBindingCheck:nonce}))refuse();
        await check();return confirmed;
    });
}

async function claimBindingReservationContinuation(models, selected, lifecycle, { operationId, owner, leaseMs, now }) {
    const M = models.TopologyOperation, db = M.db;
    const op = await M.findById(operationId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
    if (op?.kind === 'link.delete' && op.status === 'preparing') return claimPendingDeleteReservations(
        models, selected, lifecycle, { operationId, owner, leaseMs, now }, op);
    eligible(op, owner);
    const locks = await models.NodeOperationLock.find({operationId}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
    if (locks.length !== op.nodes.length || await models.TopologyExecutionBinding.exists({operationId})) refuse();
    const predecessors = [], roots = [], reservations = [];
    for (const n of op.nodes) {
        const id = String(n.node), lock = locks.find(l => String(l.node) === id);
        const e = await models.TopologyExecutionEnrollment.findOne({nodeId:id,targetProfile:n.targetProfile}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
        const o = await models.TopologyConfigOwner.findOne({node:id,profile:n.targetProfile}).select('+legacyAppliedTopology +profileTargetPin').read('primary').readConcern('majority').setOptions(OPTIONS).lean();
        if (!lock || lock.owner !== owner || lock.remoteUncertain !== true || !UUID.test(lock.generation)
            || !(lock.leaseUntil instanceof Date) || lock.leaseUntil > now || !e || !o
            || o.owner !== 'topology' || !same(o.executionContext, TEST) || e.ownerGeneration !== o.generation
            || !same(e.nodeIdentity,o.nodeIdentity) || o.handbackReceipt !== undefined) refuse();
        const b = await models.TopologyExecutionBinding.findOne({enrollmentId:e._id,operationId:o.lastSettledOperation,
            generation:o.lastSettledGeneration,'commandIds.close':o.lastSettledCloseId}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
        if (b && b.predecessorGeneration !== 'none') return require('./topologyCancelledReservation')
            .claimAfterAbsentCancellation(models,selected,lifecycle,{operationId,owner,leaseMs,now});
        if (!b || b.predecessorGeneration !== 'none' || b.bootId !== enrollmentRuntimeBootId(e)
            || b.ownerGeneration !== o.generation || b.nodeId !== id || b.generation === lock.generation) refuse();
        predecessors.push(b); roots.push({e,o});
        const hash = 'sha256:' + n.candidateHash;
        reservations.push({nodeId:id, operationId, generation:lock.generation, targetProfile:n.targetProfile,
            backupId:'topology-'+createHash('sha256').update([operationId,id,hash,n.targetProfile].join('\0')).digest('hex')});
    }
    if (new Set(predecessors.map(b => b.operationId)).size !== 1) refuse();
    if (op.nodes.length !== 2 || op.nodes.some(n => n.targetProfile !== 'xray-bridge')) refuse();
    const priorId = predecessors[0].operationId;
    const prior = await M.findById(priorId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
    if (prior?.bootstrapCancellation?.kind !== 'uncommitted-prepare-validation-cancelled' || prior.status !== 'failed'
        || prior.heldTopologyAdmission !== false || prior.attempts !== 1 || prior.nodes.length !== predecessors.length) refuse();
    return lifecycle.withTestBootstrapCancellation({operationId:priorId,bindings:predecessors,readOnly:true,reservations}, async (physical, check) => {
        if (!same(physical.proofs,prior.bootstrapCancellation.proofs) || physical.noDispatch.length !== op.nodes.length) refuse();
        for (let i=0;i<predecessors.length;i++) {
            const b=predecessors[i], r=reservations[i], p=physical.noDispatch[i], {e,o}=roots[i];
            const pin=physical.inventory.find(p=>p.nodeId===b.nodeId);
            if (!validTerminalReceipt(physical.proofs[i],b) || !same(p,{...r,bootId:b.bootId,runnerIdle:true,generationAbsent:true,operationAbsent:true,backupAbsent:true})
                || !pin || pin.bootId!==b.bootId || !same(pin.endpoint,e.endpoint) || !same(pin.nodeIdentity,e.nodeIdentity)) refuse();
            require('./topologyDeploymentRepository').validateEmptyCancelledBootstrap({operation:prior,owner:o,binding:b,enrollment:e,node:b.nodeId,profile:b.targetProfile,executionContext:TEST});
        }
        const session=await db.startSession(),nonce=randomUUID(); let attempted=false,audit,lease;
        try {
            session.startTransaction({readConcern:{level:'snapshot'},writeConcern:{w:'majority'},readPreference:'primary'});
            const current=await M.findById(operationId).select(PRIVATE).session(session).setOptions(OPTIONS).lean();eligible(current,owner);
            if (!same(current,op) || await models.TopologyExecutionBinding.findOne({operationId}).session(session).setOptions(OPTIONS).lean()
                || await M.findOne({_id:{$ne:operationId},heldTopologyAdmission:true}).session(session).setOptions(OPTIONS).lean()) refuse();
            await selected.verifySelected(current,session);
            const state=await models.CascadeTopologyState.findById('singleton').session(session).setOptions(OPTIONS).lean();
            if(state?.topologyAdmissionCount!==1 || state.remoteAdmissionCount!==0 || state.deployedRevision!==0)refuse();
            await check();lease=new Date(Date.now()+leaseMs);
            for(let i=0;i<roots.length;i++) {
                const {e,o}=roots[i],b=predecessors[i],lock=locks.find(l=>String(l.node)===b.nodeId);
                if(!await models.TopologyExecutionEnrollment.findOne(e).session(session).setOptions(OPTIONS).lean()
                    || !await models.TopologyExecutionBinding.findOne(b).session(session).setOptions(OPTIONS).lean())refuse();
                const {updatedAt:ignored,...fence}=o;
                const nodeFence={_id:b.nodeId,active:true,type:'xray',cascadeRole:op.nodes.find(n=>String(n.node)===b.nodeId).role,
                    ip:e.endpoint.ip,'ssh.port':e.endpoint.port,'ssh.username':e.endpoint.username};
                for(const [Model,filter]of [[models.TopologyConfigOwner,fence],[models.HyNode,nodeFence]])
                    if((await Model.updateOne(filter,{$set:{executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
                if((await models.NodeOperationLock.updateOne({...lock},{$set:{leaseUntil:lease,executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
            }
            if(!await M.findOne({_id:priorId,status:'failed',heldTopologyAdmission:false,bootstrapCancellation:prior.bootstrapCancellation}).session(session).setOptions(OPTIONS).lean())refuse();
            audit={kind:'predecessor-close-status-before-binding-insert',observedAt:new Date(),nonce,originalStatus:op.status,
                originalAttempts:op.attempts,locks:locks.map(l=>({node:String(l.node),generation:l.generation})),predecessorOperation:priorId,
                noDispatch:physical.noDispatch,predecessorProofs:physical.proofs};
            if((await M.updateOne({_id:operationId,status:'queued',attempts:1,leaseOwner:'',leaseUntil:null,heldTopologyAdmission:true,
                nodes:op.nodes,bindingReservationContinuation:{$exists:false}},{$set:{status:'preparing',leaseOwner:owner,leaseUntil:lease,
                bindingReservationContinuation:audit,executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
            attempted=true;
            try { const r=await db.getClient().db('admin').command({commitTransaction:1,writeConcern:{w:'majority',wtimeout:5000},maxTimeMS:5000},{session,...OPTIONS});if(r.ok!==1||r.writeConcernError||r.errorLabels?.length)refuse(); }
            finally { session.transaction.transition('TRANSACTION_COMMITTED'); }
        } catch(e) { if(!attempted&&session.inTransaction())await session.abortTransaction().catch(()=>{});throw e; }
        finally { await session.endSession(); }
        const confirmed=await M.findById(operationId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
        if(confirmed?.status!=='preparing'||confirmed.attempts!==1||confirmed.leaseOwner!==owner||confirmed.leaseUntil?.getTime()!==lease.getTime()||!same(confirmed.bindingReservationContinuation,audit))refuse();
        for(const l of locks)if(!await models.NodeOperationLock.findOne({node:l.node,operationId,generation:l.generation,owner,remoteUncertain:true,leaseUntil:lease,executionBindingCheck:nonce}).read('primary').readConcern('majority').setOptions(OPTIONS).lean())refuse();
        for(const {o}of roots)if(!await models.TopologyConfigOwner.findOne({_id:o._id,generation:o.generation,executionBindingCheck:nonce}).read('primary').readConcern('majority').setOptions(OPTIONS).lean())refuse();
        await check();return confirmed;
    });
}
module.exports={claimBindingReservationContinuation,assertBindingReservationContinuationEligible:eligible};
