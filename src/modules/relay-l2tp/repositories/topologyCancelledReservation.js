'use strict';
// A cancelled fence is NOT an applied candidate. Keep the owner's verified
// applied pointer; only the immutable reservation chain gains this native tip.
const {isDeepStrictEqual:same}=require('node:util');
const {validTerminalReceipt}=require('../models/topologyExecutionBindingContract');
const {TEST_TOPOLOGY_EXECUTION_CONTEXT:TEST}=require('../domain/topologyExecutionContext');
function validateCancelledReservation(op,b,prior){
 const a=op?.undispatchedPreparationSettlement,c=a?.cancelledSuccessors;
 const n=op?.nodes?.find(n=>String(n.node)===b.nodeId);
 if(!same(op?.executionContext,TEST)||op.status!=='failed'||op.heldTopologyAdmission!==false||op.attempts!==1
  ||a?.kind!=='failed-first-prepare-all-bindings-absent-v1'||c?.kind!=='native-absent-successor-close-v1'
  ||!same(a.originalFinishedAt,op.finishedAt)||a.originalAttempts!==op.attempts
  ||!same(a.originalNodes,op.nodes.map(n=>({node:String(n.node),state:n.state,backupId:n.backupId})))
  ||!n||b.operationId!==String(op._id)||b.attempt!==op.attempts||b.owner!==op.leaseOwner
  ||b.executionContext!==TEST.hostIdentity||b.candidateHash!=='sha256:'+n.candidateHash||b.targetProfile!==n.targetProfile
  ||b.predecessorBindingId!==prior._id||b.predecessorGeneration!==prior.generation||b.enrollmentId!==prior.enrollmentId
  ||b.ownerGeneration!==prior.ownerGeneration||!same(b.nodeIdentity,prior.nodeIdentity)||!same(b.endpoint,prior.endpoint)
  ||!validTerminalReceipt(b.predecessorReceipt,prior)||b.predecessorReceipt.terminalOutcome!=='verified'
  ||!a.bindings?.some(x=>x.id===b._id&&x.nodeId===b.nodeId&&x.generation===b.generation&&x.attemptId===b.attemptId&&same(x.commandIds,b.commandIds)))return false;
 const proofs=c.proofs?.filter(p=>p.nodeId===b.nodeId);
 return proofs?.length===1&&validTerminalReceipt(proofs[0],b)&&proofs[0].terminalOutcome==='cancelled';
}
const OPTIONS={maxTimeMS:5000,timeoutMS:5000};
const PRIVATE='+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +installedPath +undispatchedPreparationSettlement';
function refuse(){throw Object.assign(Error('TEST_CANCELLED_RESERVATION_UNPROVEN'),{code:'TEST_CANCELLED_RESERVATION_UNPROVEN'});}
async function claimAfterAbsentCancellation(models,selected,lifecycle,{operationId,owner,leaseMs,now}){
 const {randomUUID,createHash}=require('node:crypto'),{UUID}=require('../models/topologyExecutionBindingContract');
 const {enrollmentRuntimeBootId}=require('./topologyExecutionBindingStore');
 const eligible=require('./topologyBindingReservationContinuation').assertBindingReservationContinuationEligible;
 const q=(M,f,s,fields)=>{let r=M.findOne(f);if(fields)r=r.select(fields);return(s?r.session(s):r.read('primary').readConcern('majority')).setOptions(OPTIONS).lean();};
 const op=await q(models.TopologyOperation,{_id:operationId},null,PRIVATE);eligible(op,owner);
 if(!Number.isSafeInteger(leaseMs)||leaseMs<=0||!(now instanceof Date))refuse();
 const state=await q(models.CascadeTopologyState,{_id:'singleton'});
 if(state?.topologyAdmissionCount!==1||state.remoteAdmissionCount!==0||state.remoteDrain||state.replacementReservation)refuse();
 const roots=[],reservations=[];
 const load=async(s)=>{
  const rows=[];
  for(const n of op.nodes){
   const id=String(n.node),l=await q(models.NodeOperationLock,{node:id,operationId},s);
   const e=await q(models.TopologyExecutionEnrollment,{nodeId:id,targetProfile:n.targetProfile},s);
   const o=await q(models.TopologyConfigOwner,{node:id,profile:n.targetProfile},s,'+legacyAppliedTopology +profileTargetPin');
   const prior=e&&o&&await q(models.TopologyExecutionBinding,{enrollmentId:e._id,operationId:o.lastSettledOperation,generation:o.lastSettledGeneration,'commandIds.close':o.lastSettledCloseId},s);
   const b=prior&&await q(models.TopologyExecutionBinding,{enrollmentId:e._id,predecessorGeneration:prior.generation},s);
   const original=b&&await q(models.TopologyOperation,{_id:b.operationId},s,PRIVATE);
   const applied=prior&&await q(models.TopologyOperation,{_id:prior.operationId,status:'succeeded',heldTopologyAdmission:false,'v2Terminal.state':'proven'},s);
   const a=original?.undispatchedPreparationSettlement;
   if(!l||l.owner!==owner||l.remoteUncertain!==true||!UUID.test(l.generation)||!(l.leaseUntil instanceof Date)||l.leaseUntil>now
    ||!b||!prior||!original||!applied||!o||!e||o.owner!=='topology'||!same(o.executionContext,TEST)||o.handbackReceipt!==undefined
    ||b.predecessorBindingId!==prior._id||b.ownerGeneration!==o.generation||e.ownerGeneration!==o.generation
    ||b.executionContext!==TEST.hostIdentity||b.bootId!==enrollmentRuntimeBootId(e)||b.nodeId!==id||b.targetProfile!==n.targetProfile
    ||!same(b.nodeIdentity,e.nodeIdentity)||!same(b.nodeIdentity,o.nodeIdentity)||!same(b.endpoint,e.endpoint)
    ||!same(original.executionContext,TEST)||original.status!=='failed'||original.attempts!==1||original.heldTopologyAdmission!==false||original.leaseUntil!==null
    ||original.v2Terminal!==undefined||a?.kind!=='failed-first-prepare-all-bindings-absent-v1'
    ||!same(original.baselineTopology,op.baselineTopology)||!same(original.selectedOwnerPins,op.selectedOwnerPins)
    ||!validTerminalReceipt(b.predecessorReceipt,prior)||b.predecessorReceipt.terminalOutcome!=='verified'
    ||!applied.v2Terminal.proofs.some(p=>same(p,b.predecessorReceipt))
    ||!a.bindings.some(x=>x.id===b._id&&x.generation===b.generation&&x.attemptId===b.attemptId&&same(x.commandIds,b.commandIds)))refuse();
   // Validate the complete historical shape before granting any remote close.

   const en=original.nodes.find(x=>String(x.node)===id);
   if(!en||en.state!==(original.nodes.indexOf(en)===0?'failed':'pending')||b.owner!==original.leaseOwner||b.attempt!==1
    ||b.candidateHash!=='sha256:'+en.candidateHash||b.topologyRevision!==original.topologyRevision||b.priorDeployedRevision!==original.priorDeployedRevision
    ||!same(a.originalFinishedAt,original.finishedAt)||!same(a.originalNodes,original.nodes.map(n=>({node:String(n.node),state:n.state,backupId:n.backupId}))))refuse();
   if(a.cancelledSuccessors&&!validateCancelledReservation(original,b,prior))refuse();
   rows.push({l,e,o,prior,b,original});
  }
  if(new Set(rows.map(x=>x.b.operationId)).size!==1||rows[0].original.nodes.length!==op.nodes.length)refuse();
  if(await q(models.TopologyExecutionBinding,{operationId},s)||await q(models.TopologyOperation,{_id:{$ne:operationId},heldTopologyAdmission:true},s))refuse();
  const locks=await(s?models.NodeOperationLock.find({operationId}).session(s):models.NodeOperationLock.find({operationId}).read('primary').readConcern('majority')).setOptions(OPTIONS).lean();
  if(locks.length!==op.nodes.length)refuse();
  return rows;
 };
 roots.push(...await load());
 for(let i=0;i<roots.length;i++){
  const {l}=roots[i],n=op.nodes[i],id=String(n.node),hash='sha256:'+n.candidateHash;
  reservations.push({nodeId:id,operationId,generation:l.generation,targetProfile:n.targetProfile,backupId:'topology-'+createHash('sha256').update([operationId,id,hash,n.targetProfile].join('\0')).digest('hex')});
 }
 // verifySelected is a read-only join here; no owners/leases are acquired yet.
 await selected.verifySelected(op);
 return lifecycle.withTestAbsentSuccessorCancellation({bindings:roots.map(x=>x.b),reservations},async(physical,check)=>{
  if(physical.proofs.length!==roots.length||physical.noDispatch.length!==roots.length)refuse();
  physical.proofs.forEach((p,i)=>{if(!validTerminalReceipt(p,roots[i].b)||p.terminalOutcome!=='cancelled'
   ||!same(physical.noDispatch[i],{...reservations[i],bootId:roots[i].b.bootId,runnerIdle:true,generationAbsent:true,operationAbsent:true,backupAbsent:true}))refuse();});
  await check();const db=models.TopologyOperation.db,s=await db.startSession(),nonce=randomUUID();let attempted=false,lease,audit,cancellation;
  try{
   s.startTransaction({readConcern:{level:'snapshot'},writeConcern:{w:'majority'},readPreference:'primary'});
   const current=await q(models.TopologyOperation,{_id:operationId},s,PRIVATE);eligible(current,owner);
   if(!same(current,op)||!same(await load(s),roots)||!same(await q(models.CascadeTopologyState,{_id:'singleton'},s),state))refuse();
   await selected.verifySelected(current,s);await check();lease=new Date(Date.now()+leaseMs);
   const original=roots[0].original,old=original.undispatchedPreparationSettlement;
   cancellation=old.cancelledSuccessors??{kind:'native-absent-successor-close-v1',closedAt:new Date(),nextOperationId:operationId,proofs:physical.proofs};
   if(!same(cancellation.proofs,physical.proofs))refuse();
   if((await models.TopologyOperation.updateOne({_id:original._id,status:'failed',attempts:1,heldTopologyAdmission:false,finishedAt:original.finishedAt,nodes:original.nodes,undispatchedPreparationSettlement:old},
    {$set:{undispatchedPreparationSettlement:{...old,cancelledSuccessors:cancellation},executionBindingCheck:nonce}},{session:s,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
   for(let i=0;i<roots.length;i++){
    const {l,e,o,b}=roots[i],{updatedAt:ignored,...of}=o;
    for(const[M,f]of[[models.TopologyConfigOwner,of],[models.HyNode,{_id:b.nodeId,active:true,type:'xray',cascadeRole:op.nodes[i].role,ip:e.endpoint.ip,'ssh.port':e.endpoint.port,'ssh.username':e.endpoint.username}]])
     if((await M.updateOne(f,{$set:{executionBindingCheck:nonce}},{session:s,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
    if((await models.NodeOperationLock.updateOne(l,{$set:{leaseUntil:lease,executionBindingCheck:nonce}},{session:s,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
   }
   audit={kind:'native-cancelled-successor-before-binding-insert-v1',observedAt:new Date(),nonce,originalAttempts:op.attempts,predecessorOperation:roots[0].b.operationId,
    stateEpoch:{revision:state.revision,stateTransitionRevision:state.stateTransitionRevision,replacementEpoch:state.replacementEpoch},locks:roots.map(x=>({node:String(x.l.node),generation:x.l.generation})),noDispatch:physical.noDispatch,predecessorProofs:physical.proofs};
   if((await models.TopologyOperation.updateOne({_id:operationId,status:'queued',attempts:1,leaseOwner:'',leaseUntil:null,heldTopologyAdmission:true,nodes:op.nodes,bindingReservationContinuation:{$exists:false}},
    {$set:{status:'preparing',leaseOwner:owner,leaseUntil:lease,bindingReservationContinuation:audit,executionBindingCheck:nonce}},{session:s,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
   if((await models.CascadeTopologyState.updateOne(state,{$inc:{stateTransitionRevision:1}},{session:s,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
   await check();attempted=true;
   try{const r=await db.getClient().db('admin').command({commitTransaction:1,writeConcern:{w:'majority',wtimeout:5000},maxTimeMS:5000},{session:s,...OPTIONS});if(r.ok!==1||r.writeConcernError||r.errorLabels?.length)refuse();}finally{s.transaction.transition('TRANSACTION_COMMITTED');}
  }catch(e){if(!attempted&&s.inTransaction())await s.abortTransaction().catch(()=>{});throw e;}finally{await s.endSession();}
  const confirmed=await q(models.TopologyOperation,{_id:operationId},null,PRIVATE);
  if(confirmed.status!=='preparing'||confirmed.attempts!==1||confirmed.leaseUntil?.getTime()!==lease.getTime()||!same(confirmed.bindingReservationContinuation,audit))refuse();
  const original=await q(models.TopologyOperation,{_id:roots[0].b.operationId},null,PRIVATE);
  for(const {l,o,b,prior}of roots){
   if(!validateCancelledReservation(original,b,prior)||!await q(models.NodeOperationLock,{_id:l._id,operationId,owner,generation:l.generation,leaseUntil:lease,executionBindingCheck:nonce}))refuse();
   const fresh=await q(models.TopologyConfigOwner,{_id:o._id});
   for(const k of ['generation','lastSettledOperation','lastSettledGeneration','lastSettledRevision','lastSettledCloseId'])if(fresh[k]!==o[k])refuse();
  }
  await check();return confirmed;
 });
}
module.exports={validateCancelledReservation,claimAfterAbsentCancellation};
