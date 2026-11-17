'use strict';
const {isDeepStrictEqual:same}=require('node:util');
const {TEST_TOPOLOGY_EXECUTION_CONTEXT:TEST}=require('../domain/topologyExecutionContext');
const {validTerminalReceipt}=require('../models/topologyExecutionBindingContract');
const {enrollmentRuntimeBootId}=require('../repositories/topologyExecutionBindingStore');
const ISSUED=new WeakSet(),OPTIONS={maxTimeMS:5000,timeoutMS:5000};
const PRIVATE='+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +installedPath';
function refuse(){throw Object.assign(Error('TEST_BOOTSTRAP_CANCELLATION_UNPROVEN'),{code:'TEST_BOOTSTRAP_CANCELLATION_UNPROVEN'});}
function eligible(op){if(!op||!same(op.executionContext,TEST)||op.status!=='failed'||op.attempts!==1||op.heldTopologyAdmission!==true||op.leaseUntil!==null||op.v2Terminal||op.bootstrapCancellation||!op.bootstrapContinuation||op.nodes.some(n=>!['failed','pending'].includes(n.state)))refuse();}
async function cancelBootstrap({models,authority,finalizer,operationId,onSettled}){
 return authority.withHeldAuthority(TEST,async cap=>{
  await cap.assertHeld();const op=await models.TopologyOperation.findById(operationId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean();eligible(op);
  const bindings=await models.TopologyExecutionBinding.find({operationId}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();if(bindings.length!==op.nodes.length)refuse();
  return cap.withBootstrapCancellation({operationId,bindings},async({proofs},check)=>{
   proofs.forEach(p=>ISSUED.add(p));await check();
   const result=await finalizer.finalizeBootstrapCancellation({operationId,bindings,proofs});
   await check();if(result?.status!=='cancelled')refuse();if(onSettled)await onSettled(result);return result;
  });
 });
}
async function finalizeBootstrapCancellation(repo,{operationId,bindings,proofs,now}){
 if(proofs.length!==bindings.length||proofs.some((p,i)=>!ISSUED.has(p)||!validTerminalReceipt(p,bindings[i])||p.terminalOutcome!=='cancelled'))refuse();
 const M=repo.TopologyOperation,db=M.db,s=await db.startSession();let attempted=false,audit;
 try{
  s.startTransaction({readConcern:{level:'snapshot'},writeConcern:{w:'majority'},readPreference:'primary'});
  const op=await M.findById(operationId).select(PRIVATE).session(s).setOptions(OPTIONS).lean();eligible(op);
  if(bindings.length!==op.nodes.length)refuse();
  for(let i=0;i<bindings.length;i++){
   const b=bindings[i],row=await repo.TopologyExecutionBinding.findById(b._id).session(s).setOptions(OPTIONS).lean();
   const lock=await repo.NodeOperationLock.findOne({node:b.nodeId}).session(s).setOptions(OPTIONS).lean();
   const owner=await repo.TopologyConfigOwner.findOne({node:b.nodeId,profile:b.targetProfile}).session(s).setOptions(OPTIONS).lean();
   const e=await repo.TopologyExecutionEnrollment.findById(b.enrollmentId).session(s).setOptions(OPTIONS).lean();
   if(!same(row,b)||!lock||lock.operationId!==operationId||lock.generation!==b.generation||lock.owner!==b.owner||lock.remoteUncertain!==true
    ||op.leaseOwner!==b.owner||op.attempts!==b.attempt||!owner||owner.owner!=='topology'||owner.generation!==b.ownerGeneration
    ||!same(owner.executionContext,TEST)||!same(owner.nodeIdentity,b.nodeIdentity)||!e||enrollmentRuntimeBootId(e)!==b.bootId||e.ownerGeneration!==b.ownerGeneration)refuse();
   if((await repo.TopologyConfigOwner.updateOne({...owner},{$set:{lastSettledOperation:operationId,lastSettledGeneration:b.generation,lastSettledRevision:b.topologyRevision,lastSettledCloseId:b.commandIds.close}},{session:s,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
   if((await repo.NodeOperationLock.deleteOne({...lock},{session:s,...OPTIONS})).deletedCount!==1)refuse();
  }
  audit={kind:'uncommitted-prepare-validation-cancelled',settledAt:now,originalFailedAt:op.finishedAt,proofs,bindings:bindings.map(b=>({id:b._id,nodeId:b.nodeId,generation:b.generation,closeId:b.commandIds.close}))};
  if((await M.updateOne({_id:operationId,status:'failed',attempts:1,heldTopologyAdmission:true,leaseUntil:null,nodes:op.nodes,bootstrapCancellation:{$exists:false}},{$set:{heldTopologyAdmission:false,bootstrapCancellation:audit}},{session:s,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
  if((await repo.CascadeTopologyState.updateOne({_id:'singleton',topologyAdmissionCount:{$gte:1}},{$inc:{topologyAdmissionCount:-1}},{session:s,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
  attempted=true;
  try{const r=await db.getClient().db('admin').command({commitTransaction:1,writeConcern:{w:'majority',wtimeout:5000},maxTimeMS:5000},{session:s,...OPTIONS});if(r.ok!==1||r.writeConcernError||r.errorLabels?.length)refuse();}finally{s.transaction.transition('TRANSACTION_COMMITTED');}
 }catch(e){if(!attempted&&s.inTransaction())await s.abortTransaction().catch(()=>{});throw e;}finally{await s.endSession();}
 const fresh=await M.findById(operationId).read('primary').readConcern('majority').setOptions(OPTIONS).lean();if(fresh?.heldTopologyAdmission!==false||!same(fresh.bootstrapCancellation,audit))refuse();
 for(const b of bindings){if(await repo.NodeOperationLock.findOne({node:b.nodeId,generation:b.generation}).read('primary').readConcern('majority').setOptions(OPTIONS).lean())refuse();const o=await repo.TopologyConfigOwner.findOne({node:b.nodeId,profile:b.targetProfile}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();if(o?.lastSettledGeneration!==b.generation||o?.lastSettledCloseId!==b.commandIds.close)refuse();}
 return {operationId,status:'cancelled',businessSuccess:false};
}
async function resumeSettledBootstrap({models,authority,operationId,onSettled}){
 return authority.withHeldAuthority(TEST, async cap=>{
  await cap.assertHeld();
  const op=await models.TopologyOperation.findById(operationId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
  if(op?.status!=='failed'||op.heldTopologyAdmission!==false||op.attempts!==1||op.bootstrapCancellation?.kind!=='uncommitted-prepare-validation-cancelled')refuse();
  const bindings=await models.TopologyExecutionBinding.find({operationId}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();if(bindings.length!==op.nodes.length)refuse();
  return cap.withBootstrapCancellation({operationId,bindings,readOnly:true},async({proofs,inventory},check)=>{
   if(!same(proofs,op.bootstrapCancellation.proofs))refuse();
   const roots=[];
   for(const pin of inventory){
    const e=await models.TopologyExecutionEnrollment.findOne({nodeId:pin.nodeId,targetProfile:pin.targetProfile}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
    const owner=await models.TopologyConfigOwner.findOne({node:pin.nodeId,profile:pin.targetProfile}).select('+legacyAppliedTopology +profileTargetPin').read('primary').readConcern('majority').setOptions(OPTIONS).lean();
    if(!e||!owner||owner.owner!=='topology'||e.ownerGeneration!==owner.generation||!same(owner.executionContext,TEST)
     ||enrollmentRuntimeBootId(e)!==pin.bootId||!same(e.endpoint,pin.endpoint)||!same(e.nodeIdentity,pin.nodeIdentity)||!same(owner.nodeIdentity,pin.nodeIdentity)||owner.handbackReceipt!==undefined)refuse();
    const b=bindings.find(b=>b.nodeId===pin.nodeId);
    if(b)require('../repositories/topologyDeploymentRepository').validateEmptyCancelledBootstrap({operation:op,owner,binding:b,enrollment:e,node:pin.nodeId,profile:pin.targetProfile,executionContext:TEST});
    else if(owner.lastSettledOperation!==undefined)refuse();
    const node=await models.HyNode.findById(pin.nodeId).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
    if(!node||node.type!=='xray'||node.active!==true||node.ip!==pin.endpoint.ip||node.ssh?.port!==pin.endpoint.port||node.ssh?.username!==pin.endpoint.username)refuse();
    const {updatedAt: ignoredTimestamp,...ownerFence}=owner;
    // Same endpoint/role CAS ABI as TopologyExecutionBindingStore: never
    // compare a schema-projected ssh subdocument to its credential-bearing row.
    const nodeFence={_id:node._id,type:'xray',active:true,cascadeRole:node.cascadeRole,ip:pin.endpoint.ip,'ssh.port':pin.endpoint.port,'ssh.username':pin.endpoint.username};
    roots.push({owner:ownerFence,e,node:nodeFence});
   }
   if(await models.NodeOperationLock.exists({})||await models.TopologyOperation.exists({heldTopologyAdmission:true}))refuse();
   const state=await models.CascadeTopologyState.findById('singleton').read('primary').readConcern('majority').setOptions(OPTIONS).lean();if(state?.topologyAdmissionCount!==0||state.remoteAdmissionCount!==0)refuse();
   await check();
   // Reuse the existing nonce-CAS fields under the still-held physical scope.
   // No boot/enrollment/history reset and no automatic transaction retry.
   const db=models.TopologyOperation.db,session=await db.startSession(),nonce=require('node:crypto').randomUUID();let attempted=false;
   try{
    session.startTransaction({readConcern:{level:'snapshot'},writeConcern:{w:'majority'},readPreference:'primary'});
    if(await models.NodeOperationLock.findOne({}).session(session).setOptions(OPTIONS).lean()||await models.TopologyOperation.findOne({heldTopologyAdmission:true}).session(session).setOptions(OPTIONS).lean())refuse();
    for(const root of roots){
     if(!await models.TopologyExecutionEnrollment.findOne(root.e).session(session).setOptions(OPTIONS).lean())refuse();
     for(const [M,row]of [[models.TopologyConfigOwner,root.owner],[models.HyNode,root.node]])if((await M.updateOne(row,{$set:{executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
    }
    if((await models.TopologyOperation.updateOne({_id:operationId,status:'failed',heldTopologyAdmission:false,bootstrapCancellation:op.bootstrapCancellation},{$set:{executionBindingCheck:nonce}},{session,...OPTIONS})).matchedCount!==1)refuse();
    if((await models.CascadeTopologyState.updateOne({_id:'singleton',revision:state.revision,topologyAdmissionCount:0,remoteAdmissionCount:0},{$inc:{stateTransitionRevision:1}},{session,...OPTIONS})).matchedCount!==1)refuse();
    attempted=true;try{const r=await db.getClient().db('admin').command({commitTransaction:1,writeConcern:{w:'majority',wtimeout:5000},maxTimeMS:5000},{session,...OPTIONS});if(r.ok!==1||r.writeConcernError||r.errorLabels?.length)refuse();}finally{session.transaction.transition('TRANSACTION_COMMITTED');}
   }catch(e){if(!attempted&&session.inTransaction())await session.abortTransaction().catch(()=>{});throw e;}finally{await session.endSession();}
   for(const root of roots)for(const [M,row]of [[models.TopologyConfigOwner,root.owner],[models.HyNode,root.node]])if(!await M.findOne({...row,executionBindingCheck:nonce}).read('primary').readConcern('majority').setOptions(OPTIONS).lean())refuse();
   await check();const result={operationId,status:'cancelled',reconciled:true,businessSuccess:false};if(onSettled)await onSettled(result);return result;
  });
 });
}
module.exports={cancelBootstrap,resumeSettledBootstrap,finalizeBootstrapCancellation,assertCancellationEligible:eligible};
