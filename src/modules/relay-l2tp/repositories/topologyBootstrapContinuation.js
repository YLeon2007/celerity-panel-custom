'use strict';
// Only the dedicated TEST worker's fresh held pristine observation calls this.
// This continues a bootstrap that demonstrably never published a runner or
// dispatched a node command. It is NOT recovery of an unknown runner command.
const {isDeepStrictEqual:same}=require('node:util');
const {randomUUID}=require('node:crypto');
const {TEST_TOPOLOGY_EXECUTION_CONTEXT:TEST}=require('../domain/topologyExecutionContext');
const {enrollmentRuntimeBootId}=require('./topologyExecutionBindingStore');
const {UUID}=require('../models/topologyExecutionBindingContract');
const PRIVATE='+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +deleteJobId +installedPath';
const OPTIONS={maxTimeMS:5000,timeoutMS:5000};
function refuse(){throw Object.assign(Error('TEST_BOOTSTRAP_CONTINUATION_UNPROVEN'),{code:'TEST_BOOTSTRAP_CONTINUATION_UNPROVEN'});}
function eligible(op,owner){
 if(!op||!same(op.executionContext,TEST)||op.admissionScope!=='selected'||op.kind!=='link.apply'
  ||op.status!=='failed'||op.attempts!==1||op.leaseOwner!==owner||op.leaseUntil!==null
  ||op.heldTopologyAdmission!==true||op.v2Terminal!==undefined||op.pppWait!==undefined
  ||!op.finishedAt||!Array.isArray(op.nodes)||op.nodes.length<1||op.nodes.length>8
  ||op.nodes.some(n=>!['pending','failed'].includes(n.state)))refuse();
 const prior=op.bootstrapContinuation;
 if(prior===undefined){if(op.nodes.filter(n=>n.state==='failed').length!==1)refuse();}
 else if(prior.kind!=='sftp-bootstrap-before-node-dispatch'||prior.originalStatus!=='failed'
  ||!Array.isArray(prior.originalNodes)||prior.originalNodes.filter(n=>n.state==='failed').length!==1
  ||op.nodes.some(n=>n.state!=='pending'||!prior.originalNodes.some(p=>p.node===String(n.node)&&p.backupId===n.backupId))
  ||prior.corrections?.length)refuse();
}
async function claimBootstrapContinuation(models,selected,{operationId,owner,leaseMs,now,plan,check}){
 const M=models.TopologyOperation,db=M.db;eligible(await M.findById(operationId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean(),owner);
 if(!Array.isArray(plan?.nodes)||!plan.nodes.length||plan.nodes.some(n=>n.bootstrapPristine!==true))refuse();
 await check();const session=await db.startSession();let attempted=false,audit;
 const lease=new Date(now.getTime()+leaseMs),nonce=randomUUID();
 try{
  session.startTransaction({readConcern:{level:'snapshot'},writeConcern:{w:'majority'},readPreference:'primary'});
  const op=await M.findById(operationId).select(PRIVATE).session(session).setOptions(OPTIONS).lean();eligible(op,owner);
  if(plan.bootstrapFailure?.operationId!==operationId || plan.bootstrapFailure.failureCode!=='SFTP_SUBSYSTEM_UNAVAILABLE'
    || plan.bootstrapFailure.finishedAt!==(op.bootstrapContinuation?.originalFinishedAt ?? op.finishedAt).toISOString() || plan.bootstrapFailure.stoppedApp?.pid!==0
    || plan.bootstrapFailure.stoppedApp.status!=='exited' || plan.bootstrapFailure.stoppedApp.exitCode!==1)refuse();
  await selected.verifySelected(op,session);
  if (await M.findOne({_id:{$ne:operationId}}).session(session).setOptions(OPTIONS).lean()) refuse();
  for (const pin of plan.nodes) {
   const e=await models.TopologyExecutionEnrollment.findOne({nodeId:pin.nodeId,targetProfile:pin.targetProfile}).session(session).setOptions(OPTIONS).lean();
   const own=await models.TopologyConfigOwner.findOne({node:pin.nodeId,profile:pin.targetProfile}).session(session).setOptions(OPTIONS).lean();
   const node=await models.HyNode.findById(pin.nodeId).session(session).setOptions(OPTIONS).lean();
   const {proofRef,...snapshot}=pin.originalSnapshot;
   if(!e||e.executionContext!==TEST.hostIdentity||enrollmentRuntimeBootId(e)!==pin.bootId||!same(e.nodeIdentity,pin.nodeIdentity)||!same(e.endpoint,pin.endpoint)
    ||!own||!same(own.executionContext,TEST)||own.owner!=='topology'||own.generation!==e.ownerGeneration||!same(own.originalSnapshot,snapshot)
    ||!same(own.nodeIdentity,pin.nodeIdentity)||own.adoptionReceipt?.toGeneration!==own.generation||own.handbackReceipt!==undefined
    ||!node||node.type!=='xray'||node.active!==true||node.ip!==pin.endpoint.ip||node.ssh?.port!==pin.endpoint.port||node.ssh?.username!==pin.endpoint.username)refuse();
  }
  const bindings=await models.TopologyExecutionBinding.find({operationId}).session(session).setOptions(OPTIONS).lean();
  const locks=await models.NodeOperationLock.find({operationId}).session(session).setOptions(OPTIONS).lean();
  if(bindings.length!==op.nodes.length||locks.length!==op.nodes.length)refuse();
  for(const n of op.nodes){
   const id=String(n.node),pin=plan.nodes.find(p=>p.nodeId===id),row=bindings.find(b=>b.nodeId===id),lock=locks.find(l=>String(l.node)===id);
   if(!pin||!row||!lock||row.owner!==owner||row.attempt!==1||row.operationId!==operationId||row.predecessorGeneration!=='none'
    ||row.targetProfile!==n.targetProfile||row.candidateHash!=='sha256:'+n.candidateHash||row.bootId!==pin.bootId
    ||!same(row.nodeIdentity,pin.nodeIdentity)||!same(row.endpoint,pin.endpoint)||!UUID.test(row.generation)
    ||!Object.values(row.commandIds).every(x=>UUID.test(x))||lock.owner!==owner||lock.generation!==row.generation||lock.remoteUncertain!==true
    ||n.state==='failed'&&n.backupId!==row.backupId||n.state==='pending'&&n.backupId!==''&&!(op.bootstrapContinuation?.originalNodes?.some(p=>p.node===id&&p.state==='failed'&&p.backupId===n.backupId)&&n.backupId===row.backupId))refuse();
   const e=await models.TopologyExecutionEnrollment.findById(row.enrollmentId).session(session).setOptions(OPTIONS).lean();
   const own=await models.TopologyConfigOwner.findOne({node:id,profile:n.targetProfile}).session(session).setOptions(OPTIONS).lean();
   const {proofRef,...snapshot}=pin.originalSnapshot;
   if(!e||enrollmentRuntimeBootId(e)!==pin.bootId||e.ownerGeneration!==row.ownerGeneration||!own||own.owner!=='topology'
    ||own.generation!==row.ownerGeneration||!same(own.originalSnapshot,snapshot)||!same(own.nodeIdentity,pin.nodeIdentity)
    ||own.adoptionReceipt?.toGeneration!==own.generation||own.handbackReceipt!==undefined)refuse();
   if((await models.TopologyConfigOwner.updateOne({...own},{ $set:{executionBindingCheck:nonce} },{session,...OPTIONS})).matchedCount!==1)refuse();
   if((await models.NodeOperationLock.updateOne({...lock},{ $set:{leaseUntil:lease} },{session,...OPTIONS})).matchedCount!==1)refuse();
  }
  audit={kind:'sftp-bootstrap-before-node-dispatch',failureEvidence:plan.bootstrapFailure,observedAt:now,originalStatus:op.status,originalFinishedAt:op.finishedAt,
   originalNodes:op.nodes.map(n=>({node:String(n.node),state:n.state,backupId:n.backupId})),
   locks:locks.map(l=>({node:String(l.node),generation:l.generation})),bindings:bindings.map(b=>({id:b._id,nodeId:b.nodeId,generation:b.generation,commandIds:b.commandIds})),
   physical:plan.nodes.map(p=>({nodeId:p.nodeId,bootId:p.bootId,nodeIdentity:p.nodeIdentity,originalSnapshot:p.originalSnapshot,bootstrapPristine:p.bootstrapPristine})),nonce};
  if(op.bootstrapContinuation) audit={...op.bootstrapContinuation,corrections:[{kind:'local-pending-backup-plan-projection',failedAt:op.finishedAt,observedAt:now,nonce}]};
  const changed=await M.updateOne({_id:operationId,status:'failed',attempts:1,leaseOwner:owner,leaseUntil:null,heldTopologyAdmission:true,nodes:op.nodes,bootstrapContinuation:op.bootstrapContinuation??{$exists:false}},
   {$set:{status:'preparing',leaseUntil:lease,finishedAt:null,nodes:op.nodes.map(n=>({...n,state:'pending'})),bootstrapContinuation:audit}},{session,...OPTIONS,runValidators:true});
  if(changed.matchedCount!==1)refuse();
  // One commit command only. Unconfirmed commit is retained; no callback retry.
  attempted=true;
  try{const reply=await db.getClient().db('admin').command({commitTransaction:1,writeConcern:{w:'majority',wtimeout:5000},maxTimeMS:5000},{session,...OPTIONS});if(reply.ok!==1||reply.writeConcernError||reply.errorLabels?.length)refuse();}
  finally{session.transaction.transition('TRANSACTION_COMMITTED');}
 }catch(e){if(!attempted&&session.inTransaction())await session.abortTransaction().catch(()=>{});throw e;}
 finally{await session.endSession();}
 const confirmed=await M.findById(operationId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
 if(confirmed?.status!=='preparing'||!same(confirmed.bootstrapContinuation,audit)||confirmed.attempts!==1||confirmed.leaseUntil?.getTime()!==lease.getTime())refuse();
 for(const l of audit.locks){const row=await models.NodeOperationLock.findOne({node:l.node,operationId,generation:l.generation,owner,leaseUntil:lease,remoteUncertain:true}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();if(!row)refuse();}
 await check();return confirmed;
}
module.exports={claimBootstrapContinuation,assertBootstrapContinuationEligible:eligible};
