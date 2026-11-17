'use strict';
// Explicit dedicated TEST continuation of a first preparation. A pending node
// needs physical absence; a retained prepared delete node needs its exact
// completed original prepare, no other command, and unchanged live baseline.
// Expiry is only eligibility, never proof or permission to replay a command.
// The original attempt, command IDs, generations and admission epoch survive.
const {isDeepStrictEqual:same}=require('node:util');
const {randomUUID,createHash}=require('node:crypto');
const {TEST_TOPOLOGY_EXECUTION_CONTEXT:TEST}=require('../domain/topologyExecutionContext');
const {enrollmentRuntimeBootId}=require('./topologyExecutionBindingStore');
const {UUID,validTerminalReceipt}=require('../models/topologyExecutionBindingContract');
const PRIVATE='+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +deleteJobId +installedPath +undispatchedPreparationContinuation +closedSettlementContinuation +preparedCommitContinuation';
const OPTIONS={maxTimeMS:5000,timeoutMS:5000};
function refuse(){throw Object.assign(Error('TEST_UNDISPATCHED_PREPARATION_UNPROVEN'),{code:'TEST_UNDISPATCHED_PREPARATION_UNPROVEN'});}
function partialPreparation(op){return op?.kind==='link.delete' && op.nodes?.some(n=>n.state==='prepared');}
function eligible(op,owner,now){
 const partial=partialPreparation(op);
 if(!op||!same(op.executionContext,TEST)||(!partial&&op.kind!=='link.apply')||op.admissionScope!=='selected'
  ||op.status!=='preparing'||op.attempts!==1||typeof owner!=='string'||!owner||op.leaseOwner!==owner
  ||!(op.leaseUntil instanceof Date)||op.leaseUntil>now||op.heldTopologyAdmission!==true||op.finishedAt!==null
  ||['v2Terminal','pppWait','bootstrapContinuation','bootstrapCancellation','bindingReservationContinuation','retainedVerifyContinuation','undispatchedPreparationContinuation'].some(k=>op[k]!==undefined)
  ||!op.nodes?.length||op.nodes.length>8||op.resourceNodeIds?.length!==op.nodes.length
  ||new Set(op.resourceNodeIds).size!==op.nodes.length||op.nodes.some(n=>(n.state!=='pending'&&!(partial&&n.state==='prepared'))
   ||(n.state==='pending'?n.backupId!=='':typeof n.backupId!=='string'||!n.backupId)
   ||!['xray-main','xray-bridge'].includes(n.targetProfile)||!op.resourceNodeIds.includes(String(n.node)))
  ||(partial&&!op.nodes.some(n=>n.state==='pending')))refuse();
}
function eligiblePrepared(op,owner,now){
 if(!op||!same(op.executionContext,TEST)||op.kind!=='link.delete'||op.admissionScope!=='selected'||op.status!=='failed'
  ||op.attempts!==1||op.leaseOwner!==owner||op.leaseUntil!==null||op.heldTopologyAdmission!==true||!(op.finishedAt instanceof Date)
  ||op.v2Terminal!==undefined||op.pppWait!==undefined||op.preparedCommitContinuation!==undefined||!op.nodes?.length||op.nodes.length>8
  ||op.resourceNodeIds?.length!==op.nodes.length||new Set(op.resourceNodeIds).size!==op.nodes.length
  ||op.nodes.some(n=>n.state!=='failed'||!n.backupId||!op.resourceNodeIds.includes(String(n.node))))refuse();
}
function validatePrepared(bindings,priors,physical){
 if(physical.nodes?.length!==bindings.length)refuse();
 let preparedSuffix=false,committedBoundary=false;
 return bindings.map((b,i)=>{
  const p=physical.nodes.find(p=>p.nodeId===b.nodeId),j=p?.journal,g=j?.generations?.[b.generation];
  const expected=Object.fromEntries(['operationId','nodeId','candidateHash','backupId','targetProfile','executionContext','attemptId','generation','predecessorGeneration'].map(k=>[k,b[k]]));
  const phase=g?.phase;
  // Exact original command prefix, not failed DB labels: verified prefix,
  // at most one completed commit awaiting verify, then prepared-only suffix.
  // UNKNOWN/extra/rollback/close commands never authorize a replay.
  if(phase==='verified'){if(preparedSuffix||committedBoundary)refuse();}
  else if(phase==='committed'){if(preparedSuffix||committedBoundary)refuse();committedBoundary=true;}
  else if(phase==='prepared')preparedSuffix=true;
  else refuse();
  const commands=phase==='verified'?['prepare','commit','verify']:phase==='committed'?['prepare','commit']:['prepare'];
  if(!p||p.bootId!==b.bootId||p.runnerIdle!==true||j?.bootId!==b.bootId||j.head!==b.generation||!same(g?.binding,expected)
   ||!same(Object.keys(g.commands).sort(),commands.map(c=>b.commandIds[c]).sort())
   ||p.current[b.targetProfile].configSha256!==(phase==='prepared'?priors[i]:b).candidateHash.slice(7)||p.current[b.targetProfile].serviceActive!=='active')refuse();
  for(const c of commands){const r=g.commands[b.commandIds[c]],v=r?.receipt;
   if(r?.state!=='completed'||r.command!==c||!v||Object.entries(expected).some(([k,x])=>v[k]!==x)||v.commandId!==b.commandIds[c]
    ||v.bootId!==b.bootId||v.command!==c||v.completedCommand!==c||v.ok!==true||v.completion!=='completed'||v.protocolVersion!==2
    ||v.phase!==({prepare:'prepared',commit:'committed',verify:'verified'})[c])refuse();
  }
  return {nodeId:b.nodeId,bootId:b.bootId,generation:b.generation,phase:g.phase,journalSha256:createHash('sha256').update(JSON.stringify(j)).digest('hex'),originalCommands:g.commands,current:p.current};
 });
}
function eligibleClosed(op,owner,now){
 if(!op||!same(op.executionContext,TEST)||op.kind!=='link.apply'||op.admissionScope!=='selected'||op.status!=='committing'
  ||op.attempts!==1||op.leaseOwner!==owner||!(op.leaseUntil instanceof Date)||op.leaseUntil>now||op.heldTopologyAdmission!==true||op.finishedAt!==null
  ||op.pppWait!==undefined||(op.closedSettlementContinuation!==undefined
   &&(op.closedSettlementContinuation.kind!=='closed-original-commands-current-observation-v1'||op.closedSettlementContinuation.reobservations!==undefined))||op.v2Terminal?.state!=='closing'
  ||op.v2Terminal.proofs?.length!==0||op.v2Terminal.sideEffects!==undefined||!op.nodes?.length||op.nodes.length>8
  ||op.resourceNodeIds?.length!==op.nodes.length||new Set(op.resourceNodeIds).size!==op.nodes.length
  ||op.nodes.some(n=>n.state!=='committed'||!n.backupId||!op.resourceNodeIds.includes(String(n.node))))refuse();
}
function validateClosed(bindings,priors,physical){
 if(physical.nodes?.length!==bindings.length)refuse();
 return bindings.map(b=>{
  const p=physical.nodes.find(p=>p.nodeId===b.nodeId),j=p?.journal,g=j?.generations?.[b.generation];
  const expected=Object.fromEntries(['operationId','nodeId','candidateHash','backupId','targetProfile','executionContext','attemptId','generation','predecessorGeneration'].map(k=>[k,b[k]]));
  const close=g?.commands?.[b.commandIds.close];
  if(!p||p.bootId!==b.bootId||p.runnerIdle!==true||j?.bootId!==b.bootId||j.head!==b.generation||g?.phase!=='closed'||!same(g.binding,expected)
   ||p.current[b.targetProfile].configSha256!==b.candidateHash.slice(7)||p.current[b.targetProfile].serviceActive!=='active'
   ||close?.state!=='completed'||close.command!=='close'||!validTerminalReceipt({...close.receipt,command:'status'},b)||close.receipt.terminalOutcome!=='verified'
   ||['prepare','commit','verify','close'].some(c=>g.commands[b.commandIds[c]]?.state!=='completed'||g.commands[b.commandIds[c]].command!==c))refuse();
  return {nodeId:b.nodeId,bootId:b.bootId,generation:b.generation,journalSha256:createHash('sha256').update(JSON.stringify(j)).digest('hex'),current:p.current,closeReceipt:close.receipt};
 });
}
function validatePhysical(bindings,priors,physical){
 if(physical.nodes?.length!==bindings.length)refuse();
 return bindings.map((b,i)=>{
  const p=physical.nodes.find(p=>p.nodeId===b.nodeId),prior=priors[i],j=p?.journal,g=j?.generations?.[b.predecessorGeneration];
  const nd=Object.fromEntries(['nodeId','operationId','generation','backupId','targetProfile'].map(k=>[k,b[k]]));
  if(!p||p.bootId!==b.bootId||p.runnerIdle!==true||!same(p.noDispatch,{...nd,bootId:b.bootId,runnerIdle:true,generationAbsent:true,operationAbsent:true,backupAbsent:true})
   ||j?.bootId!==b.bootId||j.head!==b.predecessorGeneration||j.generations[b.generation]!==undefined||g?.phase!=='closed'
   ||g.commands[prior.commandIds.close]?.state!=='completed'||g.commands[prior.commandIds.close]?.command!=='close'
   ||!same({...g.commands[prior.commandIds.close]?.receipt,command:'status'},b.predecessorReceipt)
   ||p.current[b.targetProfile].configSha256!==prior.candidateHash.slice(7)||p.current[b.targetProfile].serviceActive!=='active')refuse();
  return {nodeId:b.nodeId,bootId:b.bootId,generation:b.generation,noDispatch:p.noDispatch,
   journalSha256:createHash('sha256').update(JSON.stringify(j)).digest('hex'),current:p.current};
 });
}
function validatePartialPreparation(bindings,priors,op,physical){
 if(!partialPreparation(op)||physical.nodes?.length!==bindings.length)refuse();
 return bindings.map((b,i)=>{
  const p=physical.nodes.find(p=>p.nodeId===b.nodeId),n=op.nodes.find(n=>String(n.node)===b.nodeId),prior=priors[i];
  if(n?.state==='pending')return validatePhysical([b],[prior],{nodes:[p]})[0];
  const j=p?.journal,g=j?.generations?.[b.generation],c=g?.commands?.[b.commandIds.prepare];
  const expected=Object.fromEntries(['operationId','nodeId','candidateHash','backupId','targetProfile','executionContext','attemptId','generation','predecessorGeneration'].map(k=>[k,b[k]]));
  const receipt={...expected,ok:true,command:'prepare',commandId:b.commandIds.prepare,protocolVersion:2,completion:'completed',phase:'prepared',terminal:false,
   ownershipRetained:true,terminalOutcome:'not-terminal',bootId:b.bootId,systemdJob:'not-applicable',serviceState:'not-applicable',completedCommand:'prepare'};
  const previous=j?.generations?.[prior.generation];
  if(n?.state!=='prepared'||n.backupId!==b.backupId||!p||p.bootId!==b.bootId||p.runnerIdle!==true
   ||j?.bootId!==b.bootId||j.head!==b.generation||g?.phase!=='prepared'||!same(g.binding,expected)
   ||!same(Object.keys(g.commands),[b.commandIds.prepare])||c?.state!=='completed'||c.command!=='prepare'||!same(c.receipt,receipt)
   ||previous?.phase!=='closed'||previous.commands?.[prior.commandIds.close]?.state!=='completed'
   ||!same({...previous.commands?.[prior.commandIds.close]?.receipt,command:'status'},b.predecessorReceipt)
   ||p.current?.[b.targetProfile]?.configSha256!==prior.candidateHash.slice(7)||p.current[b.targetProfile].serviceActive!=='active')refuse();
  return {nodeId:b.nodeId,bootId:b.bootId,generation:b.generation,phase:'prepared',originalPrepare:c.receipt,
   journalSha256:createHash('sha256').update(JSON.stringify(j)).digest('hex'),current:p.current};
 });
}
async function claimUndispatchedPreparation(models,selected,lifecycle,{operationId,owner,leaseMs,now,closed=false,preparedCommit=false}){
 const assertEligible=preparedCommit?eligiblePrepared:closed?eligibleClosed:eligible,field=preparedCommit?'preparedCommitContinuation':closed?'closedSettlementContinuation':'undispatchedPreparationContinuation';
 const M=models.TopologyOperation,db=M.db;
 const majority=(Model,q)=>Model.findOne(q).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
 const op=await M.findById(operationId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean();assertEligible(op,owner,now);
 const partial=!closed&&!preparedCommit&&partialPreparation(op);
 const all=await models.TopologyExecutionBinding.find({operationId}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
 const locks=await models.NodeOperationLock.find({operationId}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
 if(all.length!==op.nodes.length||locks.length!==op.nodes.length)refuse();
 const roots=[],bindings=[],priors=[];
 for(const n of op.nodes){
  const id=String(n.node),b=all.find(b=>b.nodeId===id),l=locks.find(l=>String(l.node)===id);
  const e=await majority(models.TopologyExecutionEnrollment,{nodeId:id,targetProfile:n.targetProfile});
  const o=await models.TopologyConfigOwner.findOne({node:id,profile:n.targetProfile}).select('+legacyAppliedTopology +profileTargetPin').read('primary').readConcern('majority').setOptions(OPTIONS).lean();
  if(!b||!l||!e||!o||b.operationId!==operationId||b.attempt!==1||b.owner!==owner||b.generation!==l.generation||!UUID.test(b.generation)
   ||l.owner!==owner||l.remoteUncertain!==true||!(l.leaseUntil instanceof Date)||l.leaseUntil>now
   ||b.executionContext!==TEST.hostIdentity||b.targetProfile!==n.targetProfile||b.candidateHash!=='sha256:'+n.candidateHash||((closed||preparedCommit||n.state==='prepared')&&b.backupId!==n.backupId)
   ||b.topologyRevision!==op.topologyRevision||b.priorDeployedRevision!==op.priorDeployedRevision
   ||b.backupId!=='topology-'+createHash('sha256').update([operationId,id,b.candidateHash,n.targetProfile].join('\0')).digest('hex')
   ||o.owner!=='topology'||!same(o.executionContext,TEST)||o.handbackReceipt!==undefined
   ||b.ownerGeneration!==o.generation||e.ownerGeneration!==o.generation||b.enrollmentId!==e._id||b.bootId!==enrollmentRuntimeBootId(e)
   ||!same(b.nodeIdentity,e.nodeIdentity)||!same(o.nodeIdentity,e.nodeIdentity)||!same(b.endpoint,e.endpoint)
   ||o.lastSettledGeneration!==b.predecessorGeneration)refuse();
  const prior=await majority(models.TopologyExecutionBinding,{_id:b.predecessorBindingId,operationId:o.lastSettledOperation,generation:o.lastSettledGeneration,'commandIds.close':o.lastSettledCloseId});
  const settled=prior&&await majority(M,{_id:prior.operationId,status:'succeeded',heldTopologyAdmission:false,'v2Terminal.state':'proven'});
  if(!prior||!settled||!validTerminalReceipt(b.predecessorReceipt,prior)||b.predecessorReceipt.terminalOutcome!=='verified'
   ||!settled.v2Terminal.proofs.some(p=>same(p,b.predecessorReceipt)))refuse();
  bindings.push(b);priors.push(prior);roots.push({e,o,l});
 }
 if(closed){const records=bindings.map(b=>Object.fromEntries(require('../models/topologyExecutionBindingContract').recordKeysFor(b).map(k=>[k,b[k]])));if(!same(op.v2Terminal.bindings,records))refuse();}
 const observe=partial ? (bindings,work)=>lifecycle.withTestRetainedVerifyObservation(bindings,async(all,checkAll)=>
  lifecycle.withTestUndispatchedPreparation(bindings.filter(b=>op.nodes.find(n=>String(n.node)===b.nodeId)?.state==='pending'),async(pending,checkPending)=>{
   const nodes=all.nodes.map(p=>{const q=pending.nodes.find(q=>q.nodeId===p.nodeId);if(q&&(!same(p.journal,q.journal)||!same(p.current,q.current)))refuse();return q??p;});
   return work({nodes},async()=>{await checkAll();await checkPending();});
  })) : (bindings,work)=>lifecycle[closed||preparedCommit?'withTestRetainedVerifyObservation':'withTestUndispatchedPreparation'](bindings,work);
 return observe(bindings,async(physical,check)=>{
  const observed=partial?validatePartialPreparation(bindings,priors,op,physical):(preparedCommit?validatePrepared:closed?validateClosed:validatePhysical)(bindings,priors,physical);await check();
  const session=await db.startSession(),nonce=randomUUID();let attempted=false,lease,audit;
  try{
   session.startTransaction({readConcern:{level:'snapshot'},writeConcern:{w:'majority'},readPreference:'primary'});
   const current=await M.findById(operationId).select(PRIVATE).session(session).setOptions(OPTIONS).lean();assertEligible(current,owner,now);if(!same(current,op))refuse();
   if(await M.findOne({_id:{$ne:operationId},heldTopologyAdmission:true}).session(session).setOptions(OPTIONS).lean())refuse();
   await selected.verifySelected(current,session);
   const state=await models.CascadeTopologyState.findById('singleton').session(session).setOptions(OPTIONS).lean();
   if(state?.topologyAdmissionCount!==1||state.remoteAdmissionCount!==0||state.remoteDrain||state.replacementReservation)refuse();
   await check();lease=new Date(Date.now()+leaseMs);
   for(let i=0;i<roots.length;i++){
    const {e,o,l}=roots[i],b=bindings[i],prior=priors[i];
    for(const[Model,filter]of [[models.TopologyExecutionEnrollment,e],[models.TopologyExecutionBinding,b],[models.TopologyExecutionBinding,prior]])
     if(!await Model.findOne(filter).session(session).setOptions(OPTIONS).lean())refuse();
    const {updatedAt:ignored,...of}=o;
    for(const[Model,f]of [[models.TopologyConfigOwner,of],[models.HyNode,{_id:b.nodeId,active:true,type:'xray',cascadeRole:op.nodes[i].role,ip:e.endpoint.ip,'ssh.port':e.endpoint.port,'ssh.username':e.endpoint.username}]])
     if((await Model.updateOne(f,{$set:{executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
    if((await models.NodeOperationLock.updateOne(l,{$set:{leaseUntil:lease,executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
   }
   if((await models.CascadeTopologyState.updateOne(state,{$inc:{stateTransitionRevision:1}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
   audit={kind:partial?'partial-first-preparation-original-completion-and-no-dispatch-v1':preparedCommit?(observed.some(p=>p.phase==='verified')?'failed-first-attempt-original-verified-prefix-and-prepared-suffix-v1':'failed-prepared-first-commit-no-verify-current-observation-v1'):closed?'closed-original-commands-current-observation-v1':'first-preparation-no-dispatch-current-observation-v1',observedAt:new Date(),nonce,originalAttempts:op.attempts,originalLeaseUntil:op.leaseUntil,
    ...(partial?{originalNodes:op.nodes.map(n=>({node:String(n.node),state:n.state,backupId:n.backupId}))}:{}),
    locks:locks.map(l=>({node:String(l.node),generation:l.generation})),bindings:bindings.map(b=>({id:b._id,generation:b.generation,attemptId:b.attemptId,commandIds:b.commandIds})),
    stateEpoch:{revision:state.revision,stateTransitionRevision:state.stateTransitionRevision,replacementEpoch:state.replacementEpoch,deployedRevision:state.deployedRevision},observed};
   if(closed&&op.closedSettlementContinuation)audit={...op.closedSettlementContinuation,reobservations:[audit]};
   if((await M.updateOne({_id:operationId,status:op.status,attempts:1,leaseOwner:owner,leaseUntil:op.leaseUntil,heldTopologyAdmission:true,nodes:op.nodes,[field]:op[field]??{$exists:false},v2Terminal:closed?op.v2Terminal:{$exists:false}},
    {$set:{leaseUntil:lease,[field]:preparedCommit?{...audit,originalNodes:op.nodes.map(n=>({node:String(n.node),state:n.state,backupId:n.backupId})),originalFinishedAt:op.finishedAt}:audit,executionBindingCheck:nonce,
     ...(preparedCommit?{status:'committing',finishedAt:null,nodes:op.nodes.map((n,i)=>({...n,state:observed[i].phase==='prepared'?'prepared':'committed'}))}:{})}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
   if(preparedCommit)audit={...audit,originalNodes:op.nodes.map(n=>({node:String(n.node),state:n.state,backupId:n.backupId})),originalFinishedAt:op.finishedAt};
   attempted=true;
   try{const r=await db.getClient().db('admin').command({commitTransaction:1,writeConcern:{w:'majority',wtimeout:5000},maxTimeMS:5000},{session,...OPTIONS});if(r.ok!==1||r.writeConcernError||r.errorLabels?.length)refuse();}
   finally{session.transaction.transition('TRANSACTION_COMMITTED');}
  }catch(e){if(!attempted&&session.inTransaction())await session.abortTransaction().catch(()=>{});throw e;}
  finally{await session.endSession();}
  const confirmed=await M.findById(operationId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
  if(confirmed?.status!==(preparedCommit?'committing':op.status)||confirmed.attempts!==1||confirmed.leaseOwner!==owner||confirmed.leaseUntil?.getTime()!==lease.getTime()||!same(confirmed[field],audit))refuse();
  for(const {l,o}of roots)if(!await majority(models.NodeOperationLock,{_id:l._id,operationId,owner,generation:l.generation,remoteUncertain:true,leaseUntil:lease,executionBindingCheck:nonce})
   ||!await majority(models.TopologyConfigOwner,{_id:o._id,generation:o.generation,executionBindingCheck:nonce}))refuse();
  await check();return confirmed;
 });
}
module.exports={claimUndispatchedPreparation,claimPreparedCommit:(m,s,l,i)=>claimUndispatchedPreparation(m,s,l,{...i,preparedCommit:true}),assertPreparedCommitEligible:eligiblePrepared,validatePreparedCommitPhysical:validatePrepared,claimClosedSettlement:(m,s,l,i)=>claimUndispatchedPreparation(m,s,l,{...i,closed:true}),assertClosedSettlementEligible:eligibleClosed,validateClosedSettlementPhysical:validateClosed,assertUndispatchedPreparationEligible:eligible,validateUndispatchedPhysical:validatePhysical,validatePartialPreparationPhysical:validatePartialPreparation};
