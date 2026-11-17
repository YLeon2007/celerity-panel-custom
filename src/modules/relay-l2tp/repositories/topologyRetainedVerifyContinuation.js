'use strict';
// One explicit dedicated TEST continuation of a lost non-activating verify.
// No attempt, binding, generation or original command allocation. No lease-expiry authority.
const {isDeepStrictEqual:same}=require('node:util');
const {randomUUID,createHash}=require('node:crypto');
const {TEST_TOPOLOGY_EXECUTION_CONTEXT:TEST}=require('../domain/topologyExecutionContext');
const {enrollmentRuntimeBootId}=require('./topologyExecutionBindingStore');
const PRIVATE='+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +installedPath +deleteJobId';
const OPTIONS={maxTimeMS:5000,timeoutMS:5000};
function refuse(){throw Object.assign(Error('TEST_RETAINED_VERIFY_UNPROVEN'),{code:'TEST_RETAINED_VERIFY_UNPROVEN'});}
// Exact reached TEST shape: all six original commands verified, but the
// pre-closure DB transaction conflicted with our heartbeat. Legacy scheduler
// claims increased the counter without allocating/replaying a native attempt.
function verifiedPreclosureRoot(op,owner,allowSettled=false){
 return Boolean(op&&same(op.executionContext,TEST)&&op.kind==='link.apply'&&op.admissionScope==='selected'
  &&Number.isSafeInteger(op.attempts)&&op.attempts>=2&&op.leaseOwner===owner
  &&(op.status==='committing'&&op.heldTopologyAdmission===true&&op.finishedAt===null
   ||allowSettled&&op.status==='succeeded'&&op.heldTopologyAdmission===false&&op.finishedAt!=null)
  &&op.staged===false&&op.routeState==='complete'
  &&op.installedPath?.kind==='link.apply'&&op.installedPath.preserveGroupPaths===true
  &&op.installedPath.selectedPathKey==='reserve'&&op.installedPath.oldPathLinkIds?.length===1
  &&op.installedPath.newPathLinkIds?.length===1&&op.installedPath.newPathLinkIds[0]===String(op.linkId)
  &&Number.isSafeInteger(op.installedPath.ownerCredentialRevision)&&op.installedPath.ownerCredentialRevision>=1
  &&op.nodes?.length===6&&op.resourceNodeIds?.length===6&&new Set(op.resourceNodeIds).size===6
  &&op.nodes.every(n=>n.state==='committed'&&n.backupId&&op.resourceNodeIds.includes(String(n.node))
   &&n.targetProfile===(n.role==='portal'?'xray-main':'xray-bridge'))
  &&['portal','relay','bridge'].every(role=>op.nodes.filter(n=>n.role===role).length===2)
  &&op.bindingReservationContinuation===undefined&&op.bootstrapContinuation===undefined&&op.bootstrapCancellation===undefined
  &&op.retainedVerifyClosureContinuation===undefined&&op.pppWait===undefined);
}
function originalExecutionAttempt(op){
 const a=op?.retainedVerifyContinuation;
 if(a?.kind!=='verified-before-closure-reclaimed-claim-v1')return op.attempts;
 if(!verifiedPreclosureRoot(op,op.leaseOwner,true)||a.originalAttempts!==op.attempts||a.originalBindingAttempt!==1
  ||a.observed?.length!==6||a.observed.some((p,i)=>p.nodeId!==String(op.nodes[i].node)||p.phase!=='verified'
   ||p.runnerIdle!==true||p.current?.[op.nodes[i].targetProfile]?.configSha256!==op.nodes[i].candidateHash))refuse();
 return a.originalBindingAttempt;
}
function verifiedDeleteClosure(op, owner) {
 return Boolean(op && same(op.executionContext,TEST) && op.kind==='link.delete' && op.admissionScope==='selected'
  && op.status==='committing' && op.attempts===1 && op.leaseOwner===owner && op.heldTopologyAdmission===true && op.finishedAt===null
  && ['no_bridge_exit','no_portal_input'].includes(op.routeState) && op.installedPath?.kind==='link.delete'
  && op.installedPath.oldPathLinkIds?.length>0 && same(op.installedPath.oldPathLinkIds,op.installedPath.newPathLinkIds)
  && !op.effectiveTopology?.links?.some(link=>link.id===op.linkId)
  && Number.isSafeInteger(op.installedPath.ownerCredentialRevision) && op.installedPath.ownerCredentialRevision>=1
  && Number.isSafeInteger(op.installedPath.ownerTopologyRevision) && op.installedPath.ownerTopologyRevision>=0
  && op.nodes?.length===4 && op.resourceNodeIds?.length===4 && new Set(op.resourceNodeIds).size===4
  && op.nodes.every(n=>n.state==='committed' && n.backupId && op.resourceNodeIds.includes(String(n.node))
   && n.targetProfile===(n.role==='portal'?'xray-main':'xray-bridge'))
  && op.nodes.filter(n=>n.role==='portal').length===1 && op.nodes.filter(n=>n.role==='bridge').length===1
  && op.nodes.filter(n=>n.role==='relay').length===2
  && op.nodes.filter(n=>n.role==='relay' && String(n.node)===op.installedPath.ownerNodeId).length===1
  && op.v2Terminal?.state==='closing' && op.v2Terminal.proofs?.length===0 && op.v2Terminal.sideEffects===undefined
  && op.retainedVerifyContinuation===undefined && op.retainedVerifyClosureContinuation===undefined
  && op.bindingReservationContinuation===undefined && op.bootstrapContinuation===undefined && op.bootstrapCancellation===undefined
  && op.pppWait===undefined);
}
function verifiedReserveDeleteClosure(op, owner) {
 try {
  const audit=op?.bindingReservationContinuation;
  if(!op||!same(op.executionContext,TEST)||op.kind!=='link.delete'||op.admissionScope!=='selected'
   ||op.status!=='committing'||op.attempts!==1||op.leaseOwner!==owner||op.heldTopologyAdmission!==true||op.finishedAt!==null
   ||op.routeState!=='complete'||op.installedPath?.kind!=='link.delete'||op.installedPath.preserveGroupPaths!==true
   ||op.installedPath.selectedPathKey!=='main'||op.installedPath.oldPathLinkIds?.length!==1
   ||!same(op.installedPath.oldPathLinkIds,op.installedPath.newPathLinkIds)||op.installedPath.oldPathLinkIds.includes(String(op.linkId))
   ||op.nodes?.length!==6||op.resourceNodeIds?.length!==6||new Set(op.resourceNodeIds).size!==6
   ||op.nodes.some(n=>n.state!=='committed'||!n.backupId||!op.resourceNodeIds.includes(String(n.node)))
   ||!['portal','relay','bridge'].every(role=>op.nodes.filter(n=>n.role===role).length===2)
   ||op.v2Terminal?.state!=='closing'||op.v2Terminal.proofs?.length!==0||op.v2Terminal.sideEffects!==undefined
   ||audit?.kind!=='partial-delete-reservations-all-native-dispatch-absent-v1'||audit.originalAttempts!==1
   ||audit.preservedBindingIds?.length!==1||audit.observed?.length!==6
   ||audit.observed.some(p=>p.noDispatch?.generationAbsent!==true||p.noDispatch.operationAbsent!==true||p.noDispatch.backupAbsent!==true)
   ||op.retainedVerifyContinuation!==undefined||op.bootstrapContinuation!==undefined||op.bootstrapCancellation!==undefined||op.pppWait!==undefined
   ||(op.retainedVerifyClosureContinuation!==undefined&&(op.retainedVerifyClosureContinuation.kind!=='original-verified-reserve-delete-before-normal-closure-v1'
    ||op.retainedVerifyClosureContinuation.readbackContinuation!==undefined)))return false;
  const deletion=require('../domain/primaryReservePolicy').selectedReserveLeafDeletion(op.baselineTopology,
   op.installedPath.groupBefore,op.installedPath,String(op.linkId));
  return Boolean(deletion&&same(op.effectiveTopology.groups.filter(g=>String(g._id??g.id)===op.installedPath.groupId),[deletion.appliedGroup])
   &&!op.effectiveTopology.links.some(l=>l.id===op.linkId));
 }catch{return false;}
}
function originalVerifiedClosure(op, owner) {
 return Boolean(op && same(op.executionContext,TEST) && op.kind==='link.apply' && op.admissionScope==='selected'
  && op.status==='committing' && op.attempts===1 && op.leaseOwner===owner && op.heldTopologyAdmission===true && op.finishedAt===null
  && op.staged===true && op.routeState==='complete' && op.installedPath?.kind==='link.apply'
  && Number.isSafeInteger(op.installedPath.ownerCredentialRevision) && op.installedPath.ownerCredentialRevision>=1
  && Number.isSafeInteger(op.installedPath.ownerTopologyRevision) && op.installedPath.ownerTopologyRevision>=0
  && op.nodes?.length===5 && op.resourceNodeIds?.length===5 && new Set(op.resourceNodeIds).size===5
  && op.nodes.every(n=>n.state==='committed' && n.backupId && op.resourceNodeIds.includes(String(n.node))
   && n.targetProfile===(n.role==='portal'?'xray-main':'xray-bridge'))
  && op.nodes.filter(n=>n.role==='portal').length===2 && op.nodes.filter(n=>n.role==='bridge').length===2
  && op.nodes.filter(n=>n.role==='relay' && String(n.node)===op.installedPath.ownerNodeId).length===1
  && op.v2Terminal?.state==='closing' && op.v2Terminal.proofs?.length===0 && op.v2Terminal.sideEffects===undefined
  && op.retainedVerifyContinuation===undefined && (op.retainedVerifyClosureContinuation===undefined
   || op.retainedVerifyClosureContinuation.kind==='original-verified-all-five-before-normal-closure-v1'
    && op.retainedVerifyClosureContinuation.originalAttempts===1
    && op.retainedVerifyClosureContinuation.readbackContinuation===undefined)
  && op.bindingReservationContinuation===undefined && op.bootstrapContinuation===undefined && op.bootstrapCancellation===undefined
  && op.pppWait===undefined);
}
function eligible(op,owner){
 if(verifiedPreclosureRoot(op,owner)&&op.v2Terminal===undefined&&op.retainedVerifyContinuation===undefined)return 'verified-preclosure-reclaimed';
 if(verifiedPreclosureRoot(op,owner)&&op.v2Terminal===undefined
  &&op.retainedVerifyContinuation?.kind==='verified-before-closure-reclaimed-claim-v1'
  &&op.retainedVerifyContinuation.readbackContinuation===undefined&&originalExecutionAttempt(op)===1)return 'verified-preclosure-reclaimed';
 if(verifiedDeleteClosure(op,owner)) return 'original-verified-delete';
 if(verifiedReserveDeleteClosure(op,owner)) return 'original-verified-reserve-delete';
 if(originalVerifiedClosure(op,owner)) return 'original-verified-all-five';
 const closing=op?.retainedVerifyContinuation?.kind==='lost-nonactivating-verify-current-observation-v1'
  && op.v2Terminal?.state==='closing' && op.v2Terminal.proofs?.length===0 && op.v2Terminal.sideEffects===undefined
  && op.retainedVerifyClosureContinuation===undefined;
 if(!op||!same(op.executionContext,TEST)||op.kind!=='link.apply'||op.admissionScope!=='selected'||op.status!=='committing'
  ||op.attempts!==1||op.leaseOwner!==owner||op.heldTopologyAdmission!==true||op.finishedAt!==null
  ||(!closing&&(op.v2Terminal!==undefined||op.retainedVerifyContinuation!==undefined))||op.pppWait!==undefined
  ||op.nodes?.length!==2||op.resourceNodeIds?.length!==2||new Set(op.resourceNodeIds).size!==2
  ||op.nodes[0].state!=='committed'||op.nodes[1].state!==(closing?'committed':'prepared')
  ||op.nodes.some(n=>n.targetProfile!=='xray-bridge'||!n.backupId||!op.resourceNodeIds.includes(String(n.node))))refuse();
 return closing;
}
function validatePhysical(op,bindings,physical){
 const closing=Boolean(op.v2Terminal);
 const beforeClosure=verifiedPreclosureRoot(op,op.leaseOwner)&&op.v2Terminal===undefined;
 const original=beforeClosure||originalVerifiedClosure(op,op.leaseOwner)||verifiedDeleteClosure(op,op.leaseOwner)||verifiedReserveDeleteClosure(op,op.leaseOwner);
 if(physical.nodes?.length!==bindings.length)refuse();
 return bindings.map((b,i)=>{
  const p=physical.nodes.find(p=>p.nodeId===b.nodeId),n=op.nodes[i],j=p?.journal,g=j?.generations?.[b.generation];
  const expected=Object.fromEntries(['operationId','nodeId','candidateHash','backupId','targetProfile','executionContext','attemptId','generation','predecessorGeneration'].map(k=>[k,b[k]]));
  if(!p||p.runnerIdle!==true||p.bootId!==b.bootId||j?.bootId!==b.bootId||j.head!==b.generation||!same(g?.binding,expected)
   ||b.nodeId!==String(n.node)||b.operationId!==String(op._id)||b.backupId!==n.backupId||b.candidateHash!=='sha256:'+n.candidateHash)refuse();
  const commands=g.commands,required=i===0||closing||beforeClosure?['prepare','commit','verify']:['prepare'];
  const restoreId=original&&!beforeClosure&&n.role==='portal'?require('../services/topologyReadinessProtocol').readinessCommandId('restore-users',b.commandIds.verify):null;
  const observationId=createHash('sha256').update('topology-retained-verify-v1:'+b.commandIds.verify).digest('hex');
  if(!same(Object.keys(commands).sort(),[...required.map(c=>b.commandIds[c]),...(closing&&i===0&&!original?[observationId]:[]),...(restoreId?[restoreId]:[])].sort())
   ||g.phase!==(closing||beforeClosure?'verified':i===0?'verify-running':'prepared'))refuse();
  if(restoreId){const r=commands[restoreId],o=r?.receipt;
   if(r?.state!=='completed'||r.command!=='restore-users'||!o||Object.entries(expected).some(([k,v])=>o[k]!==v)
    ||o.command!=='restore-users'||o.commandId!==restoreId||o.bootId!==b.bootId||o.protocolVersion!==2
    ||o.completion!=='completed'||o.phase!=='verified'||o.ownershipRetained!==true||!/^[a-f0-9]{64}$/.test(o.checksSha256)
    ||o.result?.ok!==true||o.result.code!=='XRAY_USERS_RESTORED'||!Number.isSafeInteger(o.result.userCount)||o.result.userCount<1
    ||!Number.isSafeInteger(o.result.inboundCount)||o.result.inboundCount<1)refuse();
  }
  if(closing&&i===0&&!original){const r=commands[observationId],o=r?.receipt;
   if(g.verifyObservation!==observationId||r?.state!=='completed'||r.command!=='observe-verify'||!o
    ||Object.entries(expected).some(([k,v])=>o[k]!==v)||o.bootId!==b.bootId||o.commandId!==observationId
    ||o.originalVerifyId!==b.commandIds.verify||o.commitId!==b.commandIds.commit||o.phase!=='verified'||o.completion!=='completed')refuse();
  }
  for(const c of required){const r=commands[b.commandIds[c]];
   if(c==='verify'&&i===0&&!original){if(!same(r,{command:'verify',state:'running'}))refuse();continue;}
   const receipt=r?.receipt;
   if(r?.state!=='completed'||r.command!==c||!receipt||Object.entries(expected).some(([k,v])=>receipt[k]!==v)
    ||receipt.command!==c||receipt.commandId!==b.commandIds[c]||receipt.completedCommand!==c||receipt.bootId!==b.bootId
    ||receipt.ok!==true||receipt.completion!=='completed'||receipt.protocolVersion!==2||receipt.phase!==({prepare:'prepared',commit:'committed',verify:'verified'})[c])refuse();
  }
  if((i===0||closing||beforeClosure)&&p.current[b.targetProfile].configSha256!==n.candidateHash)refuse();
  return{nodeId:b.nodeId,bootId:b.bootId,generation:b.generation,runnerIdle:true,phase:g.phase,
   journalSha256:createHash('sha256').update(JSON.stringify(j)).digest('hex'),originalCommands:commands,current:p.current};
 });
}
async function claimRetainedVerifyContinuation(models,selected,lifecycle,{operationId,owner,leaseMs,now}){
 const M=models.TopologyOperation,db=M.db;
 const majority=(Model,q)=>Model.findOne(q).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
 const op=await M.findById(operationId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean();const mode=eligible(op,owner),beforeClosure=mode==='verified-preclosure-reclaimed',closing=!beforeClosure&&Boolean(mode),original=mode==='original-verified-all-five'||mode==='original-verified-delete'||mode==='original-verified-reserve-delete';
 const locks=await models.NodeOperationLock.find({operationId}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
 const all=await models.TopologyExecutionBinding.find({operationId}).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
 if(locks.length!==op.nodes.length||all.length!==op.nodes.length)refuse();
 const roots=[],bindings=[];
 for(const n of op.nodes){const id=String(n.node),b=all.find(b=>b.nodeId===id),l=locks.find(l=>String(l.node)===id);
  const e=await majority(models.TopologyExecutionEnrollment,{nodeId:id,targetProfile:n.targetProfile});
  const o=await models.TopologyConfigOwner.findOne({node:id,profile:n.targetProfile}).select('+legacyAppliedTopology +profileTargetPin').read('primary').readConcern('majority').setOptions(OPTIONS).lean();
  if(!b||!l||!e||!o||b.attempt!==1||b.owner!==owner||b.generation!==l.generation||l.owner!==owner||l.remoteUncertain!==true
   ||o.owner!=='topology'||!same(o.executionContext,TEST)||o.handbackReceipt!==undefined||b.ownerGeneration!==o.generation||e.ownerGeneration!==o.generation
   ||b.enrollmentId!==e._id||b.bootId!==enrollmentRuntimeBootId(e)||!same(b.nodeIdentity,e.nodeIdentity)||!same(o.nodeIdentity,e.nodeIdentity)
   ||o.lastSettledGeneration!==b.predecessorGeneration)refuse();
  roots.push({e,o,l});bindings.push(b);
 }
 return lifecycle.withTestRetainedVerifyObservation(bindings,async(physical,check)=>{
  const observed=validatePhysical(op,bindings,physical);await check();
  if(beforeClosure&&op.retainedVerifyContinuation){
   const prior=op.retainedVerifyContinuation;
   if(!same(prior.observed,observed)||!same(prior.locks,locks.map(l=>({node:String(l.node),generation:l.generation}))))refuse();
  }
  if(original&&op.retainedVerifyClosureContinuation){
   // One finite fresh readback continuation. Preserve the original claim audit;
   // no closed/partial/UNKNOWN generation or changed command set is admitted.
   const prior=op.retainedVerifyClosureContinuation;
   if(!same(prior.observed,observed)||!same(prior.locks,locks.map(l=>({node:String(l.node),generation:l.generation}))))refuse();
  }
  if(closing){
   const records=bindings.map(b=>Object.fromEntries(require('../models/topologyExecutionBindingContract').recordKeysFor(b).map(k=>[k,b[k]])));
   if(!same(op.v2Terminal.bindings,records))refuse();
  }
  const session=await db.startSession(),nonce=randomUUID();let attempted=false,lease,audit;
  try{
   session.startTransaction({readConcern:{level:'snapshot'},writeConcern:{w:'majority'},readPreference:'primary'});
   const current=await M.findById(operationId).select(PRIVATE).session(session).setOptions(OPTIONS).lean();eligible(current,owner);if(!same(current,op))refuse();
   if(await M.findOne({_id:{$ne:operationId},heldTopologyAdmission:true}).session(session).setOptions(OPTIONS).lean())refuse();
   await selected.verifySelected(current,session);
   const state=await models.CascadeTopologyState.findById('singleton').session(session).setOptions(OPTIONS).lean();
   if(state?.topologyAdmissionCount!==1||state.remoteAdmissionCount!==0||state.remoteDrain||state.replacementReservation)refuse();
   await check();lease=new Date(Date.now()+leaseMs);
   // Ordinary non-PPP state producer, inside the same native claim CAS. Do not
   // infer installation, credentials or a PPP success from a missing DB row.
   const initialized=[];
   if(closing&&!original)for(const n of op.nodes.filter(n=>n.role==='relay')){
    const node=String(n.node),p=physical.nodes.find(p=>p.nodeId===node);
    if(!await models.RelayL2tpState.findOne({node}).session(session).setOptions(OPTIONS).lean()){
     if(p?.l2tpUnconfigured!==true
      ||await models.L2tpUser.findOne({relayNode:node}).session(session).setOptions(OPTIONS).lean()
      ||await models.L2tpOperation.findOne({node}).session(session).setOptions(OPTIONS).lean())refuse();
     await models.RelayL2tpState.insertMany([{node,desiredState:'absent',status:'not_installed',secretRevision:0}],{session,...OPTIONS});initialized.push(node);
    }
   }
   for(let i=0;i<roots.length;i++){
    const {e,o,l}=roots[i],b=bindings[i];
    if(!await models.TopologyExecutionEnrollment.findOne(e).session(session).setOptions(OPTIONS).lean()
     ||!await models.TopologyExecutionBinding.findOne(b).session(session).setOptions(OPTIONS).lean())refuse();
    const {updatedAt:ignored,...of}=o;
    for(const[Model,f]of [[models.TopologyConfigOwner,of],[models.HyNode,{_id:b.nodeId,active:true,type:'xray',cascadeRole:op.nodes[i].role,
      ip:e.endpoint.ip,'ssh.port':e.endpoint.port,'ssh.username':e.endpoint.username}]])
     if((await Model.updateOne(f,{$set:{executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
    if((await models.NodeOperationLock.updateOne({...l},{$set:{leaseUntil:lease,executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
   }
   if((await models.CascadeTopologyState.updateOne(state,{$inc:{stateTransitionRevision:1}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
   audit={kind:beforeClosure?'verified-before-closure-reclaimed-claim-v1':mode==='original-verified-reserve-delete'?'original-verified-reserve-delete-before-normal-closure-v1':mode==='original-verified-delete'?'original-verified-delete-before-normal-closure-v1':original?(op.retainedVerifyClosureContinuation?'original-verified-all-five-readback-before-normal-closure-v1':'original-verified-all-five-before-normal-closure-v1'):closing?'verified-suffix-before-normal-closure-v1':'lost-nonactivating-verify-current-observation-v1',observedAt:new Date(),nonce,originalAttempts:op.attempts,...(beforeClosure?{originalBindingAttempt:1}:{}),initializedAbsentPppStates:initialized,
    locks:locks.map(l=>({node:String(l.node),generation:l.generation})),originalLeaseUntil:op.leaseUntil,
    stateEpoch:{revision:state.revision,stateTransitionRevision:state.stateTransitionRevision,replacementEpoch:state.replacementEpoch,deployedRevision:state.deployedRevision},observed};
   const field=beforeClosure&&op.retainedVerifyContinuation?'retainedVerifyContinuation.readbackContinuation':original&&op.retainedVerifyClosureContinuation?'retainedVerifyClosureContinuation.readbackContinuation':closing?'retainedVerifyClosureContinuation':'retainedVerifyContinuation';
   if((await M.updateOne({_id:operationId,status:'committing',attempts:op.attempts,leaseOwner:owner,leaseUntil:op.leaseUntil,heldTopologyAdmission:true,
    nodes:op.nodes,[field]:{$exists:false},...(field.startsWith('retainedVerifyContinuation.')?{retainedVerifyContinuation:op.retainedVerifyContinuation}:field.includes('.')?{retainedVerifyClosureContinuation:op.retainedVerifyClosureContinuation}:{}),v2Terminal:closing?op.v2Terminal:{$exists:false}},{$set:{leaseUntil:lease,[field]:audit,executionBindingCheck:nonce}},{session,...OPTIONS,runValidators:true})).matchedCount!==1)refuse();
   attempted=true;
   try{const r=await db.getClient().db('admin').command({commitTransaction:1,writeConcern:{w:'majority',wtimeout:5000},maxTimeMS:5000},{session,...OPTIONS});if(r.ok!==1||r.writeConcernError||r.errorLabels?.length)refuse();}
   finally{session.transaction.transition('TRANSACTION_COMMITTED');}
  }catch(e){if(!attempted&&session.inTransaction())await session.abortTransaction().catch(()=>{});throw e;}
  finally{await session.endSession();}
  const confirmed=await M.findById(operationId).select(PRIVATE).read('primary').readConcern('majority').setOptions(OPTIONS).lean();
  const confirmedAudit=beforeClosure&&op.retainedVerifyContinuation?confirmed?.retainedVerifyContinuation?.readbackContinuation:original&&op.retainedVerifyClosureContinuation?confirmed?.retainedVerifyClosureContinuation?.readbackContinuation:confirmed?.[closing?'retainedVerifyClosureContinuation':'retainedVerifyContinuation'];
  if(confirmed?.status!=='committing'||confirmed.attempts!==op.attempts||confirmed.leaseOwner!==owner||confirmed.leaseUntil?.getTime()!==lease.getTime()||!same(confirmedAudit,audit))refuse();
  for(const {l,o}of roots){if(!await majority(models.NodeOperationLock,{_id:l._id,operationId,owner,generation:l.generation,remoteUncertain:true,leaseUntil:lease,executionBindingCheck:nonce})
   ||!await majority(models.TopologyConfigOwner,{_id:o._id,generation:o.generation,executionBindingCheck:nonce}))refuse();}
  await check();return confirmed;
 });
}
module.exports={claimRetainedVerifyContinuation,originalExecutionAttempt,assertRetainedVerifyEligible:eligible,validateRetainedVerifyPhysical:validatePhysical};
