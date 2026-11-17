'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
test('retained continuation eligibility never adopts another phase/attempt/context or a second continuation',()=>{
 const {assertRetainedVerifyEligible:eligible}=require('../repositories/topologyRetainedVerifyContinuation');
 const op={executionContext:require('../domain/topologyExecutionContext').TEST_TOPOLOGY_EXECUTION_CONTEXT,kind:'link.apply',admissionScope:'selected',status:'committing',attempts:1,leaseOwner:'owner',heldTopologyAdmission:true,finishedAt:null,resourceNodeIds:['a','b'],nodes:[{node:'a',state:'committed',backupId:'ba',targetProfile:'xray-bridge'},{node:'b',state:'prepared',backupId:'bb',targetProfile:'xray-bridge'}]};
 eligible(op,'owner');
 for(const patch of [{status:'queued'},{attempts:2},{leaseOwner:'other'},{heldTopologyAdmission:false},{v2Terminal:{}},{pppWait:{}},{retainedVerifyContinuation:{}},{executionContext:{target:'production',hostIdentity:'lm1.infograd.online'}},{nodes:[op.nodes[1],op.nodes[0]]}])assert.throws(()=>eligible({...op,...patch},'owner'));
});
test('closure continuation accepts only this proven retained suffix and never replays either commit/verify',async()=>{
 const {assertRetainedVerifyEligible:eligible}=require('../repositories/topologyRetainedVerifyContinuation');
 const op={executionContext:require('../domain/topologyExecutionContext').TEST_TOPOLOGY_EXECUTION_CONTEXT,kind:'link.apply',admissionScope:'selected',status:'committing',attempts:1,leaseOwner:'owner',heldTopologyAdmission:true,finishedAt:null,resourceNodeIds:['a','b'],nodes:['a','b'].map(node=>({node,state:'committed',backupId:'b'+node,targetProfile:'xray-bridge'})),retainedVerifyContinuation:{kind:'lost-nonactivating-verify-current-observation-v1'},v2Terminal:{state:'closing',proofs:[]}};
 assert.equal(eligible(op,'owner'),true);
 for(const patch of [{v2Terminal:{state:'proven',proofs:[]}},{v2Terminal:{state:'closing',proofs:[{}]}},{retainedVerifyClosureContinuation:{}},{retainedVerifyContinuation:{kind:'other'}}])assert.throws(()=>eligible({...op,...patch},'owner'));
 const {TopologyOperationWorker}=require('../workers/topologyOperationWorker'),calls=[];
 const self={context:(_,n,p,b)=>({node:n,prepared:p,backupId:b}),executor:{rehydrate:async c=>({ok:true,prepared:Object.freeze({}),backupId:c.backupId}),observeRetainedVerify:async(c,status)=>{assert.equal(status,true);calls.push('B-status');},restoreCompletedVerify:async()=>calls.push('R-status'),commit:async()=>assert.fail('commit replay'),verify:async()=>assert.fail('verify replay')},completeV2:async(...args)=>{assert.equal(args[5],true);calls.push('native-closure');return{status:'succeeded'};}};
 await TopologyOperationWorker.prototype.continueRetainedVerification.call(self,{operationId:'op'}, {...op,retainedVerifyClosureContinuation:{}},op.nodes,{run:f=>f()},[]);
 assert.deepEqual(calls,['B-status','R-status','native-closure']);
});
test('worker continuation never repeats committed payload: observe B, original commit/verify R, native finalizer; failed observation stops R',async()=>{
 const {TopologyOperationWorker}=require('../workers/topologyOperationWorker');
 for(const fail of [false,true]){
  const calls=[],nodes=[{node:'B'},{node:'R'}],plan={operationId:'op',nodes};
  const self={workerId:'owner',clock:{now:()=>new Date()},context:(_,node,prepared,backupId)=>({node,prepared,backupId}),
   executor:{rehydrate:async c=>({ok:true,backupId:c.backupId,prepared:Object.freeze({})}),
    observeRetainedVerify:async c=>{calls.push('observe:'+c.node.node);if(fail)throw Error('unproven');return{ok:true};},
    commit:async c=>{calls.push('commit:'+c.node.node);return{ok:true};},verify:async c=>{calls.push('verify:'+c.node.node);return{ok:true};}},
   operationRepository:{recordNode:async()=>{calls.push('record:R');return true;}},completeV2:async()=>{calls.push('native-finalizer');return{status:'succeeded'};}};
  const work=()=>TopologyOperationWorker.prototype.continueRetainedVerification.call(self,plan,{nodes:[{backupId:'b'},{backupId:'r'}]},nodes,{run:f=>f()},[]);
  if(fail){await assert.rejects(work);assert.deepEqual(calls,['observe:B']);}
  else{assert.equal((await work()).status,'succeeded');assert.deepEqual(calls,['observe:B','commit:R','record:R','verify:R','native-finalizer']);}
 }
});
