'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const TEST=require('../domain/topologyExecutionContext').TEST_TOPOLOGY_EXECUTION_CONTEXT;
const {assertBindingReservationContinuationEligible:eligible}=require('../repositories/topologyBindingReservationContinuation');
function op(){return {executionContext:TEST,kind:'link.apply',admissionScope:'selected',status:'queued',attempts:1,leaseOwner:'',leaseUntil:null,heldTopologyAdmission:true,finishedAt:null,resourceNodeIds:['a','b'],nodes:['a','b'].map(node=>({node,state:'pending',backupId:'',targetProfile:'xray-bridge'}))};}
test('reservation continuation accepts only the exact queued first TEST reservation, not unknown execution',()=>{
 eligible(op(),'worker');
 for(const patch of [{status:'preparing'},{status:'failed'},{attempts:0},{attempts:2},{heldTopologyAdmission:false},{leaseOwner:'worker'},{leaseUntil:new Date()},{finishedAt:new Date()},{v2Terminal:{}},{pppWait:{}},{bindingReservationContinuation:{}},{bootstrapContinuation:{}},{executionContext:{target:'production',hostIdentity:'lm1.infograd.online'}},{resourceNodeIds:['a']},{nodes:[{node:'a',state:'prepared',backupId:'backup',targetProfile:'xray-bridge'}]}])assert.throws(()=>eligible({...op(),...patch},'worker'));
});
test('ordinary claims never select the explicit reservation continuation',()=>{
 const fs=require('node:fs');const s=fs.readFileSync(require.resolve('../workers/topologyOperationWorker'),'utf8');
 assert.match(s,/async resumeBindingReservations/);assert.match(s,/bindingReservationContinuation\s*\? this.operationRepository.claimBindingReservationContinuation/);
 assert.match(s,/const lockErrorCode = bootstrapContinuation \|\| bindingReservationContinuation/);
});
