'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {assertCancellationEligible:eligible,finalizeBootstrapCancellation}=require('../services/topologyBootstrapCancellation');
const TEST=require('../domain/topologyExecutionContext').TEST_TOPOLOGY_EXECUTION_CONTEXT;
test('bootstrap cancellation accepts only retained first TEST operation and cannot accept committed/settled/foreign state',()=>{
 const op={executionContext:TEST,status:'failed',attempts:1,heldTopologyAdmission:true,leaseUntil:null,bootstrapContinuation:{},nodes:[{state:'failed'},{state:'pending'}]};eligible(op);for(const delta of [{attempts:2},{status:'committing'},{heldTopologyAdmission:false},{bootstrapCancellation:{}},{v2Terminal:{}},{nodes:[{state:'committed'}]},{executionContext:{target:'production',hostIdentity:'lm1.infograd.online'}}])assert.throws(()=>eligible({...op,...delta}));
});
test('forged cancellation receipts cannot enter finalizer transaction',async()=>{
 let db=0;await assert.rejects(finalizeBootstrapCancellation({get TopologyOperation(){db++;return null;}},{operationId:'id',bindings:[{}],proofs:[{}],now:new Date()}));assert.equal(db,0);
});
