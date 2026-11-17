'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const diagnostics=require('../../../routes/topologyTestDiagnostics');
const settlement=require('../repositories/topologyV2Settlement');
function fixture(error,endError){
 const calls={abort:0,end:0,commit:0,log:[]};
 const session={transaction:{transition(){}},startTransaction(){},inTransaction(){return true;},async abortTransaction(){calls.abort++;},async endSession(){calls.end++;if(endError)throw endError;}};
 const db={async startSession(){return session;},getClient(){return {db(){return {async command(){calls.commit++;throw Error('must not commit');}};}};}};
 const repository={TopologyOperation:{db,findById(){throw error;}}};
 return {repository,calls};
}
test('terminal persist inner catch records bounded original phase/type/code/static source frame and preserves primary',async()=>{
 const secret='credential=DO_NOT_LOG_private_123';
 const error=Object.assign(new TypeError(secret),{code:'untrusted-'+secret});
 // Use an actual static source location, with arbitrary raw message/stack text.
 error.stack='TypeError: '+secret+'\n at /app/src/modules/relay-l2tp/repositories/topologyV2Settlement.js:12:42\n at /app/src/modules/relay-l2tp/repositories/topologyV2Settlement.js:241:21\n at '+secret;
 const f=fixture(error),log=diagnostics.logTopologyTestFailure;
 diagnostics.logTopologyTestFailure=input=>f.calls.log.push(input);
 try{await assert.rejects(settlement.persist(f.repository,{operationId:'ab620693fb538980f0fe51a8',topologyRevision:3}),e=>e===error);}
 finally{diagnostics.logTopologyTestFailure=log;}
 assert.equal(f.calls.abort,1);assert.equal(f.calls.end,1);assert.equal(f.calls.commit,0);
 assert.equal(f.calls.log.length,1,'inner catch must emit the original boundary before worker masking');
 const input=f.calls.log[0],row=diagnostics.formatTopologyDiagnostic(input);
 assert.equal(input.phase,'persist.work');assert.equal(row.phase,'persist.work');
 assert.equal(row.errorType,'TypeError');assert.equal(row.code,'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED');
 assert.deepEqual(row.sourceFrames,['src/modules/relay-l2tp/repositories/topologyV2Settlement.js:12:42','src/modules/relay-l2tp/repositories/topologyV2Settlement.js:241:21']);
 assert.equal(JSON.stringify(input).includes(secret),false);assert.equal(JSON.stringify(row).includes(secret),false);
 assert.equal(Object.hasOwn(input.error,'message'),false);
});
test('terminal persist inner catch diagnostic failure never replaces original refusal or retries a write',async()=>{
 const error=Object.assign(Error('original-private-message'),{code:'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED'}),f=fixture(error),log=diagnostics.logTopologyTestFailure;
 diagnostics.logTopologyTestFailure=()=>{throw Error('diagnostic failure');};
 try{await assert.rejects(settlement.persist(f.repository,{operationId:'ab620693fb538980f0fe51a8'}),e=>e===error);}
 finally{diagnostics.logTopologyTestFailure=log;}
 assert.equal(f.calls.abort,1);assert.equal(f.calls.end,1);assert.equal(f.calls.commit,0);
});
test('worker v2 phase is not truncated and raw error text cannot enter bounded diagnostic',()=>{
 const row=diagnostics.formatTopologyDiagnostic({action:'topology.worker',phase:'worker.v2-terminal',error:{name:'Error',code:'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED',message:'private-secret'}});
 assert.equal(row.phase,'worker.v2-terminal');assert.equal(JSON.stringify(row).includes('private-secret'),false);
});
test('terminal session cleanup failure cannot mask primary persistence failure',async()=>{
 const primary=Object.assign(Error('primary-private-message'),{code:'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED'}),cleanup=Error('cleanup-private-message'),f=fixture(primary,cleanup),log=diagnostics.logTopologyTestFailure;
 diagnostics.logTopologyTestFailure=input=>f.calls.log.push(input);
 try{await assert.rejects(settlement.persist(f.repository,{operationId:'ab620693fb538980f0fe51a8'}),e=>e===primary);}
 finally{diagnostics.logTopologyTestFailure=log;}
 assert.deepEqual(f.calls.log.map(e=>e.phase),['persist.work','persist.end']);
 assert.equal(JSON.stringify(f.calls.log).includes('private-message'),false);
 assert.equal(f.calls.abort,1);assert.equal(f.calls.end,1);assert.equal(f.calls.commit,0);
});
