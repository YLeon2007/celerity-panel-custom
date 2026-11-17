'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../../../routes/topologyTestDiagnostics.js'),'utf8');
function logger(enabled=true){
 const writes=[],module={exports:{}};
 const fakeFs={existsSync:p=>p.endsWith('.test-topology-diagnostics-enabled'),appendFileSync:(p,s,o)=>writes.push({path:p,row:JSON.parse(s),mode:o.mode})};
 vm.runInNewContext('(function(require,module,exports,process){'+source+'\n})',{Date,Object,Number,Array,JSON})(name=>name==='node:fs'?fakeFs:path,module,module.exports,{env:{TOPOLOGY_TEST_EXECUTION_ENABLED:String(enabled)}});
 return {...module.exports,writes};
}
test('prepare diagnostic wave: private original cause retains exact node, numeric Mongo label and frame; public output remains credential-free',()=>{
 const f=logger(),inner=Object.assign(new Error('LOCAL_PRIVATE_TEST_SECRET'),{name:'MongoServerError',code:112,hasErrorLabel:l=>l==='TransientTransactionError'});
 const error=Object.assign(new Error('outer'),{code:'TOPOLOGY_EXECUTION_BINDING_UNPROVEN',cause:inner});
 const nodeId='6af8158a0a451ea4113dd7d7',operationId='ad3e2594f8c4334e61001146';
 f.logTopologyTestFailure({action:'topology.worker',phase:'worker.prepare',nodeId,operationId,error});
 assert.equal(f.writes.length,2);assert.equal(JSON.stringify(f.writes[0]).includes('LOCAL_PRIVATE_TEST_SECRET'),false);
 const privateRow=f.writes[1];assert.equal(privateRow.mode,0o600);assert.equal(privateRow.row.nodeId,nodeId);
 assert.equal(privateRow.row.causes[0].code,112);assert.equal(privateRow.row.causes[0].transientTransaction,true);assert.equal(privateRow.row.causes[0].unknownCommit,false);
 assert.equal(privateRow.row.causes[0].stack,inner.stack);
 const off=logger(false);off.logTopologyTestFailure({phase:'worker.prepare',error});assert.equal(off.writes.length,0);
});
