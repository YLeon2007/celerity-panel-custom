'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const TEST=require('../domain/topologyExecutionContext').TEST_TOPOLOGY_EXECUTION_CONTEXT;
const {assertUndispatchedPreparationEligible:eligible,validateUndispatchedPhysical:physical}=require('../repositories/topologyUndispatchedPreparationContinuation');
const op=()=>({executionContext:TEST,admissionScope:'selected',kind:'link.apply',status:'preparing',attempts:1,leaseOwner:'worker',leaseUntil:new Date(1),heldTopologyAdmission:true,finishedAt:null,resourceNodeIds:['a'],nodes:[{node:'a',state:'pending',backupId:'',targetProfile:'xray-main',candidateHash:'c'.repeat(64)}]});
test('failed delete continuation admits only actual completed first commit plus prepared suffix; UNKNOWN is never replayed',()=>{
 const {assertPreparedCommitEligible:eligible,validatePreparedCommitPhysical:validate}=require('../repositories/topologyUndispatchedPreparationContinuation');
 const current={...op(),kind:'link.delete',status:'failed',leaseUntil:null,finishedAt:new Date(),nodes:[{...op().nodes[0],state:'failed',backupId:'backup'}]};eligible(current,'worker',new Date());
 for(const delta of [{kind:'link.apply'},{status:'committing'},{attempts:2},{leaseUntil:new Date()},{finishedAt:null},{preparedCommitContinuation:{}},{v2Terminal:{}},{heldTopologyAdmission:false},{nodes:[{...current.nodes[0],state:'committed'}]}])assert.throws(()=>eligible({...current,...delta},'worker',new Date()));
 const {randomUUID}=require('node:crypto');const bindings=['a','b'].map(nodeId=>({nodeId,operationId:'op',generation:randomUUID(),attemptId:randomUUID(),bootId:randomUUID(),predecessorGeneration:randomUUID(),candidateHash:'sha256:'+'c'.repeat(64),backupId:'backup',targetProfile:'xray-main',executionContext:TEST.hostIdentity,commandIds:Object.fromEntries(['prepare','commit','verify','rollback','close'].map(c=>[c,randomUUID()]))}));
 const priors=bindings.map(()=>({candidateHash:'sha256:'+'a'.repeat(64)}));
 const nodes=bindings.map((b,i)=>{const binding=Object.fromEntries(['operationId','nodeId','candidateHash','backupId','targetProfile','executionContext','attemptId','generation','predecessorGeneration'].map(k=>[k,b[k]]));return {nodeId:b.nodeId,bootId:b.bootId,runnerIdle:true,current:{'xray-main':{configSha256:(i===0?'c':'a').repeat(64),serviceActive:'active'}},journal:{head:b.generation,bootId:b.bootId,generations:{[b.generation]:{binding,phase:i===0?'committed':'prepared',commands:Object.fromEntries((i===0?['prepare','commit']:['prepare']).map(c=>[b.commandIds[c],{command:c,state:'completed',receipt:{...binding,command:c,commandId:b.commandIds[c],bootId:b.bootId,ok:true,completion:'completed',completedCommand:c,protocolVersion:2,phase:c==='prepare'?'prepared':'committed'}}]))}}}};});
 validate(bindings,priors,{nodes});
 for(const mutate of [n=>n[0].runnerIdle=false,n=>n[0].journal.generations[bindings[0].generation].commands[bindings[0].commandIds.verify]={command:'verify',state:'running'},n=>n[1].journal.generations[bindings[1].generation].commands[bindings[1].commandIds.commit]={command:'commit',state:'completed'},n=>n[1].current['xray-main'].configSha256='c'.repeat(64)]){const copy=structuredClone(nodes);mutate(copy);assert.throws(()=>validate(bindings,priors,{nodes:copy}));}
});
test('only exact first preparing all-pending admitted TEST claim is eligible',()=>{
 eligible(op(),'worker',new Date(2));
 for(const delta of [{status:'queued'},{status:'committing'},{attempts:2},{leaseOwner:'other'},{leaseUntil:new Date(3)},{leaseUntil:null},{heldTopologyAdmission:false},{finishedAt:new Date()},{v2Terminal:{}},{pppWait:{}},{undispatchedPreparationContinuation:{}},{executionContext:{target:'production',hostIdentity:'lm1.infograd.online'}},{resourceNodeIds:[]},{nodes:[{...op().nodes[0],state:'prepared'}]},{nodes:[{...op().nodes[0],backupId:'backup'}]}])assert.throws(()=>eligible({...op(),...delta},'worker',new Date(2)));
});
function fixture(){
 const b={nodeId:'a',operationId:'operation',generation:'new',backupId:'backup',targetProfile:'xray-main',bootId:'boot',predecessorGeneration:'old',predecessorReceipt:{phase:'closed',command:'status'}};
 const p={nodeId:'a',bootId:'boot',runnerIdle:true,noDispatch:{nodeId:'a',operationId:'operation',generation:'new',backupId:'backup',targetProfile:'xray-main',bootId:'boot',runnerIdle:true,generationAbsent:true,operationAbsent:true,backupAbsent:true},journal:{head:'old',bootId:'boot',generations:{old:{phase:'closed',commands:{close:{state:'completed',command:'close',receipt:{phase:'closed',command:'close'}}}}}},current:{'xray-main':{configSha256:'a'.repeat(64),serviceActive:'active'}}};
 const prior={generation:'old',commandIds:{close:'close'},candidateHash:'sha256:'+'a'.repeat(64)};return {b,p,prior};
}
test('physical boundary requires absent dispatch artifacts and exact closed predecessor/current config',()=>{
 const {b,p,prior}=fixture();physical([b],[prior],{nodes:[p]});
 for(const mutate of [p=>p.runnerIdle=false,p=>p.bootId='other',p=>p.noDispatch.operationAbsent=false,p=>p.noDispatch.backupAbsent=false,p=>p.journal.head='foreign',p=>p.journal.generations.new={},p=>p.journal.generations.old.phase='verify-running',p=>p.current['xray-main'].configSha256='b'.repeat(64),p=>p.journal.generations.old.commands.close.state='running',p=>p.journal.generations.old.commands.close.receipt.phase='committed']){
  const q=structuredClone(p);mutate(q);assert.throws(()=>physical([b],[prior],{nodes:[q]}));
 }
});
test('closed settlement accepts no unknown command, changed original binding, running runner or second continuation',()=>{
 const {assertClosedSettlementEligible:closed,validateClosedSettlementPhysical:validate}=require('../repositories/topologyUndispatchedPreparationContinuation');
 const current={...op(),status:'committing',nodes:[{...op().nodes[0],state:'committed',backupId:'backup'}],v2Terminal:{state:'closing',proofs:[]}};
 closed(current,'worker',new Date(2));
 closed({...current,closedSettlementContinuation:{kind:'closed-original-commands-current-observation-v1'}},'worker',new Date(2));
 assert.throws(()=>closed({...current,closedSettlementContinuation:{kind:'closed-original-commands-current-observation-v1',reobservations:[{}]}},'worker',new Date(2)));
 const source=require('node:fs').readFileSync(require.resolve('../workers/topologyOperationWorker'),'utf8');
 assert.match(source,/return await this\.completeV2\(plan,operationId,prepared,heartbeat,acquiredNodeIds,true,true\)/);
 for(const delta of [{attempts:2},{status:'preparing'},{leaseOwner:'other'},{leaseUntil:new Date(3)},{closedSettlementContinuation:{}},{v2Terminal:{state:'proven',proofs:[]}},{v2Terminal:{state:'closing',proofs:[{}]}},{v2Terminal:{state:'closing',proofs:[],sideEffects:{}}}])assert.throws(()=>closed({...current,...delta},'worker',new Date(2)));
 const {randomUUID}=require('node:crypto');
 const b={operationId:'operation',nodeId:'a',candidateHash:'sha256:'+'c'.repeat(64),backupId:'backup',targetProfile:'xray-main',executionContext:TEST.hostIdentity,attemptId:randomUUID(),generation:randomUUID(),predecessorGeneration:randomUUID(),bootId:randomUUID(),commandIds:Object.fromEntries(['prepare','commit','verify','close'].map(c=>[c,randomUUID()]))};
 const binding=Object.fromEntries(['operationId','nodeId','candidateHash','backupId','targetProfile','executionContext','attemptId','generation','predecessorGeneration'].map(k=>[k,b[k]]));
 const receipt={...binding,ok:true,command:'close',commandId:b.commandIds.close,protocolVersion:2,completion:'completed',phase:'closed',terminal:true,ownershipRetained:true,terminalOutcome:'verified',bootId:b.bootId,systemdJob:'completed',serviceState:'active:running',completedCommand:'close'};
 const p={nodeId:'a',bootId:b.bootId,runnerIdle:true,current:{'xray-main':{configSha256:'c'.repeat(64),serviceActive:'active'}},journal:{head:b.generation,bootId:b.bootId,generations:{[b.generation]:{phase:'closed',binding,commands:Object.fromEntries(['prepare','commit','verify','close'].map(c=>[b.commandIds[c],{state:'completed',command:c,...(c==='close'?{receipt}:{})}]))}}}};
 validate([b],[],{nodes:[p]});
 for(const mutate of [p=>p.runnerIdle=false,p=>p.bootId=randomUUID(),p=>p.journal.head=randomUUID(),p=>p.current['xray-main'].configSha256='d'.repeat(64),p=>p.journal.generations[b.generation].commands[b.commandIds.verify].state='running',p=>p.journal.generations[b.generation].commands[b.commandIds.close].receipt.commandId=randomUUID()]){const q=structuredClone(p);mutate(q);assert.throws(()=>validate([b],[],{nodes:[q]}));}
});
