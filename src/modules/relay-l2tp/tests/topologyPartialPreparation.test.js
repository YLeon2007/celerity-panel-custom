'use strict';
// Local modelled protocol evidence, NOT physical TEST observations.
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const TEST=require('../domain/topologyExecutionContext').TEST_TOPOLOGY_EXECUTION_CONTEXT;
const {assertUndispatchedPreparationEligible:eligible,validatePartialPreparationPhysical:validate}=require('../repositories/topologyUndispatchedPreparationContinuation');
function fixture(){
 const bindings=['prepared-node','pending-node'].map(nodeId=>({nodeId,operationId:'operation',candidateHash:'sha256:'+'c'.repeat(64),backupId:'backup-'+nodeId,targetProfile:'xray-main',executionContext:TEST.hostIdentity,generation:randomUUID(),attemptId:randomUUID(),bootId:randomUUID(),predecessorGeneration:randomUUID(),commandIds:Object.fromEntries(['prepare','commit','verify','rollback','close'].map(c=>[c,randomUUID()]))}));
 const priors=bindings.map(b=>({generation:b.predecessorGeneration,candidateHash:'sha256:'+'a'.repeat(64),commandIds:{close:randomUUID()}}));
 const nodes=bindings.map((b,i)=>{
  const receipt={command:'close',phase:'closed',commandId:priors[i].commandIds.close};b.predecessorReceipt={...receipt,command:'status'};
  const old={phase:'closed',commands:{[priors[i].commandIds.close]:{command:'close',state:'completed',receipt}}};
  const journal={bootId:b.bootId,head:i===0?b.generation:b.predecessorGeneration,generations:{[b.predecessorGeneration]:old}};
  const p={nodeId:b.nodeId,bootId:b.bootId,runnerIdle:true,journal,current:{'xray-main':{configSha256:'a'.repeat(64),serviceActive:'active'}}};
  if(i===0){
   const binding=Object.fromEntries(['operationId','nodeId','candidateHash','backupId','targetProfile','executionContext','attemptId','generation','predecessorGeneration'].map(k=>[k,b[k]]));
   journal.generations[b.generation]={binding,phase:'prepared',commands:{[b.commandIds.prepare]:{command:'prepare',state:'completed',receipt:{...binding,ok:true,command:'prepare',commandId:b.commandIds.prepare,protocolVersion:2,completion:'completed',phase:'prepared',terminal:false,ownershipRetained:true,terminalOutcome:'not-terminal',bootId:b.bootId,systemdJob:'not-applicable',serviceState:'not-applicable',completedCommand:'prepare'}}}};
  }else p.noDispatch={...Object.fromEntries(['nodeId','operationId','generation','backupId','targetProfile'].map(k=>[k,b[k]])),bootId:b.bootId,runnerIdle:true,generationAbsent:true,operationAbsent:true,backupAbsent:true};
  return p;
 });
 const op={executionContext:TEST,kind:'link.delete',admissionScope:'selected',status:'preparing',attempts:1,leaseOwner:'worker',leaseUntil:new Date(1),heldTopologyAdmission:true,finishedAt:null,resourceNodeIds:bindings.map(b=>b.nodeId),nodes:bindings.map((b,i)=>({node:b.nodeId,state:i===0?'prepared':'pending',backupId:i===0?b.backupId:'',targetProfile:b.targetProfile,candidateHash:b.candidateHash.slice(7)}))};
 return {bindings,priors,op,physical:{nodes}};
}
test('verified prefix wave: exact completed command prefix restores only never-dispatched suffix',()=>{
 const validate=require('../repositories/topologyUndispatchedPreparationContinuation').validatePreparedCommitPhysical;
 function make(phases){
  const base=fixture(),bindings=[],priors=[],nodes=[];
  for(let i=0;i<phases.length;i++){
   const b={...base.bindings[0],nodeId:'node-'+i,generation:randomUUID(),commandIds:Object.fromEntries(['prepare','commit','verify','rollback','close'].map(c=>[c,randomUUID()]))};bindings.push(b);priors.push({candidateHash:'sha256:'+'a'.repeat(64)});
   const binding=Object.fromEntries(['operationId','nodeId','candidateHash','backupId','targetProfile','executionContext','attemptId','generation','predecessorGeneration'].map(k=>[k,b[k]]));
   const commands=phases[i]==='verified'?['prepare','commit','verify']:phases[i]==='committed'?['prepare','commit']:['prepare'];
   nodes.push({nodeId:b.nodeId,bootId:b.bootId,runnerIdle:true,current:{'xray-main':{configSha256:(phases[i]==='prepared'?'a':'c').repeat(64),serviceActive:'active'}},journal:{bootId:b.bootId,head:b.generation,generations:{[b.generation]:{binding,phase:phases[i],commands:Object.fromEntries(commands.map(c=>[b.commandIds[c],{command:c,state:'completed',receipt:{...binding,command:c,completedCommand:c,commandId:b.commandIds[c],bootId:b.bootId,ok:true,completion:'completed',protocolVersion:2,phase:{prepare:'prepared',commit:'committed',verify:'verified'}[c]}}]))}}}});
  }
  return {bindings,priors,physical:{nodes}};
 }
 for(const phases of [['committed','prepared'],['verified','verified','verified','prepared'],['verified','prepared','prepared']]){const f=make(phases);assert.deepEqual(validate(f.bindings,f.priors,f.physical).map(p=>p.phase),phases);}
 for(const phases of [['prepared','verified'],['committed','committed'],['verified','committed','verified']]){const f=make(phases);assert.throws(()=>validate(f.bindings,f.priors,f.physical));}
 for(const mutate of [f=>f.physical.nodes[0].runnerIdle=false,f=>f.physical.nodes[0].journal.generations[f.bindings[0].generation].commands[f.bindings[0].commandIds.verify].state='unknown',f=>f.physical.nodes[1].journal.generations[f.bindings[1].generation].commands[f.bindings[1].commandIds.commit]={command:'commit',state:'unknown'},f=>f.physical.nodes[1].current['xray-main'].configSha256='c'.repeat(64)]){const f=make(['verified','prepared']);mutate(f);assert.throws(()=>validate(f.bindings,f.priors,f.physical));}
});

test('partial prepare continuation wave: only original mixed first prepare delete is eligible',()=>{
 const {op}=fixture();eligible(op,'worker',new Date(2));
 const mutations=[o=>o.kind='link.apply',o=>o.status='committing',o=>o.attempts=2,o=>o.leaseOwner='foreign',o=>o.leaseUntil=new Date(3),o=>o.leaseUntil=null,o=>o.heldTopologyAdmission=false,o=>o.finishedAt=new Date(),o=>o.v2Terminal={},o=>o.pppWait={},o=>o.undispatchedPreparationContinuation={},o=>o.nodes[1].state='failed',o=>o.nodes[1].backupId='possibly-dispatched',o=>o.nodes[0].backupId='',o=>o.nodes[1]={...o.nodes[0]},o=>o.executionContext={target:'production',hostIdentity:'lm1.infograd.online'}];
 for(const mutate of mutations){const copy=structuredClone(op);mutate(copy);assert.throws(()=>eligible(copy,'worker',new Date(2)));}
});
test('partial prepare continuation wave: exact original completed prepare and pending physical absence are distinct evidence',()=>{
 const f=fixture();const before=structuredClone(f);const proof=validate(f.bindings,f.priors,f.op,f.physical);
 assert.equal(proof[0].originalPrepare.commandId,f.bindings[0].commandIds.prepare);
 assert.equal(proof[1].noDispatch.generationAbsent,true);assert.deepEqual(f,before,'validation never rewrites evidence');
});
test('partial prepare continuation wave: UNKNOWN, extra commands, wrong head, baseline drift and missing absence all refuse',()=>{
 const mutations=[f=>f.physical.nodes[0].runnerIdle=false,f=>f.physical.nodes[0].bootId=randomUUID(),f=>f.physical.nodes[0].journal.head=randomUUID(),f=>f.physical.nodes[0].current['xray-main'].configSha256='d'.repeat(64),f=>f.physical.nodes[1].noDispatch.backupAbsent=false,f=>delete f.physical.nodes[1].noDispatch,f=>f.physical.nodes[1].journal.generations[f.bindings[1].generation]={},f=>f.physical.nodes[0].journal.generations[f.bindings[0].generation].commands[f.bindings[0].commandIds.prepare].state='unknown',f=>f.physical.nodes[0].journal.generations[f.bindings[0].generation].commands[f.bindings[0].commandIds.commit]={command:'commit',state:'completed'},f=>f.physical.nodes[0].journal.generations[f.bindings[0].generation].commands[f.bindings[0].commandIds.prepare].receipt.commandId=randomUUID(),f=>f.physical.nodes[0].journal.generations[f.bindings[0].generation].binding.generation=randomUUID(),f=>f.physical.nodes[0].journal.generations[f.priors[0].generation].commands[f.priors[0].commandIds.close].state='running'];
 for(const mutate of mutations){const f=fixture();mutate(f);assert.throws(()=>validate(f.bindings,f.priors,f.op,f.physical));}
});
