'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
process.env.PANEL_DOMAIN='test.infograd.online';
process.env.ACME_EMAIL='admin@test.invalid';
process.env.ENCRYPTION_KEY='test-encryption-key-32-characters-long';
process.env.SESSION_SECRET='test-session-secret';
function workerClass(){
 if(!process.env.C3_LEASE_WORKER_BEFORE)return require('../workers/topologyOperationWorker').TopologyOperationWorker;
 const Module=require('node:module'),fs=require('node:fs'),p=require.resolve('../workers/topologyOperationWorker');
 const m=new Module(p,module);m.filename=p;m.paths=Module._nodeModulePaths(require('node:path').dirname(p));m._compile(fs.readFileSync(process.env.C3_LEASE_WORKER_BEFORE,'utf8'),p);return m.exports.TopologyOperationWorker;
}
test('terminal persistence and publish use one stable live lease after heartbeat is joined',async()=>{
 const Worker=workerClass(),{TopologyOperationExecutor}=require('../services/topologyOperationExecutor');
 const executor=Object.create(TopologyOperationExecutor.prototype);let epoch=Date.now(),lease,timerActive=true,hb;
 Object.assign(executor,{terminalBindings:async()=>Object.freeze([Object.freeze({})]),withVerifiedMutationScope:async(c,work)=>work(async()=>{}),close:async()=>Object.freeze({realTransportNotUnderTest:true})});
 const repo=Object.fromEntries(['claim','recordNode','setPhase','finishClaimed'].map(k=>[k,async()=>true]));
 repo.renewLease=async({now,leaseMs})=>{lease=new Date(now.getTime()+leaseMs);return true;};
 const finalizer={finalizeSucceeded:async()=>true,beginV2Closure:async()=>true,probeV2Settlement:async()=>null,
  persistV2TerminalProofs:async request=>{
   // A periodic same-owner tick can complete before checked() reads its row.
   if(timerActive)await hb.renew();
   assert.equal(request.leaseUntil.getTime(),lease.getTime(),'request fence must equal current actual lease');return true;
  },finalizeV2Succeeded:async request=>{assert.equal(timerActive,false);assert.equal(request.leaseUntil.getTime(),lease.getTime());return true;}};
 const worker=new Worker({executionContext:require('../domain/topologyExecutionContext').TEST_TOPOLOGY_EXECUTION_CONTEXT,
  operationRepository:repo,executor,finalizer,lockService:{acquire:async()=>{},renew:async()=>({ok:true}),release:async()=>{}},workerId:'unit-owner',leaseMs:30000,
  clock:{now:()=>new Date(++epoch)},userResync:{resyncPlan:async()=>({ok:true})},pppReadinessGate:{verifyPlan:async()=>({ok:true,relayRevisions:[]})}});
 worker.context=()=>Object.freeze({});
 hb={renew:()=>worker.renew('unit-operation'),run:work=>work(),exclusive:async work=>{timerActive=false;try{return await work(await worker.renew('unit-operation'));}finally{timerActive=true;}},stop:async()=>{timerActive=false;}};
 const result=await worker.completeV2({topologyRevision:1,priorDeployedRevision:0},'unit-operation',[{node:{}}],hb,[]);
 assert.equal(result.status,'succeeded');assert.equal(result.stopped,undefined);
});
test.after(()=>require('../../../services/sshPoolService').closeAll());
