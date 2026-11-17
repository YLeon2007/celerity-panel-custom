'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {TopologyUserResync}=require('../services/topologyUserResync');
const {withTopologyReadinessScope}=require('../services/topologyReadinessScope');
const {randomUUID}=require('node:crypto');
function fixture(users=[{userId:'vless-user',xrayUuid:randomUUID()}]){
 let agentCalls=0,runnerCalls=0;const node={_id:'portal',type:'xray'},syncService={_getUsersForNode:async()=>users,addXrayUser:async()=>{agentCalls++;return false;}};
 const service=new TopologyUserResync({HyNode:{findById:()=>({lean:async()=>node})},syncService,preferBoundRunner:true,attempts:1,sleep:async()=>{},logger:{warn(){},info(){}}});
 const binding={nodeId:'portal',targetProfile:'xray-main',commandIds:{verify:randomUUID()},bootId:randomUUID()};
 const entries=[{binding,poison(){},invoke:async(command,request)=>{runnerCalls++;assert.equal(command,'restore-users');assert.deepEqual(request.users,users.map(u=>({id:u.xrayUuid,email:u.userId})));return {ok:true,code:'XRAY_USERS_RESTORED',userCount:users.length};}}];
 return {service,plan:{nodes:[{node:'portal',role:'portal'}]},entries,counts:()=>({agentCalls,runnerCalls})};
}
test('dedicated native nonempty VLESS assignments use held runner, never a missing or unfenced legacy agent',async()=>{
 const f=fixture();const r=await withTopologyReadinessScope(f.entries,async()=>{},()=>f.service.resyncPlan(f.plan));assert.equal(r.ok,true);assert.equal(r.userCount,1);assert.deepEqual(f.counts(),{agentCalls:0,runnerCalls:1});
});
test('preferred bound restoration refuses absent scope without legacy fallback',async()=>{
 const f=fixture();const r=await f.service.resyncPlan(f.plan);assert.equal(r.ok,false);assert.deepEqual(f.counts(),{agentCalls:0,runnerCalls:0});
});
test('empty dedicated assignment keeps existing zero-action semantics; production restricted empty guard stays closed',async()=>{
 const f=fixture([]);const r=await f.service.resyncPlan(f.plan);assert.equal(r.ok,true);assert.deepEqual(f.counts(),{agentCalls:0,runnerCalls:0});
 f.service.restrictedRunner=true;const q=await withTopologyReadinessScope(f.entries,async()=>{},()=>f.service.resyncPlan(f.plan));assert.equal(q.ok,false);assert.equal(f.counts().runnerCalls,0);
});
