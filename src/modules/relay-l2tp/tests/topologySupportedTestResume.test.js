'use strict';
process.env.PANEL_DOMAIN ||= 'test.infograd.online';process.env.ACME_EMAIL ||= 'test@example.invalid';process.env.ENCRYPTION_KEY ||= '0'.repeat(64);process.env.SESSION_SECRET ||= 'test-secret';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const env={PANEL_DOMAIN:'test.infograd.online',L2TP_EXECUTION_ENABLED:'true',L2TP_MIGRATIONS_ENABLED:'true',TOPOLOGY_TEST_EXECUTION_ENABLED:'true',TOPOLOGY_TEST_STARTUP_MODE:'dedicated-runtime-v1'};
test.after(()=>require('../../../services/sshPoolService').closeAll());
test('real host: bounded admission, separate pending status, resume existing once, joined stop',async()=>{
 const {fixture,moduleEntry}=require('./cascadeAnyOrderRuntimeFixture');const f=fixture({deploymentEnv:env});let resolve,calls=0,options;
 const host=f.host({moduleEntry:{...moduleEntry,registerModels:()=>f.models,createTopologyDeploymentService(o){const s=moduleEntry.createTopologyDeploymentService(o);s.enrollTestOwners=x=>{options=x;calls++;return new Promise(r=>resolve=v=>{x.onReconciled(v);r(v);});};s.readTestEnrollment=async()=>({status:'enrolled',nodes:[]});return s;}}});
 host.start();assert.equal(typeof host.beginTestActivation,'function');
 assert.equal(host.beginTestActivation({resumeOnly:true}).status,'reconciling');
 await new Promise(r=>setImmediate(r));assert.equal(calls,1);assert.equal(options.resumeOnly,true);
 assert.equal((await host.readTestActivationStatus()).status,'reconciling');assert.equal(f.timer.callbacks.size,0);
 host.beginTestActivation({resumeOnly:true});assert.equal(calls,1);
 resolve({status:'enrolled',nodes:[]});await host.enrollTestOwners({resumeOnly:true});
 assert.equal((await host.readTestActivationStatus()).status,'active');assert.ok(f.timer.callbacks.size>0);await host.stop();assert.equal(f.timer.callbacks.size,0);
});
test('partial consumer start fences both lifecycles and retains activation without replay',async()=>{
 const {fixture,moduleEntry}=require('./cascadeAnyOrderRuntimeFixture');const f=fixture({deploymentEnv:env});let calls=0,executionStarts=0,executionStops=0,recoveryStops=0;
 const host=f.host({createExecutionRuntime:()=>({runtime:{stateManagementService:{}},start(){executionStarts++;},async stop(){executionStops++;return {};}}),createTopologyRecoveryLifecycle:()=>({start(){throw Error('PRIVATE_FAILURE');},async stop(){recoveryStops++;return {};}}),moduleEntry:{...moduleEntry,registerModels:()=>f.models,createTopologyDeploymentService(o){const s=moduleEntry.createTopologyDeploymentService(o);s.enrollTestOwners=async({onReconciled})=>{calls++;const r={status:'enrolled',nodes:[]};onReconciled(r);return r;};return s;}}});
 host.start();host.beginTestActivation({resumeOnly:true});await assert.rejects(host.enrollTestOwners());assert.equal(executionStarts,1);assert.ok(executionStops>0&&recoveryStops>0);assert.equal((await host.readTestActivationStatus()).status,'retained');host.beginTestActivation({resumeOnly:true});await assert.rejects(host.enrollTestOwners());assert.equal(calls,1);await host.stop();
});
test('stop fences both schedulers before joining pending reconciliation, with no late start',async()=>{
 const {fixture,moduleEntry}=require('./cascadeAnyOrderRuntimeFixture');const f=fixture({deploymentEnv:env});let resolve,stops=0,starts=0;
 const host=f.host({createExecutionRuntime:()=>({runtime:{stateManagementService:{}},start(){starts++;},async stop(){stops++;return {};}}),createTopologyRecoveryLifecycle:()=>({start(){starts++;},async stop(){stops++;return {};}}),moduleEntry:{...moduleEntry,registerModels:()=>f.models,createTopologyDeploymentService(o){const s=moduleEntry.createTopologyDeploymentService(o);s.enrollTestOwners=({onReconciled})=>new Promise(r=>resolve=()=>{const result={status:'enrolled',nodes:[]};onReconciled(result);r(result);});return s;}}});
 host.start();const pending=host.enrollTestOwners({resumeOnly:true});await new Promise(r=>setImmediate(r));const stopped=host.stop();assert.equal(stops,2);resolve();await pending;await stopped;assert.equal(starts,0);assert.equal((await host.readTestActivationStatus()).status,'stopped');
});
test('HTTP ack and status do not await slow enrollment or leak private errors',async()=>{
 const {createTopologyTestActivationRouter}=require('../../../routes/topologyTestActivation');let state='reconciling',calls=0;
 const next=(req,res,next)=>next(),auth=Object.assign(next,{requireScope:()=>next});
 const app=express();app.use(express.json());app.use(createTopologyTestActivationRouter({env,auth,csrf:next,activeHostProvider:{getActiveHost:()=>({readBusinessReentryRestriction:async()=>({blocked:false}),beginTestActivation(){calls++;return {status:state};},async readTestActivationStatus(){return {status:state};}})}}));
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
 try{const url='http://127.0.0.1:'+server.address().port;const r=await fetch(url+'/resume',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});assert.equal(r.status,202);assert.equal((await r.json()).statusUrl,'/api/cascade/topology-test/status');state='active';assert.equal((await(await fetch(url+'/status')).json()).status,'active');assert.equal(calls,1);}finally{await new Promise(r=>server.close(r));}
});
