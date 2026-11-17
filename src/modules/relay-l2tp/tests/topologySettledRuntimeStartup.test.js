'use strict';
process.env.PANEL_DOMAIN ||= 'test.infograd.online';process.env.ACME_EMAIL ||= 'test@example.invalid';process.env.ENCRYPTION_KEY ||= '0'.repeat(64);process.env.SESSION_SECRET ||= 'test-secret';
const test=require('node:test'),assert=require('node:assert/strict');
const env={PANEL_DOMAIN:'test.infograd.online',L2TP_EXECUTION_ENABLED:'true',L2TP_MIGRATIONS_ENABLED:'true',TOPOLOGY_TEST_EXECUTION_ENABLED:'true',TOPOLOGY_TEST_STARTUP_MODE:'dedicated-runtime-v1'};
test.after(()=>require('../../../services/sshPoolService').closeAll());
test('settled-runtime startup selects only strict read-only success, never binding/verify/bootstrap recovery',async()=>{
 const {fixture,moduleEntry}=require('./cascadeAnyOrderRuntimeFixture');const f=fixture({deploymentEnv:env});let calls=0;
 const host=f.host({moduleEntry:{...moduleEntry,registerModels:()=>f.models,createTopologyDeploymentService(o){
  const s=moduleEntry.createTopologyDeploymentService(o);
  s.resumeSettledRuntime=async(id,ready)=>{calls++;const r={operationId:id,status:'succeeded',claimed:false,readOnly:true};await ready(r);return r;};
  for(const name of ['resumeRetainedVerification','resumeBindingReservations','resumeBootstrapPreparation','resumeSettledBootstrap'])s[name]=()=>{throw Error('forbidden recovery entry');};return s;
 }}});
 host.start();assert.equal(host.beginBootstrapContinuation('1'.repeat(24),'runtime').status,'reconciling');
 await new Promise(r=>setImmediate(r));assert.equal(calls,1);assert.equal((await host.readTestActivationStatus()).status,'active');
 await host.stop();assert.equal(f.timer.callbacks.size,0);
});
