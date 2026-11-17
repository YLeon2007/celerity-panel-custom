'use strict';
process.env.PANEL_DOMAIN ||= 'test.infograd.online';
process.env.ACME_EMAIL ||= 'test@example.invalid';
process.env.ENCRYPTION_KEY ||= '0'.repeat(64);
process.env.SESSION_SECRET ||= 'local-test-secret';
const test = require('node:test'); const assert = require('node:assert/strict'); const express = require('express');
test.after(() => require('../../../services/sshPoolService').closeAll());
const { createTopologyTestActivationRouter } = require('../../../routes/topologyTestActivation');
const env = { PANEL_DOMAIN: 'test.infograd.online', L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_STARTUP_MODE: 'dedicated-runtime-v1' };
const next = (req,res,next) => next(); const auth = Object.assign(next, { requireScope: scope => { assert.ok(['nodes:write','nodes:read'].includes(scope)); return next; } });
async function call(router, fn, endpoint='/activate') {
    const app = express(); app.use(express.json()); app.use(router);
    const server = app.listen(0, '127.0.0.1'); await new Promise(r => server.once('listening', r));
    try { return await fn(async body => {
        const r = await fetch('http://127.0.0.1:' + server.address().port + endpoint, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body) });
        return { status:r.status, text:await r.text() };
    }); } finally { await new Promise(r => server.close(r)); }
}
test('supported activation HTTP uses the active runtime once and rejects request inventory', async () => {
    let enrolled=0;
    const router=createTopologyTestActivationRouter({ env, auth, csrf:next, activeHostProvider:{ getActiveHost:()=>({readBusinessReentryRestriction:async()=>({blocked:false}),beginTestActivation(){if (!enrolled) enrolled++;return {status:'active'};}})} });
    await call(router, async request => {
        assert.equal((await request({nodes:[]})).status,400); assert.equal(enrolled,0);
        for(let i=0;i<2;i++){const r=await request({});assert.equal(r.status,200);assert.equal(r.text.includes('MUST_NOT_LEAK'),false);}
        assert.equal(enrolled,1);
    });
});
test('a failed/unknown activation is retained instead of replaying remote writes',async()=>{
    let calls=0;
    const router=createTopologyTestActivationRouter({env,auth,csrf:next,activeHostProvider:{getActiveHost:()=>({readBusinessReentryRestriction:async()=>({blocked:false}),beginTestActivation(){if (!calls) calls++;return {status:'retained'};}})}});
    await call(router,async request=>{for(let i=0;i<2;i++){const r=await request({});assert.equal(r.status,409);assert.equal(r.text.includes('private-secret'),false);}assert.equal(calls,1);});
});
test('production and legacy TEST expose no activation endpoint',async()=>{
    for(const e of [{...env,PANEL_DOMAIN:'lm1.infograd.online'},{...env,TOPOLOGY_TEST_STARTUP_MODE:undefined}])await call(createTopologyTestActivationRouter({env:e}),async request=>assert.equal((await request({})).status,404));
});
test('actual panel host delays consumers until enrollment, and shutdown joins enrollment without late start',async()=>{
    const {fixture,moduleEntry}=require('./cascadeAnyOrderRuntimeFixture');
    for(const stopEarly of [false,true]){
        const f=fixture({deploymentEnv:env});let resolve,calls=0;
        const host=f.host({moduleEntry:{...moduleEntry,registerModels:()=>f.models,createTopologyDeploymentService(options){const service=moduleEntry.createTopologyDeploymentService(options);service.enrollTestOwners=options=>{calls++;return new Promise(r=>{resolve=v=>{options.onReconciled(v);r(v);};});};return service;}}});
        assert.equal(host.start().activationRequired,true);assert.equal(f.timer.callbacks.size,0);
        const pending=host.enrollTestOwners();await new Promise(r=>setImmediate(r));assert.equal(calls,1);
        const stopping=stopEarly?host.stop():undefined;
        resolve({status:'enrolled',nodes:[]});await pending;
        if(stopEarly){await stopping;assert.equal(f.timer.callbacks.size,0);}else{assert.ok(f.timer.callbacks.size>0);await host.stop();assert.equal(f.timer.callbacks.size,0);}
    }
});
test('ordinary TEST handback API admits only fixed inventory; business reentry refuses before physical activation',async()=>{
 let handbacks=0,activations=0;const host={beginTestHandback(){handbacks++;return{status:'handing_back'};},readBusinessReentryRestriction:async()=>({blocked:true,code:'TOPOLOGY_BUSINESS_REENTRY_BLOCKED'}),beginTestActivation(){activations++;throw Error('must not dispatch');}};
 const router=createTopologyTestActivationRouter({env,auth,csrf:next,activeHostProvider:{getActiveHost:()=>host}});
 await call(router,async request=>{assert.equal((await request({nodes:[]})).status,400);assert.equal((await request({})).status,202);},'/handback');
 await call(router,async request=>{const r=await request({});assert.equal(r.status,409);assert.equal(JSON.parse(r.text).code,'TOPOLOGY_BUSINESS_REENTRY_BLOCKED');});
 assert.equal(handbacks,1);assert.equal(activations,0);
});
test('same TEST host joins consumer drain before handback; duplicate intents never repeat restoration',async()=>{
 const {fixture,moduleEntry}=require('./cascadeAnyOrderRuntimeFixture');const f=fixture({deploymentEnv:env});let handbacks=0;
 const host=f.host({moduleEntry:{...moduleEntry,registerModels:()=>f.models,createTopologyDeploymentService(options){const service=moduleEntry.createTopologyDeploymentService(options);
  service.enrollTestOwners=async options=>{const r={status:'enrolled',nodes:[]};options.onReconciled(r);return r;};service.inspectTestOwnerHandback=async()=>[];
  service.handbackTestOwners=async()=>{assert.equal(f.timer.callbacks.size,0);handbacks++;return{status:'handed-back',nodes:[]};};return service;}}});
 await host.enrollTestOwners();assert.ok(f.timer.callbacks.size>0);host.beginTestHandback();host.beginTestHandback();
 for(let i=0;i<20&&(await host.readTestActivationStatus()).status==='handing_back';i++)await new Promise(r=>setImmediate(r));
 assert.equal((await host.readTestActivationStatus()).status,'handed-back');assert.equal(handbacks,1);assert.equal(f.timer.callbacks.size,0);
});
