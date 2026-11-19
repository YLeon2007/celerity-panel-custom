'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { runFreshRelayInstall } = require('../rebuildRelayInstall');
const id = 'aaaaaaaaaaaaaaaaaaaaaaaa';
const machineId = 'b'.repeat(32);
function fixture(change={}) {
    const events=[];
    const deps={
        authorize:()=>true, machineId, lock:fn=>fn(async()=>events.push('lock-verify')),
        inventory:async()=>({eligible:true,pristine:true}),
        connect:async()=>({ preflight:async()=>({ppp:true,masked:false,machineId}), close:async()=>events.push('close'),
            install:async()=>events.push('install'), verify:async()=>true }),
        prepare:async()=>({backupId:'fixture-backup'}), reserve:async()=>events.push('reserve'),
        verifyReservation:async()=>{}, finish:async()=>events.push('finish'), ...change
    };
    return {events,run:()=>runFreshRelayInstall(id,deps)};
}
test('install is disabled outside the explicitly authorized rebuild',async()=>{
    const f=fixture({authorize:()=>false});await assert.rejects(f.run,{code:'REBUILD_L2TP_INSTALL_DISABLED'});assert.deepEqual(f.events,[]);
});
test('refuses non-pristine or non-relay before connecting',async()=>{
    for(const inv of [{eligible:false,pristine:true},{eligible:true,pristine:false}]){
        const f=fixture({inventory:async()=>inv,connect:async()=>assert.fail('unexpected connect')});await assert.rejects(f.run,{code:'REBUILD_L2TP_NOT_FRESH_RELAY'});
    }
});
test('masked service and unregistered PPP driver block every write',async()=>{
    for(const pre of [{ppp:true,masked:true},{ppp:false,masked:false}]){
        const f=fixture({connect:async()=>({preflight:async()=>({...pre,machineId}),close:async()=>{}})});await assert.rejects(f.run,{code:'REBUILD_L2TP_HOST_NOT_READY'});assert.ok(!f.events.includes('reserve'));
    }
});
test('missing identity or invalid backup id fails before reservation',async()=>{
    const badHost=fixture({connect:async()=>({preflight:async()=>({ppp:true,masked:false}),close:async()=>{}})});
    await assert.rejects(badHost.run,{code:'REBUILD_L2TP_INSTALL_IDENTITY_MISMATCH'});assert.ok(!badHost.events.includes('reserve'));
    const badPlan=fixture({prepare:async()=>({backupId:'../foreign'})});
    await assert.rejects(badPlan.run,{code:'REBUILD_L2TP_INSTALL_PLAN_INVALID'});assert.ok(!badPlan.events.includes('reserve'));
});
test('installed state follows reservation, install and positive verification',async()=>{
    const ok=fixture();await ok.run();assert.deepEqual(ok.events.filter(k=>['reserve','install','finish','close'].includes(k)),['reserve','install','finish','close']);
});
