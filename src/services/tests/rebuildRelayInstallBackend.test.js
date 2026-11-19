'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createRebuildService}=require('../rebuildService');
const {checkRelayReadiness}=require('../rebuildRelayReadiness');
const id='a'.repeat(24);
const {canInstallRelay}=require('../rebuildRelayAuthorization');
test('an installation grant is restricted to the pinned relay and never grants legacy operations',()=>{
 const grant={C3_REBUILD_ENABLED:'true',C3_REBUILD_L2TP_INSTALL_ENABLED:'true',C3_REBUILD_L2TP_RELAY_ID:id,C3_REBUILD_L2TP_RELAY_MACHINE_ID:'b'.repeat(32)};
 assert.equal(canInstallRelay(grant,id),true);
 for(const v of [{C3_REBUILD_L2TP_RELAY_ID:'c'.repeat(24)}, {C3_REBUILD_L2TP_RELAY_MACHINE_ID:''},
  {C3_REBUILD_L2TP_RELAY_MACHINE_ID:'b'.repeat(32)+'\n'}, {C3_REBUILD_L2TP_INSTALL_ENABLED:true},
  {C3_REBUILD_ENABLED:'false'},{TOPOLOGY_TEST_EXECUTION_ENABLED:'true'}])assert.equal(canInstallRelay({...grant,...v},id),false);
});
const deps={Link:{}, Node:{}, State:{}, cache:{}, sync:{},locks:{run:async()=>assert.fail('no lock before authorization')}};
test('default concrete install backend is fail-closed outside opted-in rebuild',async()=>{
 for(const env of [{},{C3_REBUILD_ENABLED:'true'}, {C3_REBUILD_ENABLED:'true',C3_REBUILD_L2TP_INSTALL_ENABLED:'true',L2TP_EXECUTION_ENABLED:'true'}]){
   const service=createRebuildService({...deps,env});assert.equal(typeof service.installRelay,'function');await assert.rejects(()=>service.installRelay(id),{code:'REBUILD_L2TP_INSTALL_DISABLED'});
 }
});
test('the actual panel handler with its default service factory refuses missing opt-in', async t=>{
 t.after(()=>require.cache[require.resolve('../sshPoolService')]?.exports.closeAll());
 const key='C3_REBUILD_L2TP_INSTALL_ENABLED';const previous=process.env[key];delete process.env[key];
 t.after(()=>{if(previous===undefined)delete process.env[key];else process.env[key]=previous;});
 const handler=require('../../routes/panel/rebuildRelayInstall');
 const response={ status(value){this.statusCode=value;return this;}, json(value){this.body=value;return this;} };
 await handler({params:{id},query:{},body:{}},response);
 assert.equal(response.statusCode,409);
 assert.match(response.body.error.code,/^REBUILD_/);
});
test('live-format readback distinguishes a device from a registered driver and respects unit masks',async()=>{
 const ssh={exec:async()=>({code:0,stdout:'ppp=0\nxl2tpd.service=masked\nstrongswan-starter.service=masked\n'})};
 assert.deepEqual(await checkRelayReadiness(ssh),{ppp:false,masked:true,unitsLoaded:false});
 ssh.exec=async()=>({code:0,stdout:'unexpected'});await assert.rejects(()=>checkRelayReadiness(ssh),{code:'REBUILD_L2TP_PREFLIGHT_UNKNOWN'});
});
