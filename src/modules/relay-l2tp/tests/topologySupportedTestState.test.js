'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {initializeDedicatedTestState}=require('../../../../scripts/test-topology-owner');
function fixture({state=null,occupied=false}={}){
 let creates=0;const query=value=>({session(){return this;},setOptions(){return this;},read(){return this;},readConcern(){return this;},maxTimeMS(){return this;},lean:async()=>value});
 const empty={findOne:()=>query(occupied?{_id:'occupied'}:null)};
 const State={db:{transaction:async f=>f({})},findById:()=>query(state),async create(rows){creates++;state=rows[0];return rows;}};
 return {models:{CascadeTopologyState:State,CascadeLink:empty,CascadeRouteGroup:empty,RelayL2tpState:empty,TopologyOperation:empty,TopologyExecutionBinding:empty,NodeOperationLock:empty,RemoteAdmission:empty,L2tpOperation:empty,TopologyCreateIntent:empty,TopologyIntentQueueState:empty},get creates(){return creates;},get state(){return state;}};
}
test('dedicated empty TEST initializes admission singleton, never ready',async()=>{
 assert.equal(typeof initializeDedicatedTestState,'function');const f=fixture();let checks=0;await initializeDedicatedTestState(f.models,async()=>checks++);assert.equal(f.creates,1);assert.equal(f.state.topologyAdmissionCount,0);assert.equal(f.state.remoteAdmissionCount,0);assert.equal(f.state.revision,0);assert.equal(f.state.ready,undefined);assert.ok(checks>=2);
});
test('dedicated state never infers zero from occupied DB or existing incomplete state',async()=>{
 assert.equal(typeof initializeDedicatedTestState,'function');for(const options of [{occupied:true},{state:{_id:'singleton',revision:0}}]){const f=fixture(options);await assert.rejects(initializeDedicatedTestState(f.models,async()=>{}));assert.equal(f.creates,0);}
});
test('TEST handback restores before real transfer and retains alias/business history under the same authority', async () => {
 const {inspectTestOwnerHandback,handbackTestOwners}=require('../../../../scripts/test-topology-owner');
 const {TopologyConfigTransfer}=require('../../../services/topologyConfigTransfer');
 const {TEST_TOPOLOGY_EXECUTION_CONTEXT:context}=require('../domain/topologyExecutionContext');
 const {randomUUID}=require('node:crypto'),{isDeepStrictEqual:same}=require('node:util');
 const env={PANEL_DOMAIN:context.hostIdentity,L2TP_EXECUTION_ENABLED:'true',L2TP_MIGRATIONS_ENABLED:'true',TOPOLOGY_TEST_EXECUTION_ENABLED:'true',TOPOLOGY_TEST_STARTUP_MODE:'dedicated-runtime-v1'};
 const events=[],rows=[],aliases=[];
 const query=value=>({read(){return this;},readConcern(){return this;},maxTimeMS(){return this;},lean:async()=>structuredClone(value)});
 const match=(row,filter)=>Object.entries(filter).every(([k,v])=>same(row[k],v));
 const Model={collection:{indexes:async()=>[{key:{node:1,profile:1},unique:true}]},db:{transaction:async work=>work({})},
  find:filter=>query(rows.filter(r=>match(r,filter))),findOne:filter=>query(rows.find(r=>match(r,filter))??null),
  create:async list=>rows.push(...structuredClone(list)),async findOneAndUpdate(filter,update){const row=rows.find(r=>match(r,filter));if(!row)return null;Object.assign(row,structuredClone(update.$set));for(const k of Object.keys(update.$unset||{}))delete row[k];return row;}};
 const snapshot={configSha256:'3'.repeat(64),unitSha256:'4'.repeat(64),serviceActive:'active',serviceEnabled:'enabled'};
 let restored=true;const maintenanceId=randomUUID();
 // Remote IO only is modeled. Ownership transfer and its guarded DB protocol are real.
 const lifecycle={executionContext:context,run:async work=>work(),withVerifiedMaintenance:async({binding},work)=>{
  assert.equal(restored,true);events.push(binding.action);return work({status:'verified',authority:'external-maintenance-v1',binding,
   proofId:randomUUID(),maintenanceId,maintenance:'held',allWriters:'drained',oldBackend:{processTree:'stopped',dispatch:'disabled',instanceId:'modeled',pid:42,processStartTime:'modeled'},readback:{source:'node-readback',...snapshot}});}};
 const transfer=new TopologyConfigTransfer({executionContext:context,TopologyConfigOwner:Model,withVerifiedMaintenance:lifecycle.withVerifiedMaintenance});
 const node='111111111111111111111111',profile='xray-main',nodeIdentity={machineId:'1'.repeat(32),sshHostKeySha256:'2'.repeat(64)};
 const initial=await transfer.initializeClassic({node,profile,nodeIdentity});
 const adopted=await transfer.adopt({node,profile,generation:initial.generation,proofRef:'dedicated-'+maintenanceId});
 Object.assign(rows[0],{lastSettledOperation:'preserved-business-history',lastSettledRevision:12});
 aliases.push({nodeId:node,targetProfile:profile,ownerGeneration:adopted.generation,maintenanceId});
 const empty={findOne:()=>query(null)},models={TopologyConfigOwner:Model,TopologyExecutionEnrollment:{find:()=>query(aliases)},
  CascadeTopologyState:{findById:()=>query({remoteAdmissionCount:0,topologyAdmissionCount:0})},NodeOperationLock:empty,RemoteAdmission:empty,TopologyOperation:empty,TopologyCreateIntent:empty};
 const expected=await inspectTestOwnerHandback({env,models}),before=structuredClone(aliases);restored=false;
 const authority={async restoreClassicSnapshots(pins){assert.equal(pins[0].nodeId,node);events.push('restore');restored=true;},async releaseClassicSnapshots(){assert.equal(rows[0].owner,'classic');events.push('release');}};
 assert.equal((await handbackTestOwners({env,models,lifecycle,authority,expected})).status,'handed-back');
 assert.ok(events.indexOf('restore')<events.indexOf('handback'));assert.equal(events.at(-1),'release');
 assert.equal(rows[0].lastSettledOperation,'preserved-business-history');assert.deepEqual(aliases,before);
 assert.equal((await require('../services/topologyReentryPolicy').readOwnerReentryRestriction(rows[0])).code,'TOPOLOGY_BUSINESS_REENTRY_BLOCKED');
});
test('existing callback honors inactive/disabled systemctl exits without restarting an originally stopped service', () => {
 const fs=require('node:fs'),{spawnSync}=require('node:child_process');
 const source=fs.readFileSync(require.resolve('../../../../scripts/test-topology-owner'),'utf8');
 const line=source.split('\n').find(line=>line.includes('const python = `'));
 const expression=line.slice(line.indexOf('= ')+2).trim().replace(/;$/,'');
 const python=Function('payload','return '+expression)({profile:'xray-main',expected:{serviceActive:'inactive',serviceEnabled:'disabled'},backupId:null,write:true});
 const block=python.slice(python.indexOf('try:\n')+5,python.indexOf('except BaseException:')).split('\n').map(line=>line.startsWith(' ')?line.slice(1):line).join('\n');
 // Only the command-adapter contract is substituted. Execute the actual
 // generated callback verification block, never a real systemctl mutation.
 const check=`import json,sys,types\nblock=json.loads(sys.stdin.read())\ncalls=[]\ndef run(args,**kw):\n calls.append(args)\n action=args[1]\n return types.SimpleNamespace(returncode=3 if action=='is-active' else 1 if action=='is-enabled' else 0,stdout='inactive\\n' if action=='is-active' else 'disabled\\n' if action=='is-enabled' else '')\nns={'subprocess':types.SimpleNamespace(run=run,DEVNULL=-3),'service':'xray','expected':{'serviceActive':'inactive','serviceEnabled':'disabled','configSha256':'original'},'cfg':types.SimpleNamespace(read_bytes=lambda:b'original'),'sha':lambda b:'original'}\nexec(block,ns)\nassert calls[0]==['systemctl','stop','xray']\nprint('exact inactive/disabled callback contract PASS')\n`;
 const result=spawnSync('python3',['-I','-B','-c',check],{input:JSON.stringify(block),encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/callback contract PASS/);
});
