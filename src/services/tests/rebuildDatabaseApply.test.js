'use strict';
// Real Mongo replica set, real classic users and compiler, real Xray parser.
// Only the remote filesystem/service endpoints are simulated.
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),fs=require('node:fs/promises');
const {spawnSync}=require('node:child_process');const mongoose=require('mongoose');
const {fixture}=require('../../modules/relay-l2tp/tests/helpers/installedEditMongoFixture');
const {createRebuildService}=require('../rebuildService');const {generateXrayConfigWithApi}=require('../configGenerator');
const {randomUUID}=require('node:crypto');
test('database rebuild: reverse graph, actual parser, protected preview, failed middle DELETE and fresh apply',async t=>{
 const f=fixture();t.after(()=>f.stop());await f.start();const {HyNode:Node,CascadeLink:Link}=f.models;const User=require('../../models/hyUserModel');const sync=require('../syncService');
 const n=async(role,index)=>{const node={_id:new mongoose.Types.ObjectId(),name:'fixture-'+index,cascadeRole:role,type:'xray',active:true,ip:'127.0.0.'+index,port:21000+index,xray:{transport:'tcp',security:'none',apiPort:30000+index,inboundTag:'client'}};await Node.collection.insertOne(node);return node;};const nodes=[await n('portal',1),await n('relay',2),await n('bridge',3),await n('bridge',4)];
 const [p,r,b,geo]=nodes;const user={userId:'fixture',enabled:true,xrayUuid:randomUUID(),nodes:[p._id,r._id]};await User.collection.insertOne(user);
 const link=async(a,b,n,opts={})=>Link.create({name:'link'+n,portalNode:a._id,bridgeNode:b._id,tunnelUuid:randomUUID(),tunnelPort:40000+n,mode:'reverse',...opts});
 const gb=await link(r,geo,4,{geoRouting:{enabled:true,domains:['full:example.invalid'],geoip:['private']}});const rb=await link(r,b,2);const pr=await link(p,r,1);const store=new Map();const traces=[];let interrupt;
 for(const node of nodes){const users=await sync._getUsersForNode(node);store.set(String(node._id),{main:JSON.parse(generateXrayConfigWithApi(node,users)),bridge:null});}
 const service=createRebuildService({env:{C3_REBUILD_ENABLED:'true',PANEL_DOMAIN:'fixture.invalid'},cache:{async invalidateAllSubscriptions(){}},connect(node){const key=String(node._id),row=store.get(key);return {async read(profile){return structuredClone(row[profile]);},async close(){},async stagePair(pair){for(const {config,profile} of pair){const filename=path.join(process.env.TMPDIR,key+profile+'.json');await fs.writeFile(filename,JSON.stringify(config),{mode:0o600});const res=spawnSync(process.env.C3_XRAY,['run','-test','-config',filename],{env:{...process.env,XRAY_LOCATION_ASSET:path.dirname(process.env.C3_XRAY)},stdio:'ignore'});assert.equal(res.status,0,'actual xray parser refused a generated '+profile+' candidate');}},async putPair(pair){if(interrupt===key)throw Error('simulated network loss');for(const v of pair)row[v.profile]=structuredClone(v.config);traces.push(key);}};}});
 const anchor=String(rb._id);assert.equal((await service.execute({linkId:anchor,preview:true})).allowed,true);assert.equal(traces.length,0);
 await service.execute({linkId:anchor});assert.equal(traces.length,4);
 const prKey=String(p._id);store.get(prKey).main.inbounds.find(i=>i.tag==='client').port++;
 await assert.rejects(service.execute({linkId:anchor}),{code:'REBUILD_CLIENT_CHANGE'});assert.equal(traces.length,4);store.get(prKey).main.inbounds.find(i=>i.tag==='client').port--;
 interrupt=String(r._id);await assert.rejects(service.execute({linkId:String(pr._id),remove:true}),/simulated network loss/);assert.equal((await Link.findById(pr._id)).rebuildDelete,true);
 interrupt=null;const repaired=await service.execute({linkId:String(pr._id)});assert.equal(repaired.nodes.length,4);assert.equal(await Link.findById(pr._id),null);assert.equal(store.get(prKey).main.outbounds[0].protocol,'blackhole');assert.equal(store.get(prKey).main.reverse,undefined);assert.ok(await Link.exists({_id:gb._id}));
});
