'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const express=require('express'), mongoose=require('mongoose');
const {fixture}=require('../../modules/relay-l2tp/tests/helpers/installedEditMongoFixture');
const {routerForRebuild}=require('../../routes/cascadeRebuild');
const {createRebuildService}=require('../rebuildService');
const {generateXrayConfigWithApi}=require('../configGenerator');
const {randomUUID,createHash}=require('node:crypto');
const {bindProfileWire,pin}=require('./helpers/rebuildBoundProfileWire');

test('public rebuild actions use the DB component; read-only preview, user guard, explicit AutoDeploy, bridged DELETE retry',async t=>{
    const f=fixture();t.after(()=>f.stop());await f.start();
    const {HyNode:Node,CascadeLink:Link,RelayL2tpState:State}=f.models;
    const User=require('../../models/hyUserModel'), sync=require('../syncService');
    const nodes=[], files=new Map(), writes=[], stages=[];
    const group=new mongoose.Types.ObjectId();
    for(const [i,role] of ['portal','relay','bridge','bridge','bridge','portal','bridge'].entries()){
        const n={_id:new mongoose.Types.ObjectId(),name:`local-${i}`,cascadeRole:role,type:'xray',active:true,ip:`192.0.2.${i+1}`,port:21000+i,groups:[group],xray:{transport:'tcp',security:'none',apiPort:33000+i,inboundTag:'client',extraInbounds:[{inboundTag:'second',port:28000+i,transport:'tcp',security:'none'}]}};
        await Node.collection.insertOne(n);nodes.push(n);
    }
    const [portal,relay,exit,geo,replacement,x,y]=nodes, id=n=>String(n._id);
    relay.ssh={port:22,username:'root',password:'fixture-ssh-auth'};await Node.collection.updateOne({_id:relay._id},{$set:{ssh:relay.ssh}});
    const uuid=randomUUID();await User.collection.insertOne({userId:'local-user',enabled:true,xrayUuid:uuid,nodes:[],groups:[group]});
    const retainedGroup=new mongoose.Types.ObjectId();const groups=f.models.CascadeRouteGroup.collection;
    const oldGroup={_id:retainedGroup,name:'local-legacy',mode:'reverse',strategy:'priority-failover',paths:[{pathKey:'old',priority:1,enabled:true,linkIds:[new mongoose.Types.ObjectId()]}]}; await groups.insertOne(oldGroup);
    for(const n of nodes){files.set(id(n),{main:JSON.parse(generateXrayConfigWithApi(n,await sync._getUsersForNode(n))),bridge:null});}
    const tproxy={tag:`relay-l2tp-${retainedGroup}`,port:31081,protocol:'dokodemo-door',listen:'0.0.0.0',settings:{network:'tcp,udp',followRedirect:true},streamSettings:{sockopt:{tproxy:'tproxy'}}};
    files.get(id(relay)).main.inbounds.push(tproxy);
    const installed={node:relay._id,routeGroup:retainedGroup,status:'installed',desiredState:'installed',secretRevision:1,tproxyPort:tproxy.port};await State.collection.insertOne({...installed});
    let interrupt=null;
    const versions=new Map();
    const connect=node=>{const key=id(node),row=files.get(key),requireSupportedCore=async()=>versions.get(key)??'26.3.27';return {requireSupportedCore,
        async requireSupportedCoreIdentity(){const version=await requireSupportedCore();return {version,buildDigest:createHash('sha256').update(version).digest('hex')};},
        read:async p=>structuredClone(row[p]),close:async()=>{},stagePair:async()=>{stages.push(key)},putPair:async pair=>{if(interrupt===key)throw new Error('interrupted');for(const p of pair)row[p.profile]=structuredClone(p.config);writes.push(key);}};};
    const machine='b'.repeat(32);
    bindProfileWire(t.mock.method.bind(t.mock),relay.ip,machine,()=>connect(relay));
    const service=createRebuildService({env:{C3_REBUILD_ENABLED:'true',PANEL_DOMAIN:'fixture.invalid',ENCRYPTION_KEY:process.env.ENCRYPTION_KEY,
        C3_REBUILD_L2TP_INSTALL_ENABLED:'true',C3_REBUILD_L2TP_RELAY_ID:id(relay),C3_REBUILD_L2TP_RELAY_MACHINE_ID:machine,C3_REBUILD_L2TP_SSH_SHA256:pin},
        cache:{async invalidateAllSubscriptions(){}},connect});
    const csrf=randomUUID(),app=express();app.use(express.json());app.use((req,_res,next)=>{req.session={authenticated:true,panelCsrfToken:csrf};next()});app.use('/api/cascade',routerForRebuild({service,Link,Node}));
    const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise(resolve=>server.close(resolve)));
    const request=async(method,path,body,token=csrf)=>{const result=await fetch(`http://127.0.0.1:${server.address().port}/api/cascade${path}`,{method,headers:{'content-type':'application/json','x-csrf-token':token},...(body?{body:JSON.stringify(body)}:{})});return {status:result.status,body:await result.json()};};
    const ok=async(...args)=>{const r=await request(...args);assert.equal(r.status,200,r.body.error?.code);return r.body;};
    const edge=(a,b,n,other={})=>({portalNodeId:id(a),bridgeNodeId:id(b),tunnelPort:41000+n,name:`link-${n}`,priority:10*n,...other});
    const applied=async linkId=>(await Link.findById(linkId).select('+rebuildApplied').lean()).rebuildApplied;
    const make=async(b)=>{
        const result=await ok('POST','/links',b);
        assert.equal(await applied(result.linkId),null);
        return result;
    };
    assert.equal((await request('POST','/links',edge(portal,relay,1),'missing')).status,403);
    assert.equal(await Link.countDocuments(),0);
    const neighbor=await make(edge(x,y,9)), g=await make(edge(relay,geo,3,{geoRouting:{enabled:true,domains:['full:geo.invalid'],geoip:['ru']}}));
    const b=await make(edge(relay,exit,2)); assert.equal(writes.length,0);
    const pr=await make(edge(portal,relay,1,{autoDeploy:true,realityFingerprint:'random'}));assert.equal(pr.status,'awaiting_preview');assert.equal(pr.preview.allowed,true);assert.equal(stages.length,0);
    const deploy='/topology/deploy';
    const blind=await request('POST',deploy,{linkId:pr.linkId});assert.equal(blind.status,428);assert.equal(blind.body.error.code,'REBUILD_PREVIEW_REQUIRED');assert.equal(stages.length,0);
    versions.set(id(relay),'26.11.9');
    for(const [path,body] of [['/rebuild/preview',{linkId:pr.linkId}],[deploy,{linkId:pr.linkId,expectedPreview:pr.preview.previewId}]]){
        const start=f.commands.length;
        const refusal=await request('POST',path,body);
        assert.equal(refusal.status,409);
        assert.deepEqual(Object.keys(refusal.body).sort(),['error','fingerprintIssue']);
        assert.deepEqual(refusal.body.error,{code:'REBUILD_REALITY_FINGERPRINT_UNSUPPORTED'});
        const {allowed,...issue}=refusal.body.fingerprintIssue;
        assert.deepEqual(issue,{dialerId:id(relay),version:'26.11.9',fingerprint:'random'});
        assert.ok(allowed.includes('chrome'));assert.ok(!allowed.includes('random'));
        assert.equal(f.commands.slice(start).some(c=>['insert','update','delete','commitTransaction'].includes(c.name)&&c.collection!=='c3_rebuild_locks'),false);
        assert.equal(stages.length,0);assert.equal(writes.length,0);assert.equal(await applied(pr.linkId),null);
    }
    versions.delete(id(relay));
    await ok('POST',deploy,{linkId:pr.linkId,expectedPreview:pr.preview.previewId});assert.deepEqual([...new Set(writes)].sort(),[portal,relay,exit,geo].map(id).sort());
    assert.equal((await State.findOne({node:relay._id}).lean()).routingMode,'follow-relay');
    const r=files.get(id(relay));const socks=()=>r.main.inbounds.find(i=>i.tag==='rebuild-relay-ingress');const port=socks().port;
    const policy=()=>r.main.routing.rules.filter(i=>i.ruleTag?.startsWith('rebuild-policy-'));assert.ok(policy().every(i=>['client','second',socks().tag].every(tag=>i.inboundTag.includes(tag))));
    for(const tag of ['client','second'])assert.deepEqual(r.main.inbounds.find(i=>i.tag===tag).settings.clients.map(c=>c.id),[uuid]);
    const oldApplied=await applied(pr.linkId);
    assert.equal(oldApplied.port,41001);assert.equal(String(oldApplied.listener),id(portal));
    assert.equal(Object.hasOwn((await Link.findById(pr.linkId)).toJSON(),'rebuildApplied'),false);
    assert.equal((await Link.findById(pr.linkId).lean()).rebuildApplied,undefined);
    const before=writes.length;await ok('PUT',`/links/${pr.linkId}`,{name:'renamed',tunnelPort:41011,rebuildApplied:null});
    assert.equal(writes.length,before,'saved AutoDeploy metadata is not a new request');
    const edited=await Link.findById(pr.linkId).lean();assert.equal(edited.status,'pending');assert.equal(edited.tunnelPort,41011);
    assert.deepEqual(await applied(pr.linkId),oldApplied);
    const newer=await make(edge(relay,replacement,4,{priority:1,autoDeploy:true,interactivePreview:true}));assert.equal(newer.status,'awaiting_preview');assert.equal(writes.length,before);
    const preview=await ok('POST','/rebuild/preview',{linkId:newer.linkId});assert.equal(preview.allowed,true);assert.equal(writes.length,before);assert.equal(JSON.stringify(preview).includes(uuid),false);
    const changed=await request('POST',deploy,{linkId:newer.linkId,expectedPreview:'1'.repeat(64)});assert.equal(changed.body.error.code,'REBUILD_PREVIEW_CHANGED');assert.deepEqual(changed.body.preview,preview);assert.equal(writes.length,before);
    assert.equal(await applied(newer.linkId),null);assert.deepEqual(await applied(pr.linkId),oldApplied);
    await ok('POST','/topology/deploy',{linkId:newer.linkId,expectedPreview:preview.previewId});assert.equal(socks().port,port);assert.equal(policy().at(-1).outboundTag,`rebuild-rp-egress-${newer.linkId.slice(-8)}`);
    assert.equal((await applied(pr.linkId)).port,41011);
    const ticket=async(linkId,remove=false)=>({expectedPreview:(await ok('POST','/rebuild/preview',{linkId,remove})).previewId});
    const deletedPath=`/links/${b.linkId}`,priorStages=stages.length;assert.equal((await request('DELETE',deletedPath)).status,428);assert.notEqual((await Link.findById(b.linkId)).rebuildDelete,true);assert.equal(stages.length,priorStages);
    assert.equal((await request('DELETE',deletedPath,await ticket(b.linkId))).body.error.code,'REBUILD_PREVIEW_CHANGED');
    await ok('DELETE',deletedPath,await ticket(b.linkId,true));assert.equal(socks().port,port);assert.ok(!files.get(id(exit)).bridge.reverse);
    const prior=await ticket(pr.linkId);files.get(id(portal)).main.inbounds.find(i=>i.tag==='client').port++;const stageCount=stages.length;const refusal=await request('POST',deploy,{linkId:pr.linkId,...prior});assert.equal(refusal.body.error.code,'REBUILD_CLIENT_CHANGE');assert.equal(stages.length,stageCount);files.get(id(portal)).main.inbounds.find(i=>i.tag==='client').port--;
    interrupt=id(relay);assert.equal((await request('DELETE',`/links/${pr.linkId}`,await ticket(pr.linkId,true))).status,409);assert.equal((await Link.findById(pr.linkId)).rebuildDelete,true);interrupt=null;
    const retried=await ok('POST',deploy,{linkId:pr.linkId,...await ticket(pr.linkId)});assert.deepEqual(retried.nodes.map(n=>n.nodeId).sort(),[portal,relay,replacement,geo].map(id).sort());assert.ok(!files.get(id(portal)).main.reverse);assert.equal(files.get(id(portal)).main.outbounds[0].protocol,'blackhole');
    assert.equal(await Link.exists({_id:pr.linkId}),null);assert.ok(await Link.exists({_id:neighbor.linkId}));assert.ok(await Link.exists({_id:g.linkId}));assert.ok(!writes.includes(id(x))&&!writes.includes(id(y)));assert.deepEqual(await groups.findOne({_id:retainedGroup}),oldGroup);
});
