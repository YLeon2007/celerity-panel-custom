'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {fork} = require('node:child_process');
const {randomUUID,createHash} = require('node:crypto');
const mongoose = require('mongoose');
const {fixture} = require('../../modules/relay-l2tp/tests/helpers/installedEditMongoFixture');
const {generateXrayConfigWithApi} = require('../configGenerator');
const cryptoService = require('../cryptoService');
const {pin}=require('./helpers/rebuildBoundProfileWire');

// Only a synthetic inventory, an owned replica set, a loopback HTTP listener and
// disposable profile files. Never accepts a panel URL, node address or credential.
test('rebuild acceptance through the actual index.js HTTP mounts', {timeout:240000}, async t => {
    const f = fixture(); let panel, exited;
    const dir = fs.mkdtempSync(path.join(process.env.TMPDIR,'panel-'));
    t.after(async () => {
        try { if (panel && panel.exitCode === null && !panel.signalCode) { panel.kill(); const timer=setTimeout(()=>panel.kill('SIGKILL'),5000); try { await exited; } finally { clearTimeout(timer); } } }
        finally { try { await f.stop(); } finally { fs.rmSync(dir,{recursive:true,force:true}); } }
    });
    await f.start(); f.guarded();
    const {HyNode:Node, CascadeLink:Link, RelayL2tpState:State, CascadeRouteGroup:Group} = f.models;
    const User = require('../../models/hyUserModel');
    const {port:dbPort,database,replicaSet} = f.lifecycle;
    const env = Object.fromEntries(['PATH','HOME','TMPDIR','NODE_PATH','SESSION_SECRET','ENCRYPTION_KEY','C3_XRAY','C3_XRAY_26_11_9'].map(k=>[k,process.env[k]]));
    Object.assign(env,{NODE_ENV:'test',LOG_LEVEL:'error',PORT:'0',USE_CADDY:'true',C3_REBUILD_ENABLED:'true',PANEL_DOMAIN:'fixture.invalid',ACME_EMAIL:'fixture@fixture.invalid',MONGO_URI:`mongodb://127.0.0.1:${dbPort}/${database}?replicaSet=${replicaSet}`});
    const relayId = new mongoose.Types.ObjectId();
    Object.assign(env,{C3_REBUILD_L2TP_INSTALL_ENABLED:'true',C3_REBUILD_L2TP_RELAY_ID:String(relayId),
        C3_REBUILD_L2TP_RELAY_MACHINE_ID:'b'.repeat(32),C3_REBUILD_L2TP_SSH_SHA256:pin});
    panel=fork(require.resolve('./helpers/rebuildPanelChild.cjs'),[],{cwd:dir,env,execArgv:[],stdio:['ignore','ignore','ignore','ipc']});
    exited = new Promise(resolve=>panel.once('exit',resolve));
    const httpPort=await new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>reject(Error('panel HTTP startup deadline')),30000);
        panel.once('message',m=>{clearTimeout(timer); resolve(m.port);});
        exited.then(code=>{clearTimeout(timer); reject(Error('panel exited: '+code));});
    });
    assert.ok(Number.isInteger(httpPort) && httpPort>0);
    const {plainKey} = await require('../../models/apiKeyModel').createKey({name:'local acceptance',scopes:['nodes:read','nodes:write'],allowedIPs:['127.0.0.1'],rateLimit:1000});
    const call=async(method,endpoint,body,expected=200,key=plainKey)=>{
        const res=await fetch(`http://127.0.0.1:${httpPort}/api/cascade${endpoint}`,{method,headers:{'content-type':'application/json',...(key?{'x-api-key':key}:{})},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(30000)});
        const data=await res.json(); assert.equal(res.status,expected,`${method} ${endpoint}: ${res.status} ${data.error?.code||''}`); return data;
    };
    await call('GET','/rebuild/mode',null,401,null);
    assert.equal((await call('GET','/rebuild/mode')).mode,'rebuild');
    const id=()=>new mongoose.Types.ObjectId(), keys=cryptoService.generateX25519KeysLocal();
    const nodes={}, nodeIds={}, roles={p:'portal',u:'relay',r:'relay',a:'bridge',b:'bridge',c:'bridge',x:'portal',y:'bridge'};
    for (const [i,[n,role]] of Object.entries(roles).entries()) {
        const node={_id:id(),name:n,cascadeRole:role,type:'xray',active:true,ip:`192.0.2.${i+1}`,port:22000+i,xray:{inboundTag:'client',apiPort:31000+i,transport:'tcp',security:'none'}};
        if(n==='r') Object.assign(node,{_id:relayId,ssh:{port:22,username:'root',password:'fixture-ssh-auth'}});
        if(n==='p') Object.assign(node.xray,{security:'reality',realitySni:['site.invalid'],realityDest:'site.invalid:443',realityPrivateKey:keys.privateKey,realityPublicKey:keys.publicKey,realityShortIds:['0123abcd']});
        await Node.collection.insertOne(node); nodes[n]=node; nodeIds[n]=String(node._id);
    }
    const user={_id:id(),userId:'acceptance-local',enabled:true,nodes:[nodes.p._id],xrayUuid:randomUUID()};await User.collection.insertOne(user);
    const oldGroup={_id:id(),name:'retained',paths:[{pathKey:'old',linkIds:[id()]}]};await Group.collection.insertOne(oldGroup);
    const tproxy={tag:`relay-l2tp-${oldGroup._id}`,port:31281,protocol:'dokodemo-door',listen:'0.0.0.0',settings:{network:'tcp,udp',followRedirect:true},streamSettings:{sockopt:{tproxy:'tproxy'}}};
    await State.collection.insertOne({node:nodes.r._id,routeGroup:oldGroup._id,status:'installed',desiredState:'installed',secretRevision:1,tproxyPort:tproxy.port});
    const file=(n,profile)=>path.join(dir,`${nodeIds[n]}-${profile}.json`);
    for (const [n,node] of Object.entries(nodes)) {
        const cfg=JSON.parse(generateXrayConfigWithApi(node,await require('../syncService')._getUsersForNode(node)));
        if(n==='r')cfg.inbounds.push(tproxy);
        fs.writeFileSync(file(n,'main'),JSON.stringify(cfg),{mode:0o600});
    }
    fs.writeFileSync(path.join(dir,'events'),'');
    const events=()=>fs.readFileSync(path.join(dir,'events'),'utf8').split('\n').filter(Boolean);
    const config=(n,profile='main')=>JSON.parse(fs.readFileSync(file(n,profile),'utf8'));
    const digests=()=>Object.keys(nodes).flatMap(n=>['main','bridge'].map(p=>fs.existsSync(file(n,p))?createHash('sha256').update(fs.readFileSync(file(n,p))).digest('hex'):'absent'));
    const spec={pu:['p','u'],ur:['u','r'],ra:['r','a'],rb:['r','b'],rc:['r','c'],xy:['x','y']};
    const links={}, preview=(linkId,remove=false)=>call('POST','/rebuild/preview',{linkId,remove});
    const apply=async(linkId,report)=>call('POST','/topology/deploy',{linkId,expectedPreview:(report??await preview(linkId)).previewId});
    const remove=async key=>call('DELETE',`/links/${links[key]}`,{expectedPreview:(await preview(links[key],true)).previewId});
    async function create(key,autoDeploy=true) {
        const [a,b]=spec[key]; const at=events().length;
        const res=await call('POST','/links',{name:key,portalNodeId:nodeIds[a],bridgeNodeId:nodeIds[b],mode:'reverse',tunnelPort:41000+Object.keys(spec).indexOf(key),priority:key==='rc'?1:20,autoDeploy,
            ...(key==='xy'?{tunnelSecurity:'none'}:{}), // Legacy non-REALITY migration fixture, not a new-link default.
            ...(key==='rb'?{geoRouting:{enabled:true,domains:['full:geo.invalid'],geoip:['198.51.100.0/24']}}:{})});
        assert.equal(events().length,at,'no effects before confirmation'); links[key]=res.linkId;
        if(autoDeploy){assert.equal(res.status,'awaiting_preview'); assert.ok(res.preview.allowed); await apply(res.linkId,res.preview);}
    }
    const tag=k=>'rebuild-rp-egress-'+links[k].slice(-8);
    const rules=n=>config(n).routing.rules.filter(r=>r.ruleTag?.startsWith('rebuild-policy-'));
    const fallback=n=>rules(n).find(r=>r.ruleTag==='rebuild-policy-default').outboundTag;
    const assertGraph=(exit='ra')=>{
        assert.equal(fallback('p'),tag('pu')); assert.equal(fallback('u'),tag('ur'));
        assert.deepEqual(rules('r').map(r=>r.outboundTag),[tag('rb'),tag('rb'),tag(exit)]);
        assert.deepEqual(rules('r')[0].domain,['full:geo.invalid']); assert.deepEqual(rules('r')[1].ip,['198.51.100.0/24']);
        assert.equal(config('r').outbounds[0].protocol,'blackhole');
    };
    const checkPPP=()=>{
        const cfg=config('r'), socks=cfg.inbounds.find(i=>i.tag==='rebuild-relay-ingress');
        assert.equal(socks.listen,'127.0.0.1'); assert.equal(socks.sniffing.enabled,true); assert.ok(socks.sniffing.destOverride.includes('tls'));
        assert.equal(cfg.inbounds.find(i=>i.tag===tproxy.tag).port,tproxy.port);
        assert.equal(cfg.routing.rules.filter(r=>r.inboundTag?.includes(tproxy.tag)).at(-1).outboundTag,'rebuild-l2tp-handoff');
        assert.equal(cfg.outbounds.find(o=>o.tag==='rebuild-l2tp-handoff').settings.servers[0].port,socks.port);
        assert.ok(rules('r').every(r=>['client',socks.tag].every(i=>r.inboundTag.includes(i)))); return socks.port;
    };
    const appliedNodes=(result,names)=>assert.deepEqual(result.nodes.map(n=>n.nodeId).sort(),names.map(n=>nodeIds[n]).sort());
    await create('xy',false);
    await t.test('1: opposite creation orders through POST AutoDeploy produce the same routes',async()=>{
        for(const k of ['pu','ur','ra','rb'])await create(k); assertGraph();
        for(const k of ['rb','ra','ur','pu'])await remove(k);
        for(const k of ['rb','ra','ur','pu'])await create(k); assertGraph();
    });
    await t.test('2: confirmed Apply installs geo domain and IP before the priority exit',async()=>{
        const at=events().length;
        const no=await call('POST','/topology/deploy',{linkId:links.pu},428);assert.equal(no.error.code,'REBUILD_PREVIEW_REQUIRED');assert.equal(events().length,at);
        appliedNodes(await apply(links.pu),['p','u','r','a','b']); assertGraph();
    });
    const stable=checkPPP();
    await t.test('3: replacing the default bridge moves ordinary and PPP policy and cleans the removed bridge',async()=>{
        await create('rc'); assertGraph('rc'); appliedNodes(await remove('ra'),['p','u','r','a','b','c']);
        assertGraph('rc'); assert.equal(checkPPP(),stable); assert.ok(!config('a','bridge').reverse); assert.equal(config('a','bridge').outbounds[0].protocol,'blackhole');
    });
    await t.test('4: middle DELETE writes both surviving nonempty components and blocks the half without an exit',async()=>{
        const at=events().length; appliedNodes(await remove('ur'),['p','u','r','b','c']);
        assert.deepEqual(events().slice(at).filter(e=>e.startsWith('written:')).sort(),['p','u','r','b','c'].map(n=>'written:'+nodeIds[n]).sort());
        assert.equal(fallback('p'),'block');assert.equal(fallback('u'),'block');assert.equal(fallback('r'),tag('rc'));
        assert.ok(!config('u').reverse?.portals?.some(p=>p.tag===tag('ur')));
    });
    await t.test('5: installed L2TP follows relay after split/rejoin without changing SOCKS, TPROXY or route group',async()=>{
        assert.equal(checkPPP(),stable);await create('ur');assert.equal(checkPPP(),stable);assertGraph('rc');
        const state=await State.findOne({node:nodes.r._id}).lean(); assert.equal(state.routingMode,'follow-relay');assert.equal(state.tproxyPort,tproxy.port);
        assert.deepEqual(await Group.collection.findOne({_id:oldGroup._id}),oldGroup);
    });
    await t.test('6: after one successful node write and a disconnect, fresh Apply rebuilds the former component',async()=>{
        const scope=['p','u','r','b','c'], sorted=scope.map(n=>nodeIds[n]).sort();
        const marker=path.join(dir,`interrupt-${sorted[1]}`);fs.writeFileSync(marker,'');const at=events().length;
        try {const r=await call('DELETE',`/links/${links.ur}`,{expectedPreview:(await preview(links.ur,true)).previewId},409);assert.equal(r.error.code,'REBUILD_TEST_INTERRUPTED');}
        finally {fs.unlinkSync(marker);}
        assert.deepEqual(events().slice(at).filter(e=>e.startsWith('written:')),['written:'+sorted[0]]);
        assert.ok((await Link.findById(links.ur)).rebuildDelete);const retry=events().length;
        appliedNodes(await apply(links.ur),scope);assert.deepEqual(events().slice(retry).filter(e=>e.startsWith('written:')).sort(),sorted.map(n=>'written:'+n));
        assert.equal(await Link.exists({_id:links.ur}),null);assert.equal(fallback('u'),'block');assert.equal(fallback('r'),tag('rc'));await create('ur');
    });
    await t.test('portal guard: independent DB changes must stop the entire component before staging',async t=>{
        const other=cryptoService.generateX25519KeysLocal();
        for(const [label,col,filter,field,before,after] of [
            ['port',Node.collection,{_id:nodes.p._id},'port',nodes.p.port,nodes.p.port+1],
            ['private key',Node.collection,{_id:nodes.p._id},'xray.realityPrivateKey',keys.privateKey,other.privateKey],
            ['SNI',Node.collection,{_id:nodes.p._id},'xray.realitySni',nodes.p.xray.realitySni,['different.invalid']],
            ['subscriber UUID',User.collection,{_id:user._id},'xrayUuid',user.xrayUuid,randomUUID()],
            ['published public key only',Node.collection,{_id:nodes.p._id},'xray.realityPublicKey',keys.publicKey,other.publicKey]
        ]) await t.test(label,async()=>{
            const prior=await preview(links.ur);assert.ok(prior.allowed);const previous=digests(),count=events().length;
            assert.equal((await col.updateOne(filter,{$set:{[field]:after}})).matchedCount,1);
            try {
                const report=await preview(links.ur);assert.equal(report.allowed,false,label);assert.ok(report.nodes.find(n=>n.nodeId===nodeIds.p).profiles.some(p=>p.protectedChanged));
                const edit=await call('PUT',`/links/${links.ur}`,{autoDeploy:true});assert.equal(edit.preview.allowed,false);
                for(const [method,url,body] of [['POST','/topology/deploy',{linkId:links.ur,expectedPreview:prior.previewId}],['POST','/topology/deploy',{linkId:links.ur,expectedPreview:edit.preview.previewId}],['DELETE',`/links/${links.ur}`,{expectedPreview:(await preview(links.ur,true)).previewId}]]){
                    const refused=await call(method,url,body,409);assert.equal(refused.error.code,'REBUILD_CLIENT_CHANGE');
                }
                assert.notEqual((await Link.findById(links.ur)).rebuildDelete,true);
            } finally {await col.updateOne(filter,{$set:{[field]:before}});assert.equal(events().length,count,'zero stage/put attempts across ALL inventory');assert.deepEqual(digests(),previous);}
        });
    });
    assert.ok(!events().some(e=>[nodeIds.x,nodeIds.y].includes(e.split(':')[1])));
    await t.test('first Apply migrates a classic reverse pair without changing the portal client or rolling tunnel keys on repeat',async()=>{
        const classic=require('../configGenerator');
        const old=await Link.findById(links.xy).lean();
        const subscriber={_id:id(),userId:'migration-fixture',subscriptionToken:randomUUID(),enabled:true,nodes:[nodes.x._id],xrayUuid:randomUUID()};
        await User.collection.insertOne(subscriber);
        const main=JSON.parse(classic.generateXrayConfigWithApi(nodes.x,[subscriber]));
        classic.applyReversePortal(main,[old],['client']);
        fs.writeFileSync(file('x','main'),JSON.stringify(main),{mode:0o600});
        fs.writeFileSync(file('y','bridge'),classic.generateBridgeConfig(old,nodes.x),{mode:0o600});
        assert.ok(main.reverse.portals.length && config('y','bridge').reverse.bridges.length);
        const identity=cfg=>JSON.stringify(cfg.inbounds.find(i=>i.tag==='client'),(k,v)=>k==='sniffing'?undefined:v);
        const before=identity(main); const raw=()=>Link.collection.findOne({_id:old._id},{projection:{rebuildVlessKeyEnvelope:1}});
        const report=await preview(links.xy);
        assert.ok(report.allowed && report.nodes.flatMap(n=>n.profiles).filter(p=>p.tunnelMigration==='legacy-to-vless-reverse').length===2);
        assert.ok(!(await raw()).rebuildVlessKeyEnvelope);
        // An endpoint can change AFTER a valid Preview. Check both orientations;
        // neither the other node's files nor the DB key may change on refusal.
        for (const side of ['x','y']) {
            const prior=digests(), count=events().length, marker=path.join(dir,`old-core-${nodeIds[side]}`);
            fs.writeFileSync(marker,'',{flag:'wx'});
            try {
                const denied=await call('POST','/topology/deploy',{linkId:links.xy,expectedPreview:report.previewId},409);
                assert.equal(denied.error.code,'REBUILD_XRAY_VERSION_TOO_OLD');
                assert.ok(!(await raw()).rebuildVlessKeyEnvelope);
                assert.equal(events().length,count);assert.deepEqual(digests(),prior);
            } finally {fs.unlinkSync(marker);}
        }
        await apply(links.xy,report);
        const envelope=(await raw()).rebuildVlessKeyEnvelope;
        assert.ok(typeof envelope==='string' && !config('x').reverse && !config('y','bridge').reverse);
        assert.ok(identity(config('x'))===before,'client changed');
        const digest=digests();await apply(links.xy);
        assert.ok((await raw()).rebuildVlessKeyEnvelope===envelope); assert.deepEqual(digests(),digest);
    });
});
