'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const {runRebuild,componentFor,profilePreview}=require('../rebuildCoordinator');
const links=[['l','p','r'],['m','r','b'],['n','b','c'],['x','x','y']].map(([_id,portalNode,bridgeNode])=>({_id,portalNode,bridgeNode}));
const client={tag:'custom',protocol:'vless',port:443,settings:{clients:[{id:'not-a-public-value',email:'foo'}]},streamSettings:{realitySettings:{serverNames:['private.invalid'],privateKey:'private-config-text'}}};
function fixture(){const trace=[], store=new Map(),configs=new Map();let locked=false;
 const pair=id=>['main','bridge'].map(profile=>({nodeId:id,profile,config:{inbounds:profile==='main'?[structuredClone(client)]:[],outbounds:[{tag:id,protocol:'blackhole'}],routing:{rules:[]}}}));
 for(const id of ['p','r','b','c','x','y']) {configs.set(id,pair(id));store.set(id,pair(id).map(p=>({...p,config:{...p.config,outbounds:[{tag:'old',protocol:'blackhole'}]}})));}
 return { trace,store,configs, d:{global:async(fn)=>{assert.equal(locked,false);locked=true;try{return await fn()}finally{locked=false}},withNodes:async(ids,fn)=>{assert.ok(locked);return fn()},links:async()=>links,build:async(ids,desired)=>{trace.push('build:'+desired.map(l=>l._id));return ids.flatMap(id=>configs.get(id))},read:async(id,profile)=>structuredClone(store.get(id).find(p=>p.profile===profile).config),putPair:async(id,pair)=>{trace.push('put:'+id);store.set(id,structuredClone(pair))},finish:async()=>trace.push('finish')}};
}
test('DELETE scope includes both old components, never a neighbour; restarted Apply replays both halves including already written nodes',async()=>{const {d,trace}=fixture();let fail=true;const put=d.putPair;d.putPair=async(id,p)=>{if(id==='r'&&fail){fail=false;throw Error('transport interruption')}await put(id,p)};
 assert.deepEqual(componentFor(links,['p']),['b','c','p','r']);const request={linkId:'m',remove:true};await assert.rejects(runRebuild(d,request));assert.ok(!trace.includes('finish'));trace.length=0;const {nodes}=await runRebuild(d,request);assert.deepEqual(nodes.map(n=>n.nodeId),['b','c','p','r']);assert.ok(trace.includes('build:l,n'));assert.deepEqual(trace.slice(1),['put:b','put:c','put:p','put:r','finish']);});
test('one changed or removed portal credential vetoes ALL writes before dispatch, returned preview never contains its value',async()=>{const {d,configs,trace}=fixture();configs.get('r')[0].config.inbounds[0].streamSettings.realitySettings.privateKey+='changed';const res=await runRebuild(d,{linkId:'m',preview:true});assert.equal(res.allowed,false);assert.equal(JSON.stringify(res).includes('private'),false);await assert.rejects(runRebuild(d,{linkId:'m'}),{code:'REBUILD_CLIENT_CHANGE'});assert.equal(trace.some(z=>z.startsWith('put')),false);
 for(const prop of ['port','users','sni','drop']){let after=structuredClone(client);if(prop==='port')after.port++;if(prop==='users')after.settings.clients=[];if(prop==='sni')after.streamSettings.realitySettings.serverNames=[];const row=profilePreview({inbounds:[client]}, {inbounds:prop==='drop'?[]:[after]},'main');assert.ok(row.protectedChanged);}
});
test('readback mismatch is not success; next apply writes every node afresh',async()=>{const {d,trace,store}=fixture();const put=d.putPair;d.putPair=async(id,p)=>{await put(id,p);store.get(id)[0].config.routing.rules.push({tag:'drift'})};await assert.rejects(runRebuild(d,{linkId:'m'}),{code:'REBUILD_READBACK_MISMATCH'});assert.ok(!trace.includes('finish'));d.putPair=put;await runRebuild(d,{linkId:'m'});assert.ok(trace.includes('finish'));});

test('a confirmed snapshot distinguishes null, undefined and absence in nested working fields',async()=>{
    const {d,trace}=fixture();
    const inventory=structuredClone(links);
    d.links=async()=>inventory;
    inventory[1].extra={nested:[{status:undefined}]};
    const ticket=await runRebuild(d,{linkId:'m',preview:true});
    trace.length=0;
    inventory[1].extra.nested[0].status=null;
    await assert.rejects(runRebuild(d,{linkId:'m',expectedPreview:ticket.previewId}),{code:'REBUILD_LINK_CHANGED'});
    delete inventory[1].extra.nested[0].status;
    await assert.rejects(runRebuild(d,{linkId:'m',expectedPreview:ticket.previewId}),{code:'REBUILD_LINK_CHANGED'});
    assert.deepEqual(trace,[]);
});

test('the link fingerprint depends on values, not array layout or object identity',()=>{
    const {linkSnapshotBytes}=require('../rebuildLinkSnapshot');
    const packed=['x','y','z'];
    const holey=Array(3);
    for(let i=0;i<packed.length;i++)holey[i]=packed[i];
    const sample=Buffer.from([1,2]);
    const a={items:packed,binary:[sample,sample]}, b={binary:[Buffer.from(sample),Buffer.from(sample)],items:holey};
    assert.deepEqual(a,b);
    assert.ok(linkSnapshotBytes(a).equals(linkSnapshotBytes(b)));
});
