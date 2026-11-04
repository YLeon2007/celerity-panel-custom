'use strict';
// Fast HTTP-only diagnosis, NOT additional browser acceptance.
const fs=require('node:fs'),assert=require('node:assert/strict');
const {createApp}=require('./local-app.cjs');
(async()=>{const app=await createApp();let i=0;const requests=[];
  async function send(method,path,extra={}){
    const body={expectedTopologyRevision:app.f.data.CascadeTopologyState[0].revision,...extra};
    const r=await fetch(app.origin+path,{method,headers:{'content-type':'application/json','Idempotency-Key':'http-diagnostic-'+(++i)},body:JSON.stringify(body)});
    const result=await r.json();requests.push({method,path,status:r.status,result});assert.ok(r.ok,JSON.stringify(result));return result;
  }
  try{
    const draft=await send('POST','/api/cascade/links',{name:'P-R',portalNodeId:app.id(1),bridgeNodeId:app.id(2),tunnelPort:24501,tunnelSecurity:'none',mode:'reverse',autoDeploy:false});
    await send('POST','/api/cascade/links',{name:'R-B',portalNodeId:app.id(2),bridgeNodeId:app.id(3),tunnelPort:24502,tunnelSecurity:'none',mode:'reverse',autoDeploy:true});
    await send('POST','/api/cascade/links',{name:'P2-B2',portalNodeId:app.id(4),bridgeNodeId:app.id(5),tunnelPort:24503,tunnelSecurity:'none',mode:'forward',autoDeploy:true});
    app.host.start();await app.tick();
    const p=app.f.data.CascadeLink.find(l=>l.name==='P-R')._id,s=app.f.data.CascadeLink.find(l=>l.name==='R-B')._id;
    await send('POST','/api/cascade/topology/deploy',{linkId:p});await app.tick();
    await send('DELETE','/api/cascade/links/'+s);await app.tick();
    const result={scope:'HTTP-only diagnosis with same actual routes/runtime and same modeled backend, no stale revision or socket fault',requests,backend:app.summary()};
    fs.writeFileSync(process.argv[2],JSON.stringify(result,null,2)+'\n');
    console.log(JSON.stringify({operation:result.backend.operations.at(-1),diagnostics:result.backend.diagnostics}));
  }finally{await app.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
