'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const {routerForRebuild}=require('../../routes/cascadeRebuild');
const {handler}=require('../../routes/panel/rebuildRelayInstall');
const {issuePanelCsrfToken,requirePanelCsrf}=require('../../routes/panel/csrf');
const id='a'.repeat(24);
test('only panel session + CSRF can install; API key, arbitrary options and old verbs cannot dispatch', async t=>{
 const app=express();app.use(express.json());let writes=0;const session={authenticated:true};const csrf=issuePanelCsrfToken({session});
 app.use((req,res,next)=>{if(req.headers['x-test-session'])req.session=session;req.apiKey={scopes:['nodes:write']};next();});
 app.use('/api/cascade',routerForRebuild({service:{},Node:{},Link:{}}));
 app.post('/panel/rebuild/relays/:id/l2tp/install',requirePanelCsrf,handler(()=>({installRelay:async n=>{assert.equal(n,id);writes++;return {status:'installed'};}})));
 const srv=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise(r=>srv.close(r)));
 const path='/rebuild/relays/'+id+'/l2tp/install';async function call(p,headers={},body={}){return (await fetch('http://127.0.0.1:'+srv.address().port+p,{method:'POST',headers:{'content-type':'application/json',...headers},body:JSON.stringify(body)})).status;}
 const headers={'x-test-session':'1','x-csrf-token':csrf};assert.equal(await call('/api/cascade'+path,headers),404);assert.equal(await call('/panel'+path),403);assert.equal(await call('/panel'+path,{'x-test-session':'1'}),403);assert.equal(await call('/panel'+path,{...headers,origin:'https://invalid.example'}),403);
 assert.equal(await call('/panel'+path,headers,{command:'uninstall'}),400);assert.equal(await call('/panel'+path+'?target=elsewhere',headers),400);assert.equal(await call('/panel'+path.replace(/install$/,'uninstall'),headers),404);assert.equal(writes,0);
 assert.equal(await call('/panel'+path,headers),200);assert.equal(writes,1);
});
