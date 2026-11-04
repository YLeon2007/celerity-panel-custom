'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {Firefox,sleep}=require('./firefox-bidi.cjs');
const {createApp,sha}=require('./local-app.cjs');
const ROOT=path.resolve(__dirname,'..');
const OUT=path.resolve(process.argv[2]||path.join(__dirname,'run-01'));fs.mkdirSync(OUT,{recursive:true});
const CY="document.getElementById('cy')._cyreg.cy";
const evidence={scope:{browser:'real installed Firefox ESR via native WebDriver BiDi pointer actions',
  application:'actual nodes.ejs/locales/minified JS and actual public route modules/default host/runtime/worker/finalizer',
  modeled:'shared repository DB queries, transactions, adoption records, executor/node-side receipts and empty user resync',
  excluded:['real Mongo atomicity','SSH/Xray/PPP/client traffic','index.js bootstrap','cron/background-writer compatibility','login/auth/CSRF security acceptance']},cases:[],checkpoints:[]};
let app,browser;
function save(){fs.writeFileSync(path.join(OUT,'evidence.json'),JSON.stringify(evidence,null,2)+'\n');}
async function check(name,fn){const t=Date.now();try{const detail=await fn();evidence.cases.push({name,status:'PASS',durationMs:Date.now()-t,detail});console.log('PASS',name);}catch(e){evidence.cases.push({name,status:'FAIL',durationMs:Date.now()-t,error:e.stack});save();throw e;}save();}
async function graph(){return browser.evaluate(`(()=>{const c=${CY};return {nodes:c.nodes().map(n=>({id:n.id(),position:n.position()})),pan:c.pan(),zoom:c.zoom(),edges:c.edges().filter(e=>e.data('linkId')).map(e=>({linkId:e.data('linkId'),label:e.data('label'),status:e.data('status'),applicationState:e.data('applicationState'),routeState:e.data('routeState'),progress:e.data('progress')}))};})()`);}
async function edge(id){await closeDrawer();await browser.evaluate("document.getElementById('cy').scrollIntoView({block:'center'})");const p=await browser.evaluate(`(()=>{const e=${CY}.edges().filter(e=>e.data('linkId')===${JSON.stringify(id)});if(!e.length)throw Error('Missing edge');const p=e[0].renderedMidpoint(),r=document.getElementById('cy').getBoundingClientRect();return {x:p.x+r.x,y:p.y+r.y};})()`);await browser.pointer(p.x,p.y);await browser.wait("document.getElementById('nodeInfoModal').classList.contains('active')");}
async function closeDrawer(){if(await browser.evaluate("document.getElementById('nodeInfoModal').classList.contains('active')")){
  try{await browser.click('#nodeInfoClose');}catch(e){
    if(!e.message.startsWith('Button unavailable #nodeInfoClose'))throw e;
    evidence.uiObstructions??=[];evidence.uiObstructions.push({control:'nodeInfoClose',error:e.message});
    // User-visible alternative: native click on the actual modal backdrop,
    // not a JS handler call or a CSS/z-index workaround.
    const p=await browser.evaluate("(()=>{const r=document.querySelector('#nodeInfoModal .modal-card').getBoundingClientRect();return {x:Math.min(innerWidth-20,r.right+30),y:Math.min(innerHeight-30,Math.max(200,r.y+r.height/2))};})()");
    await browser.pointer(p.x,p.y);
  }
  await browser.wait("!document.getElementById('nodeInfoModal').classList.contains('active')");
}}
async function confirmClick(selector,beforeAccept=()=>{}){const before=browser.events.length;const clicking=browser.click(selector);clicking.catch(()=>{});for(let i=0;i<100;i++){const prompt=browser.events.slice(before).find(e=>e.method==='browsingContext.userPromptOpened');if(prompt){await beforeAccept();await browser.send('browsingContext.handleUserPrompt',{context:browser.context,accept:true});await clicking;return prompt.params;}await sleep(50);}throw Error('Expected native confirm dialog for '+selector);}
async function create(name,source,target,port,auto,mode='reverse'){
  await closeDrawer();await browser.click('#btnAddLink');await browser.wait("document.querySelectorAll('#selectPortal option').length>1");
  for(const [s,v]of [['#addLinkForm [name="name"]',name],['#selectPortal',source],['#selectBridge',target],['#addLinkForm [name="tunnelPort"]',String(port)]])await browser.fill(s,v);
  if(mode==='forward')await browser.click('#modeSwitcher [data-mode="forward"]');
  await sleep(700); // node/port edits can move the checkbox while warning text settles
  const checked=await browser.evaluate("document.querySelector('#addLinkForm [name=autoDeploy]').checked");
  if(checked!==auto)await browser.click('#addLinkForm [name=autoDeploy]');
  await browser.wait(`document.querySelector('#addLinkForm [name=autoDeploy]').checked===${auto}`);
  await sleep(700); // allow the real debounced port warning/layout to settle
  await browser.click('#linkModalSubmit');
  await browser.wait("!document.getElementById('addLinkModal').classList.contains('active')");
  const link=app.f.data.CascadeLink.find(l=>l.name===name);assert.ok(link,'actual route must persist link');
  await browser.wait(`${CY}.edges().some(e=>e.data('linkId')===${JSON.stringify(link._id)})`);return link._id;
}
async function refresh(){await closeDrawer();await browser.click('#btnRefresh');await browser.wait("!document.querySelector('.network-loading')");await sleep(100);}
async function settle(){app.host.start();await app.tick();for(let i=0;i<60;i++){if(app.f.data.TopologyOperation.every(o=>['succeeded','failed','rolled_back'].includes(o.status))&&app.f.data.TopologyOperation.length)break;await sleep(50);}await app.tick();assert.deepEqual(app.f.errors,[]);}
async function main(){
  const cgroup=fs.readFileSync('/proc/self/cgroup','utf8').trim().split('::')[1];
  evidence.isolation={cgroup,...Object.fromEntries(['memory.max','memory.high','cpu.max','memory.swap.max'].map(k=>[k,fs.readFileSync('/sys/fs/cgroup'+cgroup+'/'+k,'utf8').trim()]))};
  assert.ok(cgroup.includes('/hermes-heavy-'),'browser must run in a bounded heavy scope');
  app=await createApp();evidence.origin=app.origin;
  const served=await fetch(app.origin+'/js/network.min.js?v='+sha(fs.readFileSync(path.join(ROOT,'public/js/network.min.js'))).slice(0,16));
  evidence.asset={diskSha256:sha(fs.readFileSync(path.join(ROOT,'public/js/network.min.js'))),servedSha256:sha(Buffer.from(await served.arrayBuffer())),httpStatus:served.status};
  assert.equal(evidence.asset.diskSha256,evidence.asset.servedSha256);
  browser=await new Firefox().start(process.env.TMPDIR);evidence.engine=browser.session.capabilities;
  let pending,suffix,independent;
  await check('actual-template-minified-bundle-browser-boot',async()=>{
    await browser.navigate(app.origin+'/panel/nodes?lang=ru');
    assert.equal(await browser.evaluate('document.title'),'Any-order local synthetic fixture | C³ CELERITY');
    await browser.click('#tabNetwork');
    await browser.wait(`document.getElementById('cy')._cyreg?.cy?.nodes().length>=5`,30000);
    const state=await graph();evidence.checkpoints.push({name:'initial',graph:state,backend:app.summary()});
    evidence.asset.browserSha256=await browser.evaluate("fetch('/js/network.min.js').then(r=>r.arrayBuffer()).then(b=>crypto.subtle.digest('SHA-256',b)).then(b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join(''))");
    assert.equal(evidence.asset.browserSha256,evidence.asset.diskSha256);
    return {nodes:state.nodes.length,realCytoscape:await browser.evaluate('cytoscape.version'),bundleUrls:await browser.evaluate("Array.from(document.scripts).map(s=>s.src).filter(u=>u.includes('network.min.js'))")};
  });
  await check('save-only-button-persists-pending-without-job-or-executor',async()=>{
    pending=await create('Pending P-R',app.id(1),app.id(2),24501,false);
    assert.equal(app.f.data.TopologyCreateIntent.length,0);assert.equal(app.f.data.TopologyOperation.length,0);assert.deepEqual(app.f.calls,[]);
    assert.equal(app.f.data.CascadeLink.find(l=>l._id===pending).status,'pending');
    return {linkId:pending,backend:app.summary()};
  });
  await check('auto-buttons-accept-two-independent-jobs-and-poll-each-without-repost',async()=>{
    suffix=await create('Auto R-B',app.id(2),app.id(3),24502,true);
    independent=await create('Independent P2-B2',app.id(4),app.id(5),24503,true,'forward');
    assert.equal(app.f.data.TopologyCreateIntent.length,2);assert.deepEqual(app.f.calls,[]);
    const jobs=app.f.data.TopologyCreateIntent.map(j=>j._id);
    for(let i=0;i<80&&!jobs.every(id=>app.requests.some(r=>r.path==='/api/cascade/links/auto-deploy-jobs/'+id));i++)await sleep(100);
    assert.ok(jobs.every(id=>app.requests.some(r=>r.path==='/api/cascade/links/auto-deploy-jobs/'+id)));
    assert.equal(app.requests.filter(r=>r.method==='POST'&&r.path==='/api/cascade/links').length,3);
    return {jobs,suffix,independent,graph:await graph(),backend:app.summary()};
  });
  await check('actual-worker-source-less-incomplete-keeps-pending-and-native-drawer-readiness-separate',async()=>{
    await settle();assert.ok(app.f.data.TopologyOperation.every(o=>o.status==='succeeded'),JSON.stringify(app.summary()));
    const op=app.f.data.TopologyOperation.find(o=>o.linkId===suffix);assert.equal(op.routeState,'no_portal_input');assert.equal(op.staged,true);
    assert.ok(app.f.data.TopologyOperation.every(o=>!o.effectiveTopology.links.some(l=>l.id===pending)));
    await refresh();await edge(suffix);const text=await browser.evaluate("document.getElementById('nodeInfoBody').innerText");
    assert.ok(text.includes(require('../src/locales/ru.json').network.routeNoPortal),text);
    assert.ok(text.includes('PPP/L2TP')&&text.toUpperCase().includes('XRAY/VLESS/REALITY'));
    await closeDrawer();return {operationId:op._id,drawer:text,backend:app.summary()};
  });
  await check('manual-selected-deploy-button-completes-route-no-full-sync',async()=>{
    await edge(pending);const prompt=await confirmClick('#btnDeploy');
    await sleep(150);await app.tick();await refresh();
    const op=app.f.data.TopologyOperation.find(o=>o.linkId===pending);assert.ok(op,JSON.stringify(app.summary()));assert.equal(op.status,'succeeded');assert.equal(op.routeState,'complete');
    assert.deepEqual(new Set(op.effectiveTopology.links.map(l=>l.id)),new Set([pending,suffix]));
    const deploys=app.requests.filter(r=>r.method==='POST'&&r.path==='/api/cascade/topology/deploy');
    assert.equal(deploys.length,1);assert.equal(deploys[0].body.linkId,pending);return {prompt,request:deploys[0],backend:app.summary()};
  });
  await check('native-graph-drag-wheel-and-refresh-preserve-positions-zoom',async()=>{
    await browser.evaluate(`(()=>{${CY}.fit(100);return true;})()`);const original=await graph();
    const p=await browser.evaluate(`(()=>{const n=${CY}.getElementById(${JSON.stringify(app.id(1))}),p=n.renderedPosition(),r=document.getElementById('cy').getBoundingClientRect();return {x:p.x+r.x,y:p.y+r.y};})()`);
    await browser.send('input.performActions',{context:browser.context,actions:[{type:'pointer',id:'mouse',parameters:{pointerType:'mouse'},actions:[{type:'pointerMove',x:Math.round(p.x),y:Math.round(p.y),origin:'viewport'},{type:'pointerDown',button:0},{type:'pointerMove',x:Math.round(p.x+35),y:Math.round(p.y+25),duration:300,origin:'viewport'},{type:'pointerUp',button:0}]}]});
    await browser.send('input.performActions',{context:browser.context,actions:[{type:'wheel',id:'wheel',actions:[{type:'scroll',x:Math.round(p.x+35),y:Math.round(p.y+25),deltaX:0,deltaY:-80,duration:200,origin:'viewport'}]}]});
    await sleep(900);const before=await graph();assert.notEqual(before.zoom,original.zoom,'native wheel must change zoom');assert.notDeepEqual(before.nodes[0].position,original.nodes[0].position,'native drag must move a node');await refresh();const after=await graph();
    assert.deepEqual(after.nodes,before.nodes);assert.equal(after.zoom,before.zoom);assert.deepEqual(after.pan,before.pan);
    assert.ok(app.requests.some(r=>r.method==='POST'&&r.path==='/api/cascade/topology/positions'));
    evidence.mapBeforeMutation=before;return {before,after,positionRepository:app.f.data.HyNode.map(n=>({id:n._id,position:n.mapPosition}))};
  });
  await check('actual-stale-revision-delete-error-keeps-arrow-and-creates-no-job',async()=>{
    const before=app.f.data.TopologyCreateIntent.length;
    await edge(suffix);const prompt=await confirmClick('#btnDelete',()=>{app.f.data.CascadeTopologyState[0].revision++;});
    await sleep(300);
    const rejected=app.requests.filter(r=>r.method==='DELETE'&&r.path.endsWith(suffix)).at(-1);
    assert.equal(rejected.status,409,JSON.stringify(rejected));
    assert.equal(rejected.result.error.code,'STALE_TOPOLOGY_REVISION');
    assert.equal(app.f.data.TopologyCreateIntent.length,before);
    assert.ok((await graph()).edges.some(e=>e.linkId===suffix));
    await refresh();return {prompt,rejected,backend:app.summary()};
  });
  await check('lost-delete-http-responses-retain-arrow-and-one-idempotent-job',async()=>{
    const beforeDeletes=app.requests.filter(r=>r.method==='DELETE'&&r.path.endsWith(suffix)).length;
    // The fixture timer advances only on app.tick(); host.stop is terminal,
    // not a pause, so leave the idle real runtime alive while withholding ticks.
    await edge(suffix);app.dropNextDelete();const prompt=await confirmClick('#btnDelete');
    await sleep(400);const lossToast=await browser.evaluate("document.getElementById('toast').innerText");
    const deletion=app.f.data.TopologyCreateIntent.find(j=>j.kind==='link.delete'&&j.linkId===suffix);assert.ok(deletion);
    const state=await graph();assert.ok(state.edges.some(e=>e.linkId===suffix));
    const link=app.f.data.CascadeLink.find(l=>l._id===suffix);assert.equal(link.lifecycle.state,'deleting');
    // Firefox may retransmit an idempotent DELETE after a reset. All of those
    // real routes must replay the SAME key/job, and all replies are dropped.
    const lost=app.requests.filter(r=>r.method==='DELETE'&&r.path.endsWith(suffix)).slice(beforeDeletes);
    assert.ok(lost.length>=1&&lost.every(r=>r.droppedAfterRealRoute));
    assert.equal(new Set(lost.map(r=>r.key)).size,1);
    assert.ok(lost.every(r=>r.result.job.jobId===deletion._id));
    app.stopDroppingDelete();
    await edge(suffix);const drawer=await browser.evaluate("document.getElementById('nodeInfoBody').innerText");
    const beforeRepeat=app.requests.filter(r=>r.method==='DELETE'&&r.path.endsWith(suffix)).length;
    // Repeat UI click after marker recovery is suppressed, not another job.
    await browser.click('#btnDelete');await sleep(100);
    assert.equal(app.requests.filter(r=>r.method==='DELETE'&&r.path.endsWith(suffix)).length,beforeRepeat);
    assert.equal(app.f.data.TopologyCreateIntent.filter(j=>j.kind==='link.delete'&&j.linkId===suffix).length,1);
    return {prompt,lossToast,transportAttempts:lost.length,jobId:deletion._id,retainedGraph:state,drawer,backend:app.summary()};
  });
  try { await check('real-delete-terminal-plus-list-absence-removes-only-arrow-and-recreate-same-port',async()=>{
    await closeDrawer();await settle();
    const del=app.f.data.TopologyOperation.find(o=>o.kind==='link.delete'&&o.linkId===suffix);assert.ok(del);assert.equal(del.status,'succeeded',JSON.stringify(app.summary()));
    for(let i=0;i<100;i++){if(!(await graph()).edges.some(e=>e.linkId===suffix))break;await sleep(100);}
    const gone=await graph();assert.ok(!gone.edges.some(e=>e.linkId===suffix));assert.ok(gone.edges.some(e=>e.linkId===independent));
    const before=evidence.mapBeforeMutation;assert.deepEqual(gone.nodes,before.nodes);assert.equal(gone.zoom,before.zoom);assert.deepEqual(gone.pan,before.pan);
    const recreated=await create('Recreated R-B',app.id(2),app.id(3),24502,true);await app.tick();await refresh();
    assert.notEqual(recreated,suffix);const op=app.f.data.TopologyOperation.find(o=>o.linkId===recreated);assert.equal(op.status,'succeeded');assert.equal(op.routeState,'complete');
    return {deletedOperationId:del._id,recreated,backend:app.summary(),graph:await graph()};
  }); } catch(e) {
    const del=app.f.data.TopologyOperation.find(o=>o.kind==='link.delete'&&o.linkId===suffix);
    // Keep the requested reverse positive RED. Observe its real safety refusal,
    // then exercise the independent forward delete UI rather than forge success.
    if(del?.status!=='rolled_back'||del.routeState!=='no_bridge_exit')throw e;
    evidence.backendBlocker={operationId:del._id,linkId:suffix,status:del.status,routeState:del.routeState,diagnostics:app.summary().diagnostics};
    await check('rolled-back-reverse-delete-retains-arrow-and-failed-job',async()=>{
      const job=app.f.data.TopologyCreateIntent.find(j=>j.kind==='link.delete'&&j.linkId===suffix);assert.equal(job.status,'failed');
      await refresh();await edge(suffix);const state=await graph();assert.ok(state.edges.some(e=>e.linkId===suffix));
      return {jobId:job._id,drawer:await browser.evaluate("document.getElementById('nodeInfoBody').innerText"),graph:state,backend:app.summary()};
    });
    await check('independent-forward-delete-removes-only-arrow-and-recreates-same-port',async()=>{
      await edge(independent);await confirmClick('#btnDelete');await sleep(150);await app.tick();
      const deleted=app.f.data.TopologyOperation.find(o=>o.kind==='link.delete'&&o.linkId===independent);assert.equal(deleted.status,'succeeded',JSON.stringify(app.summary()));
      await closeDrawer();await refresh();
      // Real list absence precedes the browser's next exact job/operation poll.
      // The tombstone must remain until that independent terminal proof arrives.
      for(let i=0;i<100;i++){if(!(await graph()).edges.some(e=>e.linkId===independent))break;await sleep(100);}
      const state=await graph();assert.ok(!state.edges.some(e=>e.linkId===independent));assert.ok(state.edges.some(e=>e.linkId===suffix));
      assert.deepEqual(state.nodes,evidence.mapBeforeMutation.nodes);assert.equal(state.zoom,evidence.mapBeforeMutation.zoom);assert.deepEqual(state.pan,evidence.mapBeforeMutation.pan);
      const recreated=await create('Recreated P2-B2',app.id(4),app.id(5),24503,true,'forward');await app.tick();await refresh();
      const op=app.f.data.TopologyOperation.find(o=>o.linkId===recreated);assert.equal(op.status,'succeeded');assert.notEqual(recreated,independent);
      return {deletedOperationId:deleted._id,recreated,backend:app.summary(),graph:await graph()};
    });
  }
  await check('no-full-sync-or-extra-mutations-and-browser-served-hash',async()=>{
    const mutations=app.requests.filter(r=>r.method!=='GET'&&r.path.startsWith('/api/'));
    assert.ok(mutations.every(r=>!r.path.includes('/chain/deploy')&&!r.body?.fullSync&&(!r.path.endsWith('/topology/deploy')||r.body.linkId)));
    const tracked=app.f.data.TopologyOperation.filter(o=>o.status==='succeeded'&&!app.f.data.CascadeLink.find(l=>l.name.startsWith('Recreated ')&&l._id===o.linkId));
    for(const op of tracked)assert.ok(app.requests.some(r=>r.path==='/api/cascade/topology/operations/'+op._id),'exact independent operation must be polled '+op._id);
    const requested=browser.events.filter(e=>e.method==='network.responseCompleted'&&e.params.request.url.includes('/js/network.min.js'));
    assert.ok(requested.length);const browserHash=await browser.evaluate(`fetch('/js/network.min.js?v=${evidence.asset.diskSha256.slice(0,16)}').then(r=>r.arrayBuffer()).then(b=>crypto.subtle.digest('SHA-256',b)).then(b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join(''))`);
    assert.equal(browserHash,evidence.asset.diskSha256);return {browserHash,networkResponses:requested.map(e=>({url:e.params.request.url,status:e.params.response.status})),mutations};
  });
  evidence.success=evidence.cases.every(c=>c.status==='PASS');if(!evidence.success)process.exitCode=1;
}
main().catch(e=>{console.error(e.stack);evidence.success=false;evidence.error=e.stack;process.exitCode=1;}).finally(async()=>{
  if(browser){evidence.console=browser.events.filter(e=>e.method==='log.entryAdded').map(e=>e.params);evidence.firefoxLog=browser.log;
    try{evidence.finalDom=await browser.evaluate('document.body.innerText');evidence.finalControls=await browser.evaluate("Array.from(document.querySelectorAll('#addLinkForm input,#addLinkForm select')).filter(e=>!e.name.toLowerCase().includes('key')).map(e=>({name:e.name,id:e.id,value:e.value,checked:e.checked,valid:e.checkValidity()}))");}catch{}
    evidence.browserCleanup=await browser.close();}
  if(app){evidence.finalBackend=app.summary();evidence.requests=app.requests;evidence.applicationCleanup=await app.close();}
  evidence.totals={cases:evidence.cases.length,pass:evidence.cases.filter(x=>x.status==='PASS').length,fail:evidence.cases.filter(x=>x.status==='FAIL').length};
  save();console.log(JSON.stringify({success:evidence.success,totals:evidence.totals,cleanup:{browser:evidence.browserCleanup,application:evidence.applicationCleanup}}));
});
