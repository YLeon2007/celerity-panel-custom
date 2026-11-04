'use strict';
// Loopback composed application: REAL public route modules/default host/worker;
// shared fixture MODELS DB queries/transactions, ownership and node execution.
// This deliberately does not boot index.js, import .env, start cron or connect DB/SSH.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..');
const express=require('express'),ejs=require('ejs');
// Observe the existing secret-free diagnostic formatter without enabling its
// production /app file sink; decisions and returned worker values are unchanged.
const diagnostics=[],diag=require('../src/routes/topologyTestDiagnostics');
const originalDiagnostic=diag.logTopologyTestFailure;
diag.logTopologyTestFailure=input=>{diagnostics.push(diag.formatTopologyDiagnostic(input));return originalDiagnostic(input);};
const shared=require('../src/modules/relay-l2tp/tests/cascadeAnyOrderRuntimeFixture');
const {createCascadeLinksRouter}=require('../src/routes/cascadeLinks');
const {createCascadeTopologyDeployRouter}=require('../src/routes/cascadeTopologyDeploy');
const {TopologyDraftWriteService}=require('../src/modules/relay-l2tp/services/topologyDraftWriteService');
const {TopologyDraftRepository}=require('../src/modules/relay-l2tp/repositories/topologyDraftRepository');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
async function createApp(){
  const f=shared.fixture({roles:['portal','relay','bridge','portal','bridge']});
  f.data.HyNode.forEach((n,i)=>Object.assign(n,{name:['P','R','B','P2','B2'][i],status:'online',groups:[],mapPosition:{x:120+i*210,y:i>2?340:140}}));
  f.data.RelayL2tpState.push({node:shared.id(2),status:'not_installed',desiredState:'absent',secretRevision:0});
  // Bind the topology serializer and actual nodes-list route to the SAME modeled
  // repositories used by the default-host runtime. No static topology/API JSON.
  for(const [name,file]of [['HyNode','hyNodeModel'],['CascadeLink','cascadeLinkModel']]){
    const model=require('../src/models/'+file);
    for(const method of ['find','findOne','findById'])model[method]=f.models[name][method];
  }
  const Node=require('../src/models/hyNodeModel');
  Node.bulkWrite=async ops=>{for(const {updateOne:o}of ops){const n=f.data.HyNode.find(n=>n._id===o.filter._id);if(n)n.mapPosition={x:o.update.$set['mapPosition.x'],y:o.update.$set['mapPosition.y']};}return {ok:1};};
  const Settings=require('../src/models/settingsModel'); let settings=null;
  Settings.findById=()=>{const q={select:()=>q,lean:async()=>settings};return q;};
  Settings.findByIdAndUpdate=async(_id,u)=>{settings={networkMap:{internetPosition:u.$set['networkMap.internetPosition']}};};
  const host=f.host(); shared.provider.installActiveHost(host);
  const app=express(),requests=[];let dropDeleteResponse=false;
  app.disable('x-powered-by'); app.use(express.json());
  app.use((req,res,next)=>{
    if(!['127.0.0.1','::ffff:127.0.0.1'].includes(req.socket.remoteAddress))return res.sendStatus(403);
    req.session={authenticated:true}; // synthetic fixture identity, no login or real account
    const row={at:Date.now(),method:req.method,path:req.path,key:req.get('Idempotency-Key')||null,
      body:req.body&&Object.fromEntries(Object.entries(req.body).filter(([k])=>['name','mode','portalNodeId','bridgeNodeId','tunnelPort','autoDeploy','expectedTopologyRevision','linkId','anchorLinkId','fullSync'].includes(k)))};
    requests.push(row);
    const json=res.json.bind(res);res.json=value=>{
      row.status=res.statusCode;row.result=Object.fromEntries(Object.entries(value||{}).filter(([k])=>['createdLinkId','linkId','desiredSaved','acceptedTopologyRevision','applicationState','job','autoDeployJob','operationId','status','kind','routeState','phase','error'].includes(k)));
      if(dropDeleteResponse && req.method==='DELETE'){row.droppedAfterRealRoute=true;req.socket.destroy();return res;}
      return json(value);
    };res.on('finish',()=>{row.status=res.statusCode;});next();
  });
  const next=(req,res,next)=>next();
  app.use('/api/cascade/links',createCascadeLinksRouter({Link:f.models.CascadeLink,Node:f.models.HyNode,
    TopologyState:f.models.CascadeTopologyState,ClientProofOperation:f.models.TopologyOperation,
    topologyDraftWriteService:new TopologyDraftWriteService({repository:new TopologyDraftRepository(f.models)}),
    deploymentEnv:shared.env,portCheckSSH:class{constructor(){throw Error('Real SSH disabled in modeled browser fixture');}},
    maintainAutoL2tpPathsFn:async()=>{},invalidateSubscriptions:async()=>{},invalidateTopology:async()=>{}}));
  app.use('/api/cascade/topology',createCascadeTopologyDeployRouter({models:f.models,deploymentEnv:shared.env,
    requireAuth:next,requireScope:()=>next,csrf:next,deployRateLimiter:next,operationStatusRateLimiter:next}));
  // Remaining actual cascade routes are read-only graph and positions only.
  const cascade=require('../src/routes/cascade');
  app.use('/api/cascade',(req,res,next)=>{if((req.method==='GET'&&req.path==='/topology')||(req.method==='POST'&&req.path==='/topology/positions'))return cascade(req,res,next);return res.sendStatus(403);});
  const nodes=require('../src/routes/nodes');
  app.use('/api/nodes',(req,res,next)=>req.method==='GET'&&req.path==='/'?nodes(req,res,next):res.sendStatus(403));
  app.use(express.static(path.join(root,'public'),{etag:true,maxAge:0}));
  app.get('/panel/nodes',async(req,res,next)=>{try{
    const locale=['ru','en'].includes(req.query.lang)?req.query.lang:'ru';
    const dict=require('../src/locales/'+locale+'.json');
    const t=k=>k.split('.').reduce((a,b)=>a?.[b],dict)??k;
    const html=await ejs.renderFile(path.join(root,'views/nodes.ejs'),{
      nodes:f.data.HyNode,groups:[],linksCount:f.data.CascadeLink.length,ipProtocolCount:{},
      panelDomain:'panel.test.invalid',csrfToken:'synthetic-fixture-csrf',loadBalancingEnabled:false,t,
    });
    const layout=await ejs.renderFile(path.join(root,'views/layout.ejs'),{lang:locale,title:'Any-order local synthetic fixture',page:'nodes',content:html,t});
    res.type('html').send(layout);
  }catch(e){next(e);}});
  app.use((e,req,res,next)=>{console.error('App fixture route error',e);res.status(500).json({error:{code:'FIXTURE_ERROR',message:e.message}});});
  const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
  const observedGates=new WeakSet();
  function observeGates(){for(const d of f.deployments){const gate=d.operationWorker.pppReadinessGate;
    if(gate&&!observedGates.has(gate)){observedGates.add(gate);const verify=gate.verifyPlan;
      gate.verifyPlan=async function(plan){const result=await verify.call(this,plan);
        if(result?.ok!==true)diagnostics.push({action:'observer.ppp',kind:plan.kind,linkId:plan.linkId,routeState:plan.routeState,result});
        return result;};
    }
  }}
  const origin='http://127.0.0.1:'+server.address().port;
  return {f,host,server,origin,requests,id:shared.id,dropNextDelete(){dropDeleteResponse=true;},stopDroppingDelete(){dropDeleteResponse=false;},
    async tick(){observeGates();await shared.settleTick(f);await shared.settleTick(f);},
    summary(){return {revision:f.data.CascadeTopologyState[0].revision,
      links:f.data.CascadeLink.map(l=>({id:l._id,name:l.name,portalNode:l.portalNode,bridgeNode:l.bridgeNode,status:l.status,mode:l.mode,port:l.tunnelPort,lifecycle:l.lifecycle})),
      jobs:f.data.TopologyCreateIntent.map(j=>({id:j._id,kind:j.kind,linkId:j.linkId,status:j.status,operationId:j.operationId,waitingReason:j.waitingReason,error:j.error})),
      operations:f.data.TopologyOperation.map(o=>({id:o._id,kind:o.kind,linkId:o.linkId,status:o.status,routeState:o.routeState,staged:o.staged,
        heldTopologyAdmission:o.heldTopologyAdmission,error:o.error,failure:o.failure,nodeErrors:o.nodes?.filter(n=>n.error).map(n=>({node:n.node,error:n.error})),effectiveLinkIds:o.effectiveTopology?.links.map(l=>l.id)})),
      locks:f.data.NodeOperationLock.map(l=>({node:l.node,operationId:l.operationId})),diagnostics,executorCalls:f.calls.map(([phase,n])=>({phase,node:n.node,nodeRef:n.nodeRef,profile:n.targetProfile,candidateHash:n.candidateHash})),errors:f.errors};},
    async close(){await host.stop();shared.provider.clearActiveHost(host);await require('../src/services/sshPoolService').closeAll();
      await new Promise(resolve=>server.close(resolve));return {address:origin,listening:server.listening};},sha};
}
module.exports={createApp,sha};
