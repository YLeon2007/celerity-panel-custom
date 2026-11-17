'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { buildL2tpXrayFragment } = require('../services/l2tpXrayFragmentProvider');
const { composeTopologyL2tpMainFragment, validateTopologyL2tpWrite } = require('../services/topologyL2tpInstallComposition');
const context = { target: 'test', hostIdentity: 'test.infograd.online' };
const plan = { operationId: 'install1', relayId: 'relay1', routeGroupId: 'group1', selectedPathKey: 'main', nextHopNodeId: 'bridge1', topologyRevision: 2, desired: { tproxyPort: 12345 } };
const snapshot = { plan: { relay: { controlPlaneIps: ['192.0.2.1'] }, group: { id: 'group1' }, paths: [{ pathKey: 'main', healthy: true, outboundTag: 'cascade-main' }], selectedPathKey: 'main' }, tags: { inbound: 'relay-l2tp-group1', blockOutbound: 'block' }, tproxyPort: 12345 };
function fixture() {
 const config = { inbounds: [], outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }, { tag: 'fwd-one', protocol: 'vless', settings: { vnext: [{ address: '192.0.2.2', port: 24101, users: [{ id: 'existing' }] }] } }], routing: { rules: [] } };
 const hash = createHash('sha256').update(JSON.stringify(config)).digest('hex');
 return { config, hash, owner: { node: 'relay1', profile: 'xray-bridge', owner: 'topology', generation: 'owner1', executionContext: context, lastSettledOperation: 'topology1', lastSettledGeneration: 'generation1', lastSettledCloseId: 'close1' }, mainOwners: [], scope: { operationId: 'install1', owner: 'worker1' }, operation: { _id: 'install1', node: 'relay1', kind: 'install', status: 'running', admissionId: 'admission1', leaseOwner: 'worker1', ownerGeneration: 2, executionContext: context, plan }, admission: { _id: 'admission1', nodeId: 'relay1', kind: 'install', phase: 'running', operationId: 'install1', leaseOwner: 'worker1', ownerGeneration: 2 }, gate: { revision: 2, topologyAdmissionCount: 0, remoteAdmissionCount: 1 }, settled: { _id: 'topology1', status: 'succeeded', heldTopologyAdmission: false, executionContext: context, nodes: [{ node: 'relay1', targetProfile: 'xray-bridge', state: 'committed', candidateHash: hash }], v2Terminal: { state: 'proven', bindings: [{ nodeId: 'relay1', generation: 'generation1', commandIds: { close: 'close1' } }], proofs: [{ nodeId: 'relay1', commandId: 'close1', terminalOutcome: 'verified', completion: 'completed' }], ownerFences: [{ node: 'relay1', profile: 'xray-bridge', generation: 'owner1' }] } } };
}
test('first topology-owned L2TP install has MAIN-only write authority, not a classic sidecar bypass', () => {
 const f = fixture(); assert.equal(validateTopologyL2tpWrite({ ...f, plan, executionContext: context }), true);
 for (const change of [x => x.mainOwners.push({ owner: 'topology' }), x => x.admission.phase = 'completed', x => x.scope.operationId = 'foreign', x => x.settled.heldTopologyAdmission = true, x => x.owner.generation = 'foreign', x => x.gate.revision++, x => x.operation.status = 'failed']) {
  const bad = fixture(); change(bad); assert.throws(() => validateTopologyL2tpWrite({ ...bad, plan, executionContext: context }), { code: 'TOPOLOGY_L2TP_WRITE_UNAVAILABLE' });
 }
});
test('MAIN-only repair binds the actual standalone admission and exact narrow persisted steps', () => {
 const f = fixture(), repairPlan = { ...plan, steps: ['backup','compose_xray_fragment','validate_xray','activate_xray'].map(type => ({ type })) };
 f.operation.kind = 'repair'; f.operation.plan = repairPlan;
 f.scope.standaloneAdmissionId = 'admission1';
 f.admission = { _id:'admission1',nodeId:'relay1',kind:'standalone_preflight',phase:'running',ownerGeneration:1 };
 assert.equal(validateTopologyL2tpWrite({ ...f, plan:repairPlan, executionContext:context, normalization:true }),true);
 for (const mutate of [x=>delete x.scope.standaloneAdmissionId,x=>x.admission.operationId='install1',x=>x.operation.kind='install']) {
  const bad=structuredClone(f);mutate(bad);assert.throws(()=>validateTopologyL2tpWrite({...bad,plan:repairPlan,executionContext:context,normalization:true}),{code:'TOPOLOGY_L2TP_WRITE_UNAVAILABLE'});
 }
});
// The live MAIN refusal used a successful full domain.reconcile operation. Unlike
// selected operations its persisted contract has no effectiveTopology at all.
async function fullReconcilePreparation(mutate = () => {}) {
 const { createTopologyL2tpInstallComposition } = require('../services/topologyL2tpInstallComposition');
 const { withHeldL2tpNodeConfigWrite } = require('../../../services/classicNodeConfigWrite');
 const { NodeOperationLockService } = require('../services/nodeOperationLockService');
 const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');
 const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
 const f = fixture(), p = { ...plan, steps: ['backup','compose_xray_fragment','validate_xray','activate_xray'].map(type => ({type})) };
 f.config.inbounds.push({tag:'cascade-main',listen:'127.0.0.1',port:cascadePathIngressPort('group1','main'),protocol:'socks',settings:{auth:'noauth',udp:true,ip:'127.0.0.1'}});
 f.config.routing.rules.push({type:'field',inboundTag:['cascade-main'],outboundTag:'fwd-one'});
 let live = JSON.stringify(f.config);
 f.settled.kind = 'domain.reconcile'; f.settled.topologyRevision = 2; f.settled.linkIds = ['link1'];
 f.settled.nodes[0].candidateHash = createHash('sha256').update(live).digest('hex');
 f.settled.nodes[0].candidate = {bytes:[...Buffer.from(live)],sha256:f.settled.nodes[0].candidateHash};
 f.operation.kind='repair'; f.operation.plan=p;
 f.admission={_id:'admission1',nodeId:'relay1',kind:'standalone_preflight',phase:'running',ownerGeneration:1};
 const group={paths:[{pathKey:'main',enabled:true,linkIds:['link1']}]};
 const q=value=>({select(){return this;},setOptions(){return this;},async lean(){return value;}});
 const db={}, clock={now:()=>new Date()}, lock={node:'relay1',owner:'worker1',operationId:'install1',generation:'g1',remoteUncertain:true,leaseUntil:new Date(Date.now()+120000)};
 const admissions=Object.assign(Object.create(RemoteAdmissionRepository.prototype),{RemoteAdmission:{db,findOne:()=>q(f.admission)},CascadeTopologyState:{db}});
 const lockService=new NodeOperationLockService({repository:{model:{db},async findByNode(){return lock;}},clock});
 const m={Owner:{find:()=>q([f.owner])},Operation:{findById:()=>q(f.operation)},State:{findById:()=>q(f.gate)},Admission:{findById:()=>q(f.admission)},TopologyOperation:{findById:()=>q(f.settled)},Group:{findById:()=>q(group)}};
 mutate({f,p,group,setLive(value){live=value;}});
 const composition=createTopologyL2tpInstallComposition({env:{PANEL_DOMAIN:context.hostIdentity},models:m,readConfig:async()=>live});
 return withHeldL2tpNodeConfigWrite({lock,lockService,clock,standaloneAdmission:{id:'admission1',repository:admissions}},()=>composition.prepare(p,{normalization:true}));
}
test('actual held preparation accepts settled full reconcile without selected-only effectiveTopology',async()=>{
 const value=await fullReconcilePreparation(); assert.equal(value.groupId,'group1'); assert.equal(value.pathKey,'main');
 assert.equal(value.topologyConfig.inbounds[0].protocol,'socks');
});
test('full reconcile preparation still rejects stale revision, foreign path, changed bytes and absent live ingress',async()=>{
 for(const mutate of [({f})=>f.settled.topologyRevision++,({group})=>group.paths[0].linkIds=['foreign'],({setLive})=>setLive('{}'),({f})=>f.settled.kind='link.apply',({f})=>f.settled.nodes[0].candidate.sha256='foreign',({f,setLive})=>{f.config.inbounds=[];const b=JSON.stringify(f.config);setLive(b);f.settled.nodes[0].candidateHash=createHash('sha256').update(b).digest('hex');f.settled.nodes[0].candidate={bytes:[...Buffer.from(b)],sha256:f.settled.nodes[0].candidateHash};}]) {
  await assert.rejects(fullReconcilePreparation(mutate),{code:'TOPOLOGY_L2TP_PATH_UNAVAILABLE'});
 }
});
test('selected settled descriptor compiles its real explicit primary path before L2TP preparation', async () => {
 const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');
 const { compileConfiguredTopology } = require('../domain/primaryReservePolicy');
 const node = (id, role, ip) => ({ id, role, type:'xray',active:true,cascadeRole:role,ip,port:24443,
  xray:{apiPort:24441,inboundTag:'vless-in',transport:'tcp',security:'none'} });
 const topology={nodes:[node('portal1','portal','192.0.2.3'),node('relay1','relay','192.0.2.1'),node('bridge1','bridge','192.0.2.2')],
  links:[{id:'prefix1',source:'portal1',target:'relay1',mode:'forward',active:true,status:'deployed',
   tunnelPort:24102,tunnelUuid:'00000000-0000-4000-8000-000000000002',tunnelProtocol:'vless',
   tunnelSecurity:'none',tunnelTransport:'tcp',tunnelDomain:'prefix.tunnel.internal',priority:10,
   geoRouting:{enabled:false,domains:[],geoip:[]}},
   {id:'link1',source:'relay1',target:'bridge1',mode:'forward',active:true,status:'deployed',
   tunnelPort:24101,tunnelUuid:'00000000-0000-4000-8000-000000000001',tunnelProtocol:'vless',
   tunnelSecurity:'none',tunnelTransport:'tcp',tunnelDomain:'reverse.tunnel.internal',priority:10,
   geoRouting:{enabled:false,domains:[],geoip:[]}}],
  groups:[{_id:'group1',mode:'forward',strategy:'priority-failover',paths:[{pathKey:'main',linkIds:['link1'],priority:1,enabled:true}]}]};
 const generated=composeFrozenTopologyDeploymentPlan({snapshot:topology,nodeMetadata:topology.nodes,
  linkMetadata:topology.links,compiledTopology:compileConfiguredTopology(topology)});
 const rows=generated.nodes.map(row=>({...row,state:'committed',candidateHash:row.candidate.sha256}));
 const relay=rows.find(row=>row.node==='relay1'), live=Buffer.from(relay.candidate.bytes).toString('utf8');
 const result=await fullReconcilePreparation(({f,group,setLive})=>{
  f.settled.effectiveTopology=topology;f.settled.kind='link.apply';f.settled.nodes=rows;
  Object.assign(group,topology.groups[0]);setLive(live);
 });
 assert.equal(result.groupId,'group1');assert.equal(result.pathKey,'main');
 assert.deepEqual(result.topologyConfig,JSON.parse(live));
});
for (const mode of ['forward', 'reverse']) test(`${mode}: MAIN stays stable across selected suffix changes; live ingress is mandatory`, () => {
 const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
 const f = fixture(), fragment = buildL2tpXrayFragment(snapshot);
 f.config.inbounds.push({ tag: 'cascade-main', listen: '127.0.0.1', port: cascadePathIngressPort('group1', 'main'), protocol: 'socks', settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' } });
 if (mode === 'reverse') f.config.reverse = { portals: [{ tag: 'portal-one', domain: 'one.internal' }] };
 f.config.routing.rules.push({ type: 'field', inboundTag: ['cascade-main'], outboundTag: mode === 'reverse' ? 'portal-one' : 'fwd-one' });
 const compose = config => composeTopologyL2tpMainFragment({ fragment, topologyConfig: config, groupId: 'group1', pathKey: 'main' });
 const before = JSON.stringify(f.config), first = compose(f.config);
 assert.deepEqual(first, fragment); assert.equal(JSON.stringify(f.config), before);
 const changed = structuredClone(f.config);
 if (mode === 'forward') changed.outbounds[2].settings.vnext[0].address = '192.0.2.3';
 else changed.reverse.portals[0].domain = 'two.internal';
 assert.deepEqual(compose(changed), first); assert.equal(first.reverse, undefined);
 for (const mutate of [c => c.inbounds = [], c => c.inbounds[0].port++, c => c.routing.rules[0].outboundTag = 'direct', c => c.routing.rules.unshift({ type: 'field', outboundTag: 'direct' })]) {
  const bad = structuredClone(f.config); mutate(bad);
  assert.throws(() => compose(bad), { code: 'TOPOLOGY_L2TP_PATH_UNAVAILABLE' });
 }
});
