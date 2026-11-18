'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { composeRebuildProfiles } = require('../services/rebuildTopologyComposer');
const node=(id,role,n)=>({_id:id,cascadeRole:role,type:'xray',active:true,ip:`192.0.2.${n}`,port:22000+n,xray:{inboundTag:'client',security:'none',transport:'tcp',apiPort:31000+n}});
const nodes=[node('r','relay',1),node('a','bridge',2),node('b','bridge',3)];
const edge=(key,id,n,extra)=>({_id:key,portalNode:'r',bridgeNode:id,tunnelPort:20000+n,tunnelUuid:`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`,...extra});
const state={node:'r',routingMode:'follow-relay',routingVersion:1,status:'installed',desiredState:'installed',routeGroup:'retained',secretRevision:2,tproxyPort:32120};
const compile=links=>composeRebuildProfiles({nodes,links,followRelayStates:[state],controlPlaneAddresses:['panel.invalid','192.0.2.1']}).find(p=>p.nodeId==='r'&&p.profile==='main').config;
test('installed PPP honors the relay subscriber deny rules before geo and default',()=>{
 const relay={...nodes[0],aclRules:['reject(full-deny.invalid)','reject(all)']};
 const profiles=composeRebuildProfiles({nodes:[relay,...nodes.slice(1)],links:[edge('default','a',1)],followRelayStates:[state],controlPlaneAddresses:['panel.invalid']});
 const main=profiles.find(p=>p.nodeId==='r'&&p.profile==='main').config;
 const rules=main.routing.rules, firstPolicy=rules.findIndex(rule=>rule.ruleTag==='rebuild-policy-default');
 const denies=rules.filter(rule=>rule.outboundTag==='block'&&rule.inboundTag?.includes('client'));
 assert.equal(denies.length,2);for(const rule of denies){assert.ok(rule.inboundTag.includes('rebuild-relay-ingress'));assert.ok(!rule.inboundTag.includes('API_INBOUND'));assert.ok(rules.indexOf(rule)<firstPolicy);}
});
test('real graph owns a stable local SOCKS and one policy for PPP plus ordinary relay clients',()=>{
 const first=compile([edge('default','a',1),edge('geo','b',2,{geoRouting:{enabled:true,domains:['full:geo.invalid'],geoip:['ru']}})]), next=compile([edge('replacement','b',3)]), closed=compile([]);
 for(const cfg of [first,next,closed]){
  const socks=cfg.inbounds.find(i=>i.tag==='rebuild-relay-ingress'); assert.ok(socks); assert.equal(socks.listen,'127.0.0.1'); assert.equal(socks.sniffing.enabled,true);
  assert.equal(cfg.inbounds.find(i=>i.tag==='relay-l2tp-retained').port,32120);
  const p=cfg.routing.rules.filter(r=>r.ruleTag?.startsWith('rebuild-policy-')); assert.ok(p.every(r=>r.inboundTag.includes('client')&&r.inboundTag.includes(socks.tag)));assert.equal(cfg.outbounds[0].protocol,'blackhole');
  const ppp=cfg.routing.rules.filter(r=>r.inboundTag?.includes('relay-l2tp-retained'));assert.equal(ppp.at(-1).outboundTag,'rebuild-l2tp-handoff');assert.ok(ppp.some(r=>r.ip?.includes('geoip:private')));assert.equal(cfg.outbounds.find(o=>o.tag==='rebuild-l2tp-handoff').settings.servers[0].port,socks.port);
 }
 const port=c=>c.inbounds.find(i=>i.tag==='rebuild-relay-ingress').port; assert.equal(port(first),port(next)); assert.equal(port(first),port(closed));
 assert.deepEqual(first.routing.rules.filter(r=>r.ruleTag?.startsWith('rebuild-policy-')).map(r=>r.outboundTag),['portal-geo','portal-geo','portal-default']);
 const fallback=c=>c.routing.rules.find(r=>r.ruleTag==='rebuild-policy-default').outboundTag;
 assert.equal(fallback(next),'portal-lacement');assert.equal(fallback(closed),'block');
});
