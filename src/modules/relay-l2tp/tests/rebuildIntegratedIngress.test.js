'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { composeRebuildProfiles, syntheticTunnelSettings } = require('./helpers/rebuildComposerFixture');
const node=(id,role,n)=>({_id:id,cascadeRole:role,type:'xray',active:true,ip:`192.0.2.${n}`,port:22000+n,xray:{inboundTag:'client',security:'none',transport:'tcp',apiPort:31000+n}});
const nodes=[node('r','relay',1),node('a','bridge',2),node('b','bridge',3)];
const edge=(key,id,n,extra)=>({_id:key,portalNode:'r',bridgeNode:id,tunnelPort:20000+n,tunnelUuid:`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`,_rebuildVless:syntheticTunnelSettings(n),...extra});
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
 assert.deepEqual(first.routing.rules.filter(r=>r.ruleTag?.startsWith('rebuild-policy-')).map(r=>r.outboundTag),['rebuild-rp-egress-geo','rebuild-rp-egress-geo','rebuild-rp-egress-default']);
 const fallback=c=>c.routing.rules.find(r=>r.ruleTag==='rebuild-policy-default').outboundTag;
 assert.equal(fallback(next),'rebuild-rp-egress-lacement');assert.equal(fallback(closed),'block');
});

test('mixed portal ingress and local PPP share the selected reverse default and forward geo exits', () => {
    const profiles = composeRebuildProfiles({
        nodes: [...nodes, node('p1', 'portal', 4), node('p2', 'portal', 5)],
        links: [
            edge('reserve', 'b', 1, { mode: 'forward', priority: 70 }),
            edge('up-fwd', 'r', 2, { portalNode: 'p2', mode: 'forward' }),
            edge('geo', 'b', 3, { mode: 'forward', geoRouting: { enabled: true, domains: ['full:geo.invalid'], geoip: ['ru'] } }),
            edge('up-rev', 'r', 4, { portalNode: 'p1' }),
            edge('default', 'a', 5, { priority: 50, tunnelDomain: 'retired-control.invalid' }),
        ],
        followRelayStates: [state], controlPlaneAddresses: ['panel.invalid'],
    });
    const config = (nodeId, profile = 'main') => profiles.find(p => p.nodeId === nodeId && p.profile === profile).config;
    const firstMatch = (cfg, inbound, dest) => cfg.routing.rules.find(rule => rule.inboundTag?.includes(inbound)
        && (!rule.domain || rule.domain.includes(dest)) && (!rule.ip || rule.ip.includes(dest)))?.outboundTag ?? cfg.outbounds[0].tag;
    const relay = config('r');
    const upstream = relay.outbounds.find(o => o.tag === 'rebuild-rp-dial-up-rev');
    assert.equal(firstMatch(config('p1'), 'client'), 'rebuild-rp-egress-up-rev');
    assert.equal(firstMatch(config('p2'), 'client'), 'fwd-up-fwd');
    for (const ingress of [upstream.settings.reverse.tag, 'fwd-hop-up-fwd', 'client', 'rebuild-relay-ingress']) {
        assert.equal(firstMatch(relay, ingress, 'full:geo.invalid'), 'fwd-geo');
        assert.equal(firstMatch(relay, ingress, 'geoip:ru'), 'fwd-geo');
        assert.equal(firstMatch(relay, ingress, 'full:somewhere.invalid'), 'rebuild-rp-egress-default');
    }
    assert.equal(firstMatch(relay, 'rebuild-rp-conn-default'), 'block');
    assert.equal(firstMatch(relay, 'relay-l2tp-retained'), 'rebuild-l2tp-handoff');
    assert.equal(firstMatch(relay, 'rebuild-relay-ingress', 'full:panel.invalid'), 'rebuild-l2tp-block');

    const exitA = config('a', 'bridge');
    const connector = relay.inbounds.find(i => i.tag === 'rebuild-rp-conn-default');
    const native = exitA.outbounds.find(o => o.tag === 'rebuild-rp-dial-default');
    assert.equal(connector.settings.clients[0].reverse.tag, 'rebuild-rp-egress-default');
    assert.equal(native.settings.address, nodes[0].ip);
    assert.equal(native.settings.port, connector.port);
    assert.equal(native.settings.id, connector.settings.clients[0].id);
    const exitB = config('b', 'bridge');
    const forward = relay.outbounds.find(o => o.tag === 'fwd-geo').settings.vnext[0];
    const forwardListener = exitB.inbounds.find(i => i.tag === 'fwd-hop-geo');
    assert.equal(forward.address, nodes[2].ip);
    assert.equal(forward.port, forwardListener.port);
    for (const [exit, ingress] of [[exitA, native.settings.reverse.tag], [exitB, forwardListener.tag]]) {
        assert.equal(firstMatch(exit, ingress), 'freedom');
        assert.equal(firstMatch(exit, ingress, 'geoip:private'), 'block');
        assert.equal(firstMatch(exit, 'unknown'), 'block');
    }
    for (const { config: cfg } of profiles) {
        assert.equal(cfg.reverse, undefined);
        assert.equal(cfg.routing.balancers, undefined);
        assert.ok(!cfg.routing.rules.some(rule => rule.domain?.includes('full:retired-control.invalid')));
    }
    for (const id of ['a', 'b']) assert.equal(firstMatch(config(id), 'client'), 'block');
    assert.equal(config('r', 'bridge').outbounds.length, 1);
});
