'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const configPath=require.resolve('../../../../config');
require.cache[configPath]={id:configPath,filename:configPath,loaded:true,exports:{panel:{domain:'reverse-domain.invalid'},xray:{}}};
const {compileTopology}=require('../domain/topologyCompiler');
const {composeFrozenTopologyDeploymentPlan}=require('../services/frozenTopologyDeploymentPlanComposer');
function fixture(mode='reverse',domains=['full:one.one.one.one']){
 const nodes=[['p','portal'],['r','relay'],['b','bridge'],['g','bridge']].map(([id,role],index)=>({id,role,active:true,type:'xray',ip:`192.0.2.${index+1}`,port:24443,xray:{security:'none',transport:'tcp'}}));
 const links=[{id:'pr',source:'p',target:'r',mode,tunnelPort:24102},{id:'rb',source:'r',target:'b',mode:'reverse',tunnelPort:24103},{id:'rg',source:'r',target:'g',mode:'reverse',tunnelPort:24101,geoRouting:{enabled:true,domains,geoip:domains.length?[]:['ru']}}].map((x,i)=>({...x,tunnelUuid:`00000000-0000-4000-8000-${String(i+1).padStart(12,'0')}`,tunnelProtocol:'vless',tunnelSecurity:'none',tunnelTransport:'tcp',priority:i===2?20:10}));
 return {nodes,links,groups:[]};
}
function compose(snapshot,baselineTopology){return composeFrozenTopologyDeploymentPlan({snapshot,baselineTopology,compiledTopology:compileTopology(snapshot),staged:true,hopByHop:true,nodeMetadata:snapshot.nodes,linkMetadata:snapshot.links,linkRefsById:new Map(snapshot.links.map(x=>[x.id,x.id]))});}
function config(plan,id){return JSON.parse(Buffer.from(plan.nodes.find(x=>x.node===id).candidate.bytes));}
test('reverse transit preserves sniffed VLESS hostname as destination for downstream domain geo selection',()=>{
 const f=fixture(),before=structuredClone(f);const c=config(compose(f),'p'),i=c.inbounds.find(x=>x.tag==='vless-in');assert.equal(i.sniffing.enabled,true);assert.equal(i.sniffing.routeOnly,false,'route-only sniff metadata is not carried across the reverse mux');assert.deepEqual(f,before);
});
test('verified profile preservation still applies reverse-domain propagation without replacing client credentials',()=>{
 const baseline=fixture();const old=compose(baseline);for(const n of baseline.nodes)n.profileConfig=config(old,n.id);
 const client=baseline.nodes[0].profileConfig.inbounds.find(x=>x.tag==='vless-in');client.sniffing.routeOnly=true;client.settings.clients=[{id:'11111111-1111-4111-8111-111111111111',email:'kept@invalid'}];
 const after=structuredClone(baseline),out=config(compose(after,baseline),'p'),i=out.inbounds.find(x=>x.tag==='vless-in');assert.equal(i.sniffing.routeOnly,false);assert.deepEqual(i.settings.clients,client.settings.clients);
});
for(const [mode,domains]of [['forward',['full:one.one.one.one']],['reverse',[]]])test(`does not change portal destination semantics for ${mode} / ${domains.length?'domain':'geoip-only'}`,()=>{const f=fixture(mode,domains);assert.equal(config(compose(f),'p').inbounds.find(x=>x.tag==='vless-in').sniffing.routeOnly,true);});
test('dedicated guest layout lets non-root resolver traverse etc without listing directories or exposing secret files',()=>{
 const {spawnSync}=require('node:child_process'),path=require('node:path');
 const script=path.resolve(__dirname,'../../../../scripts/topology-test-dedicated-layout.py');
 const code=`import os,tempfile,runpy,stat\nwith tempfile.TemporaryDirectory(prefix='c3-dns-layout-',dir=os.environ['TMPDIR']) as root:\n os.mkdir(root+'/etc',0o700)\n with open(root+'/etc/secret','w') as f:f.write('kept-secret')\n os.chmod(root+'/etc/secret',0o600)\n runpy.run_path(${JSON.stringify(script)})['produce'](root)\n assert stat.S_IMODE(os.stat(root+'/etc').st_mode)==0o711\n assert stat.S_IMODE(os.stat(root+'/etc/secret').st_mode)==0o600\n assert open(root+'/etc/secret').read()=='kept-secret'\n`;
 const result=spawnSync('python3',['-I','-B','-c',code],{encoding:'utf8'});assert.equal(result.status,0,result.stderr);
});
