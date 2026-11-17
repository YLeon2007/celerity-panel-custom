'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process'),{createHash}=require('node:crypto');
const runner=path.join(__dirname,'../node-artifacts/topology/runner.sh');
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'retained-verify-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const put=(p,b,m=0o600)=>{p=path.join(root,p);fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,b,{mode:m});};
 const content='{"inbounds":[],"outbounds":[]}\n';const hash='sha256:'+createHash('sha256').update(content).digest('hex');
 put('proc/sys/kernel/random/boot_id','boot-1');put('usr/local/etc/xray/config.json','{"old":true}\n');fs.mkdirSync(path.join(root,'var/lib'),{recursive:true});fs.mkdirSync(path.join(root,'usr/local/share/xray'),{recursive:true});
 put('usr/local/bin/xray','#!/bin/sh\nexit 0\n',0o700);
 put('usr/bin/systemctl',`#!/bin/sh
case "$1" in
restart|stop) printf '%s\\n' "$1" >> "$CELERITY_TOPOLOGY_ROOT/mutations";;
is-active) test ! -e "$CELERITY_TOPOLOGY_ROOT/unhealthy";;
show) printf 'Job=\\nActiveState=active\\nSubState=running\\n';;
esac
`,0o700);
 const b={'operation-id':'op-1','node-id':'node-1','candidate-hash':hash,'backup-id':'backup-1','target-profile':'xray-main','execution-context':'test.infograd.online','attempt-id':'attempt-1','generation':'generation-1','predecessor-generation':'none'};
 const observeId=createHash('sha256').update('topology-retained-verify-v1:verify-1').digest('hex');
 const checks={bootId:'boot-1',originalVerifyId:'verify-1',prepareId:'prepare-1',commitId:'commit-1',checks:[]};
 function run(cmd,extra={}){const a=['--command',cmd];for(const[k,v]of Object.entries({...b,...extra.binding}))a.push('--'+k,v);a.push('--command-id',extra.id|| (cmd==='observe-verify'?observeId:cmd+'-1'));if(cmd==='verify'||cmd==='observe-verify')a.push('--checks',Buffer.from(JSON.stringify(cmd==='verify'?[]:{...checks,...extra.checks})).toString('base64url'));return spawnSync('bash',[runner,...a],{env:{...process.env,CELERITY_TOPOLOGY_ROOT:root},input:content,encoding:'utf8'});}
 const jp=path.join(root,'var/lib/celerity/topology/fences/xray-main/journal.json');const journal=()=>JSON.parse(fs.readFileSync(jp));
 function start(){for(const c of ['prepare','commit']){const r=run(c);assert.equal(r.status,0,r.stderr);}put('unhealthy','1');assert.notEqual(run('verify').status,0);fs.unlinkSync(path.join(root,'unhealthy'));}
 return{root,put,run,start,journal,jp,observeId,content};
}
test('retained verify obtains separate current observation; old UNKNOWN and commit payload remain unchanged; native close succeeds',t=>{
 const f=fixture(t);f.start();const before=f.journal(),old=structuredClone(before.generations['generation-1'].commands['verify-1']);const mutations=fs.readFileSync(path.join(f.root,'mutations'),'utf8');
 const r=f.run('observe-verify');assert.equal(r.status,0,r.stderr);const proof=JSON.parse(r.stdout);assert.equal(proof.command,'observe-verify');assert.equal(proof.originalVerifyId,'verify-1');assert.equal(proof.commandId,f.observeId);assert.equal(proof.phase,'verified');
 assert.deepEqual(f.journal().generations['generation-1'].commands['verify-1'],old);assert.match(f.run('status',{id:'verify-1'}).stderr,/UNKNOWN_COMMAND_OUTCOME/);assert.equal(fs.readFileSync(path.join(f.root,'mutations'),'utf8'),mutations);
 assert.notEqual(f.run('observe-verify').status,0,'no observation replay');const closed=f.run('close');assert.equal(closed.status,0,closed.stderr);assert.equal(JSON.parse(closed.stdout).terminalOutcome,'verified');
});
test('actual factory/typed transport/runner preserve distinct observation provenance',async t=>{
 const f=fixture(t);f.start();const b=f.journal().generations['generation-1'].binding;
 const {TopologyNodeTransportFactory}=require('../services/topologyNodeTransportFactory');
 const transport=await new TopologyNodeTransportFactory({executionContext:'test.infograd.online',nodeExecutionResolver:{resolve:async()=>({exec:async command=>{
  const args=command.split(' ');args.shift();const r=spawnSync('bash',[runner,...args],{env:{...process.env,CELERITY_TOPOLOGY_ROOT:f.root},encoding:'utf8'});return{code:r.status,stdout:r.stdout,stderr:r.stderr};
 }})}}).create({nodeId:b.nodeId,role:'portal'});
 const p=await transport.observeVerify({...b,commandId:f.observeId,observation:{bootId:'boot-1',originalVerifyId:'verify-1',prepareId:'prepare-1',commitId:'commit-1',checks:[]}});
 assert.equal(p.originalVerifyId,'verify-1');assert.equal(p.commandId,f.observeId);assert.equal(p.command,'observe-verify');
 const before=fs.readFileSync(f.jp);
 const status=await transport.observeVerify({...b,commandId:f.observeId,observation:{bootId:'boot-1',originalVerifyId:'verify-1',prepareId:'prepare-1',commitId:'commit-1',checks:[]}},true);
 assert.equal(status.command,'status');assert.equal(status.originalVerifyId,'verify-1');assert.deepEqual(fs.readFileSync(f.jp),before);
});
test('observation refuses unknown mutating command, changed boot/config, wrong provenance; no journal mutation on refusal',t=>{
 for(const fault of ['commit','boot','config','id','checks']){const f=fixture(t);f.start();if(fault==='commit'){const j=f.journal();j.generations['generation-1'].commands['commit-1']={command:'commit',state:'running'};fs.writeFileSync(f.jp,JSON.stringify(j));}if(fault==='config')f.put('usr/local/etc/xray/config.json','changed');const before=fs.readFileSync(f.jp);const r=f.run('observe-verify',fault==='boot'?{checks:{bootId:'foreign'}}:fault==='id'?{id:'foreign'}:fault==='checks'?{checks:{checks:[{type:'shell',command:'true'}]}}:{});assert.notEqual(r.status,0,fault);assert.deepEqual(fs.readFileSync(f.jp),before,fault);}
});
