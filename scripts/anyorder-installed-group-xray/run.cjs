'use strict';
// REAL public import producer + generator/materializer/executor/SSH/runner/Xray.
// SYNTHETIC local query persistence, external maintenance and binding authority.
// No native physical controller, Mongo, HTTP jobs, worker or PPP acceptance.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {createHash, randomUUID, randomBytes} = require('node:crypto');
const {model} = require('./owner-model.cjs');
const root = process.env.C3_CANDIDATE_ROOT, work = process.env.C3_FIXTURE_WORK;
const candidate = name => require(path.join(root, name));
const generator = candidate('src/services/configGenerator');
const {TopologyConfigTransfer, verifyLegacyAppliedProfile} = candidate('src/services/topologyConfigTransfer');
const {TEST_TOPOLOGY_EXECUTION_CONTEXT: context} = candidate('src/modules/relay-l2tp/domain/topologyExecutionContext');

const {TopologyOperationPlanMaterializer} = candidate('src/modules/relay-l2tp/services/topologyOperationPlanMaterializer');
const {compileTopology} = candidate('src/modules/relay-l2tp/domain/topologyCompiler');
const {TopologyOperationExecutor, isTopologyTerminalProof} = candidate('src/modules/relay-l2tp/services/topologyOperationExecutor');
const {TOPOLOGY_RUNNER_PATH, TOPOLOGY_RUNNER_SHA256} = candidate('src/modules/relay-l2tp/services/topologyRunnerBootstrapper');
const NodeSSH = candidate('src/services/nodeSSH');
const cfg = JSON.parse(fs.readFileSync(path.join(work, 'fixture.private.json')));
const copy = value => structuredClone(value);
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const sha = value => createHash('sha256').update(value).digest('hex');
const shell = value => "'" + value.replaceAll("'", "'\\''") + "'";
const save = (name, value) => fs.writeFileSync(path.join(work, name), JSON.stringify(value, null, 2) + '\n');
const ledger = row => fs.appendFileSync(path.join(work, 'cases.jsonl'), JSON.stringify({...row, scenario: cfg.scenario}) + '\n');
const connections = new Map(), heads = new Map(), originals = new Map();
let label = 'setup', sequence = 0, selectedOwners;
function causal(error) { return {name: error.name, code: error.code, message: error.message.slice(0, 2000),
    uncertain: error.remoteOutcomeUncertain, ...(error.cause ? {cause: causal(error.cause)} : {})}; }
async function exec(id, command, options) {
    const result = await connections.get(id).exec('env GOMAXPROCS=2 sh -c ' + shell(command), options);
    const action = command.match(/--command ([a-z-]+)/)?.[1] || (command.startsWith('curl ') ? 'http-probe' : 'fixture-read-or-setup');
    let receipt;
    if (command.includes('--command ')) { try { receipt = JSON.parse(result.stdout); } catch {} }
    if (receipt) fs.appendFileSync(path.join(work, 'runner-responses.jsonl'), JSON.stringify({label, node: id, action, raw: result.stdout, sha256: sha(result.stdout)}) + '\n');
    fs.appendFileSync(path.join(work, 'ssh-commands.private.jsonl'), JSON.stringify({label, node: id, command, code: result.code}) + '\n');
    fs.appendFileSync(path.join(work, 'ssh-exits.jsonl'), JSON.stringify({label, node: id, action, code: result.code,
        stdoutSha256: sha(result.stdout || ''), stderr: result.stderr.slice(0, 2000), ...(receipt ? {receipt} : {})}) + '\n');
    return result;
}
async function ok(id, command, options) {
    const r = await exec(id, command, options);
    assert.equal(r.code, 0, `node=${id} command=${command.split(' ')[0]} stderr=${r.stderr}`);
    return r.stdout;
}
async function profile(id, name) {
    const service = name === 'main' ? 'xray' : 'xray-bridge';
    const config = await ok(id, `cat /usr/local/etc/${service}/config.json`);
    const unit = await ok(id, `cat /etc/systemd/system/${service}.service`);
    const identity = await ok(id, `stat -c '%i' /usr/local/etc/${service}/config.json; systemctl show ${service}.service -p MainPID -p ExecMainStartTimestampMonotonic -p NRestarts -p ActiveState -p SubState; systemctl is-enabled ${service}.service`);
    assert.match(identity, /ActiveState=active/); assert.match(identity, /SubState=running/);
    assert.match(identity, /MainPID=[1-9][0-9]*/); assert.match(identity, /enabled/);
    return {config, unit, identity};
}
const {projectGroups} = candidate('src/modules/relay-l2tp/domain/topologyDraft');
const {buildL2tpXrayFragment} = candidate('src/modules/relay-l2tp/services/l2tpXrayFragmentProvider');
const {finishClassicConfigRouting} = candidate('src/services/classicL2tpConfigComposition');
const nodes = Object.entries(cfg.nodes).map(([id,n]) => ({id:n.nodeId,role:n.role,type:'xray',active:true,ip:n.ip,port:24443,
    xray:{protocol:'vless',inboundTag:'client-in',security:'none',transport:'tcp',extraInbounds:[]}}));
const selected = id => id === 'p' ? 'main' : 'sidecar';
const independent = id => id === 'p' ? 'sidecar' : 'main';
const target = id => selected(id) === 'main' ? 'xray-main' : 'xray-bridge';
const short = nodeId => Object.entries(cfg.nodes).find(([,n]) => n.nodeId === nodeId)[0];
const metadata = node => ({...copy(node),_id:node.id,cascadeRole:node.role});
const u = {id:randomBytes(12).toString('hex'),source:cfg.nodes.p.nodeId,target:cfg.nodes.r.nodeId,mode:'reverse',active:true,priority:1,
    tunnelProtocol:'vless',tunnelPort:25000,tunnelUuid:randomUUID(),tunnelSecurity:'none',tunnelTransport:'tcp',tunnelDomain:'installed-group.invalid'};
const d = {...copy(u),id:randomBytes(12).toString('hex'),source:cfg.nodes.r.nodeId,target:cfg.nodes.b.nodeId,tunnelPort:25001,tunnelUuid:randomUUID()};
const group = projectGroups([{_id:randomBytes(12).toString('hex'),mode:'reverse',strategy:'priority-failover',
    paths:[{pathKey:'legacy-main',linkIds:[d.id],priority:4,enabled:true}]}])[0];
const ingress = group.paths[0].cascadePathIngress;
let state = {nodes,links:[u,d],groups:[copy(group)]};
// These are protected synthetic PRE-EXISTING metadata, not node/PPP proof.
const modeledInventory = {label:'MODELED_PREEXISTING_LEGACY_INVENTORY',state:{node:cfg.nodes.r.nodeId,routeGroup:group._id,
    activePathKey:'legacy-main',status:'installed',desiredState:'installed',secretRevision:41,appliedTopologyRevision:7,
    pskEncrypted:'fixture-synthetic-'+randomBytes(24).toString('hex'),clientCidr:'10.255.30.0/24',localAddress:'10.255.30.1',
    poolStart:'10.255.30.10',poolEnd:'10.255.30.250',dnsServers:['1.1.1.1'],tproxyPort:12345,fwmark:100,routeTable:100,mtu:1400,mru:1400},
    users:[{id:randomBytes(12).toString('hex'),login:'fixture-'+randomBytes(8).toString('hex'),passwordEncrypted:randomBytes(24).toString('hex'),
        ip:'10.255.30.10',enabled:true,desiredRevision:41,appliedRevision:41,syncStatus:'synced'}]};
const inventoryHash=sha(JSON.stringify(modeledInventory));
const noReads = {find(){assert.fail('frozen descriptor composition must not query mutable metadata');}};
const materializer = new TopologyOperationPlanMaterializer({HyNode:noReads,CascadeLink:noReads});
async function materialize(before,after,kind){
    const installedPath={groupId:group._id,pathKey:'legacy-main',ownerNodeId:cfg.nodes.r.nodeId,ownerTopologyRevision:7,
        ownerCredentialRevision:41,oldPathLinkIds:copy(before.groups[0].paths[0].linkIds),newPathLinkIds:copy(after.groups[0].paths[0].linkIds),
        groupBefore:copy(before.groups[0]),kind};
    return materializer.materialize({...context,operationKind:kind,
        pinnedSnapshot:{revision:sequence+1,topology:after,compiled:compileTopology(after)},baselineTopology:before,effectiveTopology:after,
        installedPath,selectedOwnerPins:selectedOwners});
}
const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v==='object' ? Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])) : v;
function equal(a,b){assert.deepEqual(canonical(a),canonical(b));}
class SyntheticFixtureBootstrapper {
    constructor({nodeSSH}) { this.ssh = nodeSSH; }
    async ensureRunner() {
        const r = await this.ssh.exec(`sha256sum ${TOPOLOGY_RUNNER_PATH}`);
        assert.equal(r.code, 0); assert.equal('sha256:' + r.stdout.split(' ')[0], TOPOLOGY_RUNNER_SHA256);
    }
}
async function execute(plan, name, noop) {
    label = name; sequence++;
    const op = `installed-group-${sequence}`, generation = randomUUID(), fence = freeze({owner: cfg.runId, attempt: 1, generation});
    const contexts = plan.nodes.map(n => freeze({operationId: op, topologyRevision: sequence, priorDeployedRevision: sequence - 1,
        executionFence: fence, node: {...n, candidateHash: n.candidate.sha256}}));
    if (sequence === 1) {
        let dispatch = 0;
        const closed = new TopologyOperationExecutor({...context, nodeExecutionResolver: {async resolve() { dispatch++; assert.fail('must not dispatch'); }}});
        await assert.rejects(closed.prepare(contexts[0]), error => error.code === 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' && error.remoteOutcomeUncertain === false);
        assert.equal(dispatch, 0);
        ledger({kind: 'no-reader-control', dispatch, code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', status: 'expected-refusal'});
    }
    // This is the existing independent physical-fixture adapter, NOT enrollment.
    const records = new Map(contexts.map(c => [c.node.node, freeze({operationId: op, nodeId: c.node.node,
        topologyRevision: sequence, priorDeployedRevision: sequence - 1, candidateHash: `sha256:${c.node.candidateHash}`,
        backupId: `topology-${sha([op, c.node.node, `sha256:${c.node.candidateHash}`, c.node.targetProfile].join('\0'))}`,
        targetProfile: c.node.targetProfile, executionContext: context.hostIdentity, ...fence,
        attemptId: `attempt-${sequence}`, predecessorGeneration: heads.get(c.node.node) || 'none',
        bootId: cfg.nodes[short(c.node.node)].bootId, maintenanceId: cfg.runId,
        commandIds: Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close'].map(command => [command, `${command}-${sequence}-${short(c.node.node)}`]))})]));
    const reader = {async readVerified(expected) { return records.get(expected.nodeId); },
        async readVerifiedConnection(expected) { return freeze({binding: records.get(expected.nodeId), connection: cfg.nodes[short(expected.nodeId)].pin}); },
        async withVerifiedBinding(expected, fn) { return fn(records.get(expected.nodeId), async () => {}); }};
    const executor = new TopologyOperationExecutor({...context, executionBindingReader: reader, RunnerBootstrapper: SyntheticFixtureBootstrapper,
        nodeExecutionResolver: {async resolve({nodeId}, pin) { const id = short(nodeId); assert.deepEqual(pin, cfg.nodes[id].pin);
            return {exec: (command, options) => exec(id, command, options)}; }}});
    const before = new Map();
    for (const c of contexts) {
        assert.equal(c.node.targetProfile, target(short(c.node.node)));
        assert.equal(Object.hasOwn(c.node, 'profileTargetPin'), false, 'reverse uses native role-default targets, not forward pins');
        assert.equal(c.node.targetProfile, selectedOwners.find(o => o.node === c.node.node).profile);
        before.set(c.node.node, await profile(short(c.node.node), selected(short(c.node.node))));
    }
    const lifecycle = [];
    for (const c of contexts) { const p = await executor.prepare(c); lifecycle.push({...c, backupId: p.backupId, prepared: p.prepared}); }
    for (const c of lifecycle) await executor.commit(c);
    for (const c of lifecycle) await executor.verify(c);
    const evidence = [];
    for (const c of lifecycle) {
        const proof = await executor.close(c);
        assert.ok(isTopologyTerminalProof(proof)); assert.equal(proof.terminalOutcome, 'verified');
        heads.set(c.node.node, generation);
        const id = short(c.node.node), actual = await profile(id, selected(id));
        assert.equal(actual.config, Buffer.from(c.node.candidate.bytes).toString());
        assert.equal(sha(actual.config), c.node.candidate.sha256);
        assert.equal(actual.unit, originals.get(id)[selected(id)].unit);
        if (noop) assert.deepEqual(actual, before.get(c.node.node), 'byte-noop changed bytes/inode/PID/start/restarts/unit');
        const original = JSON.parse(originals.get(id)[selected(id)].config), current = JSON.parse(actual.config);
        for (const tag of ['client-in', 'unrelated-in']) equal(current.inbounds.find(i => i.tag === tag), original.inbounds.find(i => i.tag === tag));
        equal(current.policy, original.policy);
        equal(current.outbounds.find(o => o.tag === 'unrelated-out'), original.outbounds.find(o => o.tag === 'unrelated-out'));
        equal(current.routing.rules.filter(r => r.outboundTag === 'unrelated-out'), original.routing.rules.filter(r => r.outboundTag === 'unrelated-out'));
        const other = await profile(id, independent(id));
        assert.deepEqual(other, originals.get(id)[independent(id)], 'independent nonempty profile bytes/unit/inode/PID/start/restarts changed');
        state.nodes.find(n => n.id === c.node.node).profileConfig = actual.config;
        evidence.push({node: id, configSha256: sha(actual.config), checks: c.node.checks, profileTargetPin: c.node.profileTargetPin,
            before: {...before.get(c.node.node), config: sha(before.get(c.node.node).config)},
            after: {...actual, config: sha(actual.config)}, selectedProfile: target(id), independentProfile: independent(id), otherSha256: sha(other.config), otherIdentity: other.identity, proof});
    }
    ledger({kind: 'plan', label, operationId: op, noop, evidence, status: 'passed'});
}
async function transition(links,name,kind='link.apply',noop=false){
    label=name;
    const before=copy(state), after={...copy(state),links:copy(links)};
    // Fixture publication only: no Mongo/installed finalizer claim in this slice.
    after.groups[0].paths[0].linkIds=links.filter(l=>l.source===cfg.nodes.r.nodeId).map(l=>l.id);
    const plan=await materialize(before,after,kind); save(`plan-${sequence+1}.private.json`,plan);
    assert.equal(plan.nodes.length,3); for(const n of plan.nodes) assert.equal(n.targetProfile,target(short(n.node)));
    await execute(plan,name,noop); state.links=copy(links);state.groups=copy(after.groups);
    assert.equal(sha(JSON.stringify(modeledInventory)),inventoryHash);
    ledger({kind:'modeled-publication',label:name,path:copy(state.groups[0].paths[0]),inventoryUnchanged:true,status:'passed'});
}
async function traffic(origin,port,expected,name,destination='127.0.0.1'){
    const nonce=randomUUID();let last,observed;
    for(let attempt=0;attempt<(expected?12:2);attempt++){
        last=await exec(origin,`curl --silent --show-error --connect-timeout 1 --max-time 2 --socks5-hostname 127.0.0.1:${port} ${shell(`http://${destination}:18080/probe?nonce=${nonce}`)}`);
        fs.appendFileSync(path.join(work,'http-results.jsonl'),JSON.stringify({label:name,origin,nonce,port,expected,code:last.code,raw:last.stdout,sha256:sha(last.stdout)})+'\n');
        if(last.code===0){observed=JSON.parse(last.stdout);break;}
        if(expected)await new Promise(resolve=>setTimeout(resolve,400));
    }
    if(expected){assert.equal(last.code,0,`traffic ${name} failed exit=${last.code}`);assert.equal(observed.role,expected,`wrong exit ${name}`);
        assert.equal(observed.identity,cfg.nodes[expected].machineId);assert.equal(observed.nonce,nonce);assert.equal(observed.peer,'127.0.0.1');
    }else assert.notEqual(last.code,0,`blocked route leaked to ${observed?.role}`);
    ledger({kind:'traffic',label:name,origin,port,expected:expected||'blocked',nonce,rawSha256:sha(last.stdout),code:last.code,response:observed||null,status:'passed'});
}
async function probes(stage,portal='b',suffix='b'){
    await traffic('p',10808,portal,`${stage}:portal`);
    // Independent SOCKS client enters the ACTUAL retained R sidecar loopback.
    // It does not claim L2TP/PPP ingress into MAIN or kernel routing.
    await traffic('r',ingress.port,suffix,`${stage}:group-socks`);
    for(const [i,id] of ['p','r','b'].entries()){
        await traffic('p',10811+i,id,`${stage}:selected-fragment-${id}`,'198.18.43.1');
        await traffic('p',10821+i,id,`${stage}:independent-${id}`,'198.18.43.1');
    }
    for(const id of ['p','r','b']) assert.deepEqual(await profile(id,independent(id)),originals.get(id)[independent(id)]);
    assert.equal(sha(JSON.stringify(modeledInventory)),inventoryHash);
    save(`stage-${stage}.json`,{independentProfilesUnchanged:true,modeledInventoryUnchanged:true,group:state.groups[0],
        profiles:Object.fromEntries(await Promise.all(['p','r','b'].map(async id=>[id,{selected:await profile(id,selected(id)),independent:await profile(id,independent(id))}])))});
}
async function artifacts(stage,links){
    const all=Object.fromEntries(await Promise.all(['p','r','b'].map(async id=>[id,JSON.parse((await profile(id,selected(id))).config)])));
    const listeners={};
    for(const id of ['p','r','b']){const sockets=await ok(id,'ss -H -lntp');listeners[id]=sockets;
        const has=port=>sockets.split('\n').some(line=>line.trim().split(/\s+/)[3]?.endsWith(':'+port));
        for(const l of [u,d,...links])assert.equal(has(l.tunnelPort),links.some(a=>a.id===l.id)&&short(l.source)===id,`wrong inverse receiver ${id}:${l.tunnelPort}`);
        const independentConfig=JSON.parse((await profile(id,independent(id))).config);
        assert.equal(independentConfig.inbounds.some(i=>[u,d,...links].some(l=>l.tunnelPort===i.port)),false);
    }
    for(const original of [u,d])if(!links.some(l=>l.id===original.id))for(const value of Object.values(all)){
        const bytes=JSON.stringify(value);assert.equal(bytes.includes(original.tunnelUuid),false);
        for(const k of [original.id.slice(-8),sha('celerity-topology-link:'+original.id).slice(0,8)])assert.equal(bytes.includes(k),false,'removed identity survived');
    }
    for(const l of links){let count=0;const keys=[l.id.slice(-8),sha('celerity-topology-link:'+l.id).slice(0,8)];
        for(const [id,value]of Object.entries(all)){const bytes=JSON.stringify(value);const present=bytes.includes(l.tunnelUuid);
            assert.equal(present,[short(l.source),short(l.target)].includes(id));if(present){count++;assert.ok(keys.some(k=>bytes.includes(k)));}}
        assert.equal(count,2);const receiver=all[short(l.source)].inbounds.find(i=>i.port===l.tunnelPort);assert.equal(receiver.settings.clients[0].id,l.tunnelUuid);
    }
    const ing=all.r.inbounds.filter(i=>i.tag===ingress.tag);assert.equal(ing.length,1);assert.equal(ing[0].port,ingress.port);assert.equal(ing[0].listen,'127.0.0.1');
    if(!links.some(l=>l.source===cfg.nodes.r.nodeId)){
        const first=all.r.routing.rules.find(r=>!r.inboundTag||r.inboundTag.includes(ingress.tag));
        assert.deepEqual(first,{type:'field',inboundTag:[ingress.tag],outboundTag:'block'});
    }
    save(`artifacts-${stage}.json`,{listeners,ingress,links:links.map(l=>({id:l.id,port:l.tunnelPort,source:l.source,target:l.target}))});
    ledger({kind:'artifacts',label:stage,status:'passed'});
}
async function main(){
    const desired=JSON.parse(fs.readFileSync(path.join(root,'package-lock.json'))),installed=JSON.parse(fs.readFileSync('/deps/.package-lock.json'));
    const required=Object.entries(desired.packages||{}).filter(([k,v])=>k&&!v.optional&&v.version);
    const drift=required.filter(([k,v])=>installed.packages[k]?.version!==v.version).map(([k,v])=>({name:k,expected:v.version,actual:installed.packages[k]?.version||null}));
    const actual=required.map(([k,v])=>{const file=path.join('/deps',k.replace(/^node_modules\//,''),'package.json');const bytes=fs.readFileSync(file);const p=JSON.parse(bytes);
        assert.equal(p.version,v.version);return {name:k,version:p.version,sha256:sha(bytes)};});
    save('dependency-parity.json',{lockSha256:sha(fs.readFileSync(path.join(root,'package-lock.json'))),installedLockSha256:sha(fs.readFileSync('/deps/.package-lock.json')),drift,actual});assert.deepEqual(drift,[]);
    const versions={};
    for(const [id,n]of Object.entries(cfg.nodes)){
        const ssh=new NodeSSH({_id:n.nodeId,name:cfg.runId+'-'+id,ip:n.ip,ssh:{port:22,username:'root',privateKey:cfg.sshPrivateKey}},n.pin);
        ssh.usePool=false;await ssh.connect();connections.set(id,ssh);
        assert.equal((await ok(id,'cat /etc/machine-id')).trim(),n.machineId);assert.equal((await ok(id,'cat /proc/sys/kernel/random/boot_id')).trim(),n.bootId);
        assert.equal((await ok(id,'ip -4 route show default')).trim(),'');
        versions[id]=await ok(id,'/usr/local/bin/xray version; sha256sum /usr/local/bin/xray /usr/local/bin/celerity-topology-node-runner-v2');
        const own=JSON.parse(await ok(id,'curl --silent --show-error --max-time 2 http://127.0.0.1:18080/?nonce=canary'));
        assert.equal(own.role,id);assert.equal(own.identity,n.machineId);assert.equal(own.nonce,'canary');
    }
    save('binary-pins-readback.json',{node:process.version,versions});
    const client={log:{loglevel:'warning'},inbounds:[],outbounds:[],routing:{rules:[]}};
    function clientRoute(port,id,serverPort,uuid){const tag=`probe-${port}`;
        client.inbounds.push({tag,listen:'127.0.0.1',port,protocol:'socks',settings:{auth:'noauth',udp:false}});
        client.outbounds.push({tag,protocol:'vless',settings:{vnext:[{address:cfg.nodes[id].ip,port:serverPort,users:[{id:uuid,encryption:'none'}]}]},streamSettings:{network:'tcp',security:'none'}});
        client.routing.rules.push({type:'field',inboundTag:[tag],outboundTag:tag});
    }
    const populated=[u,d].map(l=>({...copy(l),_id:l.id,portalNode:metadata(nodes.find(n=>n.id===l.source)),bridgeNode:metadata(nodes.find(n=>n.id===l.target))}));
    for(const [index,node]of nodes.entries()){
        const id=short(node.id),unrelatedUuid=randomUUID(),otherUuid=randomUUID();let base;
        if(id==='p'){base=JSON.parse(generator.generateXrayConfig(metadata(node),[{xrayUuid:cfg.clientUuid,userId:'TEST-existing@invalid'}]));generator.applyReversePortal(base,[populated[0]],['client-in']);}
        else if(id==='r'){base=JSON.parse(generator.generateRelayConfig(populated[0],populated[0].portalNode,[populated[1]]));
            generator.applyCascadePathIngress(base,[{pathKey:'legacy-main',port:ingress.port,egressTag:`portal-down-${d.id.slice(-8)}`}]);finishClassicConfigRouting(base);}
        else base=JSON.parse(generator.generateCombinedBridgeConfig([populated[1]]));
        base.inbounds||=[];base.inbounds.push({tag:'unrelated-in',listen:'0.0.0.0',port:24543,protocol:'vless',settings:{clients:[{id:unrelatedUuid,email:`unrelated-${id}@invalid`}],decryption:'none'},streamSettings:{network:'tcp',security:'none'}});
        base.outbounds.push({tag:'unrelated-out',protocol:'freedom',settings:{redirect:'127.0.0.1:18080'}});
        base.routing.rules.push({type:'field',inboundTag:['unrelated-in'],outboundTag:'unrelated-out'});base.policy={levels:{0:{statsUserUplink:true,statsUserDownlink:true}}};
        node.profileConfig=JSON.stringify(base,null,2)+'\n';
        const fragments=id==='r'?[buildL2tpXrayFragment({plan:{relay:{controlPlaneIps:[node.ip]},group:{id:group._id},selectedPathKey:'legacy-main',
            paths:[{pathKey:'legacy-main',healthy:true,outboundTag:ingress.tag}]},tags:{inbound:`relay-l2tp-${group._id}`,blockOutbound:'block'},tproxyPort:12345})]:[];
        const otherMeta={...metadata(node),port:24643,xray:{...copy(node.xray),inboundTag:'independent-other'}};
        const other=JSON.parse(generator.generateXrayConfig(otherMeta,[{xrayUuid:otherUuid,userId:`other-${id}@invalid`}],{fragments}));
        finishClassicConfigRouting(other);
        // Fixed unrelated benchmark redirect configured ONCE before adoption.
        const controlOut=other.outbounds.find(o=>o.tag==='direct');assert.ok(controlOut);controlOut.settings={...(controlOut.settings||{}),redirect:'127.0.0.1:18080'};
        save(`initial-${id}.private.json`,{selected:base,independent:other,fragments});
        for(const [name,bytes]of [[selected(id),node.profileConfig],[independent(id),JSON.stringify(other,null,2)+'\n']]){
            const service=name==='main'?'xray':'xray-bridge';await connections.get(id).writeFile(`/usr/local/etc/${service}/config.json`,bytes);
            label=`initial-${id}-${name}`;
            await ok(id,`chmod 0600 /usr/local/etc/${service}/config.json; /usr/local/bin/xray run -test -config /usr/local/etc/${service}/config.json && systemctl enable ${service}.service && systemctl start ${service}.service`);
            // Real active/running/PID assertion; no fragment removal or capability retry.
            await profile(id,name);
        }
        originals.set(id,{main:await profile(id,'main'),sidecar:await profile(id,'sidecar')});
        clientRoute(10811+index,id,24543,unrelatedUuid);clientRoute(10821+index,id,24643,otherUuid);
    }
    clientRoute(10808,'p',24443,cfg.clientUuid);
    await connections.get('p').writeFile('/root/anyorder-client.json',JSON.stringify(client));
    await ok('p','chmod 0600 /root/anyorder-client.json; /usr/local/bin/xray run -test -config /root/anyorder-client.json && systemctl start anyorder-client.service');
    save('client-config.private.json',client);save('originals.private.json',Object.fromEntries(originals));save('modeled-inventory.private.json',modeledInventory);
    const db = {transaction: fn => fn({inTransaction: () => true})}, Owner = model([], db);
    const transfer = new TopologyConfigTransfer({executionContext: context, TopologyConfigOwner: Owner,
        async withVerifiedMaintenance({binding, proofRef}, fn) {
            assert.equal(proofRef, 'SYNTHETIC-private-fixture-exclusion');
            const id = short(binding.node), name = binding.profile === 'xray-main' ? 'main' : 'sidecar', actual = await profile(id, name);
            assert.deepEqual(actual, originals.get(id)[name]);
            // Existing explicit synthetic external-hold seam; not physical exclusion.
            await fn({authority: 'external-maintenance-v1', status: 'verified', binding: copy(binding), proofId: randomUUID(), maintenanceId: randomUUID(),
                maintenance: 'held', allWriters: 'drained', oldBackend: {instanceId: 'SYNTHETIC-no-classic-backend', pid: 42, processStartTime: 'SYNTHETIC', processTree: 'stopped', dispatch: 'disabled'},
                readback: {source: 'node-readback', configSha256: sha(actual.config), unitSha256: sha(actual.unit), serviceActive: 'active', serviceEnabled: 'enabled'}});
        }});
    const owners = [], allOwners = [];
    for (const node of nodes) for (const name of [selected(short(node.id)), independent(short(node.id))]) {
        const id = short(node.id), profileName = name === 'main' ? 'xray-main' : 'xray-bridge', n = cfg.nodes[id];
        const classic = await transfer.initializeClassic({node: node.id, profile: profileName,
            nodeIdentity: {machineId: n.machineId, sshHostKeySha256: n.pin.expectedHostKeySha256}});
        assert.equal(classic.owner, 'classic'); assert.equal(classic.adoptionReceipt, undefined);
        const adopted = await transfer.adopt({node: node.id, profile: profileName, generation: classic.generation,
            proofRef: 'SYNTHETIC-private-fixture-exclusion', ...(name === selected(id) ? {legacyTopology: state} : {})});
        const confirmed = await Owner.findOne({node: node.id, profile: profileName}).select('+legacyAppliedTopology +profileTargetPin').lean();
        assert.deepEqual(confirmed, adopted); allOwners.push(freeze(copy(confirmed)));
        if (name === selected(id)) {
            assert.equal(Object.hasOwn(confirmed, 'profileTargetPin'), false);
            assert.deepEqual(verifyLegacyAppliedProfile(confirmed.legacyAppliedTopology, {node: node.id,
                profile: profileName, originalSnapshot: confirmed.originalSnapshot}), confirmed.legacyAppliedTopology);
            owners.push(freeze(copy(confirmed)));
        }
        assert.deepEqual(await profile(id, name), originals.get(id)[name], 'adoption wrote profile');
    }
    selectedOwners = freeze(owners.map(({legacyAppliedTopology, ...pin}) => copy(pin)));
    const immutable = sha(JSON.stringify(owners));
    save('public-import.private.json', owners); save('all-owners.private.json', allOwners);
    ledger({kind: 'public-import', owners: selectedOwners.map(o => ({node: o.node, profile: o.profile, generation: o.generation,
        originalSnapshot: o.originalSnapshot, adoptionReceiptSha256: sha(JSON.stringify(o.adoptionReceipt))})),
        authority: 'synthetic-external-hold/local-query-model', status: 'passed'});
    save('matrix.json',{scenario:cfg.scenario,stages:cfg.scenario==='delete-d'?['baseline','apply','noop','delete','recreate']:['baseline','delete','recreate'],planStages:cfg.scenario==='delete-d'?['apply','noop','delete','recreate']:['delete','recreate'],probesPerStage:8});
    await probes('baseline');await artifacts('baseline',[u,d]);
    if(cfg.scenario==='delete-d'){
        await transition([u,d],'apply');await probes('apply');await artifacts('apply',[u,d]);
        await transition([u,d],'noop','link.apply',true);await probes('noop');await artifacts('noop',[u,d]);
    }
    const old=cfg.scenario==='delete-d'?d:u,kept=cfg.scenario==='delete-d'?u:d;
    await transition([kept],'delete','link.delete');await probes('delete',null,cfg.scenario==='delete-d'?null:'b');await artifacts('delete',[kept]);
    const replacement={...copy(old),id:randomBytes(12).toString('hex'),tunnelPort:old.tunnelPort+200,tunnelUuid:randomUUID()};
    const restored=cfg.scenario==='delete-d'?[u,replacement]:[replacement,d];
    await transition(restored,'recreate');await probes('recreate');await artifacts('recreate',restored);
    assert.notEqual(replacement.id,old.id);assert.notEqual(replacement.tunnelPort,old.tunnelPort);assert.notEqual(replacement.tunnelUuid,old.tunnelUuid);
    const witnesses=Object.fromEntries(await Promise.all(['p','r','b'].map(async id=>[id,(await ok(id,'cat /root/witness.jsonl')).trim().split('\n').map(JSON.parse)])));
    save('witnesses.json',witnesses);
    const trafficRows=fs.readFileSync(path.join(work,'cases.jsonl'),'utf8').trim().split('\n').map(JSON.parse).filter(r=>r.kind==='traffic');
    for(const row of trafficRows){const matches=Object.entries(witnesses).flatMap(([id,rows])=>rows.filter(w=>w.nonce===row.nonce).map(w=>({id,w})));
        if(row.expected==='blocked')assert.equal(matches.length,0,'blocked nonce reached exit/direct canary');
        else {assert.equal(matches.length,1);assert.equal(matches[0].id,row.expected);assert.equal(matches[0].w.identity,cfg.nodes[row.expected].machineId);}}
    assert.equal(sha(JSON.stringify(owners)),immutable);assert.deepEqual(await Owner.find({}).select('+legacyAppliedTopology +profileTargetPin').lean(),allOwners);
    assert.equal(sha(JSON.stringify(modeledInventory)),inventoryHash);
    save('recreation.json',{allocation:'synthetic fixture, NOT public POST',groupId:group._id,pathKey:'legacy-main',stableIngress:ingress,
        oldId:old.id,newId:replacement.id,oldPort:old.tunnelPort,newPort:replacement.tunnelPort,oldCredentialSha256:sha(old.tunnelUuid),newCredentialSha256:sha(replacement.tunnelUuid),importedPinsUnchanged:true});
    save('loaded-inputs.json',Object.fromEntries(Object.keys(require.cache).filter(p=>p.startsWith(root+'/')||p.startsWith('/deps/')).sort().map(p=>[p,sha(fs.readFileSync(p))])));
    ledger({kind:'scenario',name:cfg.scenario,status:'passed'});
    save('result.json',{status:'passed',scenario:cfg.scenario,planExecutions:sequence,
        authorityAdapter:'synthetic-external-hold/local-query-model/in-memory-bindings',publication:'MODELED descriptor transitions; no installed finalizer/worker physical join',
        actual:['public initializeClassic/adopt accepted verifier','real SSH original profile bytes','generator/compiler/materializer/composer','typed executor','NodeSSH','unchanged runner','systemd','Xray','VLESS portal P→R→B','independent loopback group SOCKS R→B','identity/nonce HTTP'],
        notProved:['PPP/L2TP ingress','kernel PPP/iptables','native physical authority','HTTP/Mongo/worker physical join','full deployment','public create ID allocation','Internet country exit']});
}
main().catch(async error=>{
    save('failure.json',{status:'failed',label,sequence,error:causal(error)});
    for(const[id]of connections){try{const d=await exec(id,'systemctl status xray xray-bridge anyorder-client --no-pager; journalctl -u xray -u xray-bridge -u anyorder-client --no-pager -n 100; ss -lntp');fs.writeFileSync(path.join(work,`diagnostic-${id}.private.log`),d.stdout+d.stderr);}catch{}}
    console.error(JSON.stringify({status:'failed',label,sequence,error:causal(error)}));process.exitCode=1;
}).finally(()=>{for(const ssh of connections.values())ssh.disconnect();candidate('src/services/sshPoolService').closeAll();candidate('src/utils/logger').close();});
