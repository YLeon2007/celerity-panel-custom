'use strict';
// Child of the disposable replica-set test. No HTTP listener, .env, ACME, DNS or real SSH.
// Start the same post-database root as the backend. Never inject an operation ID or worker ID.
const fs = require('node:fs'), path = require('node:path'), net = require('node:net');
const assert = require('node:assert/strict'), { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { config, uri, nodes, operationCollection, cut, fault } = JSON.parse(fs.readFileSync(0,'utf8'));
assert.match(uri, /^mongodb:\/\/127\.0\.0\.1:\d+\/binding_scratch_[a-f0-9]{32}\?replicaSet=bindingScratch$/);
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(...args) {
    const [o] = net._normalizeArgs(args.length === 1 && Array.isArray(args[0]) ? args[0] : args);
    assert.ok(nodes.some(n=>o.path===n.socket) || (o.host==='127.0.0.1' && Number(o.port)===Number(new URL(uri).port)), 'local sockets only');
    return connect.apply(this,args);
};
const mongoose = require('mongoose');
const trace = { scanned:[], attached:[], guardErrors:[], physicalPairReads:[], runner:[], ssh:0, failures:[], pid:process.pid };
const diag = require('../../../../routes/topologyTestDiagnostics');
diag.logTopologyTestFailure = input => trace.failures.push({phase:input.phase, code:input.error?.code, frames:diag.formatTopologyDiagnostic(input).sourceFrames, reason:input.error.message === 'Unclosed pair is unconfirmed' ? input.error.message : undefined});
const PROD = require('../../domain/topologyExecutionContext').PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT;
const env = { PANEL_DOMAIN:PROD.hostIdentity,L2TP_EXECUTION_ENABLED:'true',L2TP_MIGRATIONS_ENABLED:'true',TOPOLOGY_PRODUCTION_EXECUTION_ENABLED:'true' };
async function open(pin) {
    const n=nodes.find(n=>n.id===pin.nodeId); assert.ok(n);
    if(fault==='node' && n===nodes[1]) throw Object.assign(new Error('fixture host unreachable'),{code:'EHOSTUNREACH'});
    const socket=await new Promise((resolve,reject)=>{const s=net.connect(n.socket);s.once('connect',()=>resolve(s));s.once('error',err=>{trace.guardErrors.push([n.id,err.code]);reject(err);});});
    let attached=false;
    return { get alive(){return !socket.destroyed;}, close(){socket.destroy();}, async request(action,value){
        if (action==='observe' || action==='observe-unclosed') {
            if(action==='observe-unclosed') {assert.equal(attached,true);trace.physicalPairReads.push(n.id);}
            const journal=fs.existsSync(n.journal)?JSON.parse(fs.readFileSync(n.journal)):null;
            const pristine=journal===null && ['fences/'+n.pin.targetProfile,'operations','backups'].every(s=>!fs.existsSync(path.join(n.root,'var/lib/celerity/topology',s)));
            return {kind:'node',nodeId:n.id,targetProfile:n.pin.targetProfile,held:true,serverContext:PROD,physical:n.pin.physical,
                endpoint:n.pin.endpoint,policySha256:n.pin.policySha256,maintenanceId:n.pin.maintenanceId,pristine,journal,
                ...(action==='observe-unclosed'?{runnerIdle:true}:{}), oldBackend:{instanceId:'local-prior-writer',pid:42,processStartTime:'123'},
                current:{...n.pin.originalSnapshot,configSha256:createHash('sha256').update(fs.readFileSync(n.configPath)).digest('hex')}};
        }
        if(action==='attach') {assert.ok(!attached);assert.deepEqual(value,n.pin.originalScope);attached=true;trace.attached.push(n.id);}
        else assert.equal(action,'read');
        assert.ok(attached);return {...n.pin.originalScope,phase:'captured-held'};
    }};
}
class LocalNodeSSH {
    constructor(node,pin) {this.n=nodes.find(n=>n.id===String(node._id));assert.ok(this.n);trace.ssh++;
        assert.equal(pin.expectedHostKeySha256,this.n.pin.physical.sshHostKeySha256);assert.deepEqual(pin.expectedEndpoint,this.n.pin.endpoint);}
    async writeFile() { assert.fail('closure must not install anything'); }
    async exec(command,options={}) {
        // SSH is modeled; read the actual fixture digest/mode, never report an invented digest.
        const runner='/usr/local/bin/celerity-topology-node-runner-v2', unit='/etc/systemd/system/xray-bridge.service';
        if(command.startsWith('if /usr/bin/test -e /usr/local/bin/.celerity-topology') || command.startsWith('/usr/bin/systemctl show --property=FragmentPath')) {
            const isUnit=command.startsWith('/usr/bin/systemctl'), file=isUnit?unit:runner, local=path.join(this.n.root,file);
            const digest=createHash('sha256').update(fs.readFileSync(local)).digest('hex');
            return {code:0,stderr:'',stdout:isUnit?`FragmentPath=${unit}\nDropInPaths=\n${digest}  ${unit}\n`:
                `${digest}  ${runner}\n${(fs.statSync(local).mode&0o777).toString(8)}\n`};
        }
        if (command === '/usr/bin/install -d -m 0755 -o root -g root /usr/local/etc/xray' ||
            command === '/usr/bin/install -d -m 0755 -o root -g root /usr/local/etc/xray /usr/local/etc/xray-bridge') {
            for (const p of command.split(' ').filter(p=>p.startsWith('/usr/local/etc/'))) fs.mkdirSync(path.join(this.n.root,p),{recursive:true});
            return {code:0,stdout:'',stderr:''};
        }
        assert.ok(command.startsWith('/usr/local/bin/celerity-topology-node-runner-v2 '),'closing cannot bootstrap/upload');
        trace.runner.push([this.n.id,require('./topologyV2Fixture').runnerRequest(command).command]);
        const result=spawnSync('bash',[path.resolve(__dirname,'../../node-artifacts/topology/runner.sh'),...command.split(' ').slice(1)],
            {env:{...process.env,CELERITY_TOPOLOGY_ROOT:this.n.root},input:options.stdin,encoding:'utf8'});
        return {code:result.status,stdout:result.stdout,stderr:result.stderr};
    }
}
// Test-only crash injector. Hook acknowledged product boundaries, never fabricate a result,
// run a worker directly or forward the first child's identity to the recovering backend.
function injectCrash(point) {
    const stop=name=>{if(name===point){fs.writeSync(1,'CRASH_POINT '+name+'\n');process.kill(process.pid,'SIGKILL');}};
    function wrap(Type,name,before,after) {
        const original=Type.prototype[name];assert.equal(typeof original,'function');
        Type.prototype[name]=async function(...args){before?.(...args);const value=await original.apply(this,args);after?.(value,...args);return value;};
    }
    const store=require('../../repositories/topologyExecutionBindingStore').TopologyExecutionBindingStore;
    const repo=require('../../repositories/topologyOperationRepository').TopologyOperationRepository;
    const executor=require('../../services/topologyOperationExecutor').TopologyOperationExecutor;
    const finalizer=require('../../services/topologyOperationFinalizer').TopologyOperationFinalizer;
    let bindings=0;
    wrap(store,'reserveBinding',()=>{if(bindings===0)stop('bindings-0');},value=>{assert.ok(value);stop('bindings-'+(++bindings));});
    wrap(repo,'recordNode',null,(value,req)=>{if(value===true)stop(req.state+'-'+(String(req.node)===nodes[0].id?'P':'B'));});
    for (const command of ['prepare','commit']) wrap(executor,command,null,(value,ctx)=>{
        if(value?.ok) stop(command+'-receipt-'+(ctx.node.node===nodes[0].id?'P':'B'));
    });
    wrap(executor,'verify',null,(value,ctx)=>{if(value?.ok && ctx.node.node===nodes[1].id)stop('verified');});
    wrap(finalizer,'beginV2Closure',null,value=>{if(value)stop('closing');});
    wrap(require('../../services/topologyUserResync').TopologyUserResync,'resyncPlan',null,value=>{if(value?.ok)stop('users-restored');});
    wrap(executor,'close',null,(value,ctx)=>{if(value)stop(ctx.node.node===nodes[0].id?'closed-P':'closed-B');});
    wrap(finalizer,'persistV2TerminalProofs',null,value=>{if(value)stop('proven');});
    wrap(finalizer,'finalizeV2Succeeded',null,value=>{if(value)stop('succeeded');});
}
async function main(){
    if(cut) injectCrash(cut);
    mongoose.set('autoCreate',false);mongoose.set('autoIndex',false);
    await mongoose.connect(uri,{autoCreate:false,autoIndex:false,monitorCommands:true,serverSelectionTimeoutMS:2000});
    const client=mongoose.connection.getClient(), scans=new Set();
    client.on('commandStarted',e=>{const c=e.command;if(c.find===operationCollection && c.filter.executionContext?.target==='production' &&
        c.filter.$or?.some(f=>f.leaseUntil?.$lte && f.status?.$in?.includes('committing')))scans.add(e.requestId);});
    trace.transfers=[];
    client.on('commandStarted',({command:c})=>{for(const u of c.updates||[]){
        const owner=u.u?.$set?.leaseOwner??u.u?.$set?.owner;
        if(owner && u.q?.$expr?.$lte?.[1]==='$$NOW' && (c.update===operationCollection || u.q.remoteUncertain===true)){
            trace.transfers.push({from:u.q.leaseOwner??u.q.owner,to:owner,generation:u.q.generation??null,
                pairReads:trace.physicalPairReads.slice(),tx:String(c.txnNumber)});
        }
    }});
    client.on('commandSucceeded',e=>{if(scans.delete(e.requestId))trace.scanned.push(e.reply.cursor.firstBatch.map(o=>String(o._id)));});
    // Observe, do not replace, the assembled worker (and never invoke it here).
    const entry=require('../..'), makeService=entry.createTopologyDeploymentService;
    entry.createTopologyDeploymentService=options=>{
        const service=makeService(options), w=service.operationWorker;
        trace.worker={id:w.workerId,boundResync:w.userResync?.preferBoundRunner===true,pppGate:!!w.pppReadinessGate,
            typed:w.executor instanceof require('../../services/topologyOperationExecutor').TopologyOperationExecutor};
        return service;
    };
    const {createL2tpRootLifecycle,createL2tpRootHostDependencies}=require('../../../l2tpRuntimeLifecycleHook');
    const {createRootTopologyExecutionAuthority}=require('../../runtime/productionPhysicalAuthority');
    const root=createL2tpRootLifecycle({env,createTopologyExecutionAuthority:opts=>createRootTopologyExecutionAuthority({...opts,
        read(file){assert.equal(file,'/etc/celerity/topology-production.json');return JSON.stringify(config);},open}),
        createHostDependencies:opts=>createL2tpRootHostDependencies({...opts,NodeSSH:LocalNodeSSH})});
    try {await root.startAfterDatabase();trace.started=true;}
    catch(e){trace.startError=e.code??e.name;}
    finally {await root.stop();require('../../../../services/sshPoolService').closeAll();await mongoose.disconnect();}
}
main().then(()=>{fs.writeSync(1,'CLOSING_ROOT '+JSON.stringify(trace)+'\n');process.exit(0);},e=>{fs.writeSync(1,'CLOSING_ROOT '+JSON.stringify({...trace,harnessError:e.code??e.name})+'\n');process.exit(1);});
