'use strict';
// No application loader hooks or module mocks: exec the real index.js twice.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const { MongoClient } = require('mongodb');
const Redis = require('ioredis');
const ROOT = path.resolve(__dirname, '..');
const BODY = 'c3-classic-ready-v1\n';
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function port() { const s = net.createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening'); const p = s.address().port; await new Promise(r => s.close(r)); return p; }
function child(binary, args, cwd, env, log) {
    const fd = fs.openSync(log, 'a', 0o600);
    const p = spawn(binary, args, {cwd, env, stdio:['ignore',fd,fd]}); fs.closeSync(fd);
    p.done = once(p, 'exit'); return p;
}
async function stop(p, signal='SIGTERM', ms=12000) {
    if (p.exitCode !== null || p.signalCode !== null) return;
    p.kill(signal);
    const timeout = setTimeout(() => p.kill('SIGKILL'), ms);
    const [code, sig] = await p.done; clearTimeout(timeout);
    assert.equal(sig, null, 'natural finite signal shutdown, not SIGKILL'); assert.equal(code, 0);
}
async function until(fn, ms=20000) {
    const end = Date.now()+ms; let last;
    while (Date.now()<end) { try { return await fn(); } catch (e) { last=e; await pause(100); } }
    throw last || new Error('deadline');
}
function request(p, url) { return new Promise((resolve,reject) => {
    const q=http.get({hostname:'127.0.0.1',port:p,path:url,agent:false},r=> {let body='';r.on('data',b=>body+=b);r.on('end',()=>resolve({status:r.statusCode,body}));});
    q.setTimeout(1500,()=>q.destroy(new Error('HTTP deadline')));q.on('error',reject);
}); }
test('real index consumes file, serves pinned readiness with actual Mongo/Redis, restarts and shuts down finitely', {timeout:100000}, async t => {
    assert.ok(process.env.C3_MONGOD); assert.ok(process.env.C3_REDIS_SERVER); assert.ok(process.env.C3_REAL_EVIDENCE);
    const dir=fs.mkdtempSync(path.join(process.env.TMPDIR,'classic-real-'));
    const evidence=process.env.C3_REAL_EVIDENCE;
    fs.writeFileSync(path.join(evidence,'last-fixture-path.txt'), dir+'\n');
    const app=path.join(dir,'app');fs.mkdirSync(app);const state=path.join(dir,'state');fs.mkdirSync(state,{mode:0o700});
    // Copy exact tracked source, never mutate the registered source or shared dependencies.
    const tracked=execFileSync('git',['ls-files','-z'],{cwd:ROOT}).toString().split('\0').filter(Boolean);
    for (const name of tracked) { const from=path.join(ROOT,name), to=path.join(app,name); if (!fs.statSync(from).isFile()) continue; fs.mkdirSync(path.dirname(to),{recursive:true});fs.copyFileSync(from,to);fs.chmodSync(to,0o444); }
    // Include uncommitted TDD implementation during RED/GREEN; after commit it is tracked.
    for (const name of ['src/classicSettings.js']) if (!fs.existsSync(path.join(app,name)) && fs.existsSync(path.join(ROOT,name))) {fs.copyFileSync(path.join(ROOT,name),path.join(app,name));fs.chmodSync(path.join(app,name),0o444);}
    fs.writeFileSync(path.join(app,'.env'),'L2TP_EXECUTION_ENABLED=true\nPANEL_DOMAIN=dotenv.invalid\n');fs.chmodSync(path.join(app,'.env'),0o444);
    function sourceInventory(d, prefix='') {
        return fs.readdirSync(d,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(e=>{
            const name=prefix+e.name, file=path.join(d,e.name);
            return e.isDirectory()?sourceInventory(file,name+'/'):[[name,crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')]];
        });
    }
    const initialSource=sourceInventory(app);
    fs.writeFileSync(path.join(evidence,'executed-source-sha256.json'),JSON.stringify(initialSource,null,2)+'\n');
    function readonly(d) { for (const e of fs.readdirSync(d,{withFileTypes:true})) if(e.isDirectory()) readonly(path.join(d,e.name));fs.chmodSync(d,0o555); } readonly(app);
    const mp=await port(), rp=await port(), hp=await port();
    const mongoDir=path.join(dir,'mongo');fs.mkdirSync(mongoDir);
    const mongo=child(process.env.C3_MONGOD,['--dbpath',mongoDir,'--port',String(mp),'--bind_ip','127.0.0.1','--wiredTigerCacheSizeGB','0.25','--setParameter','enableTestCommands=1'],dir,process.env,path.join(evidence,'mongo.log'));
    const redis=child(process.env.C3_REDIS_SERVER,['--bind','127.0.0.1','--port',String(rp),'--save','','--appendonly','no','--dir',dir],dir,process.env,path.join(evidence,'redis.log'));
    t.after(async()=>{await stop(redis);await stop(mongo);});
    const uri=`mongodb://127.0.0.1:${mp}/classic_local`;
    const mc=new MongoClient(uri,{serverSelectionTimeoutMS:500});t.after(()=>mc.close());await until(()=>mc.connect());
    const rc=new Redis(`redis://127.0.0.1:${rp}`,{lazyConnect:true,retryStrategy:()=>null});t.after(()=>rc.disconnect());await until(async()=>{if(rc.status==='end') throw Error('Redis early exit'); if(rc.status==='wait') await rc.connect();assert.equal(await rc.ping(),'PONG');});
    const settings={version:1,context:'test.infograd.online',stateDirectory:state,listenAddress:'127.0.0.1',environment:{
        PANEL_DOMAIN:'test.infograd.online',ACME_EMAIL:'local@example.invalid',ENCRYPTION_KEY:'e'.repeat(32),SESSION_SECRET:'s'.repeat(32),
        MONGO_URI:uri,REDIS_URL:`redis://127.0.0.1:${rp}`,USE_CADDY:'true',PORT:String(hp),
        L2TP_EXECUTION_ENABLED:'false',L2TP_MIGRATIONS_ENABLED:'false',TOPOLOGY_TEST_EXECUTION_ENABLED:'false',TOPOLOGY_PRODUCTION_EXECUTION_ENABLED:'false',L2TP_PRODUCTION_EXECUTION_ENABLED:'false'}};
    const file=path.join(dir,'classic.json');fs.writeFileSync(file,JSON.stringify(settings),{mode:0o600});
    const env={C3_SETTINGS:file,NODE_ENV:'production',NODE_PATH:process.env.NODE_PATH};
    for (let generation=1;generation<=2;generation++) {
        const p=child(process.execPath,[path.join(app,'index.js')],app,env,path.join(evidence,`application-${generation}.log`));
        t.after(async()=>{if(p.exitCode===null && p.signalCode===null) {p.kill('SIGKILL');await p.done;}});
        const ready=await until(async()=>{assert.equal(p.exitCode,null,'app remains alive');const r=await request(hp,'/classic-ready');assert.equal(r.status,200);assert.equal(r.body,BODY);return r;});
        const tcp=fs.readFileSync(`/proc/${p.pid}/net/tcp`,'utf8');
        assert.ok(tcp.split('\n').some(line=>line.trim().split(/\s+/)[1]===`0100007F:${hp.toString(16).toUpperCase().padStart(4,'0')}` && line.trim().split(/\s+/)[3]==='0A'), 'listener must bind exact ingress IPv4, not wildcard/IPv6');
        assert.equal(ready.body,BODY);assert.equal((await request(hp,'/classic-ready')).body,BODY);
        await mc.db('admin').command({configureFailPoint:'failCommand',mode:{times:1},data:{failCommands:['ping'],errorCode:2}});
        assert.equal((await request(hp,'/classic-ready')).status,503,'witness fails closed when actual Mongo ping fails');
        assert.equal((await request(hp,'/classic-ready')).body,BODY);
        const health=await request(hp,'/health');assert.equal(health.status,200);assert.equal(JSON.parse(health.body).status,'ok');assert.equal(typeof JSON.parse(health.body).uptime,'number');
        assert.equal((await request(hp,'/')).status,200);
        assert.ok(await mc.db().collection('settings').countDocuments() > 0,'real application persisted its settings');
        assert.ok((await rc.info('stats')).includes('total_commands_processed:'),'actual Redis answered');
        assert.ok(fs.existsSync(path.join(state,'logs/combined.log')));assert.ok(!fs.existsSync(path.join(app,'logs')),'no source log directory');
        await stop(p,generation===1?'SIGTERM':'SIGINT');
        await assert.rejects(request(hp,'/classic-ready'));
    }
    // Same actual index; malformed settings must refuse before imports create logs,
    // DB connections/DDL, Redis commands or an HTTP listener.
    const before=await mc.db().listCollections().toArray();
    const mongoConnections=(await mc.db('admin').command({serverStatus:1})).connections.totalCreated;
    const redisConnections=()=>rc.info('stats').then(s=>Number(s.match(/^total_connections_received:(\d+)/m)[1]));
    const redisBefore=await redisConnections();
    settings.environment.L2TP_EXECUTION_ENABLED='true';settings.stateDirectory=path.join(dir,'invalid-state');
    fs.writeFileSync(file,JSON.stringify(settings));
    const invalid=child(process.execPath,[path.join(app,'index.js')],app,env,path.join(evidence,'invalid-application.log'));
    const [code,sig]=await invalid.done;assert.equal(sig,null);assert.equal(code,1);
    assert.ok(!fs.existsSync(settings.stateDirectory));assert.deepEqual(await mc.db().listCollections().toArray(),before);
    assert.equal((await mc.db('admin').command({serverStatus:1})).connections.totalCreated,mongoConnections,'invalid startup opened zero Mongo connections');
    assert.equal(await redisConnections(),redisBefore,'invalid startup opened zero Redis connections');
    await assert.rejects(request(hp,'/classic-ready'));
    assert.match(fs.readFileSync(path.join(evidence,'invalid-application.log'),'utf8'),/CLASSIC_SETTINGS_REFUSED/);
    assert.deepEqual(sourceInventory(app),initialSource,'source bytes and file inventory unchanged across both real startups and refusal');
    console.log('REAL_APPLICATION_TWO_GENERATIONS_FINITE; read-only source permissions; no namespaces/mounts/physical attestation');
});
