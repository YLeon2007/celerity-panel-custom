'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {withNodes,withNode,makeLocks}=require('../rebuildLocks');
test('agent mutation queues behind Apply; nested user-only sync does not deadlock', async()=>{
 const events=[];let release,ready;const start=new Promise(r=>ready=r), barrier=new Promise(r=>release=r);
 const applying=withNodes(['b','a','a'],async()=>{events.push('apply');ready();await barrier;});await start;
 const agent=withNode('a',async()=>withNode('a',async()=>events.push('agent')));await withNode('c',async()=>events.push('other'));assert.deepEqual(events,['apply','other']);release();await Promise.all([applying,agent]);assert.equal(events.at(-1),'agent');
});
test('Mongo singleton blocks concurrency; restart leaves stale row for exact operator button only',async()=>{
 const {spawn}=require('node:child_process'),fs=require('node:fs/promises'),path=require('node:path'),net=require('node:net');const mongoose=require('mongoose');
 const dir=await fs.mkdtemp(path.join(process.env.TMPDIR,'rebuild-lock-'));const listener=net.createServer();await new Promise(r=>listener.listen(0,'127.0.0.1',r));const port=listener.address().port;await new Promise(r=>listener.close(r));
 const daemon=spawn(process.env.C3_MONGOD||'mongod',['--dbpath',dir,'--bind_ip','127.0.0.1','--port',String(port),'--nounixsocket','--quiet'],{stdio:'ignore'});const exited=new Promise(r=>{daemon.once('error',r);daemon.once('exit',r)});let conn;
 try {conn=await mongoose.createConnection(`mongodb://127.0.0.1:${port}/rebuild_local_lock`,{serverSelectionTimeoutMS:10000}).asPromise();const store=conn.db.collection('locks'),locks=makeLocks(store);await locks.run(async check=>{await check();const status=await locks.status();assert.equal(status.stale,false);await assert.rejects(locks.unlock(status.token),{code:'REBUILD_LOCK_NOT_STALE'});await assert.rejects(locks.run(()=>assert.fail()),{code:'REBUILD_BUSY'})});
 await store.insertOne({_id:'apply',token:'abandoned',heartbeat:new Date(0)});assert.equal((await locks.status()).stale,true);await assert.rejects(locks.unlock('older'),{code:'REBUILD_LOCK_NOT_STALE'});await locks.unlock('abandoned');assert.deepEqual(await locks.status(),{locked:false});
 }finally{await conn?.close();daemon.kill();await exited;await fs.rm(dir,{recursive:true,force:true})}
});
