'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {withNodes,withNode,makeLocks}=require('../rebuildLocks');
test('agent mutation queues behind Apply; nested user-only sync does not deadlock', async()=>{
 const events=[];let release,ready;const start=new Promise(r=>ready=r), barrier=new Promise(r=>release=r);
 const applying=withNodes(['b','a','a'],async()=>{events.push('apply');ready();await barrier;});await start;
 const agent=withNode('a',async()=>withNode('a',async()=>events.push('agent')));await withNode('c',async()=>events.push('other'));assert.deepEqual(events,['apply','other']);release();await Promise.all([applying,agent]);assert.equal(events.at(-1),'agent');
});

test('unacknowledged protected lock acquisition does not enter Install or attempt cleanup', async () => {
    let inserts = 0, deletes = 0;
    const store = { deleteMany() { deletes++; }, async insertOne(row, options) {
        inserts++;
        assert.equal(row.allowStaleUnlock, false);
        assert.equal(options.writeConcern.w, 'majority');
        return { acknowledged: false };
    } };
    await assert.rejects(makeLocks(store).run(() => assert.fail('entered Install'), { allowStaleUnlock: false }),
        { code: 'REBUILD_LOCK_LOST' });
    assert.deepEqual([inserts, deletes], [1, 0]);
});

test('Apply requires an acknowledged exact-token release without retry', async t => {
    for (const [name, release, keepRow] of [
        ['acknowledged', () => ({ acknowledged: true, deletedCount: 1 }), false],
        ['replacement', () => ({ acknowledged: true, deletedCount: 0 }), true],
        ['unacknowledged', () => ({ acknowledged: false, deletedCount: 1 }), false],
        ['missing result', () => undefined, false],
        ['lost acknowledgement', token => { throw new Error(`private DB detail ${token}`); }, false],
    ]) await t.test(name, async () => {
        let row, original, mutations = 0;
        const releases = [];
        const replacement = { _id: 'apply', token: 'replacement-generation', heartbeat: new Date(0) };
        const remove = (method, filter) => {
            releases.push(method);
            assert.deepEqual(filter, { _id: 'apply', token: original.token });
            if (row?.token === filter.token) row = null;
            return release(original.token);
        };
        const store = {
            async insertOne(value) { row = original = value; },
            async findOne(filter) { return row?.token === filter.token ? row : null; },
            async deleteMany(filter) { return remove('deleteMany', filter); },
            async deleteOne(filter) { return remove('deleteOne', filter); },
        };
        const result = makeLocks(store).run(async verify => {
            await verify();
            mutations++;
            if (keepRow) row = replacement;
            return 'completed';
        });
        if (name === 'acknowledged') assert.equal(await result, 'completed');
        else await assert.rejects(result, error => {
            assert.equal(error.code, 'REBUILD_LOCK_RELEASE_UNCONFIRMED');
            assert.equal(error.message, error.code);
            assert.equal(error.cause, undefined);
            return true;
        });
        assert.deepEqual(releases, ['deleteMany']);
        assert.equal(mutations, 1);
        assert.equal(row, keepRow ? replacement : null);
    });
});

test('Apply preserves the exact primary throw and retires the active marker even if release throws', async () => {
    for (const primary of [Object.freeze(Object.assign(new Error('primary refusal'), { code: 'REBUILD_LOCK_LOST' })),
        undefined, null, false, 0, 'private detail', Symbol('private detail')]) {
        let now = 0, row, releases = 0;
        const refuseRelease = async filter => {
            releases++;
            assert.deepEqual(filter, { _id: 'apply', token: row.token });
            throw new Error('private release detail');
        };
        const store = {
            async insertOne(value) { row = value; },
            async findOne() { return row; },
            deleteMany: refuseRelease, deleteOne: refuseRelease,
        };
        const locks = makeLocks(store, () => now);
        await locks.run(() => { now = 120001; throw primary; }).then(
            () => assert.fail('primary throw was suppressed'),
            reason => assert.equal(reason, primary),
        );
        assert.equal(releases, 1);
        assert.equal((await locks.status()).stale, true);
    }
});

test('Mongo singleton blocks concurrency; restart leaves stale row for exact operator button only',async()=>{
 const {spawn}=require('node:child_process'),fs=require('node:fs/promises'),path=require('node:path'),net=require('node:net');const mongoose=require('mongoose');
 const dir=await fs.mkdtemp(path.join(process.env.TMPDIR,'rebuild-lock-'));const listener=net.createServer();await new Promise(r=>listener.listen(0,'127.0.0.1',r));const port=listener.address().port;await new Promise(r=>listener.close(r));
 const daemon=spawn(process.env.C3_MONGOD||'mongod',['--dbpath',dir,'--bind_ip','127.0.0.1','--port',String(port),'--nounixsocket','--quiet'],{stdio:'ignore'});const exited=new Promise(r=>{daemon.once('error',r);daemon.once('exit',r)});let conn;
 try {conn=await mongoose.createConnection(`mongodb://127.0.0.1:${port}/rebuild_local_lock`,{serverSelectionTimeoutMS:10000}).asPromise();const store=conn.db.collection('locks'),locks=makeLocks(store);await locks.run(async check=>{await check();const status=await locks.status();assert.equal(status.stale,false);await assert.rejects(locks.unlock(status.token),{code:'REBUILD_LOCK_NOT_STALE'});await assert.rejects(locks.run(()=>assert.fail()),{code:'REBUILD_BUSY'})});
 // Historical rows have no durable purpose; age (or a malformed flag) is not proof of Apply.
 for (const flag of [{}, {allowStaleUnlock:[true]}]) {
   const row={_id:'apply',token:'abandoned',heartbeat:new Date(0),...flag};
   await store.insertOne(row);assert.equal((await locks.status()).stale,false);
   await assert.rejects(locks.unlock(row.token),{code:'REBUILD_LOCK_NOT_STALE'});
   assert.deepEqual(await store.findOne({_id:'apply'}),row);await store.deleteOne({_id:'apply'});
 }
 await store.insertOne({_id:'apply',token:'abandoned',heartbeat:new Date(0),allowStaleUnlock:true});assert.equal((await locks.status()).stale,true);await assert.rejects(locks.unlock('older'),{code:'REBUILD_LOCK_NOT_STALE'});await locks.unlock('abandoned');assert.deepEqual(await locks.status(),{locked:false});
 }finally{await conn?.close();daemon.kill();await exited;await fs.rm(dir,{recursive:true,force:true})}
});
