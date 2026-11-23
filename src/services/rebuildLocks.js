'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const error = code => Object.assign(new Error(code), {code});
const installOwners = new WeakMap();
const installOwner = retain => installOwners.get(retain);
const lockName = 'c3_rebuild_locks';
const majority = { writeConcern: { w: 'majority' }, timeoutMS: 5000 };
const lockRead = { readPreference: 'primary', readConcern: { level: 'majority' }, timeoutMS: 5000 };
const exactLock = row => ({ _id: rowId, token: row.token, $expr: { $eq: ['$$ROOT', { $literal: row }] } });
const one = (reply, field) => reply?.acknowledged === true && reply[field] === 1;
const ownerDigest = token => createHash('sha256').update(token).digest('hex');
const generation = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const queues = new Map(), held = new AsyncLocalStorage();
async function withNode(nodeId, fn) {
    const key=String(nodeId); if (held.getStore()?.has(key)) return fn();
    const prev=queues.get(key)||Promise.resolve(); let release;
    const done=new Promise(resolve=>{release=resolve}); queues.set(key,done);
    await prev;
    try { return await held.run(new Set([...(held.getStore()||[]),key]),fn); }
    finally { release(); if(queues.get(key)===done) queues.delete(key); }
}
function withNodes(ids, fn) {
    const keys=[...new Set(ids.map(String))].sort();
    const take = n => n===keys.length?fn():withNode(keys[n],()=>take(n+1)); return take(0);
}
// Single active panel. No TTL index: only the owning invocation or an explicit
// observed-token operator action can remove this singleton.
const active=new Set(), rowId='apply', staleMs=120000;
function mongoStore(){return require('mongoose').connection.collection(lockName);}
function makeLocks(store=mongoStore(), clock=Date.now) {
    const sameDb = db => db?.collection(lockName) === store;
    const run=async (fn,{allowStaleUnlock=true}={})=>{
        const token=randomUUID(), beat=()=>new Date(clock());
        // Stamp this generation at acquisition, before any Install reservation or dispatch.
        // Marking it only on retain() would leave a crash window after the first write.
        const row={_id:rowId,token,heartbeat:beat(),allowStaleUnlock:allowStaleUnlock===true};
        try {
            if (row.allowStaleUnlock) await store.insertOne(row);
            else {
                const receipt=await store.insertOne(row,{writeConcern:{w:'majority'},timeoutMS:5000});
                if(receipt?.acknowledged!==true)throw error('REBUILD_LOCK_LOST');
            }
        } catch(e) { if(e.code===11000)throw error('REBUILD_BUSY'); throw e; }
        active.add(token);let lost=false, heartbeat, reservation, handedBack=false;
        const verify=async()=>{if(lost || !(await store.findOne({_id:rowId,token})))throw error('REBUILD_LOCK_LOST');};
        const timer=setInterval(()=>{
            if (!heartbeat) heartbeat=store.updateOne({_id:rowId,token},{$set:{heartbeat:beat()}})
                .then(x=>{if(x.matchedCount!==1)lost=true;},()=>{lost=true;}).finally(()=>{heartbeat=undefined;});
        },15000);timer.unref();
        let completed=false, retained=false;
        const retain=()=>{retained=true;};
        if (!row.allowStaleUnlock) installOwners.set(retain, {
            async bind(db, session, receipt) {
                if (reservation || !session?.inTransaction() || !active.has(token) || !sameDb(db)) throw error('REBUILD_LOCK_LOST');
                reservation = { ...receipt, ownerDigest: ownerDigest(token), phase: 'installing' };
                const bound = await store.updateMany({ _id: rowId, token, allowStaleUnlock: false,
                    installRecovery: { $exists: false } }, { $set: { installRecovery: reservation } }, { session });
                if (!one(bound, 'matchedCount')) throw error('REBUILD_LOCK_LOST');
            },
            // Called by Install only after its original DIRECT transport closes.
            handBack() { handedBack=true; },
        });
        try {
            // A lifecycle with unconfirmed settlement must not delete its
            // exclusion record on unwind. The token is never transferred.
            const result=await fn(verify,retain);
            completed=true;
            return result;
        } finally {
            clearInterval(timer);
            installOwners.delete(retain);
            let released=false;
            try {
                // The exact singleton predicate matches at most one row. Use
                // the non-retryable MongoDB delete form even on retryWrites clients.
                if (retained && reservation && handedBack) {
                    await heartbeat;
                    if (!lost) await store.updateMany({ _id: rowId, token, allowStaleUnlock: false,
                        installRecovery: reservation }, { $set: { 'installRecovery.phase': 'ready' } }, majority);
                } else if(!retained){
                    const result=await store.deleteMany({_id:rowId,token});
                    released=result?.acknowledged===true && result.deletedCount===1;
                }
            } catch {
                // Do not expose DB details or replace a primary callback refusal.
            } finally { active.delete(token); }
            if(completed&&!released)throw error('REBUILD_LOCK_RELEASE_UNCONFIRMED');
        }
    };
    const status=async()=>{const row=await store.findOne({_id:rowId});return row?{locked:true,
        ...(row.allowStaleUnlock===true&&{token:row.token}),
        stale:row.allowStaleUnlock===true&&!active.has(row.token)&&new Date(row.heartbeat).getTime()<=clock()-staleMs}:{locked:false};};
    const unlock=async token=>{
        if(typeof token!=='string'||active.has(token))throw error('REBUILD_LOCK_NOT_STALE');
        // Check eligibility inside the delete. An unmarked legacy row could be an unresolved Install.
        const res=await store.deleteOne({_id:rowId,token,heartbeat:{$lte:new Date(clock()-staleMs)},
            $expr:{$eq:['$allowStaleUnlock',true]}});
        if(res?.acknowledged!==true||res.deletedCount!==1)throw error('REBUILD_LOCK_NOT_STALE');
        return {locked:false};
    };
    // A dedicated claimant for Install; not an unlock/takeover API. The atomic
    // settlement caller supplies the same session as its state and copy CASes.
    async function readInstallRecovery(db, nodeId, actor) {
        const blocked = () => error('REBUILD_L2TP_INSTALL_RECOVERY_BLOCKED');
        if (!sameDb(db)) throw blocked();
        const row = await store.findOne({ _id: rowId }, lockRead);
        const receipt = row?.installRecovery;
        // 8a56425 and pre-handoff crashes have no durable proof the original
        // writer has exited. Neither age nor an empty local active set suffices.
        if (row?._id !== rowId || row.allowStaleUnlock !== false || typeof row.token !== 'string'
            || row.token.length !== 36 || !generation.test(row.token)
            || active.has(row.token) || Object.hasOwn(row, 'installRecoveryClaim') || receipt?.version !== 1
            || receipt.phase !== 'ready' || receipt.nodeId !== nodeId || receipt.actor !== actor
            || receipt.ownerDigest !== ownerDigest(row.token)) throw blocked();
        const filter = exactLock(row);
        return { receipt, async claim(session) {
            if (!session?.inTransaction() || active.has(row.token)) throw blocked();
            const value = randomUUID();
            if (!one(await store.updateMany(filter, { $set: { installRecoveryClaim: value } }, { session }), 'matchedCount')) throw blocked();
            const actual = await store.findOne({ _id: rowId, token: row.token, installRecoveryClaim: value }, { session });
            if (!actual) throw blocked();
            const claimed = exactLock(actual);
            return {
                async verify(session) {
                    if (!await store.findOne(claimed, session ? { session } : lockRead)) throw blocked();
                },
                async releaseClaim() {
                    if (!one(await store.updateMany(claimed, { $unset: { installRecoveryClaim: '' } }, majority), 'matchedCount')) throw blocked();
                },
                async settle(session) {
                    if (!session?.inTransaction() || !one(await store.deleteMany(claimed, { session }), 'deletedCount')) throw blocked();
                },
            };
        } };
    }
    return {run,status,unlock,readInstallRecovery};
}
module.exports={withNode,withNodes,makeLocks,installOwner};
