'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const error = code => Object.assign(new Error(code), {code});
const installOwners = new WeakMap();
const installOwner = retain => installOwners.get(retain);
const cutoverOwners = new WeakMap();
const cutoverOwner = retain => cutoverOwners.get(retain);
const lockName = 'c3_rebuild_locks';
const majority = { writeConcern: { w: 'majority' }, timeoutMS: 5000 };
const lockRead = { readPreference: 'primary', readConcern: { level: 'majority' }, timeoutMS: 5000 };
const collation = { locale: 'simple' };
const cutoverWrite = { ...majority, collation }, cutoverRead = { ...lockRead, collation };
const exactLock = row => ({ _id: rowId, token: row.token, $expr: { $eq: ['$$ROOT', { $literal: row }] } });
const one = (reply, field) => reply?.acknowledged === true && reply[field] === 1;
const ownerDigest = token => createHash('sha256').update(token).digest('hex');
const generation = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const validGeneration = value => typeof value === 'string' && value.length === 36 && generation.test(value);
const retryableClaim = value => value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === 2 && validGeneration(value.id) && value.phase === 'retryable';
// Only the nonsecret identity of the file journal's plan, never the plan itself.
const journalUuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const journalIdentityFields = Object.entries({
    scope: /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}$/,
    operationId: journalUuid,
    fenceId: journalUuid,
    planDigest: /^[a-f0-9]{64}$/,
});
function journalIdentity(input) {
    if (!input || Object.getPrototypeOf(input) !== Object.prototype || Reflect.ownKeys(input).length !== journalIdentityFields.length)
        throw error('REBUILD_LOCK_LOST');
    return Object.fromEntries(journalIdentityFields.map(([key, syntax]) => {
        const value = Object.getOwnPropertyDescriptor(input, key)?.value;
        if (typeof value !== 'string' || !syntax.test(value) || /\s/.test(value)) throw error('REBUILD_LOCK_LOST');
        return [key, value];
    }));
}
const cutoverNodeId = /^[a-f0-9]{24}(?![\s\S])/;
function writerRoster(ids) {
    if (!Array.isArray(ids) || ids.length === 0 || ids.length > 128 || new Set(ids).size !== ids.length ||
        ids.some(id => typeof id !== 'string' || !cutoverNodeId.test(id))) throw error('REBUILD_LOCK_LOST');
    return [...ids].sort();
}
const queues = new Map(), held = new AsyncLocalStorage();
function nodeLockVerifier(nodeId) {
    const key = String(nodeId), lease = held.getStore()?.get(key);
    return () => lease?.active === true && held.getStore()?.get(key) === lease;
}
async function withNode(nodeId, fn) {
    const key=String(nodeId); if (nodeLockVerifier(key)()) return fn();
    const prev=queues.get(key)||Promise.resolve(); let release;
    const done=new Promise(resolve=>{release=resolve}); queues.set(key,done);
    await prev;
    const lease = { active: true };
    try { return await held.run(new Map([...(held.getStore()||[]),[key,lease]]),fn); }
    finally { lease.active = false; release(); if(queues.get(key)===done) queues.delete(key); }
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
        let live=true, lastBeat=row.heartbeat, cutoverPhase, cutoverFilter, checks=0;
        const canVerifyCutover = () => live && !lost && (cutoverPhase === 'promoted' || cutoverPhase === 'settling');
        const verifyCutover = async () => {
            if (!canVerifyCutover()) throw error('REBUILD_LOCK_LOST');
            checks++;
            try {
                if (!await store.findOne(cutoverFilter, cutoverRead) || !canVerifyCutover()) throw error('REBUILD_LOCK_LOST');
                return true;
            } catch {
                lost=true;
                throw error('REBUILD_LOCK_LOST');
            } finally { checks--; }
        };
        const verify=async()=>{
            if(cutoverPhase)return verifyCutover();
            if(!live || lost || !(await store.findOne({_id:rowId,token})) || !live || lost || cutoverPhase)
                throw error('REBUILD_LOCK_LOST');
        };
        const timer=setInterval(()=>{
            if (!heartbeat && !cutoverPhase) {
                const nextBeat=beat();
                heartbeat=store.updateOne({_id:rowId,token},{$set:{heartbeat:nextBeat}})
                    .then(x=>{if(x.matchedCount!==1)lost=true;else lastBeat=nextBeat;},()=>{lost=true;})
                    .finally(()=>{heartbeat=undefined;});
            }
        },15000);timer.unref();
        let completed=false, retained=false;
        const retain=()=>{retained=true;};
        // Use the retain from the original run, including on already-held paths.
        // promote() is one-shot; only its acknowledged exact readback grants
        // verify(). settle(prove) takes a trusted original-writer proof callback:
        // return true only after exact terminal journal, writer drain and any
        // business settlement proofs. It revokes verify and permits deletion
        // only on successful outer return. Neither method can adopt an old row.
        cutoverOwners.set(retain, Object.freeze({
            async promote(identity, nodeIds) {
                if (!live || lost || cutoverPhase || retained || reservation || handedBack) throw error('REBUILD_LOCK_LOST');
                cutoverPhase='promoting'; // suppress ordinary cleanup before any await
                clearInterval(timer);
                try {
                    const cutover=journalIdentity(identity);
                    const roster=nodeIds === undefined ? {} : { cutoverNodes: writerRoster(nodeIds) };
                    await heartbeat;
                    if (!live || lost || retained) throw error('REBUILD_LOCK_LOST');
                    const before={...row, heartbeat:lastBeat};
                    const change={allowStaleUnlock:false, cutover, ...roster};
                    const ack=await store.updateMany(exactLock(before), { $set: change }, cutoverWrite);
                    if (!live || lost || retained || !one(ack,'matchedCount') || ack.modifiedCount!==1)
                        throw error('REBUILD_LOCK_LOST');
                    cutoverFilter=exactLock({...before, ...change});
                    if (!await store.findOne(cutoverFilter, cutoverRead) || !live || lost || retained) throw error('REBUILD_LOCK_LOST');
                    cutoverPhase='promoted';
                    return Object.freeze({verify:verifyCutover, async settle(prove) {
                        if (!live || lost || retained || cutoverPhase!=='promoted') throw error('REBUILD_LOCK_LOST');
                        cutoverPhase='settling';
                        try {
                            if (checks || typeof prove!=='function') throw error('REBUILD_LOCK_LOST');
                            await verifyCutover();
                            if (!canVerifyCutover() || retained || await prove()!==true) throw error('REBUILD_LOCK_LOST');
                            await verifyCutover();
                            if (!canVerifyCutover() || retained || checks) throw error('REBUILD_LOCK_LOST');
                            cutoverPhase='settled';
                        } catch {
                            lost=true;
                            throw error('REBUILD_LOCK_LOST');
                        }
                    }});
                } catch {
                    lost=true;
                    throw error('REBUILD_LOCK_LOST');
                }
            },
        }));
        if (!row.allowStaleUnlock) installOwners.set(retain, {
            async bind(db, session, receipt) {
                if (cutoverPhase || reservation || !session?.inTransaction() || !active.has(token) || !sameDb(db)) throw error('REBUILD_LOCK_LOST');
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
            live=false;
            clearInterval(timer);
            cutoverOwners.delete(retain);
            installOwners.delete(retain);
            let released=false;
            try {
                // The exact singleton predicate matches at most one row. Use
                // the non-retryable MongoDB delete form even on retryWrites clients.
                if (cutoverPhase) {
                    if (completed && cutoverPhase==='settled' && !lost && !retained)
                        released=one(await store.deleteMany(cutoverFilter, cutoverWrite),'deletedCount');
                } else if (retained && reservation && handedBack) {
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
            if(completed&&!released){
                const failure=error('REBUILD_LOCK_RELEASE_UNCONFIRMED');
                if(cutoverPhase==='settled')failure.settledMain=true;
                throw failure;
            }
        }
    };
    const status=async()=>{
        const row=await store.findOne({_id:rowId});
        if(!row)return {locked:false};
        const eligible=row.allowStaleUnlock===true&&!Object.hasOwn(row,'cutover');
        return {locked:true,...(eligible&&{token:row.token}),
            stale:eligible&&!active.has(row.token)&&new Date(row.heartbeat).getTime()<=clock()-staleMs};
    };
    const unlock=async token=>{
        if(typeof token!=='string'||active.has(token))throw error('REBUILD_LOCK_NOT_STALE');
        // Check eligibility inside the delete. An unmarked legacy row could be an unresolved Install.
        const res=await store.deleteOne({_id:rowId,token,heartbeat:{$lte:new Date(clock()-staleMs)},cutover:{$exists:false},
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
        if (row === null) return null;
        const receipt = row?.installRecovery;
        const prior = row?.installRecoveryClaim;
        // 8a56425 and pre-handoff crashes have no durable proof the original
        // writer has exited. Neither age nor an empty local active set suffices.
        if (row?._id !== rowId || row.allowStaleUnlock !== false || !validGeneration(row.token) || Object.hasOwn(row, 'cutover')
            || active.has(row.token) || ![1, 2].includes(receipt?.version)
            || receipt.phase !== 'ready' || receipt.nodeId !== nodeId || receipt.actor !== actor
            || receipt.ownerDigest !== ownerDigest(row.token)) throw blocked();
        // A legacy UUID cannot distinguish a host refusal from an unknown
        // settlement COMMIT. Only the positively published retryable state
        // permits rotation, even after a panel restart.
        const hadClaim = Object.hasOwn(row, 'installRecoveryClaim');
        if (hadClaim && !retryableClaim(prior)) throw blocked();
        const filter = exactLock(row);
        return { receipt, async claim(session) {
            if (!session?.inTransaction() || active.has(row.token)) throw blocked();
            const value = { id: randomUUID(), phase: 'active' };
            if (!one(await store.updateMany(filter, { $set: { installRecoveryClaim: value } }, { session }), 'matchedCount')) throw blocked();
            const actual = await store.findOne({ _id: rowId, token: row.token, installRecoveryClaim: value }, { session });
            if (!actual) throw blocked();
            const claimed = exactLock(actual);
            return {
                async verify(session) {
                    if (!await store.findOne(claimed, session ? { session } : lockRead)) throw blocked();
                },
                async releaseClaim() {
                    const update = hadClaim ? { $set: { installRecoveryClaim: prior } } : { $unset: { installRecoveryClaim: '' } };
                    if (!one(await store.updateMany(claimed, update, majority), 'matchedCount')) throw blocked();
                },
                async allowRecheck() {
                    if (!one(await store.updateMany(claimed,
                        { $set: { installRecoveryClaim: { id: value.id, phase: 'retryable' } } }, majority), 'matchedCount')) throw blocked();
                },
                async settle(session) {
                    if (!session?.inTransaction() || !one(await store.deleteMany(claimed, { session }), 'deletedCount')) throw blocked();
                },
            };
        } };
    }
    async function assertAgentWriterAllowed(nodeId) {
        // Check inside the same local queue, never before taking the lease.
        const ownsNode = nodeLockVerifier(nodeId);
        const blocked = () => error('REBUILD_AGENT_WRITER_BLOCKED');
        if (!ownsNode()) throw blocked();
        try {
            const row = await store.findOne({ _id: rowId, cutover: { $exists: true } },
                { ...lockRead, projection: { _id: 0, cutoverNodes: 1 } });
            if (!ownsNode() || (row !== null && writerRoster(row?.cutoverNodes).includes(String(nodeId)))) throw blocked();
        } catch { throw blocked(); }
    }
    return {run,status,unlock,readInstallRecovery,assertAgentWriterAllowed};
}
const assertAgentWriterAllowed = async nodeId => makeLocks().assertAgentWriterAllowed(nodeId);
module.exports={withNode,withNodes,nodeLockVerifier,makeLocks,installOwner,cutoverOwner,assertAgentWriterAllowed};
