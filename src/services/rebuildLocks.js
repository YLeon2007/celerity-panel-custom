'use strict';
const { randomUUID } = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const error = code => Object.assign(new Error(code), {code});
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
// Single active panel. No TTL index: only normal completion or an explicit
// observed-token operator action can remove this singleton.
const active=new Set(), rowId='apply', staleMs=120000;
function mongoStore(){return require('mongoose').connection.collection('c3_rebuild_locks');}
function makeLocks(store=mongoStore(), clock=Date.now) {
    const run=async fn=>{
        const token=randomUUID(), beat=()=>new Date(clock());
        try { await store.insertOne({_id:rowId,token,heartbeat:beat()}); }
        catch(e) { if(e.code===11000)throw error('REBUILD_BUSY'); throw e; }
        active.add(token);let lost=false;
        const verify=async()=>{if(lost || !(await store.findOne({_id:rowId,token})))throw error('REBUILD_LOCK_LOST');};
        const timer=setInterval(()=>{store.updateOne({_id:rowId,token},{$set:{heartbeat:beat()}}).then(x=>{if(x.matchedCount!==1)lost=true;},()=>{lost=true;});},15000);timer.unref();
        try{return await fn(verify);}finally{clearInterval(timer);try{await store.deleteOne({_id:rowId,token});}finally{active.delete(token);}}
    };
    const status=async()=>{const row=await store.findOne({_id:rowId});return row?{locked:true,token:row.token,stale:!active.has(row.token)&&new Date(row.heartbeat).getTime()<=clock()-staleMs}:{locked:false};};
    const unlock=async token=>{if(typeof token!=='string'||active.has(token))throw error('REBUILD_LOCK_NOT_STALE');const res=await store.deleteOne({_id:rowId,token,heartbeat:{$lte:new Date(clock()-staleMs)}});if(res.deletedCount!==1)throw error('REBUILD_LOCK_NOT_STALE');return {locked:false};};
    return {run,status,unlock};
}
module.exports={withNode,withNodes,makeLocks};
