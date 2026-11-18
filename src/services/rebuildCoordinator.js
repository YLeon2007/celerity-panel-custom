'use strict';
const { isDeepStrictEqual: equal } = require('node:util');
const {createHmac,randomBytes}=require('node:crypto');
// The preview fingerprint is opaque and expires when the panel restarts.
const previewKey=randomBytes(32);
const fail = code => Object.assign(new Error(code), {code});
const id = obj => String(obj?._id ?? obj);
const ends = row => [id(row.portalNode), id(row.bridgeNode)];
function componentFor(links, seeds) {
    const seen = new Set(seeds.map(id)), todo = [...seen], adjacent = new Map();
    for (const row of links) {
        if (row.active === false && !row.rebuildDelete) continue;
        const [a,b] = ends(row);
        for (const [x,y] of [[a,b],[b,a]]) { if (!adjacent.has(x)) adjacent.set(x, []); adjacent.get(x).push(y); }
    }
    for (let i=0;i<todo.length;i++) for (const next of adjacent.get(todo[i]) || []) {
        if (!seen.has(next)) { seen.add(next); todo.push(next); }
    }
    return [...seen].sort();
}
// Only managed transport/control interfaces may disappear without a client diff.
// A named subscriber on a purported tunnel makes it a client for this check.
function protectedInterfaces(config) {
    if (!Array.isArray(config?.inbounds)) throw fail('REBUILD_BASELINE_INVALID');
    const projected = config.inbounds.filter(i => {
        if (!i || typeof i !== 'object') throw fail('REBUILD_BASELINE_INVALID');
        if (['dokodemo-door','socks'].includes(i.protocol) && (i.tag==='API_INBOUND'|| /^(?:cascade-|relay-l2tp-|rebuild-relay-ingress$)/.test(i.tag))) return false;
        return !(/^(?:bridge-conn-|conn-down-|fwd-hop-|cascade-in-)[\w-]+$/.test(i.tag) && ['vless','vmess'].includes(i.protocol) && Array.isArray(i.settings?.clients) && i.settings.clients.every(c=>!c.email));
    }).map(i=>{
        const {sniffing, ...copy}=structuredClone(i); // changes how to route, not how to connect
        if (Array.isArray(copy.settings?.clients)) copy.settings.clients.sort((a,b)=>String(a.id).localeCompare(String(b.id))||String(a.email).localeCompare(String(b.email)));
        return copy;
    });
    return projected.sort((a,b)=>String(a.tag).localeCompare(String(b.tag)));
}
function profilePreview(before, after, profile) {
    if (!before && profile==='main') throw fail('REBUILD_MAIN_UNREADABLE');
    const sections=[...new Set([...Object.keys(before||{}),...Object.keys(after)])].filter(k=>!equal(before?.[k],after[k]));
    return {profile, change:!before?'create':sections.length?'replace':'unchanged', sections:sections.filter(k=>['inbounds','outbounds','routing','reverse','log','api','stats','policy','dns','observatory'].includes(k)).sort(),protectedChanged:profile==='main' && !equal(protectedInterfaces(before),protectedInterfaces(after))};
}
// DELETE retains the old endpoint row (a rebuild-only desired tombstone) until
// readback succeeds for the whole original component. A fresh Apply uses the
// same inventory after a crash. No operation replay or startup worker.
async function runRebuild(d, req) {
    return d.global(async(verify = async()=>{})=>{
        const inventory=await d.links(), anchor=inventory.find(row=>id(row)===req.linkId);
        if (!anchor && !req.nodeId) throw fail('REBUILD_LINK_NOT_FOUND');
        const nodes=componentFor(inventory,anchor?ends(anchor):[req.nodeId]);
        return d.withNodes(nodes,async()=>{
            const scope=new Set(nodes), links=inventory.filter(row=>ends(row).every(n=>scope.has(n)));
            if(links.some(row=>row.lifecycle)) throw fail('REBUILD_CONFLICTING_LINK_LIFECYCLE');
            const removed=links.filter(row=>row.rebuildDelete===true || req.remove && id(row)===req.linkId);
            const desired=links.filter(row=>!removed.includes(row)&&row.active!==false);
            const candidates=await d.build(nodes,desired);
            if(candidates.length!==2*nodes.length) throw fail('REBUILD_INCOMPLETE_PROFILES');
            const pairs=new Map(), report=[], fingerprint=createHmac('sha256',previewKey);
            fingerprint.update(JSON.stringify([req.linkId,!!req.remove,removed.map(id).sort(),desired.map(id).sort()]));
            for(const nodeId of nodes){
                const pair=candidates.filter(p=>p.nodeId===nodeId); pairs.set(nodeId,pair);
                if(pair.length!==2||new Set(pair.map(p=>p.profile)).size!==2||!pair.every(p=>['main','bridge'].includes(p.profile)))throw fail('REBUILD_INCOMPLETE_PROFILES');
                const profiles=[];
                for(const p of pair){
                    const before=await d.read(nodeId,p.profile);
                    profiles.push(profilePreview(before,p.config,p.profile));
                    fingerprint.update(JSON.stringify([nodeId,p.profile,before,p.config]));
                }
                report.push({nodeId,profiles});
            }
            const result={allowed:!report.some(n=>n.profiles.some(p=>p.protectedChanged)),nodes:report,previewId:fingerprint.digest('hex')};
            if(req.preview) return result;
            if(!result.allowed)throw Object.assign(fail('REBUILD_CLIENT_CHANGE'),{preview:result});
            if(req.expectedPreview!==undefined && req.expectedPreview!==result.previewId)throw Object.assign(fail('REBUILD_PREVIEW_CHANGED'),{preview:result});
            await verify();
            if(req.remove && !anchor?.rebuildDelete) await d.markDelete?.(req.linkId);
            if(d.stagePair) for(const [nodeId,pair] of pairs) { await verify(); await d.stagePair(nodeId,pair); }
            // A connection loss is reported as failure even if only a restart
            // was missed. Never skip an unchanged profile pair on a retry.
            for(const [nodeId,pair] of pairs) { await verify(); await d.putPair(nodeId,pair); }
            for(const [nodeId,pair] of pairs) for(const p of pair) {
                if(!equal(await d.read(nodeId,p.profile),p.config))throw fail('REBUILD_READBACK_MISMATCH');
            }
            await verify(); await d.finish({nodes,desired,removed});return result;
        });
    });
}
module.exports={runRebuild,componentFor,profilePreview};
