'use strict';
const { isDeepStrictEqual: equal } = require('node:util');
const {createHmac,randomBytes}=require('node:crypto');
const {linkSnapshotBytes}=require('./rebuildLinkSnapshot');
const {addExitImpacts,hasObservedScopedTransit}=require('./rebuildPreviewExitImpact');
const {hasReverseObservationEmail}=require('./rebuildReverseIdentity');
const {refuseStaleKcpPreview}=require('./rebuildKcpAdmission');
// The preview fingerprint is opaque and expires when the panel restarts.
const previewKey=randomBytes(32);
const fail = code => Object.assign(new Error(code), {code});
// Only coordinator-generated refusal reports are safe to send over HTTP.
const publicPreviews = new WeakMap();
function previewRefusal(code, preview) {
    const error = Object.assign(fail(code), { preview });
    publicPreviews.set(error, preview);
    return error;
}
const previewForError = error => publicPreviews.get(error);
const id = obj => String(obj?._id ?? obj);
const ends = row => [id(row.portalNode), id(row.bridgeNode)];
function fingerprintLinks(links) {
    const digest=createHmac('sha256',previewKey).update('rebuild-link-rows\0');
    for(const row of [...links].sort((a,b)=>id(a).localeCompare(id(b)))) {
        const bytes=linkSnapshotBytes(row);
        digest.update(String(bytes.length)).update(':').update(bytes);
    }
    return digest.digest('hex');
}
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
const tunnelIdentity = value => typeof value === 'string' && value
    ? (/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value) ? value.toLowerCase() : value) : null;
const tunnelIdentities = row => [row.tunnelUuid, row.rebuildApplied?.uuid].map(tunnelIdentity).filter(Boolean);

// Retirement is rooted in the old graph, not the resulting components. An
// inactive row can still own runtime artifacts; only an explicitly unapplied
// inactive non-incident draft can be left out of that closure.
function retirementScope(inventory, target) {
    const adjacent = new Map();
    for (const row of inventory) {
        const refs = new Set([...ends(row), ...[row.source, row.target, row.rebuildApplied?.listener]
            .filter(ref => ref != null).map(id)]);
        if (!refs.has(target) && row.active === false && !row.rebuildDelete && !row.lifecycle && row.rebuildApplied === null) continue;
        for (const ref of refs) {
            if (!adjacent.has(ref)) adjacent.set(ref, []);
            adjacent.get(ref).push([row, refs]);
        }
    }
    const nodes = new Set([target]), scoped = new Set();
    for (const node of nodes) for (const [row, refs] of adjacent.get(node) || []) {
        if (scoped.has(row)) continue;
        scoped.add(row);
        for (const ref of refs) nodes.add(ref);
    }
    const links = [...scoped];
    const incident = links.filter(row => ends(row).includes(target));
    // Removing an edge is not revocation if another edge retains its identity.
    // Include the last applied UUID (which can differ from the draft), and
    // inventory outside this component: retirement will not rewrite those hosts.
    const dropping = new Set(incident);
    const retiringIdentities = new Set(incident.flatMap(tunnelIdentities));
    if (retiringIdentities.size && inventory.some(row => !dropping.has(row)
        && tunnelIdentities(row).some(value => retiringIdentities.has(value)))) {
        throw fail('REBUILD_RETIRE_TUNNEL_CREDENTIAL_CONFLICT');
    }
    return { nodes: [...nodes].sort(), links, incident };
}
function checkRetirementLinks(links) {
    const seen = new Set();
    for (const row of links) {
        const [source, target] = ends(row);
        if (![id(row), source, target].every(v => /^[a-f0-9]{24}$/.test(v)) || seen.has(id(row)) || source === target
            || (row.source != null && id(row.source) !== source) || (row.target != null && id(row.target) !== target)
            || (Object.hasOwn(row, 'active') && typeof row.active !== 'boolean')) throw fail('REBUILD_INVALID_LINK');
        seen.add(id(row));
        // The receipt only names the old listener. If an endpoint moved, the
        // old dialer cannot be reconstructed from this row; refuse, not prune.
        const applied = row.rebuildApplied;
        if (applied != null && (typeof applied!=='object' || Object.keys(applied).length!==5
            || !['forward','reverse'].includes(applied.mode) || !['vless','vmess'].includes(applied.protocol)
            || (applied.mode==='reverse' && applied.protocol!=='vless')
            || id(applied.listener)!==(applied.mode==='reverse'?source:target)
            || !Number.isInteger(applied.port) || applied.port<1 || applied.port>65535
            || typeof applied.uuid!=='string' || !/^\S+$/.test(applied.uuid))) throw fail('REBUILD_L2TP_APPLIED_LINK_UNPROVED');
    }
}
// Only managed transport/control interfaces may disappear without a client diff.
// A named subscriber on a purported tunnel makes it a client for this check.
function protectedInterfaces(config) {
    if (!Array.isArray(config?.inbounds)) throw fail('REBUILD_BASELINE_INVALID');
    const projected = config.inbounds.filter(i => {
        if (!i || typeof i !== 'object') throw fail('REBUILD_BASELINE_INVALID');
        if (['dokodemo-door','socks'].includes(i.protocol) && (i.tag==='API_INBOUND'|| /^(?:cascade-|relay-l2tp-|rebuild-relay-ingress$)/.test(i.tag))) return false;
        const native=/^rebuild-rp-conn-([a-f0-9]{8})$/.exec(i.tag);
        const account = i.settings?.clients?.length === 1 ? i.settings.clients[0] : null;
        if (native && i.protocol === 'vless' && account?.reverse?.tag === `rebuild-rp-egress-${native[1]}`
            && (!account.email || hasReverseObservationEmail(i, native[1], account))) return false;
        return !(/^(?:bridge-conn-|conn-down-|fwd-hop-|cascade-in-)[\w-]+$/.test(i.tag) && ['vless','vmess'].includes(i.protocol) && Array.isArray(i.settings?.clients) && i.settings.clients.every(c=>!c.email));
    }).map(i=>{
        const {sniffing, ...copy}=structuredClone(i); // changes how to route, not how to connect
        if (Array.isArray(copy.settings?.clients)) copy.settings.clients.sort((a,b)=>String(a.id).localeCompare(String(b.id))||String(a.email).localeCompare(String(b.email)));
        return copy;
    });
    return projected.sort((a,b)=>String(a.tag).localeCompare(String(b.tag)));
}
function hasProtectedClientInbound(main, tag) {
    if (!main) throw fail('REBUILD_MAIN_UNREADABLE');
    return protectedInterfaces(main).some(i => i.protocol === 'vless' && i.tag === tag);
}
function profilePreview(before, after, profile, protectBridge = false) {
    if (!before && profile==='main') throw fail('REBUILD_MAIN_UNREADABLE');
    const sections=[...new Set([...Object.keys(before||{}),...Object.keys(after)])].filter(k=>!equal(before?.[k],after[k]));
    const legacy=Boolean(before?.reverse?.portals?.length || before?.reverse?.bridges?.length);
    const native=after.inbounds?.some(i=>i.settings?.clients?.some(c=>c.reverse?.tag)) || after.outbounds?.some(o=>o.settings?.reverse?.tag);
    const protectedChanged = (profile === 'main' || protectBridge)
        && !equal(protectedInterfaces(before ?? { inbounds: [] }), protectedInterfaces(after));
    return {profile, change:!before?'create':sections.length?'replace':'unchanged', ...(legacy&&native&&!after.reverse?{tunnelMigration:'legacy-to-vless-reverse'}:{}),sections:sections.filter(k=>['inbounds','outbounds','routing','reverse','log','api','stats','policy','dns','observatory'].includes(k)).sort(),protectedChanged};
}
// DELETE retains the old endpoint row (a rebuild-only desired tombstone) until
// readback succeeds for the whole original component. A fresh Apply uses the
// same inventory after a crash. No operation replay or startup worker.
const runRebuild = (d, req) => runGraph(d, req);
const runRetireGraph = (d, req) => runGraph(d, req, true);
async function runGraph(d, req, retire = false) {
    return d.global(async(verify = async()=>{})=>{
        const inventory=await d.links(), anchor=inventory.find(row=>id(row)===req.linkId);
        const confirmedLinks=!req.preview && req.expectedPreview?.length===128;
        if (!anchor && !req.nodeId) {
            if(req.remove&&req.linkId)await d.assertExitsUnused?.([req.linkId]);
            throw fail(confirmedLinks?'REBUILD_LINK_CHANGED':'REBUILD_LINK_NOT_FOUND');
        }
        const retirement=retire?retirementScope(inventory,req.nodeId):null;
        const lockedNodes=retirement?.nodes ?? componentFor(inventory,anchor?ends(anchor):[req.nodeId]);
        const nodes=retire&&req.mode==='abandon'?lockedNodes.filter(n=>n!==req.nodeId):lockedNodes;
        return d.withNodes(lockedNodes,async()=>{
            const scope=new Set(nodes), scopedRows=rows=>rows.filter(row=>ends(row).every(n=>scope.has(n)));
            const links=retirement?.links ?? scopedRows(inventory);
            const removed=retirement?.incident ?? links.filter(row=>row.rebuildDelete===true || req.remove && id(row)===req.linkId);
            if(removed.length)await d.assertExitsUnused?.(removed.map(id),retire?req.nodeId:undefined);
            // Bind both the working rows and the profiles to the opaque token.
            // Separate digests let Apply identify row drift before composing.
            const linkVersion=fingerprintLinks(links);
            if(retirement)retirement.version=linkVersion;
            if(confirmedLinks && !req.expectedPreview.startsWith(linkVersion)) {
                throw fail('REBUILD_LINK_CHANGED');
            }
            if(links.some(row=>row.lifecycle)) throw fail('REBUILD_CONFLICTING_LINK_LIFECYCLE');
            if(retire)checkRetirementLinks(links);
            const removedSet=new Set(removed);
            const desired=links.filter(row=>!removedSet.has(row)&&row.active!==false&&(!retire||row.rebuildDelete!==true));
            const {candidates,coreIdentities,kcpVersions,transit}=await d.build(nodes,desired,retirement);
            if(candidates.length!==2*nodes.length) throw fail('REBUILD_INCOMPLETE_PROFILES');
            const pairs=new Map(), report=[], observedMain=d.nodeRole?new Map():null, fingerprint=createHmac('sha256',previewKey);
            const survivor=retire?createHmac('sha256',previewKey):null;
            const binding=[linkVersion,req.linkId,!!req.remove,removed.map(id).sort(),desired.map(id).sort()];
            if(retire)binding.push('retire',req.nodeId,req.mode);
            fingerprint.update(JSON.stringify(binding));
            survivor?.update(JSON.stringify(['retire-survivors',binding]));
            // Even if the profiles are byte-identical, both REALITY endpoints
            // must still be the builds checked by the confirmed Preview.
            if(coreIdentities?.size){
                const identities=nodes.filter(id=>coreIdentities.has(id)).map(id=>[id,...coreIdentities.get(id)]);
                fingerprint.update(JSON.stringify(identities));
                survivor?.update(JSON.stringify(identities.filter(([id])=>id!==req.nodeId)));
            }
            // Stored endpoint versions are not configuration fields: bind them
            // independently even when supported upgrades leave identical JSON.
            if(kcpVersions?.length){
                fingerprint.update(JSON.stringify(['mkcp-health-versions',kcpVersions]));
                survivor?.update(JSON.stringify(['mkcp-health-versions',kcpVersions]));
            }
            const transitPreimages=transit?.planRestarts && [];
            for(const nodeId of nodes){
                const pair=candidates.filter(p=>p.nodeId===nodeId); pairs.set(nodeId,pair);
                if(pair.length!==2||new Set(pair.map(p=>p.profile)).size!==2||!pair.every(p=>['main','bridge'].includes(p.profile)))throw fail('REBUILD_INCOMPLETE_PROFILES');
                const profiles=[];
                for(const p of pair){
                    const before=await d.read(nodeId,p.profile,true);
                    transitPreimages?.push({nodeId,profile:p.profile,config:before});
                    if(observedMain&&p.profile==='main')observedMain.set(nodeId,before);
                    // Unlike ordinary Apply, retirement replaces every peer
                    // pair even if its links split off or all disappear.
                    const diff=profilePreview(before,p.config,p.profile,retire);
                    if(p.publishedKeyMismatch)diff.protectedChanged=true;
                    profiles.push(diff);
                    const proof=[nodeId,p.profile,before,p.config,diff.protectedChanged];
                    fingerprint.update(JSON.stringify(proof));
                    if(survivor){
                        if(nodeId!==req.nodeId)survivor.update(JSON.stringify(proof));
                        else if(p.profile==='main')survivor.update(JSON.stringify([nodeId,p.profile,
                            protectedInterfaces(before),protectedInterfaces(p.config),diff.protectedChanged]));
                    }
                }
                report.push({nodeId,profiles});
            }
            const protectedChanged=report.some(n=>n.profiles.some(p=>p.protectedChanged));
            let mainSteps=[];
            if(transitPreimages&&!protectedChanged){
                const counts=new Map();
                mainSteps=transit.planRestarts(transitPreimages);
                for(const {nodeId} of mainSteps)counts.set(nodeId,(counts.get(nodeId)||0)+1);
                for(const entry of report)if(counts.has(entry.nodeId))entry.mainRestartCount=counts.get(entry.nodeId);
            }
            const serial=transit?.serial===true && !!d.activateSerial && !removed.length && !kcpVersions?.length && mainSteps.length>0;
            const routingRequired=transitPreimages&&!protectedChanged&&d.checkSerialRouting
                ? await d.checkSerialRouting(transitPreimages,candidates,mainSteps) : [];
            const routingNodes=new Set(routingRequired);
            for(const entry of report)if(routingNodes.has(entry.nodeId))entry.routingServiceRequired=true;
            const transitBlocked=!serial&&(!!transit?.blocked||!!observedMain&&hasObservedScopedTransit(observedMain));
            if(serial)fingerprint.update(JSON.stringify(['scoped-main-v1',mainSteps.map(({nodeId,phase,kind})=>[nodeId,phase,kind])]));
            const result={allowed:!transitBlocked&&!protectedChanged&&!routingNodes.size,nodes:report,previewId:linkVersion+fingerprint.digest('hex')};
            if(transitBlocked)result.transitBlocked=true;
            if(survivor)result.survivorPreview=linkVersion+survivor.digest('hex');
            const stale=req.expectedPreview!==undefined && req.expectedPreview!==result.previewId;
            if(observedMain&&(req.preview||!result.allowed||stale))addExitImpacts(report,links,observedMain,candidates,d.nodeRole,d.nodeName,!!req.remove,transit);
            async function checkKcpSnapshot(){
                if(!kcpVersions?.length)return;
                const fresh=await d.links();
                const freshRetirement=retire?retirementScope(fresh,req.nodeId):null;
                const scopeNow=freshRetirement?.nodes??componentFor(fresh,ends(anchor));
                const rows=freshRetirement?.links??scopedRows(fresh);
                if(!equal(scopeNow,lockedNodes)||fingerprintLinks(rows)!==linkVersion)throw fail('REBUILD_LINK_CHANGED');
                await d.checkKcpAdmission();
            }
            if(req.preview){
                await checkKcpSnapshot();
                if(d.checkActivation){await verify(); await d.checkActivation(nodes,retirement,{transitBlocked:transitBlocked||serial});}
                await checkKcpSnapshot();
                return result;
            }
            if(!result.allowed)throw previewRefusal(routingNodes.size?'REBUILD_MAIN_ROUTING_SERVICE_REQUIRED':
                transitBlocked?'REBUILD_SCOPED_TRANSIT_APPLY_UNAVAILABLE':'REBUILD_CLIENT_CHANGE',result);
            if(stale&&kcpVersions?.length)refuseStaleKcpPreview();
            if(stale)throw previewRefusal('REBUILD_PREVIEW_CHANGED',result);
            await verify();
            if(serial){
                if(!confirmedLinks)throw fail('REBUILD_PREVIEW_REQUIRED');
                const outcome=await d.activateSerial({ids:nodes,linkVersion,before:transitPreimages,after:candidates,coreIdentities},verify);
                // Return even a confirmed inverse normally through the owning
                // lock callback. The route classifies it only after handback.
                return outcome.status==='applied'?result:{...result,allowed:false,status:outcome.status,failure:outcome.failure};
            }
            await checkKcpSnapshot();
            await d.checkActivation?.(nodes,retirement);
            // Re-read after potentially slow host checks, before stage writes.
            await checkKcpSnapshot();
            if(d.stagePair) for(const [nodeId,pair] of pairs) { await verify(); await d.stagePair(nodeId,pair); }
            await d.prepareActivation?.(nodes);
            await verify();
            await d.persistKeys?.(verify);
            if(req.remove && !anchor?.rebuildDelete) await d.markDelete?.(req.linkId);
            // A connection loss is reported as failure even if only a restart
            // was missed. Never skip an unchanged profile pair on a retry.
            for(const [nodeId,pair] of pairs) { await verify(); await d.putPair(nodeId,pair); }
            for(const [nodeId,pair] of pairs) for(const p of pair) {
                if(!equal(await d.read(nodeId,p.profile,false,p.config),p.config))throw fail('REBUILD_READBACK_MISMATCH');
            }
            await verify(); await d.finish({nodes,desired,removed,retirement,candidates});return result;
        });
    });
}
module.exports={runRebuild,runRetireGraph,retirementScope,fingerprintLinks,componentFor,profilePreview,hasProtectedClientInbound,previewForError};
