'use strict';
const {isRebuildEnabled}=require('./rebuildMode');
const {runRebuild,hasProtectedClientInbound}=require('./rebuildCoordinator');
const {withNodes,makeLocks}=require('./rebuildLocks');
const {composeRebuildProfiles}=require('../modules/relay-l2tp/services/rebuildTopologyComposer');
const {createTransport,createBoundRelayTransport}=require('./rebuildTransport');
const {verifyTunnelTrust}=require('./rebuildTunnelTls');
const {assertRealityFingerprint,realityDialerId}=require('./rebuildRealityFingerprint');
const {prepareLinks}=require('./rebuildLinkKeys');
const {fullLinkRead}=require('./rebuildLinkSnapshot');
const {createRebuildRelayBackend}=require('./rebuildRelayBackend');
const {createRebuildRelayRemove}=require('./rebuildRelayRemove');
const {createRebuildRelayAccounts}=require('./rebuildRelayAccounts');
const {assertNoPendingRelayAccounts}=require('./rebuildRelayAccountsStore');
const {resolveRelayBinding,captureRelayBinding}=require('./rebuildRelayAuthorization');
const {appliedLink}=require('./rebuildAppliedLink');
const {isReverse,unverified}=require('./rebuildReverseLinkHealth');
const {createPrivateKey,createPublicKey,randomBytes}=require('node:crypto');
const fail=code=>Object.assign(new Error(code),{code});
// Subscriptions publish a separate X25519 public key. It never appears in
// the server JSON, so comparing MAIN before/after cannot catch a DB-only edit.
const x25519Prefix=Buffer.from('302e020100300506032b656e04220420','hex');
function inconsistentPublishedKey(node){
    if(node.cascadeRole!=='portal')return false;
    const xray=node.xray||{};
    return [xray,...(xray.extraInbounds||[])].some(inbound=>{
        if((inbound.security||'reality')!=='reality')return false;
        try {
            const raw=Buffer.from(inbound.realityPrivateKey,'base64url');
            if(raw.length!==32 || raw.toString('base64url')!==inbound.realityPrivateKey)return true;
            const secret=createPrivateKey({key:Buffer.concat([x25519Prefix,raw]),format:'der',type:'pkcs8'});
            return createPublicKey(secret).export({format:'jwk'}).x!==inbound.realityPublicKey;
        } catch {return true;}
    });
}
function createRebuildService({Link=require('../models/cascadeLinkModel'),Node=require('../models/hyNodeModel'),
    State=require('../modules/relay-l2tp/models/relayL2tpStateModel'),sync=require('./syncService'),locks=makeLocks(),connect=createTransport,
    compose=composeRebuildProfiles,env=process.env,cache=require('./cacheService'),
    L2tpUser=require('../modules/relay-l2tp/models/l2tpUserModel'),
    createRelayDirect=options=>require('./rebuildRelayDirect').createRelayDirect(options),
    assertNoRelayAccountIntent=()=>assertNoPendingRelayAccounts(L2tpUser.db)}={}){
    const gate=()=>{if(!isRebuildEnabled(env))throw fail('REBUILD_DISABLED');};
    const checked = async (verify, fn) => {
        if (typeof verify !== 'function' || await verify() === false) throw fail('REBUILD_LOCK_LOST');
        await assertNoRelayAccountIntent();
        if (await verify() === false) throw fail('REBUILD_LOCK_LOST');
        return fn(verify);
    };
    // Reentry must use the active verifier issued by this service, not an
    // arbitrary callback passed to execute().
    const heldVerifiers=new WeakSet();
    const guardedLocks = { ...locks, run: fn => locks.run(raw=>checked(raw,async()=>{
        const verify=async()=>{
            if(!heldVerifiers.has(verify)||await raw()===false||!heldVerifiers.has(verify))throw fail('REBUILD_LOCK_LOST');
        };
        heldVerifiers.add(verify);
        try{return await fn(verify);}finally{heldVerifiers.delete(verify);}
    })) };
    const underApply=(alreadyHeld,fn)=>alreadyHeld===undefined?guardedLocks.run(fn):
        checked(heldVerifiers.has(alreadyHeld)?alreadyHeld:undefined,fn);
    const panelTLS=()=>{const cert=require('./configGenerator').buildPanelInlineCertificate();return {...cert,serverName:cert?.domain||env.PANEL_DOMAIN};};
    async function installedStates(ids){
        const states=new Map(), seen=new Set();
        const records=await State.find({node:{$in:ids}}).select('node status desiredState routingMode routingVersion routeGroup activePathKey clientCidr tproxyPort fwmark routeTable backupId secretRevision +rebuildMachineId +rebuildInstallToken').lean();
        for(const row of records){
            const id=String(row.node);
            if(seen.has(id))throw fail('REBUILD_L2TP_STATE_TRANSITION');
            seen.add(id);
            if(row.status==='not_installed'&&row.desiredState!=='installed')continue;
            if(row.status!=='installed'||row.desiredState!=='installed')throw fail('REBUILD_L2TP_STATE_TRANSITION');
            if(row.routingMode && !['follow-relay','route-group'].includes(row.routingMode))throw fail('REBUILD_L2TP_MODE');
            states.set(id,row);
        }
        return states;
    }
    async function openTransports(nodes,states,transports,bindings,verifyLock){
        await verifyLock();
        // Resolve the complete affected set before opening any transport. An
        // installed relay requires a binding; an explicit enrollment binds
        // even before L2TP is installed.
        for(const node of nodes){
            const id=String(node._id), state=states.get(id);
            const binding=captureRelayBinding(env,id,node,{optional:!state});
            if(!binding)continue;
            // Historical route-group state may predate a rebuild receipt.
            // When a receipt exists it must agree with the operator binding.
            if(state?.rebuildMachineId!=null && state.rebuildMachineId!==binding.binding.machineId)throw fail('REBUILD_L2TP_BINDING_MISMATCH');
            bindings.set(id,binding);
        }
        for(const node of nodes){
            const id=String(node._id), binding=bindings.get(id);
            if(!binding)continue;
            // The general-purpose connector is only for ordinary Xray nodes;
            // it cannot supply or replace a bound relay's attested writer.
            const state=states.get(id);
            // Old route-group rows without a DIRECT receipt are not eligible
            // for the owned-unit transition. Keep their existing Apply path.
            const direct=state?.rebuildInstallToken!=null || state?.rebuildMachineId!=null;
            const transport=createBoundRelayTransport(node,binding,verifyLock,direct?state:undefined);
            transports.set(id,transport);
            await transport.attest();
        }
        for(const node of nodes){const id=String(node._id);if(!bindings.has(id))transports.set(id,connect(node));}
    }
    async function usingTransports(transports,fn){
        let failed=false;
        try{return await fn();}
        catch(error){failed=true;throw error;}
        finally{
            const results=await Promise.allSettled([...transports.values()].map(async t=>t.close()));
            if(!failed&&results.some(x=>x.status==='rejected'))throw fail('REBUILD_TRANSPORT_CLEANUP_FAILED');
        }
    }
    async function verifyDraftTls(link,alreadyHeld){
        gate();const ids=[link.portalNode,link.bridgeNode];
        return underApply(alreadyHeld,verify=>withNodes(ids,async()=>{
            const transports=new Map();
            return usingTransports(transports,async()=>{
                const nodes=await Node.find({_id:{$in:ids},active:true,type:'xray'}).lean();
                if(nodes.length!==2)throw fail('REBUILD_NODE_UNSUPPORTED');
                await openTransports(nodes,await installedStates(ids),transports,new Map(),verify);
                await verifyTunnelTrust([link],panelTLS(),transports);
            });
        }));
    }
    async function verifyDraftRealityFingerprint(link,alreadyHeld){
        gate();
        if(!['forward','reverse'].includes(link.mode))throw fail('REBUILD_INVALID_REQUEST');
        const id=String(link.mode==='reverse'?link.bridgeNode:link.portalNode);
        return underApply(alreadyHeld,verify=>withNodes([id],async()=>{
            const transports=new Map(),bindings=new Map();
            return usingTransports(transports,async()=>{
                const node=await Node.findOne({_id:id,active:true,type:'xray'}).lean();
                if(!node||node.useCustomConfig)throw fail('REBUILD_NODE_UNSUPPORTED');
                await openTransports([node],await installedStates([id]),transports,bindings,verify);
                const version=await transports.get(id).requireSupportedCore();
                await verify();
                bindings.get(id)?.check();
                return require('./rebuildRealityFingerprint').assertRealityFingerprint(link,version);
            });
        }));
    }
    async function execute(req,alreadyHeld){
        gate();const transports=new Map(), bindings=new Map(), roles=new Map();let prepared,states,verifyLock;
        const verifyApply=async()=>{
            await verifyLock();
            // Recheck all captured grants before the coordinator effects,
            // including persistence and writes to non-L2TP members.
            for(const binding of bindings.values())binding.check();
        };
        return runRebuild({global:fn=>underApply(alreadyHeld,verify=>{
            verifyLock=verify;
            return fn(verifyApply);
        }),withNodes:(ids,fn)=>withNodes(ids,()=>usingTransports(transports,fn)),
            links:()=>Link.find({$or:[{active:true},{rebuildDelete:true}]},null,fullLinkRead).lean(),
            async build(ids,links){
                const nodes=await Node.find({_id:{$in:ids}}).select('+xray.manualKey').lean();
                if(nodes.length!==ids.length||nodes.some(n=>n.type!=='xray'||!n.active||n.useCustomConfig))throw fail('REBUILD_NODE_UNSUPPORTED');
                if(req.remove)for(const node of nodes)roles.set(String(node._id),node.role??node.cascadeRole);
                states=await installedStates(ids);
                await openTransports(nodes,states,transports,bindings,verifyLock);
                // `links` is the complete desired component, excluding both
                // the requested removal and any retained deletion tombstones.
                const realityLinks=links.filter(link=>link.tunnelSecurity==='reality');
                const dialerIds=new Set(realityLinks.map(realityDialerId));
                const coreIdentities=new Map(), dialerVersions=new Map();
                for(const id of ids){
                    const transport=transports.get(id);
                    if(!dialerIds.has(id)){await transport.requireSupportedCore();continue;}
                    const identity=await transport.requireSupportedCoreIdentity?.();
                    if(typeof identity?.buildDigest!=='string'||!/^[a-f0-9]{64}(?![\s\S])/.test(identity.buildDigest))throw fail('REBUILD_XRAY_VERSION_UNKNOWN');
                    coreIdentities.set(id,[identity.version,identity.buildDigest]);
                    dialerVersions.set(id,identity.version);
                }
                for(const link of realityLinks)assertRealityFingerprint(link,dialerVersions.get(realityDialerId(link)));
                const followRelayStates=[...states.values()].map(row=>({...row,routingMode:'follow-relay',routingVersion:1}));
                const panelTls=panelTLS();
                const usersByNode=new Map();for(const node of nodes){
                    const users=await sync._getUsersForNode(node);usersByNode.set(String(node._id),users.filter(u=>u.xrayUuid));
                }
                const controlPlaneAddresses=[...new Set([env.PANEL_DOMAIN,...nodes.flatMap(n=>[n.ip,n.domain])].filter(Boolean))];
                prepared=await prepareLinks(Link,links,{env,privateInventory:true});
                // A bridge can still serve its managed client interface with no assigned users.
                // Pass only its presence to the generator, never observed MAIN parameters.
                const bridgesWithClientInbound=new Set();
                for(const node of nodes){
                    const id=String(node._id);
                    if(node.cascadeRole!=='bridge'||usersByNode.get(id).length)continue;
                    const main=await transports.get(id).read('main');
                    if(hasProtectedClientInbound(main,node.xray?.inboundTag||'vless-in'))bridgesWithClientInbound.add(id);
                }
                const candidates=compose({nodes,links:prepared,dialerVersions,affectedNodeIds:ids,usersByNode,bridgesWithClientInbound,panelTls,followRelayStates,controlPlaneAddresses});
                await verifyTunnelTrust(prepared,panelTls,transports);
                const mismatched=new Set(nodes.filter(inconsistentPublishedKey).map(n=>String(n._id)));
                return {coreIdentities,candidates:candidates.map(p=>p.profile==='main'&&mismatched.has(p.nodeId)?{...p,publishedKeyMismatch:true}:p)};
            },
            nodeRole:id=>roles.get(id),
            async read(id,p){const current=await transports.get(id).read(p);if(p==='main'){
                const installed=states.get(id);const ingress=(current?.inbounds||[]).filter(i=>i.tag?.startsWith('relay-l2tp-'));
                if(ingress.length || installed){if(ingress.length!==1 || !installed || ingress[0].port!==installed.tproxyPort || ingress[0].tag!==`relay-l2tp-${installed.routeGroup||id}` || ingress[0].protocol!=='dokodemo-door' || ingress[0].settings?.followRedirect!==true || ingress[0].streamSettings?.sockopt?.tproxy!=='tproxy')throw fail('REBUILD_L2TP_BASELINE_MISMATCH');}
            }return current;},
            persistKeys:verify=>prepareLinks(Link,prepared,{env,persist:true,verify}),
            markDelete:async id=>{if(bindings.size)await verifyApply();const result=await Link.updateOne({_id:id,rebuildDelete:{$ne:true}},{$set:{rebuildDelete:true}});if(result.matchedCount!==1)throw fail('REBUILD_LINK_CHANGED');},
            async checkActivation(ids){for(const id of ids)await transports.get(id).checkActivation?.();},
            async prepareActivation(ids){for(const id of ids)await transports.get(id).prepareActivation?.();},
            stagePair:(id,pair)=>transports.get(id).stagePair(pair),putPair:(id,pair)=>transports.get(id).putPair(pair),
            async finish({desired,removed}){
                // Not a recovery journal. A single Mongo transaction publishes the
                // desired result; on failure the tombstone still roots both halves.
                await Link.db.transaction(async session=>{
                    if(bindings.size)await verifyApply();
                    for(const state of states.values()){
                        const result=await State.updateOne({_id:state._id,status:'installed',desiredState:'installed',secretRevision:state.secretRevision,tproxyPort:state.tproxyPort,routeGroup:state.routeGroup??null},{$set:{routingMode:'follow-relay',routingVersion:1}},{session});if(result.matchedCount!==1)throw fail('REBUILD_L2TP_STATE_TRANSITION');
                    }
                    for(const link of desired){
                        const result=await Link.updateOne({_id:link._id,active:{$ne:false},rebuildDelete:{$ne:true}},
                            {$set:{...(isReverse(link)?unverified:{status:'deployed',lastError:''}),rebuildApplied:appliedLink(link),
                                rebuildApplyEpoch:randomBytes(16).toString('hex')},
                            $unset:{rebuildReverseObservation:''}},{session,runValidators:true});
                        if(result.acknowledged!==true||result.matchedCount!==1)throw fail('REBUILD_LINK_CHANGED');
                    }
                    if(removed.length){const result=await Link.deleteMany({_id:{$in:removed.map(l=>l._id)},rebuildDelete:true},{session});if(result.deletedCount!==removed.length)throw fail('REBUILD_LINK_CHANGED');}
                });await cache.invalidateAllSubscriptions();require('./cascadeService')._invalidateTopologyCache();
            }
        },req);
    }
    const installRelay=createRebuildRelayBackend({Link,Node,State,L2tpUser,locks:guardedLocks,env,createRelayDirect});
    const relayRemoval=createRebuildRelayRemove({Link,Node,State,L2tpUser,locks:guardedLocks,env,createRelayDirect});
    const relayAccounts=()=>createRebuildRelayAccounts({Node,State,L2tpUser,locks,env,resolveRelayBinding,createRelayDirect});
    return {execute,verifyDraftTls,verifyDraftRealityFingerprint,locks:guardedLocks,installRelay,...relayRemoval,
        createRelayAccount: input=>relayAccounts().create(input),
        disableRelayAccount: input=>relayAccounts().disable(input),
        deleteRelayAccount: input=>relayAccounts().delete(input),
        // Reconciliation must acquire the account writer's lock itself; the
        // general mutation guard intentionally refuses a pending account fence.
        reconcileRelayAccounts: ()=>relayAccounts().reconcile()};
}
module.exports={createRebuildService};
