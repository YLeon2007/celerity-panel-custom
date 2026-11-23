'use strict';
const {isDeepStrictEqual}=require('node:util');
const {isRebuildEnabled}=require('./rebuildMode');
const {runRebuild,runRetireGraph,retirementScope,fingerprintLinks,hasProtectedClientInbound,profilePreview}=require('./rebuildCoordinator');
const {withNodes,makeLocks}=require('./rebuildLocks');
const {composeRebuildProfiles}=require('../modules/relay-l2tp/services/rebuildTopologyComposer');
const {createTransport,createBoundRelayTransport}=require('./rebuildTransport');
const {verifyTunnelTrust}=require('./rebuildTunnelTls');
const {assertRealityFingerprint,realityDialerId}=require('./rebuildRealityFingerprint');
const {prepareLinks}=require('./rebuildLinkKeys');
const {fullLinkRead}=require('./rebuildLinkSnapshot');
const {createRebuildRelayBackend}=require('./rebuildRelayBackend');
const {createRebuildRelayRemove}=require('./rebuildRelayRemove');
const {createRebuildRelayRetire}=require('./rebuildRelayRetire');
const {createRebuildRelayAccounts}=require('./rebuildRelayAccounts');
const {assertNoPendingRelayAccounts}=require('./rebuildRelayAccountsStore');
const {resolveRelayBinding,relayInstallEnabled}=require('./rebuildRelayAuthorization');
const {readRelayAuthority,captureRelayEffect,identityChanged}=require('./rebuildRelayEffectAuthority');
const {appliedLink}=require('./rebuildAppliedLink');
const {isReverse,unverified}=require('./rebuildReverseLinkHealth');
const {transactOnce,AcknowledgedCommitCleanupError}=require('./rebuildRelayInstallTransaction');
const {createPrivateKey,createPublicKey,randomBytes}=require('node:crypto');
const fail=code=>Object.assign(new Error(code),{code});
const networkErrors=new Set(['ECONNREFUSED','ECONNRESET','ETIMEDOUT','EHOSTUNREACH','ENETUNREACH','ENOTFOUND','EAI_AGAIN']);
// A no-install retirement must not adopt or overwrite unexplained PPP or
// handoff ownership, including an orphan reference in either profile.
function hasRetiredIngress(value){
    if(typeof value==='string')return /^(?:relay-l2tp-|rebuild-l2tp-|rebuild-relay-ingress$)/.test(value);
    if(Array.isArray(value))return value.some(hasRetiredIngress);
    return value!==null&&typeof value==='object'&&Object.entries(value).some(([k,v])=>hasRetiredIngress(k)||hasRetiredIngress(v));
}
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
    assertNoRelayAccountIntent=()=>assertNoPendingRelayAccounts(L2tpUser.db),
    grantDb=env===process.env?L2tpUser.db:undefined,
    relayGrantStore=grantDb&&{snapshot:()=>require('./rebuildRelayGrantStore').createRelayGrantStore({db:grantDb,env}).snapshot()}}={}){
    const gate=()=>{if(!isRebuildEnabled(env))throw fail('REBUILD_DISABLED');};
    const checked = async (verify, fn) => {
        if (typeof verify !== 'function' || await verify() === false) throw fail('REBUILD_LOCK_LOST');
        await assertNoRelayAccountIntent();
        if (await verify() === false) throw fail('REBUILD_LOCK_LOST');
        return fn(verify);
    };
    // Reentry must use the active verifier issued by this service, not an
    // arbitrary callback passed to execute().
    const heldVerifiers=new WeakMap();
    const guardedLocks = { ...locks, run: (fn,options) => locks.run((raw,retain)=>checked(raw,async()=>{
        const verify=async()=>{
            const scope=heldVerifiers.get(verify);
            if(!scope||await raw()===false||heldVerifiers.get(verify)!==scope)throw fail('REBUILD_LOCK_LOST');
            if(scope.fence){
                await scope.fence();
                if(await raw()===false||heldVerifiers.get(verify)!==scope)throw fail('REBUILD_LOCK_LOST');
            }
        };
        heldVerifiers.set(verify,{retain});
        try{return await fn(verify,retain);}finally{heldVerifiers.delete(verify);}
    }),options) };
    const withHeldLock=(verify,retain,fn)=>{
        const scope=heldVerifiers.get(verify);
        if(!scope||typeof retain!=='function'||scope.retain!==retain)throw fail('REBUILD_LOCK_LOST');
        return checked(verify,()=>fn(verify,retain));
    };
    const guardRetireRemove=(verify,retain,fence,fn)=>withHeldLock(verify,retain,async()=>{
        const scope=heldVerifiers.get(verify);
        if(!scope||scope.fence)throw fail('REBUILD_LOCK_LOST');
        scope.fence=fence;
        try{return await fn();}finally{delete scope.fence;}
    });
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
    async function openTransports(nodes,states,transports,bindings,verifyLock,preflight=(_,fn)=>fn()){
        await verifyLock();
        // Resolve the whole component before choosing a transport. The Install
        // flag can deny use of a grant, but cannot prove a relay has no grant.
        const effectStore=states.size || nodes.some(node=>node.cascadeRole==='relay')
            ? relayGrantStore : undefined;
        const snapshot=await readRelayAuthority(env,effectStore);
        for(const node of nodes){
            const id=String(node._id), state=states.get(id);
            const binding=captureRelayEffect(env,effectStore,snapshot,id,node,{optional:!state});
            if(!binding)continue;
            // Historical route-group state may predate a rebuild receipt.
            // When a receipt exists it must agree with the operator binding.
            if(state?.rebuildMachineId!=null && state.rebuildMachineId!==binding.binding.machineId){
                throw binding.merged?identityChanged():fail('REBUILD_L2TP_BINDING_MISMATCH');
            }
            bindings.set(id,binding);
        }
        const verifyBinding=async(id,binding,snapshot)=>{
            if(!binding.merged)return binding.check();
            const node=await Node.findOne({_id:id,active:true,type:'xray'}).select('ip ssh useCustomConfig cascadeRole').lean();
            if(!node || node.useCustomConfig)throw identityChanged();
            await binding.check(node,snapshot);
            await verifyLock();
        };
        for(const node of nodes){
            const id=String(node._id), binding=bindings.get(id);
            if(!binding)continue;
            // The general-purpose connector is only for ordinary Xray nodes;
            // it cannot supply or replace a bound relay's attested writer.
            const state=states.get(id);
            // Old route-group rows without a DIRECT receipt are not eligible
            // for the owned-unit transition. Keep their existing Apply path.
            const direct=state?.rebuildInstallToken!=null || state?.rebuildMachineId!=null;
            const transport=createBoundRelayTransport(node,binding,verifyLock,direct?state:undefined,()=>verifyBinding(id,binding));
            transports.set(id,transport);
            await preflight(id,()=>transport.attest());
        }
        for(const node of nodes){const id=String(node._id);if(!bindings.has(id))transports.set(id,await preflight(id,()=>connect(node)));}
        return verifyBinding;
    }
    async function usingTransports(transports,fn){
        let failed=false;
        try{return await fn();}
        catch(error){failed=true;throw error;}
        finally{
            try{await closeTransports(transports);}catch(error){if(!failed)throw error;}
        }
    }
    async function closeTransports(transports){
        const results=await Promise.allSettled([...transports.values()].map(async t=>t.close()));
        transports.clear();
        if(results.some(x=>x.status==='rejected'))throw fail('REBUILD_TRANSPORT_CLEANUP_FAILED');
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
                const verifyBinding=await openTransports([node],await installedStates([id]),transports,bindings,verify);
                const version=await transports.get(id).requireSupportedCore();
                await verify();
                if(bindings.has(id))await verifyBinding(id,bindings.get(id));
                return require('./rebuildRealityFingerprint').assertRealityFingerprint(link,version);
            });
        }));
    }
    const execute=(req,alreadyHeld)=>runGraph(req,alreadyHeld);
    const targetBridges=new WeakMap();
    const emptyBridge={inbounds:[]};
    const sameProtectedTarget=(before,after)=>targetBridges.has(before)&&targetBridges.has(after)
        &&!profilePreview(targetBridges.get(before),targetBridges.get(after),'main').protectedChanged;
    const observedLinks=session=>{
        const query=Link.find({},null,fullLinkRead).read('primary');
        return (session?query.session(session):query.readConcern('majority')).lean();
    };
    const verifyRetireLinks=async(nodeId,version,session)=>{
        const fresh=retirementScope(await observedLinks(session),nodeId);
        if(!version.startsWith(fingerprintLinks(fresh.links)))throw fail('REBUILD_LINK_CHANGED');
    };
    // Orchestration only. Compare survivorPreview across online L2TP Remove,
    // then confirm with the new full previewId, never with survivorPreview.
    async function retireGraph(input,heldVerify){
        gate();
        if(!heldVerifiers.has(heldVerify))throw fail('REBUILD_LOCK_LOST');
        const {nodeId,mode,preview,expectedPreview,finish,beforeEffects,onEffect,onCommit}=input??{};
        if(typeof nodeId!=='string'||!/^[a-f0-9]{24}$/.test(nodeId)||!['online','abandon'].includes(mode)
            ||typeof preview!=='boolean'||[finish,beforeEffects,onEffect,onCommit].some(fn=>fn!==undefined&&typeof fn!=='function')
            ||(expectedPreview!==undefined&&(typeof expectedPreview!=='string'||!/^[a-f0-9]{128}$/.test(expectedPreview)))){
            throw fail('REBUILD_INVALID_REQUEST');
        }
        return runGraph({nodeId,mode,preview,expectedPreview,finish,beforeEffects,onEffect,onCommit},heldVerify,true);
    }
    async function runGraph(req,alreadyHeld,retire=false){
        gate();const transports=new Map(), bindings=new Map(), roles=new Map();let prepared,states,verifyLock,verifyBinding,settlementSession;
        const baseline=new Map();
        const keyRoot=retire?env.ENCRYPTION_KEY:undefined;
        // Keep the existing preparation/validation and envelope format. For
        // retirement only, join its missing-envelope write to final settlement
        // instead of opening a second transaction. A missing seed is already
        // deterministically bound to the unchanged root and link ID.
        const keyStore=retire?{
            find:(...args)=>Link.find(...args), updateOne:(...args)=>Link.updateOne(...args),
            db:{transaction:async work=>{
                if(!settlementSession?.inTransaction())throw fail('REBUILD_LINK_KEY_STORE_FAILED');
                return work(settlementSession);
            }},
        }:Link;
        const preflight=async(id,fn)=>{
            try{return await fn();}
            catch(error){
                if(retire&&id!==req.nodeId&&(networkErrors.has(error?.code)||error?.code==='REBUILD_L2TP_SSH_CONNECT_FAILED')){
                    throw Object.assign(fail('REBUILD_NEIGHBOR_UNAVAILABLE'),{nodeId:id,
                        detail:error.code==='REBUILD_L2TP_SSH_CONNECT_FAILED'?'REBUILD_L2TP_SSH_CONNECT_FAILED':'REBUILD_TRANSPORT_UNREACHABLE'});
                }
                throw error;
            }
        };
        const readProfile=async(id,p)=>{
            const current=await transports.get(id).read(p);
            if(retire&&id===req.nodeId&&!states.has(id)&&current&&hasRetiredIngress(current)){
                throw fail('REBUILD_L2TP_BASELINE_MISMATCH');
            }
            if(p==='main'){
                const installed=states.get(id);const ingress=(current?.inbounds||[]).filter(i=>i.tag?.startsWith('relay-l2tp-'));
                if(ingress.length || installed){if(ingress.length!==1 || !installed || ingress[0].port!==installed.tproxyPort || ingress[0].tag!==`relay-l2tp-${installed.routeGroup||id}` || ingress[0].protocol!=='dokodemo-door' || ingress[0].settings?.followRedirect!==true || ingress[0].streamSettings?.sockopt?.tproxy!=='tproxy')throw fail('REBUILD_L2TP_BASELINE_MISMATCH');}
            }
            return current;
        };
        const verifyApply=async()=>{
            await verifyLock();
            // Recheck all captured grants before the coordinator effects,
            // including persistence and writes to non-L2TP members.
            if(bindings.size){
                const snapshot=await readRelayAuthority(env,[...bindings.values()].some(binding=>binding.merged)?relayGrantStore:undefined);
                for(const [id,binding] of bindings)await verifyBinding(id,binding,snapshot);
            }
            if(retire&&env.ENCRYPTION_KEY!==keyRoot)throw fail('REBUILD_LINK_KEY_UNAVAILABLE');
        };
        const checkLinks=(retirement,session)=>verifyRetireLinks(req.nodeId,retirement.version,session);
        const result=await (retire?runRetireGraph:runRebuild)({global:fn=>underApply(alreadyHeld,verify=>{
            verifyLock=verify;
            return fn(verifyApply);
        }),withNodes:(ids,fn)=>withNodes(ids,()=>usingTransports(transports,fn)),
            links:retire?observedLinks:()=>Link.find({$or:[{active:true},{rebuildDelete:true}]},null,fullLinkRead).lean(),
            async build(ids,links,retirement){
                const nodes=ids.length?await Node.find({_id:{$in:ids}}).select('+xray.manualKey').lean():[];
                if(nodes.length!==ids.length||nodes.some(n=>n.type!=='xray'||!n.active||n.useCustomConfig))throw fail('REBUILD_NODE_UNSUPPORTED');
                if(retire){
                    // Abandon only reads the target card identity/role. No
                    // target credentials, state, binding or profiles are needed.
                    const target=req.mode==='online'?nodes.find(n=>String(n._id)===req.nodeId):
                        (await Node.find({_id:{$in:[req.nodeId]}}).select('_id type active cascadeRole role useCustomConfig ip').lean())[0];
                    if(String(target?._id)!==req.nodeId||target.type!=='xray'||target.cascadeRole!=='relay'
                        ||(target.role??'relay')!=='relay'||target.useCustomConfig)throw fail('REBUILD_NODE_UNSUPPORTED');
                    const cards=new Map([...nodes,target].map(n=>[String(n._id),n]));
                    if(cards.size!==retirement.nodes.length||retirement.nodes.some(id=>!cards.has(id)))throw fail('REBUILD_NODE_UNSUPPORTED');
                    const addresses=[...cards.values()].filter(n=>typeof n.ip==='string'&&n.ip)
                        .map(n=>n.ip.toLowerCase().replace(/\.$/,''));
                    if(new Set(addresses).size!==addresses.length)throw fail('REBUILD_NODE_UNSUPPORTED');
                    for(const row of retirement.links){
                        const source=cards.get(String(row.portalNode)),target=cards.get(String(row.bridgeNode));
                        if(!['portal','relay'].includes(source.role??source.cascadeRole)
                            ||!['relay','bridge'].includes(target.role??target.cascadeRole))throw fail('REBUILD_INVALID_EDGE_ROLE');
                    }
                    if(!ids.length){states=new Map();return {candidates:[]};}
                }
                if(req.remove)for(const node of nodes)roles.set(String(node._id),node.role??node.cascadeRole);
                states=await installedStates(ids);
                if(retire&&!req.preview&&states.has(req.nodeId))throw fail('REBUILD_L2TP_STATE_TRANSITION');
                verifyBinding=await openTransports(nodes,states,transports,bindings,verifyLock,preflight);
                // Read peers before the core helper (which deliberately
                // collapses execution errors and malformed banners together).
                if(retire)for(const id of ids){
                    const main=await preflight(id,()=>readProfile(id,'main'));
                    const bridge=await preflight(id,()=>readProfile(id,'bridge'));
                    baseline.set(id,{main,bridge});
                }
                // `links` is the complete desired component, excluding both
                // the requested removal and any retained deletion tombstones.
                const realityLinks=links.filter(link=>link.tunnelSecurity==='reality');
                const dialerIds=new Set(realityLinks.map(realityDialerId));
                const coreIdentities=new Map(), dialerVersions=new Map();
                for(const id of ids){
                    const transport=transports.get(id);
                    if(!dialerIds.has(id)){await preflight(id,()=>transport.requireSupportedCore());continue;}
                    const identity=await preflight(id,()=>transport.requireSupportedCoreIdentity?.());
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
                prepared=await prepareLinks(keyStore,links,{env,privateInventory:true});
                // A bridge can still serve its managed client interface with no assigned users.
                // Pass only its presence to the generator, never observed MAIN parameters.
                const bridgesWithClientInbound=new Set();
                for(const node of nodes){
                    const id=String(node._id);
                    if(node.cascadeRole!=='bridge'||usersByNode.get(id).length)continue;
                    const main=retire?baseline.get(id).main:await transports.get(id).read('main');
                    if(hasProtectedClientInbound(main,node.xray?.inboundTag||'vless-in'))bridgesWithClientInbound.add(id);
                }
                const candidates=compose({nodes,links:prepared,dialerVersions,affectedNodeIds:ids,usersByNode,bridgesWithClientInbound,panelTls,followRelayStates,controlPlaneAddresses});
                if(retire&&candidates.some(p=>p.profile==='bridge'
                    &&profilePreview(baseline.get(p.nodeId).bridge??emptyBridge,p.config,'main').protectedChanged)){
                    throw fail('REBUILD_CLIENT_CHANGE');
                }
                await verifyTunnelTrust(prepared,panelTls,transports);
                const mismatched=new Set(nodes.filter(inconsistentPublishedKey).map(n=>String(n._id)));
                return {coreIdentities,candidates:candidates.map(p=>p.profile==='main'&&mismatched.has(p.nodeId)?{...p,publishedKeyMismatch:true}:p)};
            },
            nodeRole:id=>roles.get(id),
            async read(id,p,before){
                if(!retire||!before)return readProfile(id,p);
                // The early read established reachability and drove bridge
                // client-inbound inference. Do not confirm a stale baseline
                // if it changed while preparing the full set of candidates.
                const current=await preflight(id,()=>readProfile(id,p));
                if(!isDeepStrictEqual(current,baseline.get(id)[p]))throw fail('REBUILD_PREVIEW_CHANGED');
                return current;
            },
            persistKeys:retire?undefined:verify=>prepareLinks(Link,prepared,{env,persist:true,verify}),
            markDelete:async id=>{if(bindings.size)await verifyApply();const result=await Link.updateOne({_id:id,rebuildDelete:{$ne:true}},{$set:{rebuildDelete:true}});if(result.matchedCount!==1)throw fail('REBUILD_LINK_CHANGED');},
            async checkActivation(ids,retirement){
                if(retire)await checkLinks(retirement);
                for(const id of ids)await preflight(id,()=>transports.get(id).verifyIdentity?.());
                for(const id of ids)await preflight(id,()=>transports.get(id).checkActivation?.());
                if(!req.preview&&retire)await req.beforeEffects?.();
            },
            async prepareActivation(ids){
                // Staging can take time. Recheck the original store and graph
                // before any prepared network or live profile is activated.
                if(retire)await req.beforeEffects?.();
                for(const id of ids)await transports.get(id).prepareActivation?.();
            },
            stagePair:(id,pair)=>{if(retire)req.onEffect?.();return transports.get(id).stagePair(pair);},
            putPair:(id,pair)=>transports.get(id).putPair(pair),
            async finish({desired,removed,retirement}){
                // Close while the target card and grant still exist: bound
                // teardown may need both, and custom finish may delete either.
                if(retire)await closeTransports(transports);
                const settle=async session=>{
                    if(retire){
                        await verifyApply();
                        await checkLinks(retirement,session);
                        req.onEffect?.();
                        settlementSession=session;
                        try{if(prepared)await prepareLinks(keyStore,prepared,{env,persist:true,verify:verifyApply});}
                        finally{settlementSession=undefined;}
                    }else if(bindings.size)await verifyApply();
                    for(const state of states.values()){
                        const result=await State.updateOne({_id:state._id,status:'installed',desiredState:'installed',secretRevision:state.secretRevision,tproxyPort:state.tproxyPort,routeGroup:state.routeGroup??null},{$set:{routingMode:'follow-relay',routingVersion:1}},{session});if(result.matchedCount!==1||retire&&result.acknowledged!==true)throw fail('REBUILD_L2TP_STATE_TRANSITION');
                    }
                    for(const link of desired){
                        const result=await Link.updateOne({_id:link._id,active:{$ne:false},rebuildDelete:{$ne:true}},
                            {$set:{...(isReverse(link)?unverified:{status:'deployed',lastError:''}),rebuildApplied:appliedLink(link),
                                rebuildApplyEpoch:randomBytes(16).toString('hex')},
                            $unset:{rebuildReverseObservation:''}},{session,runValidators:true});
                        if(result.acknowledged!==true||result.matchedCount!==1)throw fail('REBUILD_LINK_CHANGED');
                    }
                    if(removed.length){const result=await Link.deleteMany({_id:{$in:removed.map(l=>l._id)},...(!retire&&{rebuildDelete:true})},{session});if(result.deletedCount!==removed.length||retire&&result.acknowledged!==true)throw fail('REBUILD_LINK_CHANGED');}
                    if(retire){await req.finish?.(session);await verifyApply();}
                };
                if(retire){
                    try{await transactOnce(Link,State,settle);}
                    catch(error){if(error instanceof AcknowledgedCommitCleanupError){req.onCommit?.();throw fail('REBUILD_GRAPH_COMMITTED_CLEANUP_FAILED');}throw error;}
                    req.onCommit?.();
                }else await Link.db.transaction(settle);
                try{await cache.invalidateAllSubscriptions();require('./cascadeService')._invalidateTopologyCache();}
                catch(error){if(retire)throw fail('REBUILD_GRAPH_COMMITTED_CLEANUP_FAILED');throw error;}
            }
        },req);
        if(retire&&req.preview&&req.mode==='online')targetBridges.set(result,baseline.get(req.nodeId).bridge??emptyBridge);
        return result;
    }
    const installDeps={Link,Node,State,L2tpUser,locks:guardedLocks,env,relayGrantStore,createRelayDirect};
    const installRelay=createRebuildRelayBackend(installDeps);
    const recoverRelayInstall=async (id,{actor}={})=>{
        if(!relayInstallEnabled(env))throw fail('REBUILD_L2TP_INSTALL_DISABLED');
        // Only this explicit entry loads the recovery backend. It owns live
        // role/grant checks and cleanup; never fall back to Install.
        const {createRebuildRelayInstallRecovery}=require('./rebuildRelayInstallRecovery');
        return createRebuildRelayInstallRecovery({...installDeps,actor})(id);
    };
    const relayRemoval=createRebuildRelayRemove({Link,Node,State,L2tpUser,locks:guardedLocks,withHeldLock,env,relayGrantStore,createRelayDirect});
    const relayRetire=createRebuildRelayRetire({Link,Node,State,L2tpUser,env,sync,relayGrantStore,locks:guardedLocks,gate,
        retireGraph,verifyLinks:verifyRetireLinks,sameProtectedTarget,removal:relayRemoval,guard:guardRetireRemove});
    const relayAccounts=()=>createRebuildRelayAccounts({Node,State,L2tpUser,locks,env,relayGrantStore,resolveRelayBinding,createRelayDirect});
    return {execute,retireGraph,verifyDraftTls,verifyDraftRealityFingerprint,locks:guardedLocks,installRelay,recoverRelayInstall,...relayRemoval,...relayRetire,
        createRelayAccount: input=>relayAccounts().create(input),
        disableRelayAccount: input=>relayAccounts().disable(input),
        deleteRelayAccount: input=>relayAccounts().delete(input),
        // Reconciliation must acquire the account writer's lock itself; the
        // general mutation guard intentionally refuses a pending account fence.
        reconcileRelayAccounts: ()=>relayAccounts().reconcile()};
}
module.exports={createRebuildService};
