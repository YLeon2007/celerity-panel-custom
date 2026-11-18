'use strict';
const {isRebuildEnabled}=require('./rebuildMode');
const {runRebuild}=require('./rebuildCoordinator');
const {withNodes,makeLocks}=require('./rebuildLocks');
const {composeRebuildProfiles}=require('../modules/relay-l2tp/services/rebuildTopologyComposer');
const {createTransport}=require('./rebuildTransport');
const fail=code=>Object.assign(new Error(code),{code});
function createRebuildService({Link=require('../models/cascadeLinkModel'),Node=require('../models/hyNodeModel'),
    State=require('../modules/relay-l2tp/models/relayL2tpStateModel'),sync=require('./syncService'),locks=makeLocks(),connect=createTransport,
    compose=composeRebuildProfiles,env=process.env,cache=require('./cacheService')}={}){
    const gate=()=>{if(!isRebuildEnabled(env))throw fail('REBUILD_DISABLED');};
    async function execute(req,alreadyHeld){
        gate();const transports=new Map(),states=new Map();
        try{return await runRebuild({global:alreadyHeld?fn=>fn(alreadyHeld):locks.run,withNodes,
            links:()=>Link.find({$or:[{active:true},{rebuildDelete:true}]}).lean(),
            async build(ids,links){
                const nodes=await Node.find({_id:{$in:ids}}).select('+xray.manualKey').lean();
                if(nodes.length!==ids.length||nodes.some(n=>n.type!=='xray'||!n.active||n.useCustomConfig))throw fail('REBUILD_NODE_UNSUPPORTED');
                const records=await State.find({node:{$in:ids}}).select('node status desiredState routingMode routingVersion routeGroup activePathKey tproxyPort secretRevision').lean();
                const followRelayStates=[];
                for(const row of records){
                    if(row.status==='not_installed'&&row.desiredState!=='installed')continue;
                    if(row.status!=='installed'||row.desiredState!=='installed')throw fail('REBUILD_L2TP_STATE_TRANSITION');
                    if(row.routingMode && !['follow-relay','route-group'].includes(row.routingMode))throw fail('REBUILD_L2TP_MODE');
                    states.set(String(row.node),row);
                    followRelayStates.push({...row,routingMode:'follow-relay',routingVersion:1});
                }
                const cert=require('./configGenerator').buildPanelInlineCertificate();
                const panelTls={...cert,serverName:cert?.domain||env.PANEL_DOMAIN};
                const usersByNode=new Map();for(const node of nodes){
                    const users=await sync._getUsersForNode(node);usersByNode.set(String(node._id),users.filter(u=>u.xrayUuid));
                    transports.set(String(node._id),connect(node));
                }
                const controlPlaneAddresses=[...new Set([env.PANEL_DOMAIN,...nodes.flatMap(n=>[n.ip,n.domain])].filter(Boolean))];
                return compose({nodes,links,affectedNodeIds:ids,usersByNode,panelTls,followRelayStates,controlPlaneAddresses});
            },
            async read(id,p){const current=await transports.get(id).read(p);if(p==='main'){
                const installed=states.get(id);const ingress=(current?.inbounds||[]).filter(i=>i.tag?.startsWith('relay-l2tp-'));
                if(ingress.length || installed){if(ingress.length!==1 || !installed || ingress[0].port!==installed.tproxyPort || ingress[0].tag!==`relay-l2tp-${installed.routeGroup||id}` || ingress[0].protocol!=='dokodemo-door' || ingress[0].settings?.followRedirect!==true || ingress[0].streamSettings?.sockopt?.tproxy!=='tproxy')throw fail('REBUILD_L2TP_BASELINE_MISMATCH');}
            }return current;},
            markDelete:async id=>{const result=await Link.updateOne({_id:id,rebuildDelete:{$ne:true}},{$set:{rebuildDelete:true}});if(result.matchedCount!==1)throw fail('REBUILD_LINK_CHANGED');},
            stagePair:(id,pair)=>transports.get(id).stagePair(pair),putPair:(id,pair)=>transports.get(id).putPair(pair),
            async finish({desired,removed}){
                // Not a recovery journal. A single Mongo transaction publishes the
                // desired result; on failure the tombstone still roots both halves.
                await Link.db.transaction(async session=>{
                    for(const state of states.values()){
                        const result=await State.updateOne({_id:state._id,status:'installed',desiredState:'installed',secretRevision:state.secretRevision,tproxyPort:state.tproxyPort,routeGroup:state.routeGroup??null},{$set:{routingMode:'follow-relay',routingVersion:1}},{session});if(result.matchedCount!==1)throw fail('REBUILD_L2TP_STATE_TRANSITION');
                    }
                    if(desired.length)await Link.updateMany({_id:{$in:desired.map(l=>l._id)}},{$set:{status:'deployed',lastError:''}},{session});
                    if(removed.length){const result=await Link.deleteMany({_id:{$in:removed.map(l=>l._id)},rebuildDelete:true},{session});if(result.deletedCount!==removed.length)throw fail('REBUILD_LINK_CHANGED');}
                });await cache.invalidateAllSubscriptions();require('./cascadeService')._invalidateTopologyCache();
            }
        },req);}finally{const results=await Promise.allSettled([...transports.values()].map(t=>t.close()));if(results.some(x=>x.status==='rejected'))throw fail('REBUILD_TRANSPORT_CLEANUP_FAILED');}
    }
    return {execute,locks};
}
module.exports={createRebuildService};
