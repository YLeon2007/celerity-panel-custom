'use strict';

const crypto=require('node:crypto');
const {CASCADE_TRANSPORTS}=require('../utils/cascadeTransport');
const {readKcpFields,assertKcpSecurity}=require('./cascadeDraftTransport');
const {inputExit,storedExit,sameExit,validateExit,assertExitsUnused,id:objectId}=require('./rebuildExit');
const {componentFor}=require('./rebuildCoordinator');
const fail=code=>Object.assign(new Error(code),{code});
const fields=('name mode tunnelPort tunnelProtocol tunnelSecurity tunnelEncryption tunnelTransport tunnelDomain tcpFastOpen tcpKeepAlive tcpNoDelay wsPath wsHost grpcServiceName xhttpPath xhttpHost xhttpMode muxEnabled muxConcurrency geoRouting priority autoDeploy realityDest realitySni realityShortIds').split(' ');

function endpoint(body, alias, path, previous) {
    const names=[alias,path].filter(key=>Object.hasOwn(body,key));
    if(!names.length)return previous;
    const values=names.map(key=>typeof body[key]==='string'?objectId(body[key]):undefined);
    if(values.some(value=>!value||value!==values[0]))throw fail('REBUILD_INVALID_REQUEST');
    return values[0];
}

// One draft writer for REST and MCP. Keep the original Apply lock around all
// DB reads and persistence, and never dispatch Apply from a draft write.
async function saveRebuildDraft({service,Link,Node,linkId,body:b,preview=false},outcome={}) {
 return service.locks.run(async verify=>{
    const editing=linkId!==undefined;
    if(editing&&!objectId(linkId))throw fail('REBUILD_INVALID_REQUEST');
    const selector=inputExit(b);
    const link=editing?await Link.findById(linkId).select('+rebuildReverseObservation'):new Link({tunnelUuid:crypto.randomUUID(),rebuildApplied:null,tunnelEncryption:'vless-enc'});
    if(!link)throw fail('REBUILD_LINK_NOT_FOUND');
    if(Object.hasOwn(b,'active')&&typeof b.active!=='boolean')throw fail('REBUILD_INVALID_REQUEST');
    if(b.active===false){
        if(editing)await assertExitsUnused({Link,Node,removedIds:[link._id]});
    }
    if(link.rebuildDelete||link.lifecycle)throw fail('REBUILD_DELETION_PENDING');
    if(b.active===false){
        // Only checked removal may deactivate an applied Rebuild tunnel.
        throw fail('REBUILD_PREVIEW_REQUIRED');
    }
    const old=editing?[String(link.portalNode),String(link.bridgeNode)]:[];
    const source=endpoint(b,'portalNodeId','portalNode',old[0]),target=endpoint(b,'bridgeNodeId','bridgeNode',old[1]);
    if(!objectId(source)||!objectId(target)||source===target)throw fail('REBUILD_INVALID_REQUEST');
    if(editing&&(source!==old[0]||target!==old[1]))throw fail('REBUILD_REPLACE_WITH_DELETE_CREATE');
    const inventory=await Node.find({_id:{$in:[source,target]},active:true,type:'xray'}).select('_id role cascadeRole type active useCustomConfig xray.realitySni xray.realityDest ip').lean();
    const from=inventory.find(n=>String(n._id)===source),to=inventory.find(n=>String(n._id)===target);
    if(!from||!to||!['portal','relay'].includes(from.cascadeRole)||!['relay','bridge'].includes(to.cascadeRole))throw fail('REBUILD_INVALID_EDGE_ROLE');
    const oldExit=link.get('rebuildExit');
    const previous=storedExit(oldExit?.toObject?.()??oldExit);
    if(selector!==undefined){
        if(!sameExit(previous,selector)||(oldExit!==undefined&&previous===undefined))link.set('rebuildExit',selector);
    }
    if(Object.hasOwn(b,'tunnelSecurity')&&!['none','tls','reality'].includes(b.tunnelSecurity))throw fail('REBUILD_INVALID_REQUEST');
    if(Object.hasOwn(b,'tunnelEncryption')&&!['vless-enc','none'].includes(b.tunnelEncryption))throw fail('REBUILD_INVALID_REQUEST');
    if(!editing&&!Object.hasOwn(b,'tunnelSecurity'))link.tunnelSecurity=b.tunnelTransport==='kcp'?'none':'reality';
    const kcpFields=readKcpFields(b);
    if(Object.hasOwn(b,'tunnelTransport')&&!CASCADE_TRANSPORTS.includes(b.tunnelTransport))throw fail('REBUILD_INVALID_REQUEST');
    for(const field of fields){
        if(!Object.hasOwn(b,field))continue;
        // Blank form controls are not a request to discard stored settings.
        const value=b[field];
        if(field==='realityDest'&&(value==null||typeof value==='string'&&!value.trim()))continue;
        if(field==='realitySni'||field==='realityShortIds'){
            const entries=(Array.isArray(value)?value:[value]).filter(v=>v!=null);
            if(entries.some(v=>typeof v!=='string'))throw fail('REBUILD_INVALID_REQUEST');
            const list=entries.flatMap(v=>v.split(',').map(s=>s.trim())).filter(Boolean);
            if(list.length)link.set(field,list);
            continue;
        }
        link.set(field,value);
    }
    assertKcpSecurity(link.tunnelTransport,link.tunnelSecurity);
    for(const [key,value] of Object.entries(kcpFields))link.set(key,value);
    if(link.tunnelEncryption==='none'&&(link.tunnelSecurity!=='none'||(link.mode==='forward'&&link.tunnelProtocol!=='vless'))){
        if(b.tunnelEncryption==='none')throw fail('REBUILD_INVALID_REQUEST');
        // Leaving the applicable mode cancels the opt-out; a later edit must opt out again.
        link.tunnelEncryption='vless-enc';
    }
    if(link.tunnelSecurity==='tls'&&Object.hasOwn(b,'tlsServerName')){
        if(typeof b.tlsServerName!=='string')throw fail('REBUILD_TLS_SERVER_NAME_REQUIRED');
        link.rebuildTlsServerName=b.tlsServerName;
    }
    if(Object.hasOwn(b,'tunnelUuid'))link.tunnelUuid=b.tunnelUuid;
    link.portalNode=source;link.bridgeNode=target;
    const tunnelEdited=!editing||link.modifiedPaths().some(field=>!['rebuildExit','autoDeploy'].includes(field.split('.')[0]))
        || ['realityFingerprint','realityPrivateKey','realityPublicKey'].some(field=>Object.hasOwn(b,field));
    if(tunnelEdited&&link.tunnelSecurity==='reality'){
        if(link.tunnelTransport==='ws')throw fail('REBUILD_INVALID_REQUEST');
        const choice=Object.hasOwn(b,'realityFingerprint')?b.realityFingerprint:undefined;
        if(choice!=null&&typeof choice!=='string')throw fail('REBUILD_INVALID_REQUEST');
        const fingerprint=choice?.trim();
        if(fingerprint||!editing)link.realityFingerprint=fingerprint||'chrome';
        const listener=link.mode==='reverse'?from:to;
        // This helper also returns a classic fingerprint default; only inherit
        // the listener settings, never that unrelated dialer choice.
        const {realityFingerprint: _classicFingerprint,...settings}=require('../routes/cascadeLinks').resolveRealitySettings({...link.toObject(),realityPrivateKey:b.realityPrivateKey||link.realityPrivateKey,realityPublicKey:b.realityPublicKey||link.realityPublicKey},listener);
        Object.assign(link,settings);
    }else if(Object.hasOwn(b,'realityFingerprint'))link.realityFingerprint=b.realityFingerprint;
    if(!Number.isInteger(link.tunnelPort)||link.tunnelPort<1||link.tunnelPort>65535||!Number.isSafeInteger(link.priority)||typeof link.name!=='string'||!link.name.trim())throw fail('REBUILD_INVALID_REQUEST');
    if(selector)await validateExit({Link,Node,selector,from,to,ingress:link.toObject(),componentFor});
    if(tunnelEdited&&link.tunnelTransport==='kcp')await service.verifyDraftKcp(link.toObject(),inventory,verify);
    if(tunnelEdited&&link.tunnelSecurity==='tls')await service.verifyDraftTls(link.toObject(),verify);
    if(tunnelEdited&&link.tunnelSecurity==='reality')link.realityFingerprint=await service.verifyDraftRealityFingerprint(link.toObject(),verify);
    if(!editing||link.isModified()){
        await verify();
        const changed=!editing||link.modifiedPaths().some(field=>field!=='autoDeploy');
        const selectorOnly=editing&&!tunnelEdited&&link.isModified('rebuildExit');
        if(changed){
            if(editing)link.rebuildDesiredEdited=true;
            if(!selectorOnly)link.status='pending';
            if(editing&&!selectorOnly){
                link.rebuildReverseObservation=undefined;
                link.markModified('rebuildReverseObservation');
            }
        }
        // A selector-only draft changes routing intent, not the live tunnel
        // identity. Health binds updatedAt; Preview instead binds the selector
        // itself through the existing link snapshot. Do not backfill defaults
        // on sparse rows as a side effect of hydrating the tunnel document.
        await link.save(selectorOnly?{timestamps:false,pathsToSave:['rebuildExit','rebuildDesiredEdited',
            ...(link.isModified('autoDeploy')?['autoDeploy']:[])]}:undefined);
        require('./cascadeService')._invalidateTopologyCache();
    }
    const savedId=String(link._id);
    outcome.linkId=savedId;
    const result={executionMode:'rebuild',desiredSaved:true,linkId:savedId,status:'saved'};
    if(!preview || b.autoDeploy!==true)return result;
    return {...result,status:'awaiting_preview',preview:await service.execute({linkId:savedId,preview:true},verify)};
 });
}

module.exports={saveRebuildDraft};
