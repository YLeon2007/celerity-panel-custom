'use strict';
const express=require('express'),crypto=require('node:crypto');
const {requireScope}=require('../middleware/auth');
const {requirePanelCsrf}=require('./panel/csrf');
const {createRebuildService}=require('../services/rebuildService');
const {componentFor,previewForError}=require('../services/rebuildCoordinator');
const fail=code=>Object.assign(new Error(code),{code});
const errorField=(error,key)=>{try{return error?.[key];}catch{return undefined;}};
const objectId=id=>typeof id==='string'&&/^[a-f\d]{24}$/i.test(id);
const fields=('name mode tunnelPort tunnelProtocol tunnelSecurity tunnelEncryption tunnelTransport tunnelDomain tcpFastOpen tcpKeepAlive tcpNoDelay wsPath wsHost grpcServiceName xhttpPath xhttpHost xhttpMode muxEnabled muxConcurrency geoRouting priority autoDeploy realityDest realitySni realityShortIds realityFingerprint').split(' ');
// Mounted ONLY in rebuild, behind regular requireAuth. API key credentials are
// scope checked; session writes also need the panel's actual CSRF token.
function routerForRebuild({service=createRebuildService(),Link=require('../models/cascadeLinkModel'),Node=require('../models/hyNodeModel')}={}){
 const router=express.Router(), write=[requireScope('nodes:write'),(req,res,next)=>req.apiKey?next():requirePanelCsrf(req,res,next)], read=requireScope('nodes:read');
 const wrap=fn=>async(req,res)=>{
    const outcome={};
    try{res.json(await fn(req,outcome));}catch(e){
        const rawCode=errorField(e,'code');
        const code=typeof rawCode==='string'&&/^(?:REBUILD_|L2TP_FOLLOW_RELAY_)[A-Z0-9_]+(?![\s\S])/.test(rawCode)?rawCode:'REBUILD_FAILED';
        const preview=previewForError(e);
        res.status(code==='REBUILD_PREVIEW_REQUIRED'?428:code==='REBUILD_LINK_NOT_FOUND'?404:code==='REBUILD_INVALID_REQUEST'?400:409)
            .json({error:{code},...(outcome.linkId?{desiredSaved:true,linkId:outcome.linkId}:{}),...(preview?{preview}:{})});
    }
 };
 const run=async(req,preview=false,remove=false)=>{const linkId=req.params.id??req.body?.linkId??req.body?.domainLinkId;
  if(linkId!==undefined&&!objectId(linkId))throw fail('REBUILD_INVALID_REQUEST');
  const expectedPreview=req.body?.expectedPreview;
  if(!preview && expectedPreview===undefined)throw fail('REBUILD_PREVIEW_REQUIRED');
  if(expectedPreview!==undefined && (typeof expectedPreview!=='string'||!/^[a-f0-9]{64}$/.test(expectedPreview)))throw fail('REBUILD_INVALID_REQUEST');
  if(linkId)return service.execute({linkId,preview,remove,expectedPreview});
  // Unscoped Apply is only unambiguous if the DB contains one component.
  if(remove)throw fail('REBUILD_INVALID_REQUEST');
  return service.locks.run(async verify=>{const all=await Link.find({active:true}).select('_id portalNode bridgeNode').sort({_id:1}).lean();if(!all.length)throw fail('REBUILD_LINK_NOT_FOUND');const seen=new Set(componentFor(all,[String(all[0].portalNode)]));if(all.some(l=>!seen.has(String(l.portalNode))))throw fail('REBUILD_SELECT_COMPONENT');return service.execute({linkId:String(all[0]._id),preview,remove,expectedPreview},verify);});};
 router.get('/rebuild/lock',requireScope('nodes:write'),wrap(()=>service.locks.status()));
 router.post('/rebuild/unlock',...write,wrap(req=>service.locks.unlock(req.body?.token)));
 router.post('/rebuild/preview',...write,wrap(req=>run(req,true,req.body?.remove===true)));
 for(const p of ['/topology/deploy','/links/:id/deploy','/chain/deploy'])router.post(p,...write,wrap(async req=>({executionMode:'rebuild',status:'succeeded',...(await run(req))})));
 router.delete('/links/:id',...write,wrap(async req=>({executionMode:'rebuild',deleted:req.params.id,...(await run(req,false,true))})));
 const save=(editing)=>async (req,outcome)=>service.locks.run(async verify=>{
    const b=req.body||{};if(editing&&!objectId(req.params.id))throw fail('REBUILD_INVALID_REQUEST');
    const link=editing?await Link.findById(req.params.id):new Link({tunnelUuid:crypto.randomUUID(),rebuildApplied:null,tunnelEncryption:'vless-enc'});
    if(!link)throw fail('REBUILD_LINK_NOT_FOUND');if(link.rebuildDelete||link.lifecycle)throw fail('REBUILD_DELETION_PENDING');
    const old=editing?[String(link.portalNode),String(link.bridgeNode)]:[];
    const source=b.portalNodeId??old[0],target=b.bridgeNodeId??old[1];
    if(!objectId(source)||!objectId(target)||source===target)throw fail('REBUILD_INVALID_REQUEST');
    if(editing&&(source!==old[0]||target!==old[1]))throw fail('REBUILD_REPLACE_WITH_DELETE_CREATE');
    const inventory=await Node.find({_id:{$in:[source,target]},active:true,type:'xray'}).select('_id cascadeRole xray.realitySni xray.realityDest').lean();
    const from=inventory.find(n=>String(n._id)===source),to=inventory.find(n=>String(n._id)===target);
    if(!from||!to||!['portal','relay'].includes(from.cascadeRole)||!['relay','bridge'].includes(to.cascadeRole))throw fail('REBUILD_INVALID_EDGE_ROLE');
    if(Object.hasOwn(b,'tunnelSecurity')&&!['none','tls','reality'].includes(b.tunnelSecurity))throw fail('REBUILD_INVALID_REQUEST');
    if(Object.hasOwn(b,'tunnelEncryption')&&!['vless-enc','none'].includes(b.tunnelEncryption))throw fail('REBUILD_INVALID_REQUEST');
    if(!editing&&!Object.hasOwn(b,'tunnelSecurity'))link.tunnelSecurity='reality';
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
    if(link.tunnelSecurity==='reality'){
        if(link.tunnelTransport==='ws')throw fail('REBUILD_INVALID_REQUEST');
        const listener=link.mode==='reverse'?from:to;
        Object.assign(link,require('./cascadeLinks').resolveRealitySettings({...link.toObject(),realityPrivateKey:b.realityPrivateKey||link.realityPrivateKey,realityPublicKey:b.realityPublicKey||link.realityPublicKey},listener));
    }
    if(!Number.isInteger(link.tunnelPort)||link.tunnelPort<1||link.tunnelPort>65535||!Number.isSafeInteger(link.priority)||typeof link.name!=='string'||!link.name.trim())throw fail('REBUILD_INVALID_REQUEST');
    if(link.tunnelSecurity==='tls')await service.verifyDraftTls(link.toObject(),verify);
    await verify();link.status='pending';await link.save();const linkId=String(link._id);
    // Latch the acknowledged draft independently of preview and lock cleanup.
    outcome.linkId=linkId;
    require('../services/cascadeService')._invalidateTopologyCache();
    if(b.autoDeploy!==true)return {executionMode:'rebuild',desiredSaved:true,linkId,status:'saved'};
    // Creating a link assigns its identity. Only the resulting component can
    // be previewed. Return that preview before dispatching any node write.
    return {executionMode:'rebuild',desiredSaved:true,linkId,status:'awaiting_preview',preview:await service.execute({linkId,preview:true},verify)};
 });
 router.post('/links',...write,wrap(save(false)));router.put('/links/:id',...write,wrap(save(true)));
 router.get('/rebuild/mode',read,wrap(()=>({mode:'rebuild'})));
 return router;
}
module.exports={routerForRebuild};
