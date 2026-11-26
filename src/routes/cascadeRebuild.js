'use strict';
const express=require('express');
const {requireScope}=require('../middleware/auth');
const {issuePanelCsrfToken, originMatchesHost, requirePanelCsrf}=require('./panel/csrf');
const {createRebuildService}=require('../services/rebuildService');
const {componentFor,previewForError}=require('../services/rebuildCoordinator');
const {neighborRefusalForError}=require('../services/rebuildNeighborRefusal');
const {operationRefusalForError}=require('../services/rebuildKcpAdmission');
const {detectLanguage,t}=require('../middleware/i18n');
const {INVALID_KCP_LINK_SETTINGS}=require('../services/cascadeDraftTransport');
const {saveRebuildDraft}=require('../services/rebuildDraftLink');
const {exitRefusalForError,PORTAL_EXIT_INVALID}=require('../services/rebuildExit');
const fail=code=>Object.assign(new Error(code),{code});
const errorField=(error,key)=>{try{return error?.[key];}catch{return undefined;}};
const ownValue=(obj,key)=>Object.getOwnPropertyDescriptor(obj,key)?.value;
const objectId=id=>typeof id==='string'&&/^[a-f\d]{24}(?![\s\S])/i.test(id);
// Public projection of rebuildTransitMainApply's failure, not of its wire,
// journal record, or nested exception. Missing details never change outcome.
const mainCutoverPhases=new Set(['agent-stop','main-publication','xray-restart','agent-start','agent-reconcile']);
const mainCutoverReasons=new Set([
    'REBUILD_AGENT_STOP_UNCONFIRMED','REBUILD_AGENT_EXCLUSION_UNPROVED','REBUILD_AGENT_START_UNCONFIRMED',
    'REBUILD_AGENT_RECONCILE_UNPROVED','REBUILD_MAIN_PUBLICATION_UNCONFIRMED','REBUILD_MAIN_RESTART_UNCONFIRMED',
    'REBUILD_MAIN_RUNTIME_UNPROVED','REBUILD_MAIN_LOCK_UNPROVED','REBUILD_MAIN_AUTHORITY_UNPROVED',
    'REBUILD_MAIN_WIRE_SETTLEMENT','REBUILD_CUTOVER_ARTIFACT_UNPROVED','REBUILD_MAIN_CAS_UNPROVED',
    'REBUILD_NODE_USER_SYNC_UNCONFIRMED','REBUILD_NODE_USER_SYNC_PREPARE_FAILED','REBUILD_NODE_USER_SYNC_FENCE_UNPROVED',
    'REBUILD_NODE_USER_SYNC_PAYLOAD_UNPROVED','REBUILD_MAIN_PROOF_UNCONFIRMED',
    'REBUILD_DIRECT_RECEIPT_UNPROVED','REBUILD_DIRECT_RECEIPT_LAYOUT_UNSUPPORTED',
    'REBUILD_DIRECT_RECEIPT_REQUIRES_NETWORK','REBUILD_DIRECT_RECEIPT_MAIN_DRIFT',
    'REBUILD_DIRECT_RECEIPT_WRITER_EXCLUSION_UNPROVED','REBUILD_DIRECT_RECEIPT_FINAL_UNPROVED',
    'REBUILD_DIRECT_RECEIPT_WRITE_UNCONFIRMED',
]);
function formatTransitRefusal(req,res,error,code){
    const outcomes={REBUILD_MAIN_CUTOVER_UNRESOLVED:['unknown','unknown'],
        REBUILD_MAIN_CUTOVER_ROLLED_BACK:['rolled-back','rolledBack'],
        REBUILD_MAIN_CUTOVER_NOT_DISPATCHED:['not-dispatched','notDispatched']};
    if(!Object.hasOwn(outcomes,code)&&code!=='REBUILD_SCOPED_TRANSIT_APPLY_UNAVAILABLE')return;
    const lang=res.locals.lang||detectLanguage(req);
    const copy=key=>t(`network.rebuildPreview.mainCutover.${key}`,lang);
    if(code==='REBUILD_SCOPED_TRANSIT_APPLY_UNAVAILABLE')return {
        code,outcome:'not-dispatched',reason:'guarded-preflight',retryAllowed:false,message:copy('guardedPreflight'),
    };
    let phase=null,reason=null;
    try {
        const failure=ownValue(error,'failure');
        if(failure){
            const rawPhase=ownValue(failure,'phase'),rawReason=ownValue(failure,'reason');
            phase=mainCutoverPhases.has(rawPhase)?rawPhase:null;
            reason=mainCutoverReasons.has(rawReason)?rawReason:null;
        }
    }catch{/* Unreadable metadata still means an unknown outcome. */}
    const [outcome,label]=outcomes[code];
    return {code,outcome,retryAllowed:false,failure:{phase,reason},
        message:[copy(label),outcome==='unknown'&&phase&&copy(`phase.${phase}`),reason&&copy(`reason.${reason}`)].filter(Boolean).join(' ')};
}
// Do not echo arbitrary fingerprint input or any transport diagnostics. This
// is the public label vocabulary, not the version-specific acceptance policy.
const publicFingerprints=new Set(['chrome','firefox','safari','ios','android','edge','360','qq','random','randomized']);
function fingerprintIssueForError(error,code){
    if(code!=='REBUILD_REALITY_FINGERPRINT_UNSUPPORTED')return;
    try{
        const issue=ownValue(error,'fingerprintIssue');
        const endpointId=ownValue(issue,'endpointId'),endpointRole=ownValue(issue,'endpointRole');
        const dialerId=ownValue(issue,'dialerId');
        const endpoint=objectId(endpointId)&&['dialer','listener'].includes(endpointRole)
            ? {endpointId,endpointRole} : endpointId===undefined&&endpointRole===undefined&&objectId(dialerId)?{dialerId}:null;
        if(!endpoint)return;
        const version=ownValue(issue,'version'),fingerprint=ownValue(issue,'fingerprint'),choices=ownValue(issue,'allowed');
        const allowed=[];
        const count=Array.isArray(choices)?ownValue(choices,'length'):0;
        if(Number.isSafeInteger(count)&&count<=publicFingerprints.size){
            for(let i=0;i<count;i++){
                const value=ownValue(choices,i);
                if(['chrome','firefox','safari'].includes(value)&&!allowed.includes(value))allowed.push(value);
            }
        }
        return {...endpoint,version:typeof version==='string'&&/^\d{1,4}\.\d{1,4}\.\d{1,4}(?![\s\S])/.test(version)?version:null,
            fingerprint:publicFingerprints.has(fingerprint)?fingerprint:'unknown',allowed};
    }catch{return undefined;}
}
// API and panel clients use the same localized, plain-text refusal. Only typed
// data from the admission policy is included, never raw runtime/driver errors.
const udpPortCopy={
    en:'Node {nodeName}: UDP port {port} is already reserved. Choose a different mKCP port.',
    ru:'Нода {nodeName}: UDP-порт {port} уже занят. Выберите другой порт для mKCP.',
    'zh-CN':'节点 {nodeName}：UDP 端口 {port} 已被占用。请选择其他 mKCP 端口。',
};
function formatOperationRefusal(req,res,error){
    const refusal=operationRefusalForError(error);
    if(!refusal)return;
    const lang=res.locals.lang||detectLanguage(req);
    const copy=(template,values)=>template.replace(/\{(\w+)\}/g,(_,key)=>values[key]??'');
    const versionCopy=key=>t(`network.rebuildKcpVersion${key}`,lang);
    const {code,minimumVersion}=refusal;
    if(!refusal.issues)return {code,message:versionCopy('PreviewChanged')};
    const transportCopy=code==='REBUILD_L2TP_KCP_LISTENER_UNSUPPORTED'
        ?t('network.rebuildKcpL2tpListenerUnsupported',lang):(udpPortCopy[lang]||udpPortCopy.en);
    const issues=refusal.issues.map(issue=>({ ...issue,message:copy(minimumVersion
        ?versionCopy(issue.reason==='too_old'?'TooOld':'Unknown'):transportCopy, {...issue,minimumVersion}) }));
    return {code,...(minimumVersion&&{minimumVersion}),issues,message:issues.map(issue=>issue.message).join(' ')};
}
// Mounted ONLY in rebuild, behind regular requireAuth. API key credentials are
// scope checked; session writes also need the panel's actual CSRF token.
function routerForRebuild({service=createRebuildService(),Link=require('../models/cascadeLinkModel'),Node=require('../models/hyNodeModel')}={}){
 const router=express.Router(), write=[requireScope('nodes:write'),(req,res,next)=>req.apiKey?next():requirePanelCsrf(req,res,next)], read=requireScope('nodes:read');
 const wrap=fn=>async(req,res)=>{
    const outcome={};
    try{res.json(await fn(req,outcome));}catch(e){
        const rawCode=errorField(e,'code');
        const code=rawCode===INVALID_KCP_LINK_SETTINGS?rawCode:typeof rawCode==='string'&&rawCode!=='REBUILD_RETIRE_NEIGHBOR_REFUSED'&&/^(?:REBUILD_|L2TP_FOLLOW_RELAY_)[A-Z0-9_]+(?![\s\S])/.test(rawCode)?rawCode:'REBUILD_FAILED';
        const refusal=formatTransitRefusal(req,res,e,code)??exitRefusalForError(e)??formatOperationRefusal(req,res,e)??neighborRefusalForError(e);
        const preview=previewForError(e);
        const fingerprintIssue=fingerprintIssueForError(e,code);
        res.status(code==='REBUILD_PREVIEW_REQUIRED'?428:code==='REBUILD_LINK_NOT_FOUND'?404:(['REBUILD_INVALID_REQUEST',PORTAL_EXIT_INVALID,INVALID_KCP_LINK_SETTINGS].includes(code))?400:409)
            .json({error:refusal??{code},...(outcome.linkId?{desiredSaved:true,linkId:outcome.linkId}:{}),...(preview?{preview}:{}),...(fingerprintIssue?{fingerprintIssue}:{})});
    }
 };
 const run=async(req,preview=false,remove=false)=>{const linkId=req.params.id??req.body?.linkId??req.body?.domainLinkId;
  if(linkId!==undefined&&!objectId(linkId))throw fail('REBUILD_INVALID_REQUEST');
  const expectedPreview=req.body?.expectedPreview;
  if(!preview && expectedPreview===undefined)throw fail('REBUILD_PREVIEW_REQUIRED');
  // Accept the previous format only so a pre-restart token gets a stale-preview conflict.
  if(expectedPreview!==undefined && (typeof expectedPreview!=='string'||!/^(?:[a-f0-9]{64}|[a-f0-9]{128})$/.test(expectedPreview)))throw fail('REBUILD_INVALID_REQUEST');
  if(linkId)return service.execute({linkId:linkId.toLowerCase(),preview,remove,expectedPreview});
  // Unscoped Apply is only unambiguous if the DB contains one component.
  if(remove)throw fail('REBUILD_INVALID_REQUEST');
  return service.locks.run(async verify=>{const all=await Link.find({active:true}).select('_id portalNode bridgeNode').sort({_id:1}).lean();if(!all.length)throw fail('REBUILD_LINK_NOT_FOUND');const seen=new Set(componentFor(all,[String(all[0].portalNode)]));if(all.some(l=>!seen.has(String(l.portalNode))))throw fail('REBUILD_SELECT_COMPONENT');return service.execute({linkId:String(all[0]._id),preview,remove,expectedPreview},verify);});};
 // The transfer-drafts token route is disabled in rebuild. Reread the same
 // panel-session token used by the page and write guard, never an API-key token.
 router.get('/rebuild/csrf-token',read,(req,res)=>{
    res.set('Cache-Control','no-store');
    res.removeHeader('Access-Control-Allow-Origin');
    if(req.apiKey || !req.session?.authenticated) return res.sendStatus(403);
    const site=req.get('Sec-Fetch-Site');
    if((site && site!=='same-origin') || !originMatchesHost(req)) return res.sendStatus(403);
    return res.json({csrfRequired:true,csrfToken:issuePanelCsrfToken(req)});
 });
 router.get('/rebuild/lock',requireScope('nodes:write'),wrap(()=>service.locks.status()));
 router.post('/rebuild/unlock',...write,wrap(req=>service.locks.unlock(req.body?.token)));
 router.post('/rebuild/preview',...write,wrap(req=>run(req,true,req.body?.remove===true)));
 for(const p of ['/topology/deploy','/links/:id/deploy','/chain/deploy'])router.post(p,...write,wrap(async req=>{
    const result=await run(req);
    // Also outside the owning callback for unscoped Apply.
    if(result.status==='rolled-back'||result.status==='not-dispatched'){
        throw Object.assign(fail(result.status==='rolled-back'?'REBUILD_MAIN_CUTOVER_ROLLED_BACK':'REBUILD_MAIN_CUTOVER_NOT_DISPATCHED'),{failure:result.failure});
    }
    return {executionMode:'rebuild',status:'succeeded',...result};
 }));
 router.delete('/links/:id',...write,wrap(async req=>({executionMode:'rebuild',deleted:req.params.id,...(await run(req,false,true))})));
 const save=editing=>(req,outcome)=>saveRebuildDraft({service,Link,Node,
    linkId:editing?req.params.id:undefined,body:req.body??{},preview:true},outcome);
 router.post('/links',...write,wrap(save(false)));router.put('/links/:id',...write,wrap(save(true)));
 router.get('/rebuild/mode',read,wrap(()=>({mode:'rebuild'})));
 return router;
}
module.exports={routerForRebuild};
