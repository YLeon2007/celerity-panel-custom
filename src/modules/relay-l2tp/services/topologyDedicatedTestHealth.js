'use strict';
// Dedicated TEST has no legacy HTTP agent. This on-demand source observes the
// existing held node runtime and actual selected listener; it never manufactures
// heartbeats, updates HyNode status, or grants mutation authority.
const net=require('node:net');
function tcp(ip,port){return new Promise(resolve=>{const s=net.createConnection({host:ip,port});let done=false;const finish=v=>{if(done)return;done=true;s.destroy();resolve(v);};s.setTimeout(2000,()=>finish(false));s.once('connect',()=>finish(true));s.once('error',()=>finish(false));});}
function createDedicatedTestPathHealth({authority,CascadeLink,CascadeRouteGroup,connect=tcp}){
 return async()=>{
  try{
   const nodes=new Map((await authority.readCurrentHealth()).map(n=>[n.nodeId,n]));
   const [links,groups]=await Promise.all([CascadeLink.find({active:true}).select('_id active mode portalNode bridgeNode tunnelPort').lean(),CascadeRouteGroup.find({}).select('_id paths').lean()]);
   const byId=new Map(links.map(l=>[String(l._id),l])),result={};
   for(const group of groups)for(const path of group.paths||[]){
    let healthy=Array.isArray(path.linkIds)&&path.linkIds.length>0;
    for(const id of path.linkIds||[]){
     const l=byId.get(String(id)),a=nodes.get(String(l?.portalNode)),b=nodes.get(String(l?.bridgeNode));
     if(!l||l.active!==true||a?.healthy!==true||b?.healthy!==true||!Number.isInteger(l.tunnelPort)||l.tunnelPort<1||l.tunnelPort>65535){healthy=false;break;}
     const listener=l.mode==='forward'?b:l.mode==='reverse'?a:null;
     if(!listener||!await connect(listener.endpoint.ip,l.tunnelPort)){healthy=false;break;}
    }
    result[String(group._id)+':'+path.pathKey]=healthy;
   }
   return result;
  }catch{return{};}
 };
}
// Ordinary publication on dedicated TEST has no cc-agent heartbeat. Preserve
// the normal hideOffline predicate, but feed it an on-demand physical service
// observation bound to the SAME verified applied candidate and real listener.
// This never changes HyNode.status, saved settings or unowned/classic behavior.
function createDedicatedTestNodeHealth({authority,connect=tcp}){
 return async({nodes})=>{
  const result=new Map(nodes.map(n=>[n.nodeId,false]));
  try{
   const observed=new Map((await authority.readCurrentHealth()).map(n=>[n.nodeId,n]));
   await Promise.all(nodes.map(async n=>{
    const live=observed.get(n.nodeId);
    if(live?.healthy===true && /^[a-f0-9]{64}$/.test(n.candidateHash||'')
      && live.configSha256===n.candidateHash && live.endpoint?.ip===n.ip
      && Number.isInteger(n.port) && n.port>0 && n.port<=65535){
     result.set(n.nodeId,await connect(n.ip,n.port));
    }
   }));
  }catch{ /* An unavailable observation is unavailable, never desired-as-health. */ }
  return [...result].map(([nodeId,healthy])=>({nodeId,healthy}));
 };
}
module.exports={createDedicatedTestPathHealth,createDedicatedTestNodeHealth};
