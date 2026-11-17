'use strict';
// Repository orchestration/CAS payload modeled in memory. Real Mongo proof is
// the separately retained live dedicated API resume, not these mocked queries.
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto'),{isDeepStrictEqual:same}=require('node:util');
const {Types:{ObjectId}}=require('mongoose');
const {TopologyExecutionBindingStore}=require('../repositories/topologyExecutionBindingStore');
const {freeze}=require('../models/topologyExecutionBindingContract');
const TEST=require('../domain/topologyExecutionContext').TEST_TOPOLOGY_EXECUTION_CONTEXT;
const keys=['nodeId','targetProfile','endpoint','nodeIdentity','ownerGeneration','predecessorGeneration','bootId'];
function fixture({occupied=false,nodeMissing=false}={}){
 const id='123456789012345678901234',oldBoot=randomUUID(),newBoot=randomUUID(),generation=randomUUID(),maintenance=randomUUID();
 const identity={machineId:'1'.repeat(32),sshHostKeySha256:'2'.repeat(64)},endpoint={ip:'192.0.2.1',port:2223,username:'root'};
 const snapshot={configSha256:'a'.repeat(64),unitSha256:'b'.repeat(64),serviceActive:'inactive',serviceEnabled:'disabled'};
 let row={_id:randomUUID(),executionContext:TEST.hostIdentity,nodeId:id,targetProfile:'xray-bridge',endpoint,nodeIdentity:identity,ownerGeneration:generation,predecessorGeneration:'none',bootId:oldBoot,proofId:randomUUID(),maintenanceId:maintenance,provisioningReceipt:{generation:'none',bootId:oldBoot,status:'empty',protocolVersion:2,journal:'absent',legacyState:'absent',writers:'excluded'}};
 const original=structuredClone(row),writes=[];
 const owner={executionContext:TEST,node:new ObjectId(id),profile:'xray-bridge',owner:'topology',generation,nodeIdentity:identity,originalSnapshot:snapshot,adoptionReceipt:{proofId:randomUUID(),maintenanceId:maintenance,fromGeneration:randomUUID(),toGeneration:generation,oldBackendInstanceId:'prior-instance',oldPid:42,oldProcessStartTime:'123',verifiedAt:new Date(Date.now()-1000)}};
 const node={_id:new ObjectId(id),ip:endpoint.ip,type:'xray',active:true,cascadeRole:'bridge',ssh:{port:2223,username:'root'}};
 const db={getClient:()=>({options:{},topology:{description:{type:'ReplicaSetWithPrimary'}}}),async startSession(){return {startTransaction(){},async commitTransaction(){writes.push(['commit']);},inTransaction:()=>true,async abortTransaction(){},async endSession(){}};}};
 const q=v=>{const a={select:()=>a,session:()=>a,setOptions:()=>a,read:()=>a,readConcern:()=>a,lean:async()=>v};return a;};
 const indexKeys={Owner:[{node:1,profile:1}],Lock:[{node:1}],Enrollment:[{nodeId:1,targetProfile:1},{'nodeIdentity.machineId':1,targetProfile:1},{'nodeIdentity.sshHostKeySha256':1,targetProfile:1},{'nodeIdentity.machineId':1},{'nodeIdentity.sshHostKeySha256':1},{'endpoint.ip':1,'endpoint.port':1}],Binding:[{operationId:1,nodeId:1,targetProfile:1},{enrollmentId:1,predecessorGeneration:1},{enrollmentId:1,generation:1},{attemptId:1},{commandTokens:1}]};
 const models={};
 for(const name of ['Owner','Lock','Enrollment','Binding','Operation','HyNode'])models[name]={db,collection:{indexes:async()=>indexKeys[name].map(key=>({key,unique:true}))},findOne(filter){
  let value=name==='Owner'?owner:name==='HyNode'?(nodeMissing?null:node):name==='Enrollment'?row:occupied?{_id:'occupied'}:null;
  if(filter.executionBindingCheck&&value?.executionBindingCheck!==filter.executionBindingCheck)value=null;return q(value);
 },async updateOne(filter,update){assert.ok(filter.$expr);if(name==='Owner'){assert.equal(filter.generation,generation);assert.deepEqual(filter.nodeIdentity,identity);}writes.push([name,filter,update]);Object.assign(name==='Owner'?owner:node,update.$set);return {matchedCount:1};}};
 models.Enrollment.collection.updateOne=async(filter,update)=>{assert.equal(filter._id,row._id);assert.equal(filter.bootId,oldBoot);assert.deepEqual(filter.provisioningReceipt,original.provisioningReceipt);assert.deepEqual(filter.pristineBootResume,{$exists:false});assert.deepEqual(Object.keys(update.$set),['pristineBootResume']);writes.push(['bootCAS']);row={...row,...update.$set};return {matchedCount:1};};
 const store=new TopologyExecutionBindingStore({executionContext:TEST,...models,assertAuthorityHeld:async()=>{},withVerifiedAuthority:async(challenge,work)=>{assert.equal(challenge.action,'reconcile-pristine');return work({authority:'external-execution-maintenance-v1',status:'verified',challenge,proofId:randomUUID(),maintenanceId:maintenance,maintenance:'held',allWriters:'drained',bootstrapWriters:'excluded',owner:'topology',physicalIdentity:identity,predecessor:{generation:'none',bootId:challenge.enrollment.bootId,status:'pre-enrolled'},oldBackend:{processTree:'stopped',dispatch:'disabled',instanceId:'prior-instance',pid:42,processStartTime:'123'},connectionAttestation:{authority:'server-physical-ssh-endpoint-v1',endpoint,physicalIdentity:identity,maintenanceId:maintenance,aliases:'excluded',hostKeyDigest:'raw-ssh-public-key-sha256',endpointReassignment:'excluded'}});}});
 const input=boot=>freeze(Object.fromEntries(keys.map(k=>[k,k==='bootId'?boot:original[k]])));
 return {store,input,oldBoot,newBoot,snapshot,writes,original,get row(){return row;}};
}
test('pristine new boot adds audited receipt with exact CAS; initial enrollment and epoch preserved',async()=>{
 const f=fixture();const result=await f.store.verifyPristineEnrollment(f.input(f.newBoot),f.snapshot);assert.equal(result.bootId,f.newBoot);assert.equal(result.enrollmentId,f.original._id);const {pristineBootResume,...base}=f.row;assert.deepEqual(base,f.original);assert.equal(pristineBootResume.initialBootId,f.oldBoot);assert.equal(pristineBootResume.bootId,f.newBoot);assert.deepEqual(pristineBootResume.previousBootIds,[f.oldBoot]);assert.equal(f.writes.filter(x=>x[0]==='bootCAS').length,1);assert.ok(f.writes.some(x=>x[0]==='Owner')&&f.writes.some(x=>x[0]==='HyNode'));
});
test('same boot reconciles with owner/node CAS and does not create a new enrollment or boot receipt',async()=>{
 const f=fixture();await f.store.verifyPristineEnrollment(f.input(f.oldBoot),f.snapshot);assert.deepEqual(f.row,f.original);assert.equal(f.writes.some(x=>x[0]==='bootCAS'),false);
});
test('existing bindings/locks/operations, changed snapshot, missing HyNode and changed owner epoch refuse without writes',async()=>{
 for(const option of ['occupied','snapshot','nodeMissing','generation']){const f=fixture({occupied:option==='occupied',nodeMissing:option==='nodeMissing'});let input=f.input(f.newBoot),snapshot=f.snapshot;if(option==='snapshot')snapshot={...snapshot,configSha256:'c'.repeat(64)};if(option==='generation')input=freeze({...input,ownerGeneration:randomUUID()});await assert.rejects(f.store.verifyPristineEnrollment(input,snapshot));assert.deepEqual(f.writes,[]);assert.deepEqual(f.row,f.original);}
});
