'use strict';
process.env.PANEL_DOMAIN||='test.infograd.online';process.env.ACME_EMAIL||='test@example.invalid';process.env.ENCRYPTION_KEY||='0'.repeat(64);process.env.SESSION_SECRET||='test-secret';
const test=require('node:test'),assert=require('node:assert/strict');
const {TopologyOperationWorker}=require('../workers/topologyOperationWorker');
const {assertBootstrapContinuationEligible:eligible}=require('../repositories/topologyBootstrapContinuation');
const TEST=require('../domain/topologyExecutionContext').TEST_TOPOLOGY_EXECUTION_CONTEXT;
test('continuation plan retains the same reserved backup while ordinary pending plans still reject it',()=>{
 const {durablePlan}=require('../workers/topologyOperationWorker');const bytes=Buffer.from('{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n'),sha=require('node:crypto').createHash('sha256').update(bytes).digest('hex');
 const id='123456789012345678901234',n={node:id,nodeRef:'bridge',role:'bridge',targetProfile:'xray-bridge',checks:[],state:'pending',backupId:'reserved-original-backup',candidateHash:sha,candidate:{mediaType:'application/vnd.celerity.xray-topology-node+json;version=1',bytes:[...bytes],sha256:sha}};
 const op={_id:'operation-1',status:'preparing',topologyRevision:1,priorDeployedRevision:0,nodes:[n],bootstrapContinuation:{originalNodes:[{node:id,state:'failed',backupId:n.backupId}]}};
 assert.throws(()=>durablePlan(op,'operation-1'));assert.equal(durablePlan(op,'operation-1',true).nodes[0].node,id);assert.equal(op.nodes[0].backupId,n.backupId);
 op.bootstrapContinuation.originalNodes[0].backupId='foreign';assert.throws(()=>durablePlan(op,'operation-1',true));
});
test.after(()=>require('../../../services/sshPoolService').closeAll());
test('real worker exposes only an explicit held bootstrap continuation, not ordinary failed retry',()=>assert.equal(typeof TopologyOperationWorker.prototype.resumeBootstrapPreparation,'function'));
test('only exact first failed selected TEST preparation is eligible; unknown runner phases and repeated claims refuse',()=>{
 const op={executionContext:TEST,admissionScope:'selected',kind:'link.apply',status:'failed',attempts:1,leaseOwner:'owner',leaseUntil:null,heldTopologyAdmission:true,finishedAt:new Date(),nodes:[{state:'failed'},{state:'pending'}]};eligible(op,'owner');for(const patch of [{attempts:2},{status:'committing'},{executionContext:{target:'production',hostIdentity:'lm1.infograd.online'}},{v2Terminal:{}},{bootstrapContinuation:{}},{nodes:[{state:'committed'},{state:'failed'}]},{leaseOwner:'other'}])assert.throws(()=>eligible({...op,...patch},'owner'));
});
