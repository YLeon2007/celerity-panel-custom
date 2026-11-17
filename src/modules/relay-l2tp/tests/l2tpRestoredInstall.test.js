'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
const {RemoteAdmissionRepository}=require('../repositories/remoteAdmissionRepository');
const {restoredInstallProbe}=require('../services/l2tpRestoredInstallReadback');
const ctx={target:'test',hostIdentity:'test.infograd.online'},id='1'.repeat(24);
function fixture(){
 const data={operation:{_id:id,node:'relay',kind:'install',status:'failed',step:'start_l2tp',errorCode:'ROLLBACK_SYSTEM_FAILED',logs:[{code:'L2TP_ROLLBACK_FAILED'}],admissionId:'admission',leaseOwner:'worker',ownerGeneration:2},lock:{_id:'lock',node:'relay',owner:'worker',operationId:id,generation:'generation',remoteUncertain:true},admission:{_id:'admission',phase:'recovery_required'},gate:{remoteAdmissionCount:1}};
 const q=f=>({lean:async()=>structuredClone(f()),session(){return this;}});let writes=0;
 const Operation={findOne:()=>q(()=>data.operation),findById:()=>q(()=>data.operation),async updateOne(filter,change){writes++;Object.assign(data.operation,change.$set);data.operation.logs.push(change.$push.logs);return{matchedCount:1};}};
 const Lock={findOne:()=>q(()=>data.lock),async deleteOne(){writes++;data.lock=null;return{deletedCount:1};}};
 const Admission={create(){},findById:()=>q(()=>data.admission),async updateOne(){writes++;data.admission.phase='completed';return{matchedCount:1};}};
 const Gate={async updateOne(){writes++;data.gate.remoteAdmissionCount--;return{matchedCount:1};}};
 const repo=new RemoteAdmissionRepository({CascadeTopologyState:Gate,RemoteAdmission:Admission,L2tpOperation:Operation,NodeOperationLock:Lock,transactionRunner:work=>work({})});return{repo,data,writes:()=>writes};
}
test('known returned rollback failure settles only after complete physical restored readback, retaining failed history',async()=>{
 const f=fixture(),logs=structuredClone(f.data.operation.logs);
 await assert.rejects(f.repo.reconcileRestoredFailedInstall({operationId:id,executionContext:ctx,verifyRestored:async()=>({ok:false})}),{code:'L2TP_ROLLBACK_RECONCILIATION_REFUSED'});assert.equal(f.writes(),0);
 const r=await f.repo.reconcileRestoredFailedInstall({operationId:id,executionContext:ctx,verifyRestored:async()=>({ok:true,operationId:id,managedPaths:7,firewallRestored:true,servicesRestored:true,runnerIdle:true,backupSha256:'a'.repeat(64),sidecarSha256:'b'.repeat(64)})});
 assert.equal(r.admission,'completed');assert.equal(f.data.operation.status,'failed');assert.equal(f.data.operation.errorCode,'ROLLBACK_SYSTEM_FAILED');assert.deepEqual(f.data.operation.logs.slice(0,1),logs);assert.equal(f.data.gate.remoteAdmissionCount,0);assert.equal(f.data.lock,null);
});
test('native xl2tpd fallback unit is exclusive and preserves an existing unit',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'l2tp-unit-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const helper=path.join(__dirname,'../node-artifacts/l2tp/ensure-xl2tpd-unit.py');const run=()=>spawnSync('python3',['-B',helper,root]);
 assert.equal(run().status,0);const p=path.join(root,'etc/systemd/system/xl2tpd.service'),before=fs.readFileSync(p);assert.match(before.toString(),/ExecStart=\/usr\/sbin\/xl2tpd -D/);assert.equal(run().status,73);assert.deepEqual(fs.readFileSync(p),before);
 assert.throws(()=>restoredInstallProbe('bad/id'));assert.match(restoredInstallProbe(id),/backupSha256/);
});
