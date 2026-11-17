'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {initializeDedicatedTestState}=require('../../../../scripts/test-topology-owner');
const NODE='1234567890abcdef12345678';
function fixture({physical=true,users=false,active=false}={}) {
 let state=null,absent=[];const db={transaction:async work=>work({})};
 const q=value=>({session(){return this;},setOptions(){return this;},select(){return this;},read(){return this;},readConcern(){return this;},maxTimeMS(){return this;},lean:async()=>value});
 const empty={db,findOne:()=>q(null)};
 const State={db,findById:()=>q(state),async create(rows){state=rows[0];}};
 const Relay={db,findOne:()=>q(absent[0]||null),async insertMany(rows){absent.push(...rows);}};
 const models={CascadeTopologyState:State,CascadeLink:empty,CascadeRouteGroup:empty,RelayL2tpState:Relay,TopologyOperation:empty,TopologyExecutionBinding:empty,NodeOperationLock:empty,RemoteAdmission:empty,L2tpOperation:{db,findOne:()=>q(active?{_id:'active'}:null)},TopologyCreateIntent:empty,TopologyIntentQueueState:empty,HyNode:{db,findById:()=>q({_id:NODE,cascadeRole:'relay'})},L2tpUser:{db,findOne:()=>q(users?{_id:'user'}:null)}};
 return {models,plan:{nodes:[{nodeId:NODE,targetProfile:'xray-bridge',l2tpUnconfigured:physical}]},get absent(){return absent;},get state(){return state;}};
}
test('fresh physically unconfigured dedicated relay receives serializable absent epoch, not PPP readiness',async()=>{
 const f=fixture();await initializeDedicatedTestState(f.models,async()=>{},f.plan);
 assert.deepEqual(f.absent,[{node:NODE,desiredState:'absent',status:'not_installed',secretRevision:0}]);assert.equal(f.state.revision,0);assert.equal(f.absent[0].ready,undefined);
});
for(const [label,options]of [['physical absence unproven',{physical:false}],['orphan user',{users:true}],['prior PPP operation',{active:true}]])test('fresh absence producer refuses '+label,async()=>{
 const f=fixture(options);await assert.rejects(initializeDedicatedTestState(f.models,async()=>{},f.plan));assert.equal(f.absent.length,0);
});
