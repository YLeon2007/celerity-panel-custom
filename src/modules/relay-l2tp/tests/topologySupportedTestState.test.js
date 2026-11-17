'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {initializeDedicatedTestState}=require('../../../../scripts/test-topology-owner');
function fixture({state=null,occupied=false}={}){
 let creates=0;const query=value=>({session(){return this;},setOptions(){return this;},read(){return this;},readConcern(){return this;},maxTimeMS(){return this;},lean:async()=>value});
 const empty={findOne:()=>query(occupied?{_id:'occupied'}:null)};
 const State={db:{transaction:async f=>f({})},findById:()=>query(state),async create(rows){creates++;state=rows[0];return rows;}};
 return {models:{CascadeTopologyState:State,CascadeLink:empty,CascadeRouteGroup:empty,RelayL2tpState:empty,TopologyOperation:empty,TopologyExecutionBinding:empty,NodeOperationLock:empty,RemoteAdmission:empty,L2tpOperation:empty,TopologyCreateIntent:empty,TopologyIntentQueueState:empty},get creates(){return creates;},get state(){return state;}};
}
test('dedicated empty TEST initializes admission singleton, never ready',async()=>{
 assert.equal(typeof initializeDedicatedTestState,'function');const f=fixture();let checks=0;await initializeDedicatedTestState(f.models,async()=>checks++);assert.equal(f.creates,1);assert.equal(f.state.topologyAdmissionCount,0);assert.equal(f.state.remoteAdmissionCount,0);assert.equal(f.state.revision,0);assert.equal(f.state.ready,undefined);assert.ok(checks>=2);
});
test('dedicated state never infers zero from occupied DB or existing incomplete state',async()=>{
 assert.equal(typeof initializeDedicatedTestState,'function');for(const options of [{occupied:true},{state:{_id:'singleton',revision:0}}]){const f=fixture(options);await assert.rejects(initializeDedicatedTestState(f.models,async()=>{}));assert.equal(f.creates,0);}
});
