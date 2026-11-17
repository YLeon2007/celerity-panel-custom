'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createL2tpRouteBindings}=require('../l2tpActiveHostProvider');
test('MAIN normalization route binding reaches the current actual host service with its receiver',async()=>{
 const calls=[],service={async normalizeMainIngress(id){assert.equal(this,service);calls.push(id);return {operationId:'repair',status:'succeeded'};}};
 const bindings=createL2tpRouteBindings({getActiveHost:()=>({runtime:{service}})});
 assert.deepEqual(await bindings.l2tpService.normalizeMainIngress('relay'),{operationId:'repair',status:'succeeded'});assert.deepEqual(calls,['relay']);
});
test('missing normalizer is unavailable, never silently replaced by install or sync',()=>{
 const bindings=createL2tpRouteBindings({getActiveHost:()=>null});
 assert.throws(()=>bindings.l2tpService.normalizeMainIngress('relay'),{code:'L2TP_RUNTIME_UNAVAILABLE'});
});
