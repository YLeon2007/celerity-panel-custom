'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
test('dedicated TEST path health requires held physical health and a real selected TCP endpoint, never writes agent status',async()=>{
 const {createDedicatedTestPathHealth}=require('../services/topologyDedicatedTestHealth');
 for(const healthy of [true,false])for(const tcp of [true,false]){
  let probes=0;const q=rows=>({select(){return this;},lean:async()=>rows});
  const read=createDedicatedTestPathHealth({authority:{readCurrentHealth:async()=>[{nodeId:'r',healthy:true,endpoint:{ip:'10.0.0.1'}},{nodeId:'b',healthy,endpoint:{ip:'10.0.0.2'}}]},CascadeLink:{find:()=>q([{_id:'l',active:true,mode:'forward',portalNode:'r',bridgeNode:'b',tunnelPort:24101}])},CascadeRouteGroup:{find:()=>q([{_id:'g',paths:[{pathKey:'main',linkIds:['l']}]}])},connect:async(ip,port)=>{assert.equal(ip,'10.0.0.2');assert.equal(port,24101);probes++;return tcp;}});
  assert.deepEqual(await read(),{'g:main':healthy&&tcp});assert.equal(probes,healthy?1:0);
 }
});
test('dedicated TEST publication health binds physical service and listener to verified applied candidate, fails closed',async()=>{
 const {createDedicatedTestNodeHealth}=require('../services/topologyDedicatedTestHealth');
 const node={nodeId:'p',ip:'10.0.0.1',port:443,candidateHash:'a'.repeat(64)};
 for(const healthy of [true,false])for(const matches of [true,false])for(const tcp of [true,false]){
  let probes=0;
  const read=createDedicatedTestNodeHealth({authority:{readCurrentHealth:async()=>[{
   nodeId:'p',healthy,endpoint:{ip:node.ip},configSha256:(matches?'a':'b').repeat(64)}]},
   connect:async(ip,port)=>{assert.equal(ip,node.ip);assert.equal(port,443);probes++;return tcp;}});
  assert.deepEqual(await read({nodes:[node]}),[{nodeId:'p',healthy:healthy&&matches&&tcp}]);
  assert.equal(probes,healthy&&matches?1:0);
 }
 const unavailable=createDedicatedTestNodeHealth({authority:{readCurrentHealth:async()=>{throw Error('unavailable');}}});
 assert.deepEqual(await unavailable({nodes:[node]}),[{nodeId:'p',healthy:false}]);
 const before=structuredClone(node);
 const missing=createDedicatedTestNodeHealth({authority:{readCurrentHealth:async()=>[]},connect:()=>{throw Error('must not probe');}});
 assert.deepEqual(await missing({nodes:[node]}),[{nodeId:'p',healthy:false}]);assert.deepEqual(node,before);
});

test('publication health uses an actual loopback listener and does not equate TCP alone with applied health', async () => {
 const { createDedicatedTestNodeHealth } = require('../services/topologyDedicatedTestHealth');
 const { createServer } = require('node:net');
 const { once } = require('node:events');
 const server = createServer(socket => socket.end()).listen(0, '127.0.0.1');
 await once(server, 'listening');
 const node = { nodeId: 'p', ip: '127.0.0.1', port: server.address().port, candidateHash: 'a'.repeat(64) };
 let observedHash = node.candidateHash;
 const read = createDedicatedTestNodeHealth({ authority: { readCurrentHealth: async () => [
  { nodeId: node.nodeId, endpoint: { ip: node.ip }, healthy: true, configSha256: observedHash },
 ] } });
 const expectHealth = async healthy => assert.deepEqual(await read({ nodes: [node] }), [{ nodeId: node.nodeId, healthy }]);
 try {
  await expectHealth(true);
  observedHash = 'b'.repeat(64);
  await expectHealth(false);
 } finally {
  await new Promise(resolve => server.close(resolve));
 }
 observedHash = node.candidateHash;
 await expectHealth(false);
});
