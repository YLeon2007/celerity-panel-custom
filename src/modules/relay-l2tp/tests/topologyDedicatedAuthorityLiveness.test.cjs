'use strict';
// Real loopback SSH2 transport with a bounded peer-read stall. This is not a
// physical TEST enrollment or an attestation of any historical failure cause.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {Server,Client,utils}=require('ssh2');
const {createHash,generateKeyPairSync,randomUUID}=require('node:crypto');
const filename=require.resolve('../runtime/dedicatedTestAuthority');
const f=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NOATIME);const source=fs.readFileSync(f,'utf8');fs.closeSync(f);
function compile(text){
 const body=text.slice(text.indexOf('async function connect('),text.indexOf('function createDedicatedTestAuthority('));
 return vm.runInNewContext('('+body.trim()+')',{require:name=>{assert.equal(name,'ssh2');return {Client}},sha:x=>createHash('sha256').update(x).digest('hex'),need:x=>{if(!x)throw Error('LOCAL_AUTHORITY_PREDICATE')},randomUUID,Buffer,setTimeout,clearTimeout,JSON,Error});
}
function key(){return generateKeyPairSync('rsa',{modulusLength:2048,privateKeyEncoding:{type:'pkcs1',format:'pem'},publicKeyEncoding:{type:'pkcs1',format:'pem'}}).privateKey;}
async function exercise(text,stallMs,{withholdExec=false}={}){
 const host=key(),privateKey=key(),sockets=new Set();
 let execAt;
 const server=new Server({hostKeys:[host]},client=>{
  sockets.add(client);client.on('error',()=>{});client.on('close',()=>sockets.delete(client));client.on('authentication',c=>c.accept());
  client.on('ready',()=>client.on('session',accept=>accept().on('exec',(accept,_reject,info)=>{
   assert.equal(info.command,'/usr/bin/python3 -I -B /usr/local/libexec/celerity-test-dedicated-node');
   execAt=Date.now();if(withholdExec)return;
   const stream=accept();stream.on('error',()=>{});let buffer='';
   stream.on('data',b=>{buffer+=b;let i;while((i=buffer.indexOf('\n'))>=0){const request=JSON.parse(buffer.slice(0,i));buffer=buffer.slice(i+1);
    // Pause the real SSH peer's reads, including keepalive responses. The
    // existing nonce response still arrives within the original 10s budget.
    client._sock.pause();const timer=setTimeout(()=>{client._sock.resume();if(!stream.destroyed&&!stream.writableEnded)stream.write(JSON.stringify({nonce:request.nonce,boundedResponse:true})+'\n')},stallMs);timer.unref();
   }});
  })));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const started=Date.now();let c;
 // Separate fixture watchdog: unbounded baseline must fail rather than hang.
 let watchdog;
 try{
  const opening=compile(text)({endpoint:{ip:'127.0.0.1',port:server.address().port,username:'local-fixture'},privateKeyPath:'in-memory-fixture',hostKeySha256:createHash('sha256').update(utils.parseKey(host).getPublicSSH()).digest('hex')},()=>privateKey);
  try { c=await Promise.race([opening,new Promise((_,reject)=>{watchdog=setTimeout(()=>reject(Error('LOCAL_WATCHDOG')),12000);})]); }
  catch(error){return {outcome:'open-rejected',elapsedMs:Date.now()-started,execRequestMs:execAt===undefined?null:execAt-started,message:error.message};}
  try{const response=await c.observe();return {outcome:'response',elapsedMs:Date.now()-started,response};}
  catch(error){return {outcome:'rejected',elapsedMs:Date.now()-started,message:error.message};}
 }finally{clearTimeout(watchdog);c?.close();for(const socket of sockets)socket.end();await new Promise(resolve=>server.close(resolve));}
}
test('authority setup timeout includes a silent exec acknowledgement on real loopback SSH2',{timeout:18000},async()=>{
 const stalled=await exercise(source,0,{withholdExec:true});
 assert.equal(stalled.outcome,'open-rejected');
 assert.notEqual(stalled.execRequestMs,null,'fixture authenticated and reached the helper exec request');
 assert.equal(stalled.message,'DEDICATED_AUTHORITY_OPEN_TIMEOUT');
 assert.ok(stalled.elapsedMs>=9500&&stalled.elapsedMs<12000);
 console.info(JSON.stringify({localActualSsh2:true,stalled}));
});
test('authority liveness wave: real SSH peer stall does not undercut the unchanged observation deadline',{timeout:40000},async()=>{
 assert.match(source,/keepaliveCountMax: 12/);assert.match(source,/OBSERVATION_TIMEOUT[\s\S]*10000/);
 const old=await exercise(source.replace('keepaliveCountMax: 12,','keepaliveCountMax: 2,'),4500);
 const current=await exercise(source,4500);
 assert.equal(old.outcome,'rejected');assert.equal(old.message,'CHANNEL_LOST');assert.ok(old.elapsedMs<10000);
 assert.equal(current.outcome,'response');assert.equal(current.response.boundedResponse,true);
 const silent=await exercise(source,11000);assert.equal(silent.outcome,'rejected');assert.ok(silent.elapsedMs>=9000&&silent.elapsedMs<12000,'the original 10s observation deadline still revokes authority');
 console.info(JSON.stringify({localActualSsh2:true,old,current,silent,clockChanged:false,leaseChanged:false}));
});
