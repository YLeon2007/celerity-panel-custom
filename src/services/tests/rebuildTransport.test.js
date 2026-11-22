'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const {createTransport}=require('../rebuildTransport');
function fake(run){return class {async connect(){} disconnect(){} async exec(cmd,opts){return run(cmd,opts);}};}
test('version floor uses the exact unit binary and returns only its numeric triplet',async()=>{
    for(const [stdout,code,expected] of [['Xray 25.9.10 (fixture)',0,'REBUILD_XRAY_VERSION_TOO_OLD'],['Xray 25.8.30',0,'REBUILD_XRAY_VERSION_TOO_OLD'],['not a version',0,'REBUILD_XRAY_VERSION_UNKNOWN'],['Xray 26.11.9-custom',0,'REBUILD_XRAY_VERSION_UNKNOWN'],['Xray 26.11.9',1,'REBUILD_XRAY_VERSION_UNKNOWN'],['Xray 25.9.11 (fixture)',0,'25.9.11'],['Xray 26.11.9 (Xray, Penetrates Everything.) 676eaf6 (go1.27.3 linux/amd64)\nA unified platform for anti-censorship.\n',0,'26.11.9']]){
        const seen=[];const t=createTransport({},fake(async cmd=>{seen.push(cmd);return {code,stdout};}));
        try {if(expected.startsWith('REBUILD_')) await assert.rejects(t.requireSupportedCore(),{code:expected});
            else assert.equal(await t.requireSupportedCore(),expected);}
        finally{await t.close();}
        assert.deepEqual(seen,['/usr/local/bin/xray version']);
    }
});
test('core attestations use one fresh read-only probe each and never return the raw build banner',async()=>{
    let build='676eaf6';const seen=[];
    const t=createTransport({},fake(async(cmd,opts)=>{seen.push(cmd);assert.equal(opts.stdin,undefined);
        return {code:0,stdout:`Xray 26.11.9 (Xray, Penetrates Everything.) ${build} (go1.27.3 linux/amd64)\n`};}));
    try {
        const first=await t.requireSupportedCoreIdentity();
        assert.deepEqual(Object.keys(first).sort(),['buildDigest','version']);
        assert.match(first.buildDigest,/^[a-f0-9]{64}$/);
        assert.equal(first.version,'26.11.9');
        build='ffffffa';
        const second=await t.requireSupportedCoreIdentity();
        assert.equal(second.version,first.version);
        assert.notEqual(second.buildDigest,first.buildDigest);
        assert.deepEqual(await t.requireSupportedCoreIdentity(),second);
    } finally {await t.close();}
    assert.deepEqual(seen,Array(3).fill('/usr/local/bin/xray version'));
});
test('listenerless native bridge is enabled; parser failure cannot stop or restart any unit',async()=>{
    for(const broken of [true,false]){
        const ops=[];let parsed=0;
        const t=createTransport({},fake(async(cmd,opts)=>{ops.push(cmd);let stdout='',code=0;
            if(cmd.includes('LoadState'))stdout=cmd.includes('xray-bridge')?'not-found':'loaded';
            if(cmd.includes('ExecStart'))stdout='path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json ;';
            if(cmd.includes(' run -test -config ')){parsed++;assert.ok(opts.stdin);if(broken && parsed===2)code=1;}
            return {stdout,code};}));
        const pair=['main','bridge'].map(profile=>({profile,config:{inbounds:[],outbounds:profile==='bridge'?[{protocol:'vless',settings:{reverse:{tag:'fixture'}}}]:[]}}));
        try {if(broken){await assert.rejects(t.stagePair(pair),{code:'REBUILD_NODE_COMMAND_FAILED'});await assert.rejects(t.putPair(),{code:'REBUILD_PAIR_NOT_STAGED'});}else{await t.stagePair(pair);await t.putPair();}}
        finally{await t.close();}
        assert.equal(parsed,2);assert.equal(ops.some(cmd=>cmd.includes('restart xray-bridge.service')), !broken);
        if(broken) assert.ok(!ops.some(cmd=>/systemctl (?:stop|restart|enable|disable)|mv -fT/.test(cmd)));
    }
});
