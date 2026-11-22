'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const {mkdtempSync,writeFileSync,openSync,closeSync,rmSync}=require('node:fs');
const {tmpdir}=require('node:os');
const {join}=require('node:path');
const {createTransport}=require('../rebuildTransport');
const {MAIN,BRIDGE}=require('../classicAppliedConfig');
const {rebuildApplyMachineGuard}=require('./helpers/rebuildApplyMachineGuard');
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

test('bound shell commands check exact machine ID bytes before their effect and preserve stdin',async t=>{
    const machineId='0123456789abcdef'.repeat(2), payload='fixture payload\n';
    const dir=mkdtempSync(join(tmpdir(),'apply-machine-'));
    t.after(()=>rmSync(dir,{recursive:true,force:true}));
    const file=join(dir,'machine-id');
    const inputFile=join(dir,'stdin');
    writeFileSync(inputFile,payload);
    const runShell=(guard, path=file)=>{
        // Run the emitted prologue, not systemctl or the real file writes.
        assert.ok(guard?.includes(' -- /etc/machine-id '));
        const shell=guard.replace(' -- /etc/machine-id ', ' -- "$FIXTURE_MACHINE_ID" ');
        const fd=openSync(inputFile,'r');
        try {
            // A refusal may exit without consuming stdin. A file avoids a
            // pipe write race masking the host's checked refusal status.
            const result=spawnSync('/bin/sh',['-c',`${shell}printf 'effect\\n'; /bin/cat`],{
                env:{FIXTURE_MACHINE_ID:path},stdio:[fd,'pipe','pipe'],encoding:'utf8',timeout:2000,
            });
            assert.ifError(result.error);
            return {code:result.status,stdout:result.stdout,stderr:result.stderr};
        } finally {closeSync(fd);}
    };
    const seen=new Set();
    let sample;
    for(const [loaded,active] of [[true,true],[false,true],[true,false]]){
        let connects=0;
        const SSH=class {
            async connectDirectOnce(){connects++;}
            async exec(frame,options){
                if(frame==='/usr/bin/head -c 34 /etc/machine-id')return {code:0,stdout:`${machineId}\n`,stderr:''};
                for(const [unit,path] of [['xray',MAIN],['xray-bridge',BRIDGE]]){
                    if(frame===`systemctl show -p LoadState --value ${unit}.service`)return {code:0,stdout:unit==='xray'||loaded?'loaded':'not-found'};
                    if(frame===`systemctl show -p ExecStart --value ${unit}.service`)return {code:0,stdout:`path=/usr/local/bin/xray ; -config ${path} ;`};
                }
                const {preamble,command}=rebuildApplyMachineGuard(frame);
                assert.ok(preamble,'every bound shell mutation has its guard in the same exec');
                sample??=preamble;
                assert.equal(preamble,sample);
                const effect=command.includes('run -test -config')?'stage':command.includes('mv -fT')?'replace':
                    command.includes('daemon-reload')?'create-unit':command.startsWith('rm -f -- ')?'cleanup':command;
                seen.add(effect);
                assert.equal(typeof options.stdin,effect==='stage'||effect==='create-unit'?'string':'undefined');
                return {code:0,stdout:'',stderr:''};
            }
            disconnect(){}
        };
        const bound=createTransport({},SSH,{machineId,verify:async()=>{}});
        await bound.attest();
        const pair=['main','bridge'].map(profile=>({profile,config:{inbounds:profile==='bridge'&&active?[{}]:[],outbounds:[]}}));
        await bound.stagePair(pair);
        await bound.putPair();
        await bound.close();
        assert.equal(connects,1);
    }
    assert.deepEqual(seen,new Set(['stage','replace','create-unit','cleanup','systemctl stop xray-bridge.service',
        'systemctl enable xray.service && systemctl restart xray.service && systemctl is-active --quiet xray.service',
        'systemctl enable xray-bridge.service && systemctl restart xray-bridge.service && systemctl is-active --quiet xray-bridge.service',
        'systemctl disable xray-bridge.service']));
    for(const bytes of [machineId,`${machineId}\n`]){
        writeFileSync(file,bytes);
        assert.deepEqual(runShell(sample),{code:0,stdout:`effect\n${payload}`,stderr:''});
    }
    for(const bytes of ['', 'f'.repeat(32), `${machineId}\n\n`, `${machineId}\0`, `${machineId}\r\n`, `${machineId}\nextra`]){
        writeFileSync(file,bytes);
        assert.deepEqual(runShell(sample),{code:70,stdout:'',stderr:'REBUILD_APPLY_MACHINE_ID_MISMATCH\n'});
    }
    assert.deepEqual(runShell(sample,join(dir,'missing')),{code:70,stdout:'',stderr:'REBUILD_APPLY_MACHINE_ID_UNAVAILABLE\n'});
});
