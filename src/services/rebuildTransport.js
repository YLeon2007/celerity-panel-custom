'use strict';
const { createHash, randomUUID } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { MAIN, BRIDGE, readClassicProfile }=require('./classicAppliedConfig');
const {generateBridgeSystemdService}=require('./configGenerator');
const {READ_CHAIN,VERIFY_CHAIN}=require('./rebuildTunnelTls');
const {identityChanged,isIdentityChanged,isGrantAuthorityError}=require('./rebuildRelayEffectAuthority');
const {CONNECT_TIMEOUT_MS}=require('./rebuildSshLimits');
const {heldOptions}=require('./sshHeldExec');
const fail=code=>Object.assign(new Error(code),{code});
const profileBytes=config=>JSON.stringify(config);
const profileSha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const paths={main:MAIN,bridge:BRIDGE},services={main:'xray',bridge:'xray-bridge'};
const readMachineId='/usr/bin/head -c 34 /etc/machine-id';
const readArchitecture='/usr/bin/uname -m';
const proofArchitectures=new Map([['x86_64\n',['amd64',62]],['aarch64\n',['arm64',183]]]);
const proofs=new Map();

const applyActions={check:'check-apply-network',prepare:'prepare-apply-network',
    verify_before_restart:'verify-apply-network',publish:'publish-apply-profiles',
    restart:'restart-apply-network',verify_after_restart:'finalize-apply-profiles'};
const guardExit=70, machineUnavailable='REBUILD_APPLY_MACHINE_ID_UNAVAILABLE', machineMismatch='REBUILD_APPLY_MACHINE_ID_MISMATCH';
function guardMutation(machineId,command){
    // Read at most one byte past the longest accepted value. Encoding bytes
    // avoids shell command substitution silently dropping LF or NUL bytes.
    const expected=Buffer.from(machineId).toString('hex').replace(/../g,' $&');
    return `c3_machine_bytes=$(LC_ALL=C /usr/bin/od -An -v -N 34 -w34 -tx1 -- /etc/machine-id 2>/dev/null) || { printf '%s\\n' ${machineUnavailable} >&2; exit ${guardExit}; }; `+
        `case "$c3_machine_bytes" in '${expected}'|'${expected} 0a') ;; *) printf '%s\\n' ${machineMismatch} >&2; exit ${guardExit};; esac; ${command}`;
}
// All shell strings are fixed or constructed from locally generated constants.
// Profile contents (including REALITY private keys) are only passed via stdin.
function createTransport(node, SSH=require('./nodeSSH'), authority) {
    const ssh=new SSH(node,authority?.sshOptions), token=randomUUID(), staged=new Map();
    let connected=false, attemptedStage=false, attestationStarted=false, attested=false, closed=false;
    let execPinned, runtimeUnsafe=false, mainWindowUsed=false;
    // A pooled channel can reconnect between commands. A bound transport keeps
    // one direct client from machine-ID attestation through cleanup, with no replay.
    if(authority)ssh.usePool=false;
    const temp=profile=>`${paths[profile]}.rebuild-${token}.json`;
    async function attestMachine(){
        let result;
        try{result=await (authority.mainApply?execPinned(readMachineId,{timeout:10000,maxOutputBytes:34}):ssh.exec(readMachineId,{timeout:10000}));}
        catch{throw fail(authority.merged?'REBUILD_L2TP_SSH_CONNECT_FAILED':'REBUILD_L2TP_MACHINE_ID_MISMATCH');}
        if(result?.code!==0 || result.stderr!==''){
            throw fail(authority.merged?'REBUILD_L2TP_SSH_CONNECT_FAILED':'REBUILD_L2TP_MACHINE_ID_MISMATCH');
        }
        if(![authority.machineId,`${authority.machineId}\n`].includes(result.stdout)){
            throw authority.merged?identityChanged():fail('REBUILD_L2TP_MACHINE_ID_MISMATCH');
        }
    }
    async function attest(){
        if(closed||attestationStarted)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
        attestationStarted=true;
        await authority.verify();
        if(closed)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
        try{execPinned=await (authority.mainApply&&!authority.relay?ssh.connectApplyOnce(CONNECT_TIMEOUT_MS):ssh.connectDirectOnce(CONNECT_TIMEOUT_MS));}catch(error){
            if(authority.merged && error?.code==='SSH_HOST_KEY_MISMATCH')throw identityChanged();
            throw fail('REBUILD_L2TP_SSH_CONNECT_FAILED');
        }
        if(closed)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
        connected=true;
        await authority.verify();
        if(closed)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
        if(authority.machineId!=null)await attestMachine();
        await authority.verify();attested=true;
    }
    async function verifyIdentity(){
        await authority.verify();
        await attestMachine();
        await authority.verify();
    }
    async function openMainWindow(options){
        const live=()=>{
            if(closed||!connected||!attested||runtimeUnsafe||typeof execPinned?.openHeld!=='function'){
                throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
            }
        };
        live();
        if(mainWindowUsed)throw fail('REBUILD_MAIN_WINDOW_USED');
        const {timeout,maxFrameBytes,verifyOwner,verifyBeforeFrame,bootstrap}=options??{};
        if(typeof verifyOwner!=='function'||typeof verifyBeforeFrame!=='function')throw fail('REBUILD_MAIN_AUTHORITY_UNPROVED');
        const verify=async frame=>{
            live();
            let owned;
            try{owned=await verifyOwner();}catch{ /* A missing owner proof is a refusal. */ }
            if(owned!==true)throw fail('REBUILD_MAIN_AUTHORITY_UNPROVED');
            if(frame&&await verifyBeforeFrame()!==true)return false;
            live();
            await authority.verifyMainBinding();
            live();
            return true;
        };
        // Opening needs its own owner fence: the phase verifier may only be
        // usable once the caller has installed the returned channel.
        if(!bootstrap||bootstrap.machineId!==(authority.machineId??null))throw fail('REBUILD_MAIN_AUTHORITY_UNPROVED');
        heldOptions(readArchitecture,{timeout,maxFrameBytes,verifyBeforeFrame:()=>verify(true)});
        mainWindowUsed=true;
        await verify(false);
        const result=await execPinned(readArchitecture,{timeout:5000,maxOutputBytes:32});
        const target=result?.code===0&&result.stderr===''&&proofArchitectures.get(result.stdout);
        if(!target)throw fail('REBUILD_MAIN_AUTHORITY_UNPROVED');
        const [arch,machine]=target;
        let proof=proofs.get(arch);
        if(!proof){
            try{proof=readFileSync(join(__dirname,'../../libexec',`rebuild-main-proof-linux-${arch}`));}
            catch{throw fail('REBUILD_MAIN_AUTHORITY_UNPROVED');}
            if(proof.length<64||proof.length>16*1024*1024||proof.readUInt16LE(18)!==machine)throw fail('REBUILD_MAIN_AUTHORITY_UNPROVED');
            proofs.set(arch,proof);
        }
        const {command,preamble}=require('./rebuildRelayDirect').bundledMainReceiverCommand(bootstrap,proof);
        const limits=heldOptions(command,{timeout,maxFrameBytes,preamble,verifyBeforeFrame:()=>verify(true)});
        await verify(false);
        live();
        return execPinned.openHeld(command,limits);
    }
    async function run(command,options,write=false,onExec,execute){
        if(closed || runtimeUnsafe || authority && !attested)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
        if(authority){
            if(authority.merged && write)await verifyIdentity();
            else await authority.verify();
            if(closed||!connected)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
        }else if(!connected){await ssh.connect();connected=true;}
        onExec?.();
        return execute ? execute(command,options) : authority?.mainApply ? execPinned(command,options) : ssh.exec(command,options);
    }
    async function check(command,stdin,write=false) {
        const guarded=authority?.machineId!=null&&write;
        const result=await run(guarded?guardMutation(authority.machineId,command):command,{timeout:60000,...(stdin===undefined?{}:{stdin})},write);
        // This refusal only describes this command, not earlier Apply effects.
        if(guarded&&result?.code===guardExit&&result.stdout===''){
            if(result.stderr===`${machineMismatch}\n`)throw authority.merged?identityChanged():fail('REBUILD_L2TP_MACHINE_ID_MISMATCH');
            if(result.stderr===`${machineUnavailable}\n`)throw fail(authority.merged?'REBUILD_L2TP_SSH_CONNECT_FAILED':'REBUILD_L2TP_MACHINE_ID_MISMATCH');
        }
        if(result?.code!==0)throw fail('REBUILD_NODE_COMMAND_FAILED');return result.stdout;
    }
    async function read(profile,expectedMainSha256){
        if(!Object.hasOwn(paths,profile))throw fail('REBUILD_INVALID_PROFILE');
        return readClassicProfile({exec:async command=>{
            const result=await run(command,authority?{timeout:60000}:undefined);
            if(profile==='main'&&expectedMainSha256!==undefined&&result?.code===0&&
                (typeof result.stdout!=='string'||profileSha256(result.stdout)!==expectedMainSha256))throw fail('REBUILD_READBACK_MISMATCH');
            return result;
        }},paths[profile],{allowAbsent:profile==='bridge'});
    }
    async function readMainSha256(){
        const command=require('./rebuildRelayDirect').bundledMainFingerprintCommand();
        const result=await run(command,{timeout:7000,maxOutputBytes:65},false,undefined,authority?execPinned:undefined);
        if(result?.code!==0||result.stderr!==''||typeof result.stdout!=='string'||
            !/^[a-f0-9]{64}\n(?![\s\S])/.test(result.stdout))throw fail('REBUILD_MAIN_AUTHORITY_UNPROVED');
        if(authority)await authority.verify();
        return result.stdout.slice(0,64);
    }
    async function requireSupportedCoreIdentity(){
        // Probe the exact binary used by the checked units, not a cached DB
        // value or the agent's PATH. Do not include remote output in errors.
        let output;
        try {output=await check('/usr/local/bin/xray version');} catch(error) {
            if(isIdentityChanged(error)||isGrantAuthorityError(error))throw error;
            throw fail('REBUILD_XRAY_VERSION_UNKNOWN');
        }
        const match=typeof output==='string' && /^Xray (\d{1,4}\.\d{1,4}\.\d{1,4})(?=\s|$)/.exec(output);
        if(!match)throw fail('REBUILD_XRAY_VERSION_UNKNOWN');
        const version=match[1], [year,month,day]=version.split('.').map(Number);
        if(year<25 || year===25 && (month<9 || month===9 && day<11))throw fail('REBUILD_XRAY_VERSION_TOO_OLD');
        // Keep revision and build metadata from this same observation without
        // making the remote banner part of a public report or error.
        return {version,buildDigest:createHash('sha256').update(output).digest('hex')};
    }
    async function requireSupportedCore(){return (await requireSupportedCoreIdentity()).version;}
    async function stagePair(pair){
        for(const {profile,config} of pair){
            const path=paths[profile],file=temp(profile),dir=path.slice(0,path.lastIndexOf('/')),unit=services[profile];
            // Never replace a custom executable, config path or symlink silently.
            const state=(await check(`systemctl show -p LoadState --value ${unit}.service`)).trim();
            if(state!=='loaded' && !(profile==='bridge'&&state==='not-found'))throw fail('REBUILD_SERVICE_LAYOUT');
            if(state==='loaded'){
                const start=await check(`systemctl show -p ExecStart --value ${unit}.service`);
                if(!start.includes('path=/usr/local/bin/xray ;') || !start.includes(` -config ${path} ;`))throw fail('REBUILD_SERVICE_LAYOUT');
            }
            const active=profile==='main'||config.inbounds.length>0||config.outbounds.some(o=>o.protocol==='vless' && o.settings?.reverse?.tag);
            attemptedStage=true;
            const bytes=profileBytes(config);
            await check(`set -eu; umask 077; test ! -L ${dir}; test ! -L ${path}; if ! test -d ${dir}; then install -d -m 0755 ${dir}; fi; (set -C; cat > ${file}); /usr/local/bin/xray run -test -config ${file} >/dev/null 2>&1`,bytes,true);
            staged.set(profile,{active,state,sha256:profileSha256(bytes)});
        }
    }
    let networkProof;
    // DIRECT checks the machine ID within its own command under its host flock.
    async function relayNetwork(phase,proof,{readOnly=false,reattestRuntime=false,publication}={}){
        let failureClass='local_check';
        const observePinned=phase==='check'&&typeof execPinned==='function' ? execPinned : undefined;
        const observe=async(cmd,options)=>{
            const result=await run(cmd,options,['prepare','publish','restart','verify_after_restart'].includes(phase),()=>{failureClass='ssh_no_reply';},observePinned);
            // Record only what the caller observed, not a guess about host writes.
            // A clean exit still needs the existing DIRECT decoder's exact receipt.
            const status=result?.code;
            if(!Number.isInteger(status))failureClass='missing_exit_status';
            else if(status===70)failureClass='unrecognized_exit_70';
            else if(status===75)failureClass='remote_exit_75';
            else failureClass=status===0?'invalid_reply':'other_nonzero_exit';
            return result;
        };
        // Read-only probes default to no writes. The fenced panel Preview
        // may opt into this one metadata repair, never activation writes.
        const runtime=observePinned&&(!readOnly||reattestRuntime===true) ? {
            nodeId: String(node._id??''),
            async run(command,options){
                // This is a metadata write, not a second read. Requalify the
                // held lock and machine, and gate stdin on that same client.
                const verify=async()=>{
                    if(closed||!attested||runtimeUnsafe)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
                    if(await authority.verify()===false)throw fail('REBUILD_LOCK_LOST');
                    if(closed||runtimeUnsafe)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
                };
                failureClass='local_check';
                await verify();
                let observed;
                try{observed=await observePinned(readMachineId,{timeout:5000,maxOutputBytes:34});}
                catch{throw fail('REBUILD_L2TP_SSH_CONNECT_FAILED');}
                if(observed?.code!==0||observed.stderr!==''||typeof observed.stdout!=='string'
                    || !/^[a-f0-9]{32}\n?(?![\s\S])/.test(observed.stdout))throw fail('REBUILD_L2TP_SSH_CONNECT_FAILED');
                if(observed.stdout!==authority.machineId&&observed.stdout!==`${authority.machineId}\n`)throw identityChanged();
                await verify();
                const uncertain=()=>Object.assign(fail('REBUILD_L2TP_APPLY_NETWORK_OUTCOME_UNKNOWN'),{remoteOutcomeUncertain:true});
                let veto;
                failureClass='ssh_no_reply';
                let result;
                try{
                    result=await observePinned(command,options,async()=>{
                        try{await verify();}
                        catch(error){veto={error};throw error;}
                    });
                }catch(error){
                    if(veto)throw veto.error;
                    if(SSH.execStdinWasNotAttempted?.(error))throw fail('REBUILD_L2TP_SSH_CONNECT_FAILED');
                    throw uncertain();
                }
                try{await verify();}catch(error){if(isIdentityChanged(error))throw error;throw uncertain();}
                failureClass=result?.code===70?'unrecognized_exit_70':'invalid_reply';
                return result;
            },
        } : undefined;
        try {
            return await require('./rebuildRelayDirect').applyRelayNetwork(observe,authority.machineId,
                authority.installation,applyActions[phase],proof,authority.merged,runtime,publication);
        } catch(error) {
            if(runtime&&(error?.remoteOutcomeUncertain||isIdentityChanged(error)))runtimeUnsafe=true;
            // Only the existing decoder can confirm a refusal. A guard error or an
            // unframed exit 70 cannot vouch for it, nor for any earlier Apply step.
            if(failureClass==='unrecognized_exit_70' && (['REBUILD_L2TP_APPLY_NETWORK_REFUSED',
                'REBUILD_L2TP_APPLY_BRIDGE_PLACEHOLDER_UNPROVED'].includes(error?.code)||isIdentityChanged(error)))failureClass='direct_refusal';
            try { require('../utils/logger').warn(JSON.stringify({event:'rebuild.apply_network.failure',phase,failureClass})); }
            catch { /* Logging must never replace the original outcome. */ }
            throw error;
        }
    }
    async function prepareActivation(){
        networkProof=await relayNetwork('prepare');
    }
    async function putPair(){
        if(staged.size!==2)throw fail('REBUILD_PAIR_NOT_STAGED');
        if(authority?.installation){
            if(!networkProof)throw fail('REBUILD_L2TP_APPLY_NETWORK_REFUSED');
            await relayNetwork('verify_before_restart',networkProof);
            networkProof=await relayNetwork('publish',networkProof,{publication:{nodeId:String(node._id),stageId:token,
                profiles:Object.fromEntries(['main','bridge'].map(key=>[key,staged.get(key).sha256])),
                bridgeUnit:generateBridgeSystemdService()}});
        }
        // Release the previous socket owner before moving any listener between
        // services; enable both effective profiles for a normal unattended boot.
        const side=staged.get('bridge');
        if(side.state==='loaded')await check('systemctl stop xray-bridge.service',undefined,true);
        for(const profile of authority?.installation ? [] : ['bridge','main']){
            const path=paths[profile], f=temp(profile);
            // Keep an existing profile's service readability and privileges;
            // classic freshly provisioned bridge units run as nobody.
            await check(`set -eu; if test -f ${path}; then chown --reference=${path} ${f}; chmod --reference=${path} ${f}; else chown root:$(id -gn nobody) ${f}; chmod 0640 ${f}; fi; mv -fT ${f} ${path}`,undefined,true);
        }
        if(side.active && side.state==='not-found'){
            if(authority?.installation)await check('systemctl daemon-reload',undefined,true);
            else {
                const unit='/etc/systemd/system/xray-bridge.service';
                await check(`set -eu; test ! -e ${unit}; test ! -L ${unit}; (umask 022; set -C; cat > ${unit}); systemctl daemon-reload`,generateBridgeSystemdService(),true);
            }
        }
        if(authority?.installation){
            await check('systemctl enable xray.service',undefined,true);
            await relayNetwork('restart',networkProof);
        }else await check('systemctl enable xray.service && systemctl restart xray.service && systemctl is-active --quiet xray.service',undefined,true);
        if(side.active)await check('systemctl enable xray-bridge.service && systemctl restart xray-bridge.service && systemctl is-active --quiet xray-bridge.service',undefined,true);
        else if(side.state==='loaded') await check('systemctl disable xray-bridge.service',undefined,true);
        if(authority?.installation)await relayNetwork('verify_after_restart',networkProof);
    }
    async function checkMainRoutingService(config){
        const api=config?.inbounds?.filter(row=>row.tag==='API_INBOUND');
        const port=api?.length===1&&api[0].listen==='127.0.0.1'&&api[0].protocol==='dokodemo-door'&&api[0].port;
        const first=config?.routing?.rules?.[0];
        if(!Number.isInteger(port)||port<1||port>65535||!config.api?.services?.includes('RoutingService')||
            !config.api.tag||first?.outboundTag!==config.api.tag||first.type!=='field'||
            first.inboundTag?.length!==1||first.inboundTag[0]!=='API_INBOUND')return false;
        const result=await run(`/usr/local/bin/xray api lsrules --server=127.0.0.1:${port} --timeout=3`,{timeout:5000});
        if(result?.code!==0||result.stderr!=='')return false;
        try {
            const reply=JSON.parse(result.stdout);
            // Both supported cores return {} when there are no tagged rules.
            return !!reply&&Object.getPrototypeOf(reply)===Object.prototype&&
                (Object.keys(reply).length===0||Array.isArray(reply.rules));
        } catch {return false;}
    }
    async function close(){
        if(closed)return;
        try{if(connected&&attemptedStage)await check(`rm -f -- ${temp('main')} ${temp('bridge')}`,undefined,true);}
        finally{closed=true;if(connected||attestationStarted)ssh.disconnect();}
    }
    return {read,readMainSha256,requireSupportedCore,requireSupportedCoreIdentity,stagePair,putPair,close,checkMainRoutingService,
        ...(authority&&{attest}),
        ...(authority?.verifyMainBinding&&{openMainWindow}),
        ...(authority?.mainApply&&{async verifyMainConnection(){
            if(closed||!attested||runtimeUnsafe)throw fail('REBUILD_MAIN_AUTHORITY_UNPROVED');
            await authority.verifyMainBinding();
            if(closed||execPinned?.verifyConnection?.()!==true)throw fail('REBUILD_MAIN_AUTHORITY_UNPROVED');
            return true;
        }, observeMain:command=>run(command,{timeout:12000,maxOutputBytes:65536})}),
        ...(authority?.merged&&{verifyIdentity}),
        ...(authority?.installation&&{checkActivation:options=>relayNetwork('check',undefined,options),prepareActivation}),
        readTunnelCertificate:()=>check(READ_CHAIN),verifyTunnelCertificate:input=>check(VERIFY_CHAIN,input)};
}

function createBoundRelayTransport(node,fence,verifyLock,installation,verifyBinding=()=>fence.check(),mainApply=false){
    const {nodeId,host:ip,port,username,sshHostKeySha256,machineId}=fence.binding;
    // Same binding as DIRECT. In list mode, use the operator endpoint and
    // take only authentication material from the corroborating card.
    const target={_id:nodeId,name:nodeId,ip,ssh:{port,username,password:node.ssh.password,privateKey:node.ssh.privateKey}};
    const revalidate=async()=>{if(await verifyLock()===false)throw fail('REBUILD_LOCK_LOST');return verifyBinding();};
    return createTransport(target,undefined,{machineId,installation,merged:fence.merged,mainApply,relay:true,sshOptions:{expectedHostKeySha256:sshHostKeySha256,
        expectedEndpoint:{ip,port,username}},async verify(){await revalidate();},async verifyMainBinding(){
        if(await revalidate()===false)throw fence.merged?identityChanged():fail('REBUILD_L2TP_BINDING_MISMATCH');
    }});
}
function createMainApplyTransport(node,{machineId,sshHostKeySha256},verify){
    const {ip}=node, port=node.ssh?.port||22, username=node.ssh?.username||'root';
    const target={...node,ssh:{...node.ssh,port,username}};
    const sshOptions=sshHostKeySha256===null?undefined:{expectedHostKeySha256:sshHostKeySha256,expectedEndpoint:{ip,port,username}};
    return createTransport(target,undefined,{mainApply:true,machineId,sshOptions,verify,verifyMainBinding:verify});
}
module.exports={createTransport,createBoundRelayTransport,createMainApplyTransport,profileBytes,profileSha256};
