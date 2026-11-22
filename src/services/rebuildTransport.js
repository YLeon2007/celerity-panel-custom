'use strict';
const { createHash, randomUUID } = require('node:crypto');
const { MAIN, BRIDGE, readClassicProfile }=require('./classicAppliedConfig');
const {generateBridgeSystemdService}=require('./configGenerator');
const {READ_CHAIN,VERIFY_CHAIN}=require('./rebuildTunnelTls');
const {identityChanged,isIdentityChanged,isGrantAuthorityError}=require('./rebuildRelayEffectAuthority');
const {CONNECT_TIMEOUT_MS}=require('./rebuildSshLimits');
const fail=code=>Object.assign(new Error(code),{code});
const paths={main:MAIN,bridge:BRIDGE},services={main:'xray',bridge:'xray-bridge'};
const readMachineId='/usr/bin/head -c 34 /etc/machine-id';
// All shell strings are fixed or constructed from locally generated constants.
// Profile contents (including REALITY private keys) are only passed via stdin.
function createTransport(node, SSH=require('./nodeSSH'), authority) {
    const ssh=new SSH(node,authority?.sshOptions), token=randomUUID(), staged=new Map();
    let connected=false, attemptedStage=false, attestationStarted=false, attested=false, closed=false;
    // A pooled channel can reconnect between commands. A bound transport keeps
    // one direct client from machine-ID attestation through cleanup, with no replay.
    if(authority)ssh.usePool=false;
    const temp=profile=>`${paths[profile]}.rebuild-${token}.json`;
    async function attestMachine(){
        let result;
        try{result=await ssh.exec(readMachineId,{timeout:10000});}
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
        try{await ssh.connectDirectOnce(CONNECT_TIMEOUT_MS);}catch(error){
            if(authority.merged && error?.code==='SSH_HOST_KEY_MISMATCH')throw identityChanged();
            throw fail('REBUILD_L2TP_SSH_CONNECT_FAILED');
        }
        if(closed)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
        connected=true;
        await authority.verify();
        if(closed)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
        await attestMachine();
        await authority.verify();attested=true;
    }
    async function verifyIdentity(){
        await authority.verify();
        await attestMachine();
        await authority.verify();
    }
    async function run(command,options,write=false){
        if(closed || authority && !attested)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
        if(authority){
            if(authority.merged && write)await verifyIdentity();
            else await authority.verify();
            if(closed||!connected)throw fail('REBUILD_L2TP_TRANSPORT_NOT_ATTESTED');
        }else if(!connected){await ssh.connect();connected=true;}
        return ssh.exec(command,options);
    }
    async function check(command,stdin,write=false) {
        const result=await run(command,{timeout:60000,...(stdin===undefined?{}:{stdin})},write);
        if(result?.code!==0)throw fail('REBUILD_NODE_COMMAND_FAILED');return result.stdout;
    }
    async function read(profile){
        if(!Object.hasOwn(paths,profile))throw fail('REBUILD_INVALID_PROFILE');
        return readClassicProfile({exec:command=>run(command,authority?{timeout:60000}:undefined)},paths[profile],{allowAbsent:profile==='bridge'});
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
            await check(`set -eu; umask 077; test ! -L ${dir}; test ! -L ${path}; if ! test -d ${dir}; then install -d -m 0755 ${dir}; fi; (set -C; cat > ${file}); /usr/local/bin/xray run -test -config ${file} >/dev/null 2>&1`,JSON.stringify(config),true);
            staged.set(profile,{active,state});
        }
    }
    let networkProof;
    const relayNetwork=(action,proof)=>require('./rebuildRelayDirect').applyRelayNetwork(
        (cmd,options)=>run(cmd,options,['prepare-apply-network','restart-apply-network'].includes(action)),
        authority.machineId,authority.installation,action,proof,authority.merged);
    async function prepareActivation(){
        networkProof=await relayNetwork('prepare-apply-network');
    }
    async function putPair(){
        if(staged.size!==2)throw fail('REBUILD_PAIR_NOT_STAGED');
        if(authority?.installation){
            if(!networkProof)throw fail('REBUILD_L2TP_APPLY_NETWORK_REFUSED');
            await relayNetwork('verify-apply-network',networkProof);
        }
        // Release the previous socket owner before moving any listener between
        // services; enable both effective profiles for a normal unattended boot.
        const side=staged.get('bridge');
        if(side.state==='loaded')await check('systemctl stop xray-bridge.service',undefined,true);
        for(const profile of ['bridge','main']){
            const path=paths[profile], f=temp(profile);
            // Keep an existing profile's service readability and privileges;
            // classic freshly provisioned bridge units run as nobody.
            await check(`set -eu; if test -f ${path}; then chown --reference=${path} ${f}; chmod --reference=${path} ${f}; else chown root:$(id -gn nobody) ${f}; chmod 0640 ${f}; fi; mv -fT ${f} ${path}`,undefined,true);
        }
        if(side.active && side.state==='not-found'){
            const unit='/etc/systemd/system/xray-bridge.service';
            await check(`set -eu; test ! -e ${unit}; test ! -L ${unit}; (umask 022; set -C; cat > ${unit}); systemctl daemon-reload`,generateBridgeSystemdService(),true);
        }
        if(authority?.installation){
            await check('systemctl enable xray.service',undefined,true);
            await relayNetwork('restart-apply-network',networkProof);
        }else await check('systemctl enable xray.service && systemctl restart xray.service && systemctl is-active --quiet xray.service',undefined,true);
        if(side.active)await check('systemctl enable xray-bridge.service && systemctl restart xray-bridge.service && systemctl is-active --quiet xray-bridge.service',undefined,true);
        else if(side.state==='loaded') await check('systemctl disable xray-bridge.service',undefined,true);
        if(authority?.installation)await relayNetwork('verify-apply-network',networkProof);
    }
    async function close(){
        if(closed)return;
        try{if(connected&&attemptedStage)await check(`rm -f -- ${temp('main')} ${temp('bridge')}`,undefined,true);}
        finally{closed=true;if(connected||attestationStarted)ssh.disconnect();}
    }
    return {read,requireSupportedCore,requireSupportedCoreIdentity,stagePair,putPair,close,
        ...(authority&&{attest}),
        ...(authority?.merged&&{verifyIdentity}),
        ...(authority?.installation&&{checkActivation:()=>relayNetwork('check-apply-network'),prepareActivation}),
        readTunnelCertificate:()=>check(READ_CHAIN),verifyTunnelCertificate:input=>check(VERIFY_CHAIN,input)};
}

function createBoundRelayTransport(node,fence,verifyLock,installation,verifyBinding=()=>fence.check()){
    const {nodeId,host:ip,port,username,sshHostKeySha256,machineId}=fence.binding;
    // Same binding as DIRECT. In list mode, use the operator endpoint and
    // take only authentication material from the corroborating card.
    const target={_id:nodeId,name:nodeId,ip,ssh:{port,username,password:node.ssh.password,privateKey:node.ssh.privateKey}};
    return createTransport(target,undefined,{machineId,installation,merged:fence.merged,sshOptions:{expectedHostKeySha256:sshHostKeySha256,
        expectedEndpoint:{ip,port,username}},async verify(){await verifyLock();await verifyBinding();}});
}
module.exports={createTransport,createBoundRelayTransport};
