'use strict';
const { randomUUID } = require('node:crypto');
const { MAIN, BRIDGE, readClassicProfile }=require('./classicAppliedConfig');
const {generateBridgeSystemdService}=require('./configGenerator');
const {READ_CHAIN,VERIFY_CHAIN}=require('./rebuildTunnelTls');
const fail=code=>Object.assign(new Error(code),{code});
const paths={main:MAIN,bridge:BRIDGE},services={main:'xray',bridge:'xray-bridge'};
// All shell strings are fixed or constructed from locally generated constants.
// Profile contents (including REALITY private keys) are only passed via stdin.
function createTransport(node, SSH=require('./nodeSSH')) {
    const ssh=new SSH(node), token=randomUUID(), staged=new Map();let connected=false, attemptedStage=false;
    const temp=profile=>`${paths[profile]}.rebuild-${token}.json`;
    async function check(command,stdin) {
        if(!connected){await ssh.connect();connected=true;}
        const result=await ssh.exec(command,{timeout:60000,...(stdin===undefined?{}:{stdin})});
        if(result?.code!==0)throw fail('REBUILD_NODE_COMMAND_FAILED');return result.stdout;
    }
    async function read(profile){if(!Object.hasOwn(paths,profile))throw fail('REBUILD_INVALID_PROFILE');if(!connected){await ssh.connect();connected=true;}return readClassicProfile(ssh,paths[profile],{allowAbsent:profile==='bridge'});}
    async function requireSupportedCore(){
        // Probe the exact binary used by the checked units, not a cached DB
        // value or the agent's PATH. Do not include remote output in errors.
        let output;
        try {output=await check('/usr/local/bin/xray version');} catch {throw fail('REBUILD_XRAY_VERSION_UNKNOWN');}
        const match=/^Xray (\d{1,4})\.(\d{1,4})\.(\d{1,4})(?=\s|$)/.exec(String(output));
        if(!match)throw fail('REBUILD_XRAY_VERSION_UNKNOWN');
        const [year,month,day]=match.slice(1).map(Number);
        if(year<25 || year===25 && (month<9 || month===9 && day<11))throw fail('REBUILD_XRAY_VERSION_TOO_OLD');
    }
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
            await check(`set -eu; umask 077; test ! -L ${dir}; test ! -L ${path}; if ! test -d ${dir}; then install -d -m 0755 ${dir}; fi; (set -C; cat > ${file}); /usr/local/bin/xray run -test -config ${file} >/dev/null 2>&1`,JSON.stringify(config));
            staged.set(profile,{active,state});
        }
    }
    async function putPair(){
        if(staged.size!==2)throw fail('REBUILD_PAIR_NOT_STAGED');
        // Release the previous socket owner before moving any listener between
        // services; enable both effective profiles for a normal unattended boot.
        const side=staged.get('bridge');
        if(side.state==='loaded')await check('systemctl stop xray-bridge.service');
        for(const profile of ['bridge','main']){
            const path=paths[profile], f=temp(profile);
            // Keep an existing profile's service readability and privileges;
            // classic freshly provisioned bridge units run as nobody.
            await check(`set -eu; if test -f ${path}; then chown --reference=${path} ${f}; chmod --reference=${path} ${f}; else chown root:$(id -gn nobody) ${f}; chmod 0640 ${f}; fi; mv -fT ${f} ${path}`);
        }
        if(side.active && side.state==='not-found'){
            const unit='/etc/systemd/system/xray-bridge.service';
            await check(`set -eu; test ! -e ${unit}; test ! -L ${unit}; (umask 022; set -C; cat > ${unit}); systemctl daemon-reload`,generateBridgeSystemdService());
        }
        await check('systemctl enable xray.service && systemctl restart xray.service && systemctl is-active --quiet xray.service');
        if(side.active)await check('systemctl enable xray-bridge.service && systemctl restart xray-bridge.service && systemctl is-active --quiet xray-bridge.service');
        else if(side.state==='loaded') await check('systemctl disable xray-bridge.service');
    }
    async function close(){if(connected){try{if(attemptedStage)await check(`rm -f -- ${temp('main')} ${temp('bridge')}`);}finally{ssh.disconnect();}}}
    return {read,requireSupportedCore,stagePair,putPair,close,
        readTunnelCertificate:()=>check(READ_CHAIN),verifyTunnelCertificate:input=>check(VERIFY_CHAIN,input)};
}
module.exports={createTransport};
