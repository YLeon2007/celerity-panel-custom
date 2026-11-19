'use strict';
const fail=code=>Object.assign(new Error(code),{code});
// A character node alone is not evidence of a registered driver. Do not open it
// here: opening a dormant major may autoload modules on the host kernel.
const readinessCommand=`set -eu
if test -c /dev/ppp && grep -Eq '^[[:space:]]*108[[:space:]]+ppp$' /proc/devices; then printf 'ppp=1\n'; else printf 'ppp=0\n'; fi
for u in xl2tpd.service strongswan-starter.service; do
  s=$(systemctl show --property=LoadState --value "$u") || exit 1
  case "$s" in loaded|masked|not-found) printf '%s=%s\n' "$u" "$s";; *) exit 1;; esac
done`;
async function checkRelayReadiness(ssh){
    const result=await ssh.exec(readinessCommand,{timeout:15000});
    const m=result?.code===0 && /^ppp=([01])\nxl2tpd\.service=(loaded|masked|not-found)\nstrongswan-starter\.service=(loaded|masked|not-found)\n?$/.exec(result.stdout);
    if(!m)throw fail('REBUILD_L2TP_PREFLIGHT_UNKNOWN');
    return {ppp:m[1]==='1', masked:m[2]==='masked'||m[3]==='masked', unitsLoaded:m[2]==='loaded'&&m[3]==='loaded'};
}
module.exports={checkRelayReadiness,readinessCommand};
