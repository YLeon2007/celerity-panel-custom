#!/bin/bash
set -euo pipefail
umask 077
usage() {
    printf 'Usage: %s --xray PATH --cover PATH [--root SOURCE] [--relay-xray PATH] [--bridge-xray PATH] [--mode reverse|mixed] [--without-preferred | --chain-probe | --scoped-proof | --scoped-matrix | --staged-matrix]\n' "$0"
    printf 'Set TMPDIR to a scratch directory for private evidence. The cover binary accepts: port cert key (loopback TLS 1.3/H2).\n'
}
scripts=$(realpath -e -- "$(dirname -- "$0")")
root=$scripts/../..
xray=
relay_xray=
bridge_xray=
cover=
mode=reverse
preferred=yes
chain=no
while (($#)); do
    case "$1" in
        --root|--xray|--relay-xray|--bridge-xray|--cover|--mode)
            (($# >= 2)) || { usage >&2; exit 2; }
            case "$1" in
                --root) root=$2;;
                --xray) xray=$2;;
                --relay-xray) relay_xray=$2;;
                --bridge-xray) bridge_xray=$2;;
                --cover) cover=$2;;
                --mode) mode=$2;;
            esac
            shift 2;;
        --without-preferred) preferred=no; shift;;
        --chain-probe) [[ $chain == no ]] || exit 2; chain=yes; shift;;
        --scoped-proof) [[ $chain == no ]] || exit 2; chain=proof; shift;;
        --scoped-matrix) [[ $chain == no ]] || exit 2; chain=matrix; shift;;
        --staged-matrix) [[ $chain == no ]] || exit 2; chain=stage; shift;;
        -h|--help) usage; exit;;
        *) usage >&2; exit 2;;
    esac
done
[[ -n $root && -n $xray && -n $cover && ($mode == reverse || $mode == mixed) ]] || { usage >&2; exit 2; }
[[ $chain == no || $preferred == yes ]] || { usage >&2; exit 2; }
[[ $chain != proof || -z $bridge_xray ]] || { usage >&2; exit 2; }
root=$(realpath -e -- "$root")
xray=$(realpath -e -- "$xray")
relay_xray=$(realpath -e -- "${relay_xray:-$xray}")
bridge_xray=$(realpath -e -- "${bridge_xray:-$xray}")
cover=$(realpath -e -- "$cover")
node=$(realpath -e -- "$(command -v node)")
deps=$(realpath -e -- "$root/node_modules")
[[ -f "$root/src/modules/relay-l2tp/services/rebuildTopologyComposer.js" && -d $deps && -x $xray && -x $relay_xray && -x $bridge_xray && -x $cover && -x $node ]]
work=$(mktemp -d -- "${TMPDIR:?Set TMPDIR to a scratch directory}/portal-exit-native.XXXXXXXX")
mkdir -m 700 -- "$work/home" "$work/tmp" "$work/assets"
printf 'Source: %s\nEvidence: %s\n' "$root" "$work"
parent_net=$(readlink /proc/self/ns/net)
# The only writable host mount is the per-run scratch directory. There is no
# host /etc, HOME or /run in the sandbox, and no inherited proxy/env settings.
exec /usr/bin/env -i PATH=/usr/bin:/usr/sbin /usr/bin/unshare -Urn --fork --kill-child=SIGKILL \
    /bin/sh -ec '
    /usr/sbin/ip link set dev lo up
    exec /usr/bin/bwrap --unshare-pid --die-with-parent --new-session \
        --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
        --symlink usr/bin /bin --symlink usr/sbin /sbin --dev /dev --proc /proc \
        --ro-bind "$1/src" /source/src --ro-bind "$1/package.json" /source/package.json \
        --ro-bind "$1/config.js" /source/config.js --ro-bind "$2" /source/node_modules \
        --ro-bind "$3" /tools/node --ro-bind "$4" /tools/xray --ro-bind "$5" /tools/bridge-xray \
        --ro-bind "${13}" /tools/relay-xray \
        --ro-bind "$6" /tools/cover --ro-bind "$7" /scripts --bind "$8" /work \
        --bind "$8/tmp" /tmp --chdir /work --clearenv --setenv PATH /tools:/usr/bin:/usr/sbin \
        --setenv HOME /work/home --setenv TMPDIR /work/tmp --setenv LC_ALL C \
        --setenv XRAY_LOCATION_ASSET /work/assets --setenv GODEBUG netdns=go \
        -- /usr/bin/python3 -I -B -u /scripts/probe.py "$9" "${10}" "${11}" "$1" "${12}"
' verify-portal-exits "$root" "$deps" "$node" "$xray" "$bridge_xray" "$cover" "$scripts" "$work" "$parent_net" "$mode" "$preferred" "$chain" "$relay_xray"
