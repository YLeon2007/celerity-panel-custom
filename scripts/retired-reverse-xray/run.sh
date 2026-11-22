#!/bin/bash
set -euo pipefail

if [[ $# != 2 ]]; then
    printf 'Usage: %s /path/to/xray-26.11.9 /path/to/node_modules\n' "$0" >&2
    exit 2
fi
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../.." && pwd)
xray=$(realpath -e -- "$1")
deps=$(realpath -e -- "$2")
node=$(realpath -e -- "$(type -P node)")
python=$(realpath -e -- /usr/bin/python3)
ip=$(realpath -e -- /usr/sbin/ip)
[[ -x "$xray" && -d "$deps/yaml" ]] || { printf 'Missing offline Xray or Node dependencies\n' >&2; exit 2; }

# No host config, sockets, project writes, or inherited app/proxy environment.
# Only the fresh namespace's loopback is brought up by bubblewrap.
ulimit -c 0
exec /usr/bin/env -i PATH=/tools HOME=/tmp LC_ALL=C GOMAXPROCS=2 \
    PARENT_NETNS="$(readlink /proc/self/ns/net)" \
    /usr/bin/timeout -k 5s 65s /usr/bin/bwrap \
    --unshare-all --unshare-user --disable-userns --new-session --die-with-parent --cap-drop ALL \
    --ro-bind /usr/lib /usr/lib --symlink usr/lib /lib \
    --ro-bind /usr/lib64 /usr/lib64 --symlink usr/lib64 /lib64 \
    --dev /dev --proc /proc --tmpfs /tmp --chdir /tmp \
    --ro-bind "$root/src" /panel/src --ro-bind "$deps" /panel/node_modules \
    --ro-bind "$here/compose.cjs" /panel/compose.cjs --ro-bind "$here/verify.py" /panel/verify.py \
    --ro-bind "$xray" /tools/xray --ro-bind "$ip" /tools/ip \
    --ro-bind "$node" /tools/node --ro-bind "$python" /usr/bin/python3 \
    -- /usr/bin/python3 -IBS /panel/verify.py
