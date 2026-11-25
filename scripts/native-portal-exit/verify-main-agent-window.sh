#!/usr/bin/env bash
# Native children in a loopback-only sandbox. The service manager is modeled;
# this runner never invokes systemctl, journalctl, a package manager, or SSH.
set -eu
if [ "$#" -ne 2 ]; then
    printf 'Usage: bash %s XRAY_26.3.27 XRAY_26.11.9\n' "$0" >&2
    exit 2
fi
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
go=$(command -v go)
out=$(mktemp -d "${TMPDIR:?}/c3-1642-main-agent-window.XXXXXXXX")
printf 'Evidence: %s\n' "$out"
git -C "$root" archive HEAD cc-agent | tar -x -C "$out"
modules=$(GOTOOLCHAIN=local "$go" env GOMODCACHE)
cache=$(GOTOOLCHAIN=local "$go" env GOCACHE)
env -i PATH="$PATH" HOME="$out" TMPDIR="$out" GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
    GOWORK=off GOENV=off GOMODCACHE="$modules" GOCACHE="$cache" GOMAXPROCS=2 CGO_ENABLED=0 \
    unshare -Urn --fork --kill-child=SIGKILL "$go" -C "$out/cc-agent" build -mod=readonly -p 2 -o "$out/agent" .
parent=$(readlink /proc/self/ns/net)
layout=old
for core in "$@"; do
    core=$(realpath -e -- "$core")
    for mode in full timeout; do
        work="$out/$layout-$mode"
        mkdir -m 0700 -- "$work"
        if ! env -i PATH=/usr/bin:/usr/sbin unshare -Urn --fork --kill-child=SIGKILL /bin/sh -ec '
            ip link set lo up
            work=$1 core=$2 agent=$3 src=$4 parent=$5
            shift 5
            if [ "$1" = full ]; then shift; fi
            exec bwrap --unshare-pid --die-with-parent --new-session \
                --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin \
                --dev /dev --proc /proc --bind "$work" /work --tmpfs /usr/local \
                --dir /etc/cc-agent --dir /usr/local/etc/xray --ro-bind "$agent" /usr/local/bin/cc-agent \
                --ro-bind "$core" /tools/xray --symlink /tools/xray /usr/local/bin/xray \
                --ro-bind "$src/rebuildTransitMainWindow.py" /src/services/rebuildTransitMainWindow.py \
                --ro-bind "$src/tests/rebuildTransitMainWindowHost.py" /src/services/tests/rebuildTransitMainWindowHost.py \
                --ro-bind "$src/tests/rebuildTransitMainWindowNative.py" /src/services/tests/rebuildTransitMainWindowNative.py \
                --clearenv --setenv PATH /tools:/usr/bin --setenv HOME /work --setenv TMPDIR /work \
                --setenv C3_CUTOVER_PARENT_NETNS "$parent" --chdir /work -- \
                /usr/bin/timeout -k 3 85 /usr/bin/python3 -B /src/services/tests/rebuildTransitMainWindowNative.py "$@"
        ' fixture "$work" "$core" "$out/agent" "$root/src/services" "$parent" "$mode" > "$work.log" 2>&1; then
            printf 'FAIL %s\n' "$work.log"
            exit 1
        fi
        printf 'PASS %s\n' "$work.log"
    done
    layout=new
done
