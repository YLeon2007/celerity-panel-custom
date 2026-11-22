#!/bin/bash
# No panel entrypoint or host services. An explicit local mongod is mandatory.
set -euo pipefail
umask 077
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
root=$(git -C "$here" rev-parse --show-toplevel)
mode=${1:-public}
[[ $mode == graph || $mode == public ]] || { printf 'usage: %s [graph|public] [local source commit]\n' "$0" >&2; exit 2; }
[[ $# -le 2 ]]
# Never fetch missing objects, even if this is a partial clone.
export GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1
source_commit=$(git -C "$root" rev-parse --verify --end-of-options "${2:-HEAD}^{commit}")
: "${MONGOD:?set MONGOD to the existing local mongod fixture}"
: "${NODE_PATH:?set NODE_PATH to the existing local node_modules directory}"
[[ $MONGOD == /* && $NODE_PATH == /* && $NODE_PATH != *:* ]]
[[ -x $MONGOD && -d $NODE_PATH/mongoose && -d $NODE_PATH/express ]]
node=$(readlink -e -- "$(command -v node)")
ip=$(readlink -e -- "$(command -v ip)")
parent_netns=$(readlink /proc/self/ns/net)
stage=$(mktemp -d "${TMPDIR:-/tmp}/relay-retire-join.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/source" "$stage/source/scripts" "$stage/source/logs"
git -C "$root" archive "$source_commit" src views public/js/rebuild-relay-retire.js config.js package.json | tar -xf - -C "$stage/source"
# A committed controller overlay is just a different Git archive here. Only
# these runner-owned files come from the invoking checkout, no other live tree.
cp -- "$here/fixture.cjs" "$here/integration.cjs" "$here/online.cjs" "$stage/source/scripts/"
printf 'source_commit=%s mode=%s\n' "$source_commit" "$mode"
sha256sum -- "$stage/source/scripts/"*.cjs "$MONGOD" "$node"
# Only explicit local inputs and system libraries are visible. No host /etc,
# /run, /home, binaries for service managers, or inherited service settings.
/usr/bin/timeout --kill-after=5s 105s /usr/bin/bwrap \
    --unshare-all --unshare-user --disable-userns --new-session --die-with-parent --cap-drop ALL \
    --clearenv --setenv HOME /tmp --setenv TMPDIR /tmp --setenv PATH /tools \
    --setenv LC_ALL C --setenv TZ UTC --setenv DOTENV_CONFIG_PATH /dev/null --setenv OPENSSL_CONF /dev/null \
    --setenv NODE_PATH /deps --setenv PARENT_NETNS "$parent_netns" --setenv FIXTURE_MODE "$mode" \
    --setenv C3_REBUILD_ENABLED true --setenv C3_REBUILD_L2TP_INSTALL_ENABLED true \
    --setenv PANEL_DOMAIN fixture.invalid --setenv PANEL_IP_WHITELIST 127.0.0.1 \
    --setenv ACME_EMAIL fixture@fixture.invalid --setenv SESSION_SECRET synthetic-local-fixture \
    --setenv ENCRYPTION_KEY synthetic-local-fixture-32-bytes-only \
    --ro-bind /usr/lib /usr/lib --symlink usr/lib /lib \
    --ro-bind /usr/lib64 /usr/lib64 --symlink usr/lib64 /lib64 \
    --ro-bind "$node" /tools/node --ro-bind "$ip" /tools/ip \
    --ro-bind "$MONGOD" /tools/mongod --ro-bind "$NODE_PATH" /deps \
    --proc /proc --dev /dev --size 536870912 --tmpfs /tmp --dir /run \
    --ro-bind "$stage/source" /app --tmpfs /app/logs --chdir /tmp \
    -- /tools/node /app/scripts/fixture.cjs
