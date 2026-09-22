#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
PACKAGE_SOURCE="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp"
TMP_DIR="$(mktemp -d)"
TEST_ROOT="$TMP_DIR/root"
PACKAGE="$TMP_DIR/package"
LIB_DIR="$TEST_ROOT/usr/local/lib/celerity/relay-l2tp"
RUNNER_LINK="$TEST_ROOT/usr/local/bin/celerity-l2tp-artifact-runner"
RECEIVER_LINK="$TEST_ROOT/usr/local/bin/celerity-l2tp-artifact-receiver"
trap 'rm -rf "$TMP_DIR"' EXIT

readonly -a PAYLOADS=(
    runner.sh
    receive-artifact.py
    apply.sh
    preflight.sh
    backup.sh
    compose-xray-fragment.sh
    validate-xray.sh
    validate-nft.sh
    activate-xray.sh
    apply-firewall-policy.sh
    start-l2tp.sh
    sync-users.sh
    verify.sh
    commit.sh
    rollback.sh
    install-runtime.sh
)

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

mkdir -p "$TEST_ROOT" "$PACKAGE"
chmod 0755 "$TEST_ROOT"
cp -a "$PACKAGE_SOURCE/." "$PACKAGE/"
chmod 0755 "$PACKAGE" "$PACKAGE"/*.sh "$PACKAGE/receive-artifact.py"

output="$TMP_DIR/install.out"
status=0
set +e
/usr/bin/bwrap \
    --unshare-user --uid 0 --gid 0 \
    --unshare-pid \
    --ro-bind / / \
    --bind "$TEST_ROOT" "$TEST_ROOT" \
    --dev /dev \
    --proc /proc \
    /usr/bin/env CELERITY_L2TP_ROOT="$TEST_ROOT" "$PACKAGE/install.sh" >"$output" 2>&1
status=$?
set -e
[[ "$status" -eq 0 ]] || fail "complete artifact installation into the test root failed: $(<"$output")"
[[ "$(<"$output")" == '{"status":"ok"}' ]] || fail 'installer returned unexpected output'

for payload in "${PAYLOADS[@]}"; do
    [[ -f "$LIB_DIR/$payload" && ! -L "$LIB_DIR/$payload" ]] \
        || fail "$payload was not installed as a regular library payload"
done
[[ "$(find "$LIB_DIR" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)" == \
   "$(printf '%s\n' "${PAYLOADS[@]}" | sort)" ]] \
    || fail 'installed library payload set was not exact'

[[ -L "$RUNNER_LINK" ]] || fail 'runner fixed path is not a link'
[[ "$(readlink "$RUNNER_LINK")" == '../lib/celerity/relay-l2tp/runner.sh' ]] \
    || fail 'runner fixed path does not target the module library'
[[ -L "$RECEIVER_LINK" ]] || fail 'receiver fixed path is not a link'
[[ "$(readlink "$RECEIVER_LINK")" == '../lib/celerity/relay-l2tp/receive-artifact.py' ]] \
    || fail 'receiver fixed path does not target the module library'

mapfile -t metadata < <(
    /usr/bin/bwrap \
        --unshare-user --uid 0 --gid 0 \
        --unshare-pid \
        --ro-bind / / \
        --bind "$TEST_ROOT" "$TEST_ROOT" \
        --dev /dev \
        --proc /proc \
        /usr/bin/stat -c '%u:%g:%a:%F' \
        "$LIB_DIR" \
        "${PAYLOADS[@]/#/$LIB_DIR/}"
)
[[ "${metadata[0]}" == '0:0:755:directory' ]] \
    || fail 'module library is not an exact root-owned mode 0755 directory'
for item_metadata in "${metadata[@]:1}"; do
    [[ "$item_metadata" == '0:0:755:regular file' ]] \
        || fail 'installed payload is not an exact root-owned mode 0755 regular file'
done

runner_output="$TMP_DIR/runner.out"
runner_status=0
set +e
/usr/bin/bwrap \
    --unshare-user --uid 0 --gid 0 \
    --unshare-pid \
    --ro-bind / / \
    --bind "$TEST_ROOT" "$TEST_ROOT" \
    --bind "$TEST_ROOT/var/lib" /var/lib \
    --dev /dev \
    --proc /proc \
    /usr/bin/env CELERITY_L2TP_ROOT="$TEST_ROOT" \
    "$RUNNER_LINK" \
        --operation-id installed-layout-probe --command preflight >"$runner_output" 2>&1
runner_status=$?
set -e
[[ "$runner_status" -ne 69 ]] || fail 'installed runner could not reach its sibling preflight artifact'
[[ "$(<"$runner_output")" == \
   '{"check":"desired_state","status":"error","code":"INVALID_DESIRED_STATE_FILE"}' ]] \
    || fail 'installed runner did not execute its sibling preflight artifact'

printf 'installed node artifact layout fixture tests passed\n'
