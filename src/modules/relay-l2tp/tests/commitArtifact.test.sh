#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/commit.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_commit() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    set +e
    unshare --user --map-root-user "$ARTIFACT" "$@" >"$output" 2>&1
    status=$?
    set -e
}

[[ -x "$ARTIFACT" ]] || fail 'commit artifact is missing or not executable'
mkdir -p "$TMP_DIR/operation/state"
printf '%s\n' '{"fwmark":77,"routeTable":177,"priority":10077,"namespace":"celerity_l2tp"}' \
    >"$TMP_DIR/operation/state/verified.json"

invoke_commit valid "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'commit failed for a verified operation'
[[ "$(<"$output")" == '{"status":"ok","changed":1,"committed":true}' ]] \
    || fail 'commit returned the wrong structured result'
[[ -f "$TMP_DIR/operation/state/committed.json" \
    && ! -L "$TMP_DIR/operation/state/committed.json" ]] \
    || fail 'commit did not create an operation-local regular marker'
[[ "$(<"$TMP_DIR/operation/state/committed.json")" == '{"fwmark":77,"routeTable":177,"priority":10077,"namespace":"celerity_l2tp","committed":true}' ]] \
    || fail 'commit marker contains unexpected data'
[[ "$(unshare --user --map-root-user stat --format='%u:%g:%a' -- "$TMP_DIR/operation/state/committed.json")" == '0:0:600' ]] \
    || fail 'commit marker is not root-owned mode 0600'

invoke_commit idempotent "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'idempotent commit failed'
[[ "$(<"$output")" == '{"status":"ok","changed":0,"committed":true}' ]] \
    || fail 'idempotent commit returned the wrong result'

unsafe_operation="$TMP_DIR/unsafe-operation"
outside="$TMP_DIR/outside"
mkdir -p "$unsafe_operation/state"
printf '%s\n' '{"secret":"must-not-leak"}' >"$outside"
ln -s "$outside" "$unsafe_operation/state/verified.json"
invoke_commit unsafe "$unsafe_operation"
[[ "$status" -ne 0 ]] || fail 'commit accepted a symlinked verification marker'
[[ "$(<"$output")" == '{"status":"error","code":"VERIFICATION_REQUIRED"}' ]] \
    || fail 'unsafe verification marker returned the wrong error'
[[ ! -e "$unsafe_operation/state/committed.json" ]] || fail 'unsafe commit created a marker'
[[ "$(<"$outside")" == '{"secret":"must-not-leak"}' ]] || fail 'unsafe commit changed a symlink target'
! grep -Fq -- 'must-not-leak' "$output" || fail 'unsafe commit leaked marker content'

invoke_commit extra "$TMP_DIR/operation" "$outside"
[[ "$status" -ne 0 ]] || fail 'commit accepted an arbitrary path'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'extra argument returned the wrong error'

printf 'commit artifact fixture tests passed\n'
