#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/activate-xray.sh"
ORIGINAL_PATH="$PATH"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_activate() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    rm -f "$TMP_DIR/xray-call.log" "$TMP_DIR/systemctl-call.log"
    set +e
    PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
        XRAY_CALL_LOG="$TMP_DIR/xray-call.log" \
        SYSTEMCTL_CALL_LOG="$TMP_DIR/systemctl-call.log" \
        XRAY_STATUS="${XRAY_STATUS:-0}" \
        unshare --user --map-root-user "$ARTIFACT" "$@" >"$output" 2>&1
    status=$?
    set -e
}

[[ -x "$ARTIFACT" ]] || fail 'activate Xray artifact is missing or not executable'
mkdir -p "$TMP_DIR/bin" "$TMP_DIR/operation/candidate" "$TMP_DIR/root/usr/local/etc/xray"
printf '%s\n' '{"files":[],"absent":["usr/local/etc/xray/config.json"]}' >"$TMP_DIR/operation/backup.json"
printf '%s\n' '{"old":true}' >"$TMP_DIR/root/usr/local/etc/xray/config.json"
printf '%s\n' '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}' \
    >"$TMP_DIR/operation/candidate/xray.json"

cat >"$TMP_DIR/bin/xray" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$@" >"$XRAY_CALL_LOG"
exit "$XRAY_STATUS"
STUB
chmod +x "$TMP_DIR/bin/xray"
cat >"$TMP_DIR/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$@" >>"$SYSTEMCTL_CALL_LOG"
[[ "$1" == 'restart' || ( "$1" == 'is-active' && "$2" == '--quiet' ) ]]
STUB
chmod +x "$TMP_DIR/bin/systemctl"

XRAY_STATUS=23 invoke_activate invalid "$TMP_DIR/operation" "$TMP_DIR/root"
[[ "$status" -ne 0 ]] || fail 'invalid Xray candidate was activated'
[[ "$(<"$output")" == '{"status":"error","code":"XRAY_CANDIDATE_INVALID"}' ]] \
    || fail 'invalid Xray candidate returned the wrong error'
[[ "$(<"$TMP_DIR/root/usr/local/etc/xray/config.json")" == '{"old":true}' ]] \
    || fail 'invalid Xray candidate changed the active config'
[[ ! -e "$TMP_DIR/systemctl-call.log" ]] || fail 'invalid Xray candidate restarted Xray'

XRAY_STATUS=0 invoke_activate valid "$TMP_DIR/operation" "$TMP_DIR/root"
[[ "$status" -eq 0 ]] || fail 'valid Xray activation failed'
[[ "$(<"$output")" == '{"status":"ok","service":"xray.service","changed":1}' ]] \
    || fail 'Xray activation returned the wrong structured result'
cmp -s "$TMP_DIR/operation/candidate/xray.json" "$TMP_DIR/root/usr/local/etc/xray/config.json" \
    || fail 'Xray activation did not install the exact official composer output'
[[ "$(unshare --user --map-root-user stat --format='%u:%g:%a' -- "$TMP_DIR/root/usr/local/etc/xray/config.json")" == '0:0:644' ]] \
    || fail 'active Xray config metadata is incorrect'
mapfile -t systemctl_call <"$TMP_DIR/systemctl-call.log"
[[ "${systemctl_call[*]}" == 'is-active --quiet xray.service restart xray.service is-active --quiet xray.service' ]] \
    || fail 'Xray activation did not capture prior state and use fixed health commands'
[[ "$(<"$TMP_DIR/operation/state/xray.before.json")" == '{"wasActive":true}' ]] \
    || fail 'Xray activation did not record operation-local prior unit state'
[[ -f "$TMP_DIR/operation/state/xray.activated" && ! -L "$TMP_DIR/operation/state/xray.activated" ]] \
    || fail 'Xray activation did not create its operation-local state marker'

invoke_activate extra "$TMP_DIR/operation" "$TMP_DIR/root" "$TMP_DIR/root/usr/local/etc/xray/other.json"
[[ "$status" -ne 0 ]] || fail 'Xray activation accepted an arbitrary target'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'arbitrary Xray target returned the wrong error'
[[ ! -e "$TMP_DIR/systemctl-call.log" ]] || fail 'rejected Xray activation invoked systemctl'

printf 'activate Xray artifact fixture tests passed\n'
