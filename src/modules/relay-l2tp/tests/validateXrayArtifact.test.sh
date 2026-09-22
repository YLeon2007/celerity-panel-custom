#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/validate-xray.sh"
ORIGINAL_PATH="$PATH"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_validator() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    rm -f "$TMP_DIR/xray-call.log"
    set +e
    PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
        XRAY_CALL_LOG="$TMP_DIR/xray-call.log" \
        XRAY_STUB_STATUS="${XRAY_STUB_STATUS:-0}" \
        "$ARTIFACT" "$@" >"$output" 2>&1
    status=$?
    set -e
}

expect_error() {
    local label="$1"
    local expected_code="$2"
    shift 2
    invoke_validator "$label" "$@"
    [[ "$status" -ne 0 ]] || fail "$label unexpectedly succeeded"
    [[ "$(<"$output")" == "{\"status\":\"error\",\"code\":\"$expected_code\"}" ]] \
        || fail "$label returned the wrong structured error"
}

[[ -x "$ARTIFACT" ]] || fail 'Xray validation artifact is missing or not executable'
mkdir -p "$TMP_DIR/bin" "$TMP_DIR/operation/candidate"
cat >"$TMP_DIR/bin/xray" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$@" >"$XRAY_CALL_LOG"
exit "$XRAY_STUB_STATUS"
STUB
chmod +x "$TMP_DIR/bin/xray"
printf '%s\n' '{"inbounds":[],"outbounds":[]}' >"$TMP_DIR/operation/candidate/xray.json"

invoke_validator valid "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'valid Xray candidate was rejected'
[[ "$(<"$output")" == '{"status":"ok","validator":"xray","candidate":"candidate/xray.json"}' ]] \
    || fail 'valid Xray candidate returned the wrong structured result'
mapfile -t call <"$TMP_DIR/xray-call.log"
[[ "${#call[@]}" -eq 4 ]] || fail 'Xray received an unexpected argument count'
[[ "${call[0]}" == 'run' && "${call[1]}" == '-test' && "${call[2]}" == '-config' ]] \
    || fail 'Xray was not invoked in config test mode'
[[ "${call[3]}" == "$TMP_DIR/operation/candidate/xray.json" ]] \
    || fail 'Xray did not receive the fixed operation candidate path'

XRAY_STUB_STATUS=23 expect_error invalid-candidate XRAY_CANDIDATE_INVALID "$TMP_DIR/operation"
[[ -e "$TMP_DIR/xray-call.log" ]] || fail 'invalid candidate was not checked by Xray'

rm -f "$TMP_DIR/operation/candidate/xray.json"
expect_error missing-candidate XRAY_CANDIDATE_MISSING "$TMP_DIR/operation"
[[ ! -e "$TMP_DIR/xray-call.log" ]] || fail 'missing candidate invoked Xray'

outside="$TMP_DIR/outside-xray.json"
printf '%s\n' '{"unexpected":true}' >"$outside"
expect_error extra-argument INVALID_ARGUMENTS "$TMP_DIR/operation" "$outside"
[[ ! -e "$TMP_DIR/xray-call.log" ]] || fail 'extra path argument invoked Xray'

printf 'Xray validation artifact fixture tests passed\n'
