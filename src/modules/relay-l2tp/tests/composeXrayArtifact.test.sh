#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/compose-xray-fragment.sh"
ORIGINAL_PATH="$PATH"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_compose() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    rm -f "$TMP_DIR/xray-call.log"
    set +e
    PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
        XRAY_CALL_LOG="$TMP_DIR/xray-call.log" \
        unshare --user --map-root-user "$ARTIFACT" "$@" >"$output" 2>&1
    status=$?
    set -e
}

[[ -x "$ARTIFACT" ]] || fail 'compose Xray artifact is missing or not executable'
mkdir -p "$TMP_DIR/bin" "$TMP_DIR/operation/candidate"
cat >"$TMP_DIR/bin/xray" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$@" >"$XRAY_CALL_LOG"
exit 0
STUB
chmod +x "$TMP_DIR/bin/xray"
printf '%s\n' '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}' \
    >"$TMP_DIR/operation/candidate/xray.json"
before_hash="$(sha256sum "$TMP_DIR/operation/candidate/xray.json")"

invoke_compose valid "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'official composer candidate verification failed'
[[ "$(<"$output")" == '{"status":"ok","mode":"verify_official_composer_output","candidate":"candidate/xray.json"}' ]] \
    || fail 'compose verification returned the wrong structured result'
mapfile -t call <"$TMP_DIR/xray-call.log"
[[ "${call[*]}" == "run -test -config $TMP_DIR/operation/candidate/xray.json" ]] \
    || fail 'compose verification did not validate the fixed candidate path'
[[ "$(sha256sum "$TMP_DIR/operation/candidate/xray.json")" == "$before_hash" ]] \
    || fail 'compose verification patched generated Xray JSON'
candidate_files=("$TMP_DIR/operation/candidate"/*)
[[ "${#candidate_files[@]}" -eq 1 && "${candidate_files[0]}" == "$TMP_DIR/operation/candidate/xray.json" ]] \
    || fail 'compose verification generated an unofficial Xray file'

outside="$TMP_DIR/outside.json"
printf '%s\n' '{"inbounds":[{"tag":"attacker"}]}' >"$outside"
invoke_compose extra-path "$TMP_DIR/operation" "$outside"
[[ "$status" -ne 0 ]] || fail 'compose verification accepted an arbitrary input path'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'compose arbitrary path returned the wrong error'
[[ ! -e "$TMP_DIR/xray-call.log" ]] || fail 'rejected compose input invoked Xray'

rm -f "$TMP_DIR/operation/candidate/xray.json"
ln -s "$outside" "$TMP_DIR/operation/candidate/xray.json"
invoke_compose symlink "$TMP_DIR/operation"
[[ "$status" -ne 0 ]] || fail 'compose verification followed a symlinked candidate'
[[ "$(<"$output")" == '{"status":"error","code":"XRAY_CANDIDATE_MISSING"}' ]] \
    || fail 'symlinked compose candidate returned the wrong error'
[[ ! -e "$TMP_DIR/xray-call.log" ]] || fail 'symlinked compose candidate invoked Xray'

printf 'compose Xray artifact fixture tests passed\n'
