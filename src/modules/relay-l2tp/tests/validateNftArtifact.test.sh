#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/validate-nft.sh"
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
    rm -f "$TMP_DIR/nft-call.log"
    set +e
    PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
        NFT_CALL_LOG="$TMP_DIR/nft-call.log" \
        NFT_STUB_STATUS="${NFT_STUB_STATUS:-0}" \
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

[[ -x "$ARTIFACT" ]] || fail 'nft validation artifact is missing or not executable'
mkdir -p "$TMP_DIR/bin" "$TMP_DIR/operation/candidate"
cat >"$TMP_DIR/bin/nft" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$@" >"$NFT_CALL_LOG"
exit "$NFT_STUB_STATUS"
STUB
chmod +x "$TMP_DIR/bin/nft"
printf '%s\n' 'table inet celerity_l2tp {}' >"$TMP_DIR/operation/candidate/celerity-l2tp.nft"

invoke_validator valid "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'valid nft candidate was rejected'
[[ "$(<"$output")" == '{"status":"ok","validator":"nft","candidate":"candidate/celerity-l2tp.nft"}' ]] \
    || fail 'valid nft candidate returned the wrong structured result'
mapfile -t call <"$TMP_DIR/nft-call.log"
[[ "${#call[@]}" -eq 3 ]] || fail 'nft received an unexpected argument count'
[[ "${call[0]}" == '-c' && "${call[1]}" == '-f' ]] \
    || fail 'nft was not invoked in check-file mode'
[[ "${call[2]}" == "$TMP_DIR/operation/candidate/celerity-l2tp.nft" ]] \
    || fail 'nft did not receive the fixed operation candidate path'

NFT_STUB_STATUS=23 expect_error invalid-candidate NFT_CANDIDATE_INVALID "$TMP_DIR/operation"
[[ -e "$TMP_DIR/nft-call.log" ]] || fail 'invalid candidate was not checked by nft'

rm -f "$TMP_DIR/operation/candidate/celerity-l2tp.nft"
expect_error missing-candidate NFT_CANDIDATE_MISSING "$TMP_DIR/operation"
[[ ! -e "$TMP_DIR/nft-call.log" ]] || fail 'missing candidate invoked nft'

outside="$TMP_DIR/outside.nft"
printf '%s\n' 'table inet unexpected {}' >"$outside"
expect_error extra-argument INVALID_ARGUMENTS "$TMP_DIR/operation" "$outside"
[[ ! -e "$TMP_DIR/nft-call.log" ]] || fail 'extra path argument invoked nft'

printf 'nft validation artifact fixture tests passed\n'
