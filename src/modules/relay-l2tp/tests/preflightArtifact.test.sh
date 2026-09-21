#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/preflight.sh"
ORIGINAL_PATH="$PATH"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

assert_line() {
    local expected="$1"
    local output_file="$2"
    grep -Fqx -- "$expected" "$output_file" \
        || fail "missing output line: $expected"
}

make_stub() {
    local name="$1"
    shift
    {
        printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
        printf '%s\n' "$@"
    } >"$TMP_DIR/bin/$name"
    chmod +x "$TMP_DIR/bin/$name"
}

mkdir -p "$TMP_DIR/bin"
printf '%s\n' '{"clientCidr":"10.77.0.0/24","psk":"must-not-leak"}' >"$TMP_DIR/desired-state.json"
: >"$TMP_DIR/mutations.log"

make_stub stat '
if [[ "$*" == *"%u"* ]]; then
    printf "0\\n"
    exit 0
fi
exit 1
'
make_stub cat '
if [[ "${1:-}" == "--" && "${2:-}" == "/etc/os-release" ]]; then
    printf "ID=%s\\nVERSION_ID=%s\\n" "$PREFLIGHT_TEST_OS_ID" "$PREFLIGHT_TEST_OS_VERSION"
    exit 0
fi
exit 1
'

output="$TMP_DIR/unsupported.out"
set +e
PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
    MUTATION_LOG="$TMP_DIR/mutations.log" \
    PREFLIGHT_TEST_OS_ID=alpine \
    PREFLIGHT_TEST_OS_VERSION=3.20 \
    "$ARTIFACT" "$TMP_DIR/desired-state.json" >"$output" 2>&1
status=$?
set -e

[[ "$status" -ne 0 ]] || fail 'unsupported OS must return nonzero'
assert_line '{"check":"os","status":"error","code":"UNSUPPORTED_OS","id":"alpine","version":"3.20"}' "$output"
[[ ! -s "$TMP_DIR/mutations.log" ]] || fail 'unsupported OS path attempted a mutation'
! grep -Fq -- 'must-not-leak' "$output" || fail 'desired-state secret leaked to output'

make_stub xray '
if [[ "${1:-}" == "version" ]]; then
    printf "%s\\n" "Xray 26.3.27"
    exit 0
fi
if [[ "${1:-}" == "run" && "${2:-}" == "-test" ]]; then
    exit 0
fi
exit 1
'
make_stub systemctl '
if [[ "${1:-}" == "show" && "${2:-}" == "xray.service" ]]; then
    printf "loaded\\n"
    exit 0
fi
exit 1
'
make_stub nft '
if [[ "${1:-}" == "--version" ]]; then
    printf "%s\\n" "nftables v1.0.9"
    exit 0
fi
exit 1
'
printf '%s\n' '{}' >"$TMP_DIR/xray-config.json"
output="$TMP_DIR/supported.out"
PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
    PREFLIGHT_TEST_OS_ID=debian \
    PREFLIGHT_TEST_OS_VERSION=13 \
    CELERITY_PREFLIGHT_XRAY_CONFIG_PATH="$TMP_DIR/xray-config.json" \
    "$ARTIFACT" "$TMP_DIR/desired-state.json" >"$output" 2>&1
assert_line '{"check":"os","status":"ok","id":"debian","version":"13"}' "$output"
assert_line '{"check":"xray","status":"ok","version":"Xray 26.3.27"}' "$output"
assert_line "{\"check\":\"xray_config\",\"status\":\"ok\",\"path\":\"$TMP_DIR/xray-config.json\"}" "$output"
assert_line '{"check":"xray_unit","status":"ok","unit":"xray.service"}' "$output"
assert_line '{"check":"nft","status":"ok","version":"nftables v1.0.9"}' "$output"
assert_line '{"check":"client_cidr","status":"ok","cidr":"10.77.0.0/24"}' "$output"
[[ ! -s "$TMP_DIR/mutations.log" ]] || fail 'supported path attempted a mutation'
! grep -Fq -- 'must-not-leak' "$output" || fail 'supported path leaked desired-state secret'

printf 'preflight artifact fixture tests passed\n'
