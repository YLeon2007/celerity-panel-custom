#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/verify.sh"
ORIGINAL_PATH="$PATH"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_verify() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    rm -f "$TMP_DIR/call.log" "$TMP_DIR/mutation.log"
    set +e
    PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
        CELERITY_L2TP_ROOT="$TMP_DIR/root" \
        CALL_LOG="$TMP_DIR/call.log" \
        MUTATION_LOG="$TMP_DIR/mutation.log" \
        NFT_STATUS="${NFT_STATUS:-0}" \
        unshare --user --map-root-user "$ARTIFACT" "$@" >"$output" 2>&1
    status=$?
    set -e
}

[[ -x "$ARTIFACT" ]] || fail 'verify artifact is missing or not executable'
mkdir -p "$TMP_DIR/bin" "$TMP_DIR/operation/state" "$TMP_DIR/root/usr/local/etc/xray"
printf '%s\n' '{"fwmark":77,"routeTable":177,"psk":"must-not-leak"}' >"$TMP_DIR/operation/desired.json"
printf '%s\n' '{"fwmark":77,"routeTable":177,"priority":10077}' >"$TMP_DIR/operation/state/firewall.applied.json"
printf '%s\n' '{}' >"$TMP_DIR/root/usr/local/etc/xray/config.json"

cat >"$TMP_DIR/bin/xray" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'xray %s\n' "$*" >>"$CALL_LOG"
[[ "$*" == "run -test -config $CELERITY_L2TP_ROOT/usr/local/etc/xray/config.json" ]]
STUB
cat >"$TMP_DIR/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'systemctl %s\n' "$*" >>"$CALL_LOG"
[[ "$1" == 'is-active' && "$2" == '--quiet' ]]
case "$3" in
    xray.service|strongswan-starter.service|xl2tpd.service) exit 0 ;;
    *) exit 90 ;;
esac
STUB
cat >"$TMP_DIR/bin/nft" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'nft %s\n' "$*" >>"$CALL_LOG"
[[ "$*" == 'list table inet celerity_l2tp' ]] || exit 90
exit "$NFT_STATUS"
STUB
cat >"$TMP_DIR/bin/ip" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'ip %s\n' "$*" >>"$CALL_LOG"
case "$*" in
    '-4 rule show priority 10077') printf '%s\n' '10077: from all fwmark 0x4d lookup 177' ;;
    '-4 route show table 177 type local') printf '%s\n' 'local 0.0.0.0/0 dev lo scope host' ;;
    *) exit 90 ;;
esac
STUB
chmod +x "$TMP_DIR/bin/xray" "$TMP_DIR/bin/systemctl" "$TMP_DIR/bin/nft" "$TMP_DIR/bin/ip"
for command in iptables iptables-nft service; do
    cat >"$TMP_DIR/bin/$command" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "${0##*/}" >>"$MUTATION_LOG"
exit 99
STUB
    chmod +x "$TMP_DIR/bin/$command"
done

invoke_verify valid "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'fixed verification failed'
[[ "$(<"$output")" == '{"status":"ok","checks":7,"namespace":"celerity_l2tp"}' ]] \
    || fail 'verification returned the wrong structured result'
expected_calls=(
    "xray run -test -config $TMP_DIR/root/usr/local/etc/xray/config.json"
    'systemctl is-active --quiet xray.service'
    'systemctl is-active --quiet strongswan-starter.service'
    'systemctl is-active --quiet xl2tpd.service'
    'nft list table inet celerity_l2tp'
    'ip -4 rule show priority 10077'
    'ip -4 route show table 177 type local'
)
mapfile -t calls <"$TMP_DIR/call.log"
[[ "${calls[*]}" == "${expected_calls[*]}" ]] || fail 'verification used unexpected checks'
[[ "$(<"$TMP_DIR/operation/state/verified.json")" == '{"fwmark":77,"routeTable":177,"priority":10077,"namespace":"celerity_l2tp"}' ]] \
    || fail 'verification did not record a sanitized operation-local marker'
[[ ! -s "$TMP_DIR/mutation.log" ]] || fail 'verification invoked a fallback mutation command'
! grep -Fq -- 'must-not-leak' "$output" || fail 'verification leaked desired secrets'

NFT_STATUS=23 invoke_verify nft-failure "$TMP_DIR/operation"
[[ "$status" -ne 0 ]] || fail 'missing nft namespace was accepted'
[[ "$(<"$output")" == '{"status":"error","code":"NFT_VERIFY_FAILED"}' ]] \
    || fail 'nft failure returned the wrong structured error'
! grep -Fq -- 'must-not-leak' "$output" || fail 'nft failure leaked desired secrets'

invoke_verify extra "$TMP_DIR/operation" "$TMP_DIR/root"
[[ "$status" -ne 0 ]] || fail 'verification accepted an arbitrary root argument'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'extra argument returned the wrong error'
[[ ! -e "$TMP_DIR/call.log" ]] || fail 'rejected verification ran a check'

printf 'verify artifact fixture tests passed\n'
