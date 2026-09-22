#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/apply-firewall-policy.sh"
ORIGINAL_PATH="$PATH"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_firewall() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    rm -f "$TMP_DIR/nft-call.log" "$TMP_DIR/ip-call.log" "$TMP_DIR/table-present"
    set +e
    PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
        NFT_CALL_LOG="$TMP_DIR/nft-call.log" \
        IP_CALL_LOG="$TMP_DIR/ip-call.log" \
        NFT_TABLE_STATE="$TMP_DIR/table-present" \
        NFT_VALIDATE_STATUS="${NFT_VALIDATE_STATUS:-0}" \
        unshare --user --map-root-user "$ARTIFACT" "$@" >"$output" 2>&1
    status=$?
    set -e
}

[[ -x "$ARTIFACT" ]] || fail 'firewall policy artifact is missing or not executable'
mkdir -p "$TMP_DIR/bin" "$TMP_DIR/operation/candidate"
printf '%s\n' '{"fwmark":77,"routeTable":177,"psk":"must-not-leak"}' \
    >"$TMP_DIR/operation/desired.json"
printf '%s\n' '{"files":[],"absent":["etc/nftables.d/celerity-l2tp.nft"]}' \
    >"$TMP_DIR/operation/backup.json"
printf '%s\n' 'table inet celerity_l2tp { chain input { type filter hook input priority 0; policy accept; } }' \
    >"$TMP_DIR/operation/candidate/celerity-l2tp.nft"

cat >"$TMP_DIR/bin/nft" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s' "$1" >>"$NFT_CALL_LOG"
printf ' %s' "${@:2}" >>"$NFT_CALL_LOG"
printf '\n' >>"$NFT_CALL_LOG"
if [[ "$1" == '-c' ]]; then
    exit "$NFT_VALIDATE_STATUS"
fi
if [[ "$1" == 'list' ]]; then
    [[ -e "$NFT_TABLE_STATE" ]]
    exit
fi
if [[ "$1" == '-f' ]]; then
    : >"$NFT_TABLE_STATE"
    exit 0
fi
if [[ "$1" == 'delete' ]]; then
    rm -f "$NFT_TABLE_STATE"
    exit 0
fi
exit 90
STUB
chmod +x "$TMP_DIR/bin/nft"
cat >"$TMP_DIR/bin/ip" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s' "$1" >>"$IP_CALL_LOG"
printf ' %s' "${@:2}" >>"$IP_CALL_LOG"
printf '\n' >>"$IP_CALL_LOG"
exit 0
STUB
chmod +x "$TMP_DIR/bin/ip"

NFT_VALIDATE_STATUS=23 invoke_firewall invalid "$TMP_DIR/operation"
[[ "$status" -ne 0 ]] || fail 'invalid nft candidate was applied'
[[ "$(<"$output")" == '{"status":"error","code":"NFT_CANDIDATE_INVALID"}' ]] \
    || fail 'invalid nft candidate returned the wrong structured error'
[[ "$(<"$TMP_DIR/nft-call.log")" == "-c -f $TMP_DIR/operation/candidate/celerity-l2tp.nft" ]] \
    || fail 'invalid nft candidate ran a mutation command'
[[ ! -e "$TMP_DIR/ip-call.log" ]] || fail 'invalid nft candidate changed policy routing'
! grep -Fq -- 'must-not-leak' "$output" || fail 'firewall error leaked desired secrets'

NFT_VALIDATE_STATUS=0 invoke_firewall valid "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'valid firewall policy failed'
[[ "$(<"$output")" == '{"status":"ok","namespace":"celerity_l2tp","changed":1}' ]] \
    || fail 'firewall policy returned the wrong structured result'
mapfile -t nft_calls <"$TMP_DIR/nft-call.log"
[[ "${nft_calls[0]}" == "-c -f $TMP_DIR/operation/candidate/celerity-l2tp.nft" ]] \
    || fail 'firewall policy did not validate before mutation'
[[ "${nft_calls[1]}" == 'list table inet celerity_l2tp' ]] \
    || fail 'firewall policy did not detect namespace conflicts'
[[ "${nft_calls[2]}" == "-f $TMP_DIR/operation/candidate/celerity-l2tp.nft" ]] \
    || fail 'firewall policy did not load only the fixed candidate'
mapfile -t ip_calls <"$TMP_DIR/ip-call.log"
[[ "${ip_calls[0]}" == '-4 rule add priority 10077 fwmark 77 table 177' ]] \
    || fail 'firewall policy used the wrong fixed ip rule command'
[[ "${ip_calls[1]}" == '-4 route add local 0.0.0.0/0 dev lo table 177' ]] \
    || fail 'firewall policy used the wrong fixed local route command'
[[ -f "$TMP_DIR/operation/state/firewall.applied.json" \
    && ! -L "$TMP_DIR/operation/state/firewall.applied.json" ]] \
    || fail 'firewall policy did not record operation-local ownership'
[[ "$(<"$TMP_DIR/operation/state/firewall.applied.json")" == '{"fwmark":77,"routeTable":177,"priority":10077}' ]] \
    || fail 'firewall ownership marker contains unexpected data'

outside="$TMP_DIR/outside.nft"
printf '%s\n' 'table inet attacker {}' >"$outside"
invoke_firewall extra "$TMP_DIR/operation" "$outside"
[[ "$status" -ne 0 ]] || fail 'firewall policy accepted an arbitrary ruleset path'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'arbitrary firewall path returned the wrong error'
[[ ! -e "$TMP_DIR/nft-call.log" && ! -e "$TMP_DIR/ip-call.log" ]] \
    || fail 'rejected firewall input invoked mutation commands'

printf 'firewall policy artifact fixture tests passed\n'
