#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/rollback.sh"
ORIGINAL_PATH="$PATH"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_rollback() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    rm -f "$TMP_DIR/command.log"
    set +e
    PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
        CELERITY_L2TP_ROOT="$TMP_DIR/root" \
        COMMAND_LOG="$TMP_DIR/command.log" \
        unshare --user --map-root-user "$ARTIFACT" "$@" >"$output" 2>&1
    status=$?
    set -e
}

write_current_files() {
    local root="$1"
    mkdir -p \
        "$root/etc/ipsec.d" \
        "$root/etc/xl2tpd" \
        "$root/etc/ppp" \
        "$root/etc/nftables.d" \
        "$root/usr/local/etc/xray"
    for relative in \
        etc/ipsec.d/celerity-l2tp.conf \
        etc/ipsec.secrets \
        etc/xl2tpd/xl2tpd.conf \
        etc/ppp/options.xl2tpd \
        etc/ppp/chap-secrets \
        etc/nftables.d/celerity-l2tp.nft \
        usr/local/etc/xray/config.json; do
        printf 'current %s\n' "$relative" >"$root/$relative"
    done
    printf '%s\n' 'unmanaged global sentinel' >"$root/etc/ipsec.conf"
    chmod 755 \
        "$root" \
        "$root/etc" \
        "$root/etc/ipsec.d" \
        "$root/etc/xl2tpd" \
        "$root/etc/ppp" \
        "$root/etc/nftables.d" \
        "$root/usr" \
        "$root/usr/local" \
        "$root/usr/local/etc" \
        "$root/usr/local/etc/xray"
}

[[ -x "$ARTIFACT" ]] || fail 'rollback artifact is missing or not executable'
mkdir -p "$TMP_DIR/bin" "$TMP_DIR/operation/state" "$TMP_DIR/root"
write_current_files "$TMP_DIR/root"
printf '%s\n' '{"files":[{"path":"etc/ipsec.d/celerity-l2tp.conf","mode":416,"content":"old ipsec drop-in\n"},{"path":"etc/ppp/chap-secrets","mode":384,"content":"local chap entry\n"},{"path":"usr/local/etc/xray/config.json","mode":420,"content":"{\"old\":true}\n"}],"absent":["etc/ipsec.secrets","etc/xl2tpd/xl2tpd.conf","etc/ppp/options.xl2tpd","etc/nftables.d/celerity-l2tp.nft"]}' \
    >"$TMP_DIR/operation/backup.json"
printf '%s\n' '{"fwmark":77,"routeTable":177,"priority":10077}' \
    >"$TMP_DIR/operation/state/firewall.applied.json"
printf '%s\n' '{"wasActive":false}' >"$TMP_DIR/operation/state/xray.before.json"
printf '%s\n' '{"strongswan-starter.service":true,"xl2tpd.service":false}' \
    >"$TMP_DIR/operation/state/l2tp-services.before.json"
chmod 700 "$TMP_DIR/operation" "$TMP_DIR/operation/state"
chmod 600 \
    "$TMP_DIR/operation/backup.json" \
    "$TMP_DIR/operation/state/firewall.applied.json" \
    "$TMP_DIR/operation/state/xray.before.json" \
    "$TMP_DIR/operation/state/l2tp-services.before.json"

cat >"$TMP_DIR/bin/ip" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'ip %s\n' "$*" >>"$COMMAND_LOG"
case "$*" in
    '-4 route del local 0.0.0.0/0 dev lo table 177'|'-4 rule del priority 10077 fwmark 77 table 177') exit 0 ;;
    *) exit 90 ;;
esac
STUB
cat >"$TMP_DIR/bin/nft" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'nft %s\n' "$*" >>"$COMMAND_LOG"
[[ "$*" == 'delete table inet celerity_l2tp' ]]
STUB
cat >"$TMP_DIR/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'systemctl %s\n' "$*" >>"$COMMAND_LOG"
case "$*" in
    'stop xray.service'|'restart strongswan-starter.service'|'stop xl2tpd.service') exit 0 ;;
    *) exit 90 ;;
esac
STUB
chmod +x "$TMP_DIR/bin/ip" "$TMP_DIR/bin/nft" "$TMP_DIR/bin/systemctl"
for command in iptables iptables-nft cp mv install apply.sh; do
    cat >"$TMP_DIR/bin/$command" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'forbidden %s\n' "${0##*/}" >>"$COMMAND_LOG"
exit 99
STUB
    chmod +x "$TMP_DIR/bin/$command"
done

invoke_rollback valid "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'scoped rollback failed'
[[ "$(<"$output")" == '{"status":"ok","restored":3,"removed":4,"firewallReverted":true,"servicesReverted":3}' ]] \
    || fail 'rollback returned the wrong structured result'
[[ "$(<"$TMP_DIR/root/etc/ipsec.d/celerity-l2tp.conf")" == 'old ipsec drop-in' ]] \
    || fail 'rollback did not restore the managed IPsec drop-in'
[[ "$(<"$TMP_DIR/root/etc/ppp/chap-secrets")" == 'local chap entry' ]] \
    || fail 'rollback did not restore chap-secrets'
[[ "$(<"$TMP_DIR/root/usr/local/etc/xray/config.json")" == '{"old":true}' ]] \
    || fail 'rollback did not restore Xray config'
[[ "$(unshare --user --map-root-user stat --format='%a' -- "$TMP_DIR/root/etc/ipsec.d/celerity-l2tp.conf")" == '640' ]] \
    || fail 'rollback did not restore the backed-up mode'
for relative in \
    etc/ipsec.secrets \
    etc/xl2tpd/xl2tpd.conf \
    etc/ppp/options.xl2tpd \
    etc/nftables.d/celerity-l2tp.nft; do
    [[ ! -e "$TMP_DIR/root/$relative" ]] || fail "rollback did not remove originally absent $relative"
done
[[ "$(<"$TMP_DIR/root/etc/ipsec.conf")" == 'unmanaged global sentinel' ]] \
    || fail 'rollback changed unmanaged global configuration'
mapfile -t calls <"$TMP_DIR/command.log"
expected_calls=(
    'ip -4 route del local 0.0.0.0/0 dev lo table 177'
    'ip -4 rule del priority 10077 fwmark 77 table 177'
    'nft delete table inet celerity_l2tp'
    'systemctl stop xray.service'
    'systemctl restart strongswan-starter.service'
    'systemctl stop xl2tpd.service'
)
[[ "${calls[*]}" == "${expected_calls[*]}" ]] || fail 'rollback reversed unexpected system state'
[[ -f "$TMP_DIR/operation/state/rolled-back.json" ]] || fail 'rollback did not record completion'
[[ ! -e "$TMP_DIR/operation/state/firewall.applied.json" \
    && ! -e "$TMP_DIR/operation/state/xray.before.json" \
    && ! -e "$TMP_DIR/operation/state/l2tp-services.before.json" ]] \
    || fail 'rollback retained applied-state ownership markers'

missing_operation="$TMP_DIR/missing-operation"
mkdir -p "$missing_operation/state"
write_current_files "$TMP_DIR/root"
before="$(<"$TMP_DIR/root/etc/ipsec.d/celerity-l2tp.conf")"
invoke_rollback missing "$missing_operation"
[[ "$status" -ne 0 ]] || fail 'rollback ran without an operation backup'
[[ "$(<"$output")" == '{"status":"error","code":"BACKUP_REQUIRED"}' ]] \
    || fail 'missing backup returned the wrong structured error'
[[ "$(<"$TMP_DIR/root/etc/ipsec.d/celerity-l2tp.conf")" == "$before" ]] \
    || fail 'missing backup changed a managed target'
[[ ! -e "$TMP_DIR/command.log" ]] || fail 'missing backup ran a system command'

unsafe_operation="$TMP_DIR/unsafe-operation"
mkdir -p "$unsafe_operation/state"
printf '%s\n' '{"files":[{"path":"etc/ipsec.conf","mode":420,"content":"attacker\n"}],"absent":[]}' \
    >"$unsafe_operation/backup.json"
chmod 700 "$unsafe_operation" "$unsafe_operation/state"
chmod 600 "$unsafe_operation/backup.json"
invoke_rollback unsafe "$unsafe_operation"
[[ "$status" -ne 0 ]] || fail 'rollback accepted an unmanaged backup path'
[[ "$(<"$output")" == '{"status":"error","code":"UNSAFE_BACKUP"}' ]] \
    || fail 'unsafe backup returned the wrong structured error'
[[ "$(<"$TMP_DIR/root/etc/ipsec.conf")" == 'unmanaged global sentinel' ]] \
    || fail 'unsafe backup changed global configuration'
[[ ! -e "$TMP_DIR/command.log" ]] || fail 'unsafe backup ran a system command'

invoke_rollback extra "$TMP_DIR/operation" "$TMP_DIR/root"
[[ "$status" -ne 0 ]] || fail 'rollback accepted an arbitrary root argument'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'extra argument returned the wrong error'
[[ ! -e "$TMP_DIR/command.log" ]] || fail 'rejected rollback ran a system command'

printf 'rollback artifact fixture tests passed\n'
