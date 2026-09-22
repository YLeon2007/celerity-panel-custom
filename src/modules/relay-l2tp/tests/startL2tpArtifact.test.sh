#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/start-l2tp.sh"
ORIGINAL_PATH="$PATH"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_start() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    rm -f "$TMP_DIR/systemctl-call.log" "$TMP_DIR/mutation.log"
    set +e
    PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
        SYSTEMCTL_CALL_LOG="$TMP_DIR/systemctl-call.log" \
        SYSTEMCTL_STATE="$TMP_DIR/systemctl-state" \
        SYSTEMCTL_RESTART_STATUS="${SYSTEMCTL_RESTART_STATUS:-0}" \
        MUTATION_LOG="$TMP_DIR/mutation.log" \
        unshare --user --map-root-user "$ARTIFACT" "$@" >"$output" 2>&1
    status=$?
    set -e
}

[[ -x "$ARTIFACT" ]] || fail 'start L2TP artifact is missing or not executable'
mkdir -p "$TMP_DIR/bin" "$TMP_DIR/operation"
printf '%s\n' '{"files":[],"absent":[]}' >"$TMP_DIR/operation/backup.json"
printf '%s\n' 'strongswan-starter.service' >"$TMP_DIR/systemctl-state"

cat >"$TMP_DIR/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"$SYSTEMCTL_CALL_LOG"
case "$1" in
    is-active)
        unit="$3"
        grep -Fqx -- "$unit" "$SYSTEMCTL_STATE"
        ;;
    restart)
        [[ "$SYSTEMCTL_RESTART_STATUS" == '0' ]] || exit "$SYSTEMCTL_RESTART_STATUS"
        unit="$2"
        grep -Fqx -- "$unit" "$SYSTEMCTL_STATE" || printf '%s\n' "$unit" >>"$SYSTEMCTL_STATE"
        ;;
    stop)
        unit="$2"
        grep -Fvx -- "$unit" "$SYSTEMCTL_STATE" >"$SYSTEMCTL_STATE.next" || true
        mv "$SYSTEMCTL_STATE.next" "$SYSTEMCTL_STATE"
        ;;
    *) exit 90 ;;
esac
STUB
chmod +x "$TMP_DIR/bin/systemctl"
for command in iptables iptables-nft nft ip; do
    cat >"$TMP_DIR/bin/$command" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "${0##*/}" >>"$MUTATION_LOG"
exit 99
STUB
    chmod +x "$TMP_DIR/bin/$command"
done

invoke_start valid "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'fixed L2TP service start failed'
[[ "$(<"$output")" == '{"status":"ok","services":2,"changed":2}' ]] \
    || fail 'start returned the wrong structured result'
mapfile -t calls <"$TMP_DIR/systemctl-call.log"
expected_calls=(
    'is-active --quiet strongswan-starter.service'
    'is-active --quiet xl2tpd.service'
    'restart strongswan-starter.service'
    'is-active --quiet strongswan-starter.service'
    'restart xl2tpd.service'
    'is-active --quiet xl2tpd.service'
)
[[ "${calls[*]}" == "${expected_calls[*]}" ]] || fail 'start used unexpected unit commands'
[[ "$(<"$TMP_DIR/operation/state/l2tp-services.before.json")" == '{"strongswan-starter.service":true,"xl2tpd.service":false}' ]] \
    || fail 'start did not record operation-local prior unit state'
[[ ! -s "$TMP_DIR/mutation.log" ]] || fail 'start invoked a firewall fallback command'

secret='restart-secret-must-not-leak'
SYSTEMCTL_RESTART_STATUS=23 invoke_start restart-failure "$TMP_DIR/operation"
[[ "$status" -ne 0 ]] || fail 'failed restart was accepted'
[[ "$(<"$output")" == '{"status":"error","code":"L2TP_SERVICE_RESTART_FAILED"}' ]] \
    || fail 'restart failure returned the wrong structured error'
! grep -Fq -- "$secret" "$output" || fail 'restart failure leaked command output'

invoke_start extra "$TMP_DIR/operation" "$TMP_DIR/other"
[[ "$status" -ne 0 ]] || fail 'start accepted an arbitrary path'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'extra argument returned the wrong error'
[[ ! -e "$TMP_DIR/systemctl-call.log" ]] || fail 'rejected start invoked systemctl'

printf 'start L2TP artifact fixture tests passed\n'
