#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
RUNNER="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/topology/runner.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
TEST_ROOT="$TMP_DIR/root"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

receipt() {
    local command="$1"
    local operation_id="$2"
    local node_id="$3"
    local candidate_hash="$4"
    local backup_id="$5"
    local profile="$6"
    printf '{"ok":true,"command":"%s","operationId":"%s","nodeId":"%s","candidateHash":"%s","backupId":"%s","targetProfile":"%s"}' \
        "$command" "$operation_id" "$node_id" "$candidate_hash" "$backup_id" "$profile"
}

invoke() {
    local label="$1"
    local command="$2"
    local operation_id="$3"
    local node_id="$4"
    local candidate_hash="$5"
    local backup_id="$6"
    local profile="$7"
    local candidate="${8-}"
    shift 8 || true
    stdout_file="$TMP_DIR/$label.stdout"
    stderr_file="$TMP_DIR/$label.stderr"
    status=0
    set +e
    printf '%s' "$candidate" | CELERITY_TOPOLOGY_ROOT="$TEST_ROOT" "$RUNNER" \
        --command "$command" \
        --operation-id "$operation_id" \
        --node-id "$node_id" \
        --candidate-hash "$candidate_hash" \
        --backup-id "$backup_id" \
        --target-profile "$profile" \
        "$@" >"$stdout_file" 2>"$stderr_file"
    status=$?
    set -e
    output="$(<"$stdout_file")"
    errors="$(<"$stderr_file")"
}

[[ -x "$RUNNER" ]] || fail 'topology runner is missing or not executable'
mkdir -p \
    "$TEST_ROOT/usr/local/bin" \
    "$TEST_ROOT/usr/bin" \
    "$TEST_ROOT/usr/local/etc/xray" \
    "$TEST_ROOT/usr/local/etc/xray-bridge" \
    "$TEST_ROOT/var/lib"
printf '%s\n' '{"old":"main"}' >"$TEST_ROOT/usr/local/etc/xray/config.json"
printf '%s\n' '{"old":"bridge"}' >"$TEST_ROOT/usr/local/etc/xray-bridge/config.json"
printf '%s\n' 'outside-rollback-scope' >"$TEST_ROOT/do-not-touch"

printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' \
    'printf '\''xray %s\n'\'' "$*" >>"${CELERITY_TOPOLOGY_ROOT}/xray.log"' \
    '[[ "$1" == "run" && "$2" == "-test" && "$3" == "-config" && "$4" == "${CELERITY_TOPOLOGY_ROOT}"/* ]]' \
    >"$TEST_ROOT/usr/local/bin/xray"
chmod +x "$TEST_ROOT/usr/local/bin/xray"
printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' \
    'printf '\''systemctl %s\n'\'' "$*" >>"${CELERITY_TOPOLOGY_ROOT}/systemctl.log"' \
    'case "$1" in restart|stop) exit 0 ;; is-active) [[ "$2" == "--quiet" ]] && exit 0 ;; esac' \
    'exit 64' \
    >"$TEST_ROOT/usr/bin/systemctl"
chmod +x "$TEST_ROOT/usr/bin/systemctl"

main_candidate='{"secret":"main-candidate-secret-canary","profile":"main"}\n'
main_hash="sha256:$(printf '%s' "$main_candidate" | sha256sum | cut -d' ' -f1)"
main_operation='topology-operation-main'
main_node='main-node-1'
main_backup='topology-backup-main'

invoke main-prepare prepare "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main "$main_candidate"
[[ "$status" -eq 0 ]] || fail 'xray-main prepare failed'
[[ "$output" == "$(receipt prepare "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main)" ]] \
    || fail 'xray-main prepare receipt was not strict and bound'
[[ -z "$errors" ]] || fail 'xray-main prepare wrote diagnostics'
[[ "$output$errors" != *'main-candidate-secret-canary'* ]] || fail 'prepare printed candidate secrets'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray/config.json")" == '{"old":"main"}' ]] \
    || fail 'prepare mutated the active main config'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray-bridge/config.json")" == '{"old":"bridge"}' ]] \
    || fail 'prepare mutated the bridge config'

invoke main-commit commit "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main ''
[[ "$status" -eq 0 ]] || fail 'xray-main commit failed'
[[ "$output" == "$(receipt commit "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main)" ]] \
    || fail 'xray-main commit receipt was not strict and bound'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray/config.json")" == "$main_candidate" ]] \
    || fail 'commit did not activate the prepared main candidate'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray-bridge/config.json")" == '{"old":"bridge"}' ]] \
    || fail 'main commit escaped to the bridge target'
[[ "$(<"$TEST_ROOT/systemctl.log")" == 'systemctl restart xray.service' ]] \
    || fail 'main commit used a non-fixed service'

invoke main-verify verify "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main ''
[[ "$status" -eq 0 ]] || fail 'xray-main verify failed'
[[ "$output" == "$(receipt verify "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main)" ]] \
    || fail 'xray-main verify receipt was not strict and bound'

: >"$TEST_ROOT/systemctl.log"
invoke main-rollback rollback "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main ''
[[ "$status" -eq 0 ]] || fail 'xray-main rollback failed'
[[ "$output" == "$(receipt rollback "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main)" ]] \
    || fail 'xray-main rollback receipt was not strict and bound'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray/config.json")" == '{"old":"main"}' ]] \
    || fail 'rollback did not restore the fixed main target'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray-bridge/config.json")" == '{"old":"bridge"}' ]] \
    || fail 'main rollback escaped to the bridge target'
[[ "$(<"$TEST_ROOT/do-not-touch")" == 'outside-rollback-scope' ]] \
    || fail 'rollback mutated a target outside its fixed scope'
[[ "$(<"$TEST_ROOT/systemctl.log")" == 'systemctl restart xray.service' ]] \
    || fail 'main rollback used a non-fixed service'

bridge_candidate='{"secret":"bridge-candidate-secret-canary","profile":"bridge"}\n'
bridge_hash="sha256:$(printf '%s' "$bridge_candidate" | sha256sum | cut -d' ' -f1)"
bridge_operation='topology-operation-bridge'
bridge_node='bridge-node-1'
bridge_backup='topology-backup-bridge'
invoke bridge-prepare prepare "$bridge_operation" "$bridge_node" "$bridge_hash" "$bridge_backup" xray-bridge "$bridge_candidate"
[[ "$status" -eq 0 ]] || fail 'xray-bridge prepare failed'
[[ "$output$errors" != *'bridge-candidate-secret-canary'* ]] || fail 'bridge prepare printed candidate secrets'
: >"$TEST_ROOT/systemctl.log"
invoke bridge-commit commit "$bridge_operation" "$bridge_node" "$bridge_hash" "$bridge_backup" xray-bridge ''
[[ "$status" -eq 0 ]] || fail 'xray-bridge commit failed'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray-bridge/config.json")" == "$bridge_candidate" ]] \
    || fail 'commit did not activate the bridge candidate'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray/config.json")" == '{"old":"main"}' ]] \
    || fail 'bridge commit escaped to the main target'
[[ "$(<"$TEST_ROOT/systemctl.log")" == 'systemctl restart xray-bridge.service' ]] \
    || fail 'bridge commit used a non-fixed service'
invoke bridge-rollback rollback "$bridge_operation" "$bridge_node" "$bridge_hash" "$bridge_backup" xray-bridge ''
[[ "$status" -eq 0 ]] || fail 'xray-bridge rollback failed'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray-bridge/config.json")" == '{"old":"bridge"}' ]] \
    || fail 'bridge rollback did not restore its fixed target'

invoke extra-field prepare raw-operation raw-node "$main_hash" raw-backup xray-main "$main_candidate" --path /tmp/foreign
[[ "$status" -ne 0 ]] || fail 'raw path field was accepted'
[[ "$output$errors" != *'/tmp/foreign'* && "$output$errors" != *'main-candidate-secret-canary'* ]] \
    || fail 'rejected raw input or candidate content leaked'

invoke unknown-profile prepare raw-operation raw-node "$main_hash" raw-backup xray-other "$main_candidate"
[[ "$status" -ne 0 ]] || fail 'unknown target profile was accepted'
[[ "$output$errors" != *'main-candidate-secret-canary'* ]] || fail 'unknown-profile failure leaked candidate content'

invoke wrong-hash prepare raw-operation raw-node "sha256:$(printf '0%.0s' {1..64})" raw-backup xray-main "$main_candidate"
[[ "$status" -ne 0 ]] || fail 'candidate hash mismatch was accepted'
[[ "$output$errors" != *'main-candidate-secret-canary'* ]] || fail 'hash mismatch leaked candidate content'

invoke wrong-binding commit "$main_operation" another-node "$main_hash" "$main_backup" xray-main ''
[[ "$status" -ne 0 ]] || fail 'commit accepted a receipt-binding mismatch'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray/config.json")" == '{"old":"main"}' ]] \
    || fail 'binding mismatch mutated the active target'

printf 'topology node artifact fixture tests passed\n'
