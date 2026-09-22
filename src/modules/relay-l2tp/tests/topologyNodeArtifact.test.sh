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
/usr/bin/cp "$TEST_ROOT/usr/local/etc/xray/config.json" "$TMP_DIR/main-config.before"
/usr/bin/cp "$TEST_ROOT/usr/local/etc/xray-bridge/config.json" "$TMP_DIR/bridge-config.before"
printf '%s\n' 'outside-rollback-scope' >"$TEST_ROOT/do-not-touch"

printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' \
    'printf '\''xray asset=%s %s\n'\'' "${XRAY_LOCATION_ASSET-}" "$*" >>"${CELERITY_TOPOLOGY_ROOT}/xray.log"' \
    '[[ "${XRAY_LOCATION_ASSET-}" == "${CELERITY_TOPOLOGY_ROOT}/usr/local/share/xray" ]]' \
    '[[ -d "$XRAY_LOCATION_ASSET" && ! -L "$XRAY_LOCATION_ASSET" && -r "$XRAY_LOCATION_ASSET" && -x "$XRAY_LOCATION_ASSET" ]]' \
    '[[ "$1" == "run" && "$2" == "-test" && "$3" == "-config" && -f "$4" && ! -L "$4" ]]' \
    '[[ "$4" == "${CELERITY_TOPOLOGY_ROOT}/var/lib/celerity/topology/operations/"*/xray-*/candidate.json \
        || "$4" == "${CELERITY_TOPOLOGY_ROOT}/usr/local/etc/xray/config.json" \
        || "$4" == "${CELERITY_TOPOLOGY_ROOT}/usr/local/etc/xray-bridge/config.json" ]]' \
    '! /usr/bin/grep -Fq '\''"protocol":"unsupported-protocol"'\'' "$4"' \
    >"$TEST_ROOT/usr/local/bin/xray"
chmod +x "$TEST_ROOT/usr/local/bin/xray"
printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' \
    'printf '\''systemctl %s\n'\'' "$*" >>"${CELERITY_TOPOLOGY_ROOT}/systemctl.log"' \
    'case "$1" in restart|stop) exit 0 ;; is-active) [[ "$2" == "--quiet" && ! -e "${CELERITY_TOPOLOGY_ROOT}/service.inactive" ]] && exit 0 ;; esac' \
    'exit 64' \
    >"$TEST_ROOT/usr/bin/systemctl"
chmod +x "$TEST_ROOT/usr/bin/systemctl"

asset_candidate=$'{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[]}\n'
asset_hash="sha256:$(printf '%s' "$asset_candidate" | sha256sum | cut -d' ' -f1)"
invoke missing-assets-prepare prepare missing-assets-operation missing-assets-node "$asset_hash" missing-assets-backup xray-main "$asset_candidate"
[[ "$status" -ne 0 ]] || fail 'prepare accepted a missing fixed Xray asset directory'
[[ "$errors" == '{"ok":false,"code":"XRAY_ASSETS_UNAVAILABLE"}' ]] \
    || fail 'missing fixed Xray assets returned the wrong error'
[[ ! -e "$TEST_ROOT/xray.log" ]] || fail 'missing fixed Xray assets reached Xray validation'
[[ ! -e "$TEST_ROOT/systemctl.log" ]] || fail 'missing fixed Xray assets reached service activation'
/usr/bin/cmp -s "$TMP_DIR/main-config.before" "$TEST_ROOT/usr/local/etc/xray/config.json" \
    || fail 'missing fixed Xray assets mutated the active config'
mkdir -p "$TEST_ROOT/usr/local/share/xray"

metadata_candidate=$'{"schemaVersion":1,"kind":"xray-topology-node-candidate","mode":"forward","nodeRef":"portal","role":"portal","targetProfile":"xray-main","links":[],"checks":[]}\n'
metadata_hash="sha256:$(printf '%s' "$metadata_candidate" | sha256sum | cut -d' ' -f1)"
invoke metadata-prepare prepare metadata-operation metadata-node "$metadata_hash" metadata-backup xray-main "$metadata_candidate"
[[ "$status" -ne 0 ]] || fail 'metadata-shaped candidate was accepted'
[[ "$errors" == '{"ok":false,"code":"INVALID_CANDIDATE"}' ]] \
    || fail 'metadata-shaped candidate returned the wrong error'
[[ ! -e "$TEST_ROOT/xray.log" ]] || fail 'metadata-shaped candidate reached Xray validation'
[[ ! -e "$TEST_ROOT/systemctl.log" ]] || fail 'metadata-shaped candidate reached service activation'
/usr/bin/cmp -s "$TMP_DIR/main-config.before" "$TEST_ROOT/usr/local/etc/xray/config.json" \
    || fail 'metadata rejection mutated the active config'

invalid_xray_candidate=$'{"log":{"loglevel":"warning"},"inbounds":[{"tag":"invalid-in","listen":"127.0.0.1","port":1080,"protocol":"unsupported-protocol","settings":{}}],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}],"routing":{"rules":[]}}\n'
invalid_xray_hash="sha256:$(printf '%s' "$invalid_xray_candidate" | sha256sum | cut -d' ' -f1)"
invoke invalid-xray-prepare prepare invalid-xray-operation invalid-xray-node "$invalid_xray_hash" invalid-xray-backup xray-main "$invalid_xray_candidate"
[[ "$status" -ne 0 ]] || fail 'Xray-invalid candidate was accepted'
[[ "$errors" == '{"ok":false,"code":"CANDIDATE_INVALID"}' ]] \
    || fail 'Xray-invalid candidate returned the wrong error'
[[ "$(<"$TEST_ROOT/xray.log")" == 'xray asset='"$TEST_ROOT"'/usr/local/share/xray run -test -config '"$TEST_ROOT"'/var/lib/celerity/topology/operations/invalid-xray-operation/xray-main/candidate.json' ]] \
    || fail 'Xray validation was not bound to the fixed assets and staged candidate'
[[ ! -e "$TEST_ROOT/systemctl.log" ]] || fail 'failed Xray validation reached service activation'
/usr/bin/cmp -s "$TMP_DIR/main-config.before" "$TEST_ROOT/usr/local/etc/xray/config.json" \
    || fail 'failed Xray validation mutated the active config'
rm -f "$TEST_ROOT/xray.log"

main_candidate=$'{"log":{"loglevel":"warning"},"inbounds":[{"tag":"main-candidate-secret-canary","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}],"routing":{"rules":[]}}\n'
printf '%s' "$main_candidate" >"$TMP_DIR/main-candidate.expected"
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
[[ "$(<"$TEST_ROOT/xray.log")" == 'xray asset='"$TEST_ROOT"'/usr/local/share/xray run -test -config '"$TEST_ROOT"'/var/lib/celerity/topology/operations/topology-operation-main/xray-main/candidate.json' ]] \
    || fail 'prepare did not bind the staged main config to the fixed Xray assets'

invoke main-commit commit "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main ''
[[ "$status" -eq 0 ]] || fail 'xray-main commit failed'
[[ "$output" == "$(receipt commit "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main)" ]] \
    || fail 'xray-main commit receipt was not strict and bound'
/usr/bin/cmp -s "$TMP_DIR/main-candidate.expected" "$TEST_ROOT/usr/local/etc/xray/config.json" \
    || fail 'commit did not activate the prepared main candidate'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray-bridge/config.json")" == '{"old":"bridge"}' ]] \
    || fail 'main commit escaped to the bridge target'
[[ "$(<"$TEST_ROOT/systemctl.log")" == 'systemctl restart xray.service' ]] \
    || fail 'main commit used a non-fixed service'

xray_calls_before_missing_assets="$(<"$TEST_ROOT/xray.log")"
systemctl_calls_before_missing_assets="$(<"$TEST_ROOT/systemctl.log")"
rmdir "$TEST_ROOT/usr/local/share/xray"
invoke missing-assets-main-verify verify "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main ''
[[ "$status" -ne 0 ]] || fail 'verify accepted a missing fixed Xray asset directory'
[[ "$errors" == '{"ok":false,"code":"XRAY_ASSETS_UNAVAILABLE"}' ]] \
    || fail 'active verification with missing Xray assets returned the wrong error'
[[ "$(<"$TEST_ROOT/xray.log")" == "$xray_calls_before_missing_assets" ]] \
    || fail 'active verification reached Xray with missing fixed assets'
[[ "$(<"$TEST_ROOT/systemctl.log")" == "$systemctl_calls_before_missing_assets" ]] \
    || fail 'active verification reached systemctl with missing fixed assets'
mkdir -p "$TEST_ROOT/usr/local/share/xray"

invoke main-verify verify "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main ''
[[ "$status" -eq 0 ]] || fail 'xray-main verify failed'
[[ "$output" == "$(receipt verify "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main)" ]] \
    || fail 'xray-main verify receipt was not strict and bound'
mapfile -t xray_calls <"$TEST_ROOT/xray.log"
[[ "${#xray_calls[@]}" -eq 2 \
    && "${xray_calls[0]}" == 'xray asset='"$TEST_ROOT"'/usr/local/share/xray run -test -config '"$TEST_ROOT"'/var/lib/celerity/topology/operations/topology-operation-main/xray-main/candidate.json' \
    && "${xray_calls[1]}" == 'xray asset='"$TEST_ROOT"'/usr/local/share/xray run -test -config '"$TEST_ROOT"'/usr/local/etc/xray/config.json' ]] \
    || fail 'active verification was not bound to the fixed Xray assets and config'
mapfile -t systemctl_calls <"$TEST_ROOT/systemctl.log"
[[ "${#systemctl_calls[@]}" -eq 2 \
    && "${systemctl_calls[0]}" == 'systemctl restart xray.service' \
    && "${systemctl_calls[1]}" == 'systemctl is-active --quiet xray.service' ]] \
    || fail 'verify did not explicitly require the main service to be active'

touch "$TEST_ROOT/service.inactive"
invoke inactive-main-verify verify "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main ''
[[ "$status" -ne 0 ]] || fail 'verify accepted an inactive main service'
[[ "$errors" == '{"ok":false,"code":"VERIFICATION_FAILED"}' ]] \
    || fail 'inactive main service returned the wrong verification error'
rm -f "$TEST_ROOT/service.inactive"

: >"$TEST_ROOT/xray.log"
: >"$TEST_ROOT/systemctl.log"
printf '%s\n' '{"inbounds":[],"outbounds":[]}' >"$TEST_ROOT/usr/local/etc/xray/config.json"
invoke wrong-active-hash verify "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main ''
[[ "$status" -ne 0 ]] || fail 'verify accepted an active config hash mismatch'
[[ "$errors" == '{"ok":false,"code":"VERIFICATION_FAILED"}' ]] \
    || fail 'active config hash mismatch returned the wrong verification error'
[[ ! -s "$TEST_ROOT/xray.log" && ! -s "$TEST_ROOT/systemctl.log" ]] \
    || fail 'active config hash mismatch reached runtime verification'
/usr/bin/cp "$TMP_DIR/main-candidate.expected" "$TEST_ROOT/usr/local/etc/xray/config.json"

: >"$TEST_ROOT/systemctl.log"
invoke main-rollback rollback "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main ''
[[ "$status" -eq 0 ]] || fail 'xray-main rollback failed'
[[ "$output" == "$(receipt rollback "$main_operation" "$main_node" "$main_hash" "$main_backup" xray-main)" ]] \
    || fail 'xray-main rollback receipt was not strict and bound'
/usr/bin/cmp -s "$TMP_DIR/main-config.before" "$TEST_ROOT/usr/local/etc/xray/config.json" \
    || fail 'rollback did not restore the exact main backup'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray-bridge/config.json")" == '{"old":"bridge"}' ]] \
    || fail 'main rollback escaped to the bridge target'
[[ "$(<"$TEST_ROOT/do-not-touch")" == 'outside-rollback-scope' ]] \
    || fail 'rollback mutated a target outside its fixed scope'
[[ "$(<"$TEST_ROOT/systemctl.log")" == 'systemctl restart xray.service' ]] \
    || fail 'main rollback used a non-fixed service'

bridge_candidate=$'{"log":{"loglevel":"warning"},"inbounds":[{"tag":"bridge-candidate-secret-canary","listen":"127.0.0.1","port":1081,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}],"routing":{"rules":[]}}\n'
printf '%s' "$bridge_candidate" >"$TMP_DIR/bridge-candidate.expected"
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
/usr/bin/cmp -s "$TMP_DIR/bridge-candidate.expected" "$TEST_ROOT/usr/local/etc/xray-bridge/config.json" \
    || fail 'commit did not activate the bridge candidate'
[[ "$(<"$TEST_ROOT/usr/local/etc/xray/config.json")" == '{"old":"main"}' ]] \
    || fail 'bridge commit escaped to the main target'
[[ "$(<"$TEST_ROOT/systemctl.log")" == 'systemctl restart xray-bridge.service' ]] \
    || fail 'bridge commit used a non-fixed service'
invoke bridge-rollback rollback "$bridge_operation" "$bridge_node" "$bridge_hash" "$bridge_backup" xray-bridge ''
[[ "$status" -eq 0 ]] || fail 'xray-bridge rollback failed'
/usr/bin/cmp -s "$TMP_DIR/bridge-config.before" "$TEST_ROOT/usr/local/etc/xray-bridge/config.json" \
    || fail 'bridge rollback did not restore its exact backup'

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
