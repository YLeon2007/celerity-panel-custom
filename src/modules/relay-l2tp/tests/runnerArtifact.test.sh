#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
RUNNER_SOURCE="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/runner.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

make_sibling_artifact() {
    local name="$1"
    {
        printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
        printf '%s\n' 'printf '\''%s\n'\'' "${0##*/}" "$@" >>"$RUNNER_CALL_LOG"'
        printf '%s\n' 'printf '\''{"status":"ok","artifact":"%s"}\n'\'' "${0##*/}"'
    } >"$TMP_DIR/lib/$name"
    chmod +x "$TMP_DIR/lib/$name"
}

make_materializer_artifact() {
    cat >"$TMP_DIR/lib/materialize-nft-candidate.sh" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "${0##*/}" "$@" >>"$RUNNER_CALL_LOG"
printf '%s\n' '{"status":"ok","artifact":"materialize-nft-candidate.sh"}'
exit "${MATERIALIZE_NFT_STATUS:-0}"
STUB
    chmod +x "$TMP_DIR/lib/materialize-nft-candidate.sh"
}

make_forbidden_command() {
    local name="$1"
    {
        printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
        printf '%s\n' 'printf '\''%s\n'\'' "${0##*/}" >>"$MUTATION_LOG"'
        printf '%s\n' 'exit 99'
    } >"$TMP_DIR/bin/$name"
    chmod +x "$TMP_DIR/bin/$name"
}

invoke_runner() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    set +e
    PATH="$TMP_DIR/bin:$PATH" \
        RUNNER_CALL_LOG="$TMP_DIR/call.log" \
        MUTATION_LOG="$TMP_DIR/mutations.log" \
        MATERIALIZE_NFT_STATUS="${MATERIALIZE_NFT_STATUS:-0}" \
        "$TMP_DIR/bin/celerity-l2tp-artifact-runner" "$@" >"$output" 2>&1
    status=$?
    set -e
}

expect_error() {
    local label="$1"
    local expected_code="$2"
    shift 2
    rm -f "$TMP_DIR/call.log"
    invoke_runner "$label" "$@"
    [[ "$status" -ne 0 ]] || fail "$label was accepted"
    [[ "$(<"$output")" == "{\"status\":\"error\",\"code\":\"$expected_code\"}" ]] \
        || fail "$label returned the wrong structured error"
    [[ ! -e "$TMP_DIR/call.log" ]] || fail "$label invoked an artifact"
}

[[ -x "$RUNNER_SOURCE" ]] || fail 'runner artifact is missing or not executable'
mkdir -p "$TMP_DIR/lib" "$TMP_DIR/bin"
: >"$TMP_DIR/mutations.log"
cp "$RUNNER_SOURCE" "$TMP_DIR/lib/runner.sh"
chmod +x "$TMP_DIR/lib/runner.sh"
ln -s "$TMP_DIR/lib/runner.sh" "$TMP_DIR/bin/celerity-l2tp-artifact-runner"
make_sibling_artifact preflight.sh
make_sibling_artifact install-runtime.sh
make_sibling_artifact backup.sh
make_sibling_artifact apply.sh
make_sibling_artifact compose-xray-fragment.sh
make_sibling_artifact validate-xray.sh
make_materializer_artifact
make_sibling_artifact validate-nft.sh
make_sibling_artifact activate-xray.sh
make_sibling_artifact apply-firewall-policy.sh
make_sibling_artifact start-l2tp.sh
make_sibling_artifact sync-users.sh
make_sibling_artifact verify.sh
make_sibling_artifact commit.sh
make_sibling_artifact rollback.sh
for forbidden in preflight.sh install-runtime.sh backup.sh apply.sh compose-xray-fragment.sh validate-xray.sh materialize-nft-candidate.sh validate-nft.sh activate-xray.sh apply-firewall-policy.sh start-l2tp.sh sync-users.sh verify.sh commit.sh rollback.sh apt apt-get systemctl nft; do
    make_forbidden_command "$forbidden"
done

invoke_runner preflight --operation-id operation_18-ABC --command preflight
[[ "$status" -eq 0 ]] || fail 'preflight dispatch failed'
[[ "$(<"$output")" == '{"status":"ok","artifact":"preflight.sh"}' ]] \
    || fail 'preflight did not execute the fixed sibling artifact'
mapfile -t call <"$TMP_DIR/call.log"
[[ "${#call[@]}" -eq 2 ]] || fail 'preflight received an unexpected argument count'
[[ "${call[0]}" == 'preflight.sh' ]] || fail 'preflight invoked the wrong artifact'
[[ "${call[1]}" == '/var/lib/celerity/l2tp/operations/operation_18-ABC/desired.json' ]] \
    || fail 'preflight received the wrong desired-state path'

rm -f "$TMP_DIR/call.log"
invoke_runner stage --operation-id operation-19 --command stage_managed_files
[[ "$status" -eq 0 ]] || fail 'stage_managed_files dispatch failed'
[[ "$(<"$output")" == '{"status":"ok","artifact":"apply.sh"}' ]] \
    || fail 'stage_managed_files did not execute the fixed sibling artifact'
mapfile -t call <"$TMP_DIR/call.log"
[[ "${#call[@]}" -eq 3 ]] || fail 'stage_managed_files received an unexpected argument count'
[[ "${call[0]}" == 'apply.sh' ]] || fail 'stage_managed_files invoked the wrong artifact'
[[ "${call[1]}" == '/var/lib/celerity/l2tp/operations/operation-19/artifacts.json' ]] \
    || fail 'stage_managed_files received the wrong manifest path'
[[ "${call[2]}" == '/' ]] || fail 'stage_managed_files received a non-root apply target'

rm -f "$TMP_DIR/call.log"
invoke_runner backup --operation-id operation-19 --command backup
[[ "$status" -eq 0 ]] || fail 'backup dispatch failed'
[[ "$(<"$output")" == '{"status":"ok","artifact":"backup.sh"}' ]] \
    || fail 'backup did not execute the fixed sibling artifact'
mapfile -t call <"$TMP_DIR/call.log"
[[ "${#call[@]}" -eq 3 ]] || fail 'backup received an unexpected argument count'
[[ "${call[0]}" == 'backup.sh' ]] || fail 'backup invoked the wrong artifact'
[[ "${call[1]}" == '/var/lib/celerity/l2tp/operations/operation-19' ]] \
    || fail 'backup received the wrong operation directory'
[[ "${call[2]}" == '/' ]] || fail 'backup received a non-root backup target'

rm -f "$TMP_DIR/call.log"
invoke_runner install-runtime --operation-id operation-19 --command install_runtime
[[ "$status" -eq 0 ]] || fail 'install_runtime dispatch failed'
[[ "$(<"$output")" == '{"status":"ok","artifact":"install-runtime.sh"}' ]] \
    || fail 'install_runtime did not execute the fixed sibling artifact'
mapfile -t call <"$TMP_DIR/call.log"
[[ "${#call[@]}" -eq 1 ]] || fail 'install_runtime received arguments'
[[ "${call[0]}" == 'install-runtime.sh' ]] || fail 'install_runtime invoked the wrong artifact'

max_operation_id="$(printf 'a%.0s' {1..128})"
rm -f "$TMP_DIR/call.log"
invoke_runner max-id --operation-id "$max_operation_id" --command preflight
[[ "$status" -eq 0 ]] || fail '128-character operation id was rejected'
mapfile -t call <"$TMP_DIR/call.log"
[[ "${call[1]}" == "/var/lib/celerity/l2tp/operations/$max_operation_id/desired.json" ]] \
    || fail 'maximum-length operation id was not passed as data'

declare -A command_artifacts=(
    [compose_xray_fragment]='compose-xray-fragment.sh'
    [validate_xray]='validate-xray.sh'
    [apply_firewall_policy]='apply-firewall-policy.sh'
    [start_l2tp]='start-l2tp.sh'
    [sync_users]='sync-users.sh'
    [verify]='verify.sh'
    [commit]='commit.sh'
    [rollback]='rollback.sh'
)
for command in compose_xray_fragment validate_xray apply_firewall_policy start_l2tp sync_users verify commit rollback; do
    rm -f "$TMP_DIR/call.log"
    invoke_runner "$command" --operation-id operation-20 --command "$command"
    [[ "$status" -eq 0 ]] || fail "$command dispatch failed"
    artifact="${command_artifacts[$command]}"
    [[ "$(<"$output")" == "{\"status\":\"ok\",\"artifact\":\"$artifact\"}" ]] \
        || fail "$command did not execute the fixed sibling artifact"
    mapfile -t call <"$TMP_DIR/call.log"
    [[ "${#call[@]}" -eq 2 ]] || fail "$command received an unexpected argument count"
    [[ "${call[0]}" == "$artifact" ]] || fail "$command invoked the wrong artifact"
    [[ "${call[1]}" == '/var/lib/celerity/l2tp/operations/operation-20' ]] \
        || fail "$command received the wrong operation directory"
done

rm -f "$TMP_DIR/call.log"
invoke_runner validate_nft --operation-id operation-20 --command validate_nft
[[ "$status" -eq 0 ]] || fail 'validate_nft dispatch failed'
[[ "$(<"$output")" == '{"status":"ok","artifact":"validate-nft.sh"}' ]] \
    || fail 'validate_nft did not return only the validator result'
mapfile -t call <"$TMP_DIR/call.log"
[[ "${#call[@]}" -eq 4 ]] || fail 'validate_nft did not invoke exactly two fixed artifacts'
[[ "${call[0]}" == 'materialize-nft-candidate.sh' \
    && "${call[1]}" == '/var/lib/celerity/l2tp/operations/operation-20' \
    && "${call[2]}" == 'validate-nft.sh' \
    && "${call[3]}" == '/var/lib/celerity/l2tp/operations/operation-20' ]] \
    || fail 'validate_nft did not materialize the fixed candidate before validation'

rm -f "$TMP_DIR/call.log"
MATERIALIZE_NFT_STATUS=23 invoke_runner validate_nft-materializer-failure \
    --operation-id operation-20 --command validate_nft
unset MATERIALIZE_NFT_STATUS
[[ "$status" -ne 0 ]] || fail 'validate_nft continued after candidate materialization failed'
mapfile -t call <"$TMP_DIR/call.log"
[[ "${#call[@]}" -eq 2 \
    && "${call[0]}" == 'materialize-nft-candidate.sh' \
    && "${call[1]}" == '/var/lib/celerity/l2tp/operations/operation-20' ]] \
    || fail 'validate_nft invoked the validator after materialization failed'

rm -f "$TMP_DIR/call.log"
invoke_runner activate_xray --operation-id operation-20 --command activate_xray
[[ "$status" -eq 0 ]] || fail 'activate_xray dispatch failed'
[[ "$(<"$output")" == '{"status":"ok","artifact":"activate-xray.sh"}' ]] \
    || fail 'activate_xray did not execute the fixed sibling artifact'
mapfile -t call <"$TMP_DIR/call.log"
[[ "${#call[@]}" -eq 3 ]] || fail 'activate_xray received an unexpected argument count'
[[ "${call[0]}" == 'activate-xray.sh' ]] || fail 'activate_xray invoked the wrong artifact'
[[ "${call[1]}" == '/var/lib/celerity/l2tp/operations/operation-20' ]] \
    || fail 'activate_xray received the wrong operation directory'
[[ "${call[2]}" == '/' ]] || fail 'activate_xray received a non-root activation target'

expect_error unknown-command UNKNOWN_COMMAND \
    --operation-id operation-21 --command install_runtime_raw
expect_error missing-arguments INVALID_ARGUMENTS \
    --operation-id operation-21
expect_error extra-arguments INVALID_ARGUMENTS \
    --operation-id operation-21 --command preflight --raw-command id
expect_error reordered-flags INVALID_ARGUMENTS \
    --command preflight --operation-id operation-21
expect_error duplicate-command INVALID_ARGUMENTS \
    --operation-id operation-21 --command preflight --command rollback

long_operation_id="$(printf 'a%.0s' {1..129})"
for invalid_operation_id in \
    '' \
    '-starts-with-dash' \
    '.hidden' \
    '../escape' \
    'nested/id' \
    'contains space' \
    'operation;id' \
    'operation$id' \
    "$long_operation_id"; do
    expect_error "invalid-operation-${RANDOM}" INVALID_OPERATION_ID \
        --operation-id "$invalid_operation_id" --command preflight
done

marker="$TMP_DIR/raw-command-ran"
secret='do-not-echo-this-secret'
expect_error injected-command UNKNOWN_COMMAND \
    --operation-id operation-22 --command "preflight; touch $marker; $secret"
[[ ! -e "$marker" ]] || fail 'raw command input was executed'
! grep -Fq -- "$secret" "$output" || fail 'rejected raw command input leaked to output'
[[ ! -s "$TMP_DIR/mutations.log" ]] || fail 'runner attempted a forbidden system command or PATH artifact'

printf 'runner artifact fixture tests passed\n'
