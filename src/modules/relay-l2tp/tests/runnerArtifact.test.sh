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
        printf '%s\n' 'printf '\''%s\n'\'' "${0##*/}" "$@" >"$RUNNER_CALL_LOG"'
        printf '%s\n' 'printf '\''{"status":"ok","artifact":"%s"}\n'\'' "${0##*/}"'
    } >"$TMP_DIR/lib/$name"
    chmod +x "$TMP_DIR/lib/$name"
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
make_sibling_artifact apply.sh
for forbidden in preflight.sh apply.sh apt apt-get systemctl nft; do
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

max_operation_id="$(printf 'a%.0s' {1..128})"
rm -f "$TMP_DIR/call.log"
invoke_runner max-id --operation-id "$max_operation_id" --command preflight
[[ "$status" -eq 0 ]] || fail '128-character operation id was rejected'
mapfile -t call <"$TMP_DIR/call.log"
[[ "${call[1]}" == "/var/lib/celerity/l2tp/operations/$max_operation_id/desired.json" ]] \
    || fail 'maximum-length operation id was not passed as data'

for command in validate_xray validate_nft rollback; do
    rm -f "$TMP_DIR/call.log"
    invoke_runner "not-implemented-$command" --operation-id operation-20 --command "$command"
    [[ "$status" -ne 0 ]] || fail "$command unexpectedly succeeded"
    [[ "$(<"$output")" == "{\"status\":\"error\",\"code\":\"NOT_IMPLEMENTED\",\"command\":\"$command\"}" ]] \
        || fail "$command returned the wrong structured error"
    [[ ! -e "$TMP_DIR/call.log" ]] || fail "$command invoked an artifact"
done

expect_error unknown-command UNKNOWN_COMMAND \
    --operation-id operation-21 --command backup
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
