#!/usr/bin/env bash
set -Eeuo pipefail

readonly OPERATIONS_ROOT='/var/lib/celerity/l2tp/operations'
readonly RUNNER_PATH="$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}")"
readonly ARTIFACT_DIR="${RUNNER_PATH%/*}"

emit_error() {
    local code="$1"
    printf '{"status":"error","code":"%s"}\n' "$code" >&2
}

exec_artifact() {
    local artifact_path="$1"
    shift
    if [[ ! -x "$artifact_path" ]]; then
        emit_error 'ARTIFACT_UNAVAILABLE'
        exit 69
    fi
    exec "$artifact_path" "$@"
}

if [[ "$#" -ne 4 || "$1" != '--operation-id' || "$3" != '--command' ]]; then
    emit_error 'INVALID_ARGUMENTS'
    exit 64
fi

readonly OPERATION_ID="$2"
readonly COMMAND="$4"
if [[ ! "$OPERATION_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$ ]]; then
    emit_error 'INVALID_OPERATION_ID'
    exit 65
fi

readonly OPERATION_DIR="$OPERATIONS_ROOT/$OPERATION_ID"
case "$COMMAND" in
    preflight)
        exec_artifact "$ARTIFACT_DIR/preflight.sh" "$OPERATION_DIR/desired.json"
        ;;
    stage_managed_files)
        exec_artifact "$ARTIFACT_DIR/apply.sh" "$OPERATION_DIR/artifacts.json" '/'
        ;;
    validate_xray)
        exec_artifact "$ARTIFACT_DIR/validate-xray.sh" "$OPERATION_DIR"
        ;;
    validate_nft)
        exec_artifact "$ARTIFACT_DIR/validate-nft.sh" "$OPERATION_DIR"
        ;;
    rollback)
        exec_artifact "$ARTIFACT_DIR/rollback.sh" "$OPERATION_DIR"
        ;;
    *)
        emit_error 'UNKNOWN_COMMAND'
        exit 64
        ;;
esac
