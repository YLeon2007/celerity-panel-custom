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
# Operations whose first step carries no artifacts (e.g. sync_users backup)
# have no upload to create the directory — create it on demand.
if [[ -L "$OPERATION_DIR" ]]; then
    emit_error 'INVALID_OPERATION_DIRECTORY'
    exit 66
fi
if [[ ! -d "$OPERATION_DIR" ]]; then
    if ! /usr/bin/install -d -m 0700 -o root -g root -- "$OPERATION_DIR"; then
        emit_error 'INVALID_OPERATION_DIRECTORY'
        exit 66
    fi
fi
case "$COMMAND" in
    preflight)
        exec_artifact "$ARTIFACT_DIR/preflight.sh" "$OPERATION_DIR/desired.json"
        ;;
    install_runtime)
        exec_artifact "$ARTIFACT_DIR/install-runtime.sh"
        ;;
    backup)
        exec_artifact "$ARTIFACT_DIR/backup.sh" "$OPERATION_DIR" '/'
        ;;
    stage_managed_files)
        exec_artifact "$ARTIFACT_DIR/apply.sh" "$OPERATION_DIR/artifacts.json" '/'
        ;;
    compose_xray_fragment)
        exec_artifact "$ARTIFACT_DIR/compose-xray-fragment.sh" "$OPERATION_DIR"
        ;;
    validate_xray)
        exec_artifact "$ARTIFACT_DIR/validate-xray.sh" "$OPERATION_DIR"
        ;;
    validate_nft)
        if [[ ! -x "$ARTIFACT_DIR/materialize-nft-candidate.sh" ]]; then
            emit_error 'ARTIFACT_UNAVAILABLE'
            exit 69
        fi
        "$ARTIFACT_DIR/materialize-nft-candidate.sh" "$OPERATION_DIR" >/dev/null
        exec_artifact "$ARTIFACT_DIR/validate-nft.sh" "$OPERATION_DIR"
        ;;
    activate_xray)
        exec_artifact "$ARTIFACT_DIR/activate-xray.sh" "$OPERATION_DIR" '/'
        ;;
    apply_firewall_policy)
        exec_artifact "$ARTIFACT_DIR/apply-firewall-policy.sh" "$OPERATION_DIR"
        ;;
    start_l2tp)
        exec_artifact "$ARTIFACT_DIR/start-l2tp.sh" "$OPERATION_DIR"
        ;;
    sync-users)
        exec_artifact "$ARTIFACT_DIR/sync-users.sh" "$OPERATION_DIR"
        ;;
    verify-users)
        exec_artifact "$ARTIFACT_DIR/verify-users.sh" "$OPERATION_DIR"
        ;;
    verify)
        exec_artifact "$ARTIFACT_DIR/verify.sh" "$OPERATION_DIR"
        ;;
    commit)
        exec_artifact "$ARTIFACT_DIR/commit.sh" "$OPERATION_DIR"
        ;;
    rollback)
        exec_artifact "$ARTIFACT_DIR/rollback.sh" "$OPERATION_DIR"
        ;;
    *)
        emit_error 'UNKNOWN_COMMAND'
        exit 64
        ;;
esac
