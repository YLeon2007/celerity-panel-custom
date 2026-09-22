#!/usr/bin/env bash
set -Eeuo pipefail

emit_error() {
    local code="$1"
    printf '{"status":"error","code":"%s"}\n' "$code" >&2
}

if [[ "$#" -ne 1 ]]; then
    emit_error 'INVALID_ARGUMENTS'
    exit 64
fi

readonly OPERATION_DIR="$1"
readonly ROLLBACK_PATH="$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}")"
readonly ARTIFACT_DIR="${ROLLBACK_PATH%/*}"
readonly APPLY_PATH="$ARTIFACT_DIR/apply.sh"
readonly BACKUP_MANIFEST_PATH="$OPERATION_DIR/backup.json"

if [[ ! -x "$APPLY_PATH" ]]; then
    emit_error 'ARTIFACT_UNAVAILABLE'
    exit 69
fi

exec "$APPLY_PATH" "$BACKUP_MANIFEST_PATH" '/'
