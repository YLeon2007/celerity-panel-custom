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
readonly CANDIDATE_RELATIVE_PATH='candidate/xray.json'
readonly CANDIDATE_PATH="$OPERATION_DIR/$CANDIDATE_RELATIVE_PATH"

if [[ ! -f "$CANDIDATE_PATH" || ! -r "$CANDIDATE_PATH" || -L "$CANDIDATE_PATH" ]]; then
    emit_error 'XRAY_CANDIDATE_MISSING'
    exit 66
fi

xray_path="$(command -v xray || true)"
if [[ -z "$xray_path" ]]; then
    emit_error 'XRAY_BINARY_MISSING'
    exit 69
fi

if ! "$xray_path" run -test -config "$CANDIDATE_PATH" >/dev/null 2>&1; then
    emit_error 'XRAY_CANDIDATE_INVALID'
    exit 65
fi

printf '{"status":"ok","validator":"xray","candidate":"%s"}\n' "$CANDIDATE_RELATIVE_PATH"
