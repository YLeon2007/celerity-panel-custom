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
readonly CANDIDATE_DIR="$OPERATION_DIR/candidate"
readonly CANDIDATE_PATH="$CANDIDATE_DIR/xray.json"
if [[ ! -d "$OPERATION_DIR" || -L "$OPERATION_DIR" \
    || ! -d "$CANDIDATE_DIR" || -L "$CANDIDATE_DIR" \
    || ! -f "$CANDIDATE_PATH" || ! -r "$CANDIDATE_PATH" || -L "$CANDIDATE_PATH" ]]; then
    emit_error 'XRAY_CANDIDATE_MISSING'
    exit 66
fi
if [[ "$(stat --format='%u' -- "$CANDIDATE_PATH" 2>/dev/null || true)" != '0' ]]; then
    emit_error 'XRAY_CANDIDATE_NOT_ROOT_OWNED'
    exit 77
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

printf '%s\n' '{"status":"ok","mode":"verify_official_composer_output","candidate":"candidate/xray.json"}'
