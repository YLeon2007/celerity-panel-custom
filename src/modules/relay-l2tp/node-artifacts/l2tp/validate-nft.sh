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
readonly CANDIDATE_RELATIVE_PATH='candidate/celerity-l2tp.nft'
readonly CANDIDATE_PATH="$OPERATION_DIR/$CANDIDATE_RELATIVE_PATH"

if [[ ! -f "$CANDIDATE_PATH" || ! -r "$CANDIDATE_PATH" || -L "$CANDIDATE_PATH" ]]; then
    emit_error 'NFT_CANDIDATE_MISSING'
    exit 66
fi

nft_path="$(command -v nft || true)"
if [[ -z "$nft_path" ]]; then
    emit_error 'NFT_BINARY_MISSING'
    exit 69
fi

if ! "$nft_path" -c -f "$CANDIDATE_PATH" >/dev/null 2>&1; then
    emit_error 'NFT_CANDIDATE_INVALID'
    exit 65
fi

printf '{"status":"ok","validator":"nft","candidate":"%s"}\n' "$CANDIDATE_RELATIVE_PATH"
