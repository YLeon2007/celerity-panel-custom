#!/bin/bash
set -Eeuo pipefail

readonly RECEIVER_SHA256='b9c602a7af257a774addebe25042fca8fc83b9e0d544207e2228dd78a448a8b2'
readonly RUNNER_SHA256='6c8ff782b2d95a9b9f0c7e7009e93c3a3caf97e914cf74ddc6c96b7e14ca3041'
readonly RECEIVER_TARGET='/usr/local/bin/celerity-l2tp-artifact-receiver'
readonly RUNNER_TARGET='/usr/local/bin/celerity-l2tp-artifact-runner'
readonly OPERATIONS_ROOT='/var/lib/celerity/l2tp/operations'
TEMPORARY_TARGETS=()

emit_error() {
    local code="$1"
    printf '{"status":"error","code":"%s"}\n' "$code" >&2
}

fail() {
    local code="$1"
    local status="$2"
    emit_error "$code"
    exit "$status"
}

cleanup() {
    local target
    for target in "${TEMPORARY_TARGETS[@]}"; do
        /usr/bin/rm -f -- "$target" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

verify_directory() {
    local directory="$1"
    local metadata owner group mode file_type
    [[ -d "$directory" && ! -L "$directory" ]] || return 1
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$directory" 2>/dev/null)" || return 1
    IFS=: read -r owner group mode file_type <<<"$metadata"
    [[ "$owner" == '0' && "$group" == '0' && "$file_type" == 'directory' ]] || return 1
    (( (8#$mode & 0002) == 0 ))
}

verify_artifact() {
    local artifact="$1"
    local expected_digest="$2"
    local metadata digest_line digest

    [[ -f "$artifact" && ! -L "$artifact" ]] || return 1
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$artifact" 2>/dev/null)" || return 1
    [[ "$metadata" == '0:0:755:regular file' ]] || return 1
    digest_line="$(/usr/bin/sha256sum -- "$artifact" 2>/dev/null)" || return 1
    digest="${digest_line%% *}"
    [[ "$digest" == "$expected_digest" ]]
}

verify_exact_directory() {
    local directory="$1"
    local expected_mode="$2"
    local metadata
    [[ -d "$directory" && ! -L "$directory" ]] || return 1
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$directory" 2>/dev/null)" || return 1
    [[ "$metadata" == "0:0:$expected_mode:directory" ]]
}

prepare_operations_root() {
    local directory
    for directory in '/var/lib/celerity' '/var/lib/celerity/l2tp' "$OPERATIONS_ROOT"; do
        if [[ -e "$directory" || -L "$directory" ]]; then
            verify_directory "$directory" || fail 'INVALID_TARGET' 73
        fi
    done

    /usr/bin/install -d -o 0 -g 0 -m 0755 -- '/var/lib/celerity' >/dev/null 2>&1 \
        || fail 'INSTALL_FAILED' 70
    /usr/bin/install -d -o 0 -g 0 -m 0700 -- '/var/lib/celerity/l2tp' "$OPERATIONS_ROOT" \
        >/dev/null 2>&1 || fail 'INSTALL_FAILED' 70
    verify_exact_directory '/var/lib/celerity' '755' || fail 'INSTALL_FAILED' 70
    verify_exact_directory '/var/lib/celerity/l2tp' '700' || fail 'INSTALL_FAILED' 70
    verify_exact_directory "$OPERATIONS_ROOT" '700' || fail 'INSTALL_FAILED' 70
}

install_artifact() {
    local source="$1"
    local target="$2"
    local expected_digest="$3"
    local temporary

    temporary="$(/usr/bin/mktemp --tmpdir=/usr/local/bin ".${target##*/}.XXXXXX" 2>/dev/null)" \
        || fail 'INSTALL_FAILED' 70
    TEMPORARY_TARGETS+=("$temporary")
    /usr/bin/install -o 0 -g 0 -m 0755 -- "$source" "$temporary" >/dev/null 2>&1 \
        || fail 'INSTALL_FAILED' 70
    verify_artifact "$temporary" "$expected_digest" || fail 'INSTALL_FAILED' 70
    /usr/bin/mv -fT -- "$temporary" "$target" >/dev/null 2>&1 \
        || fail 'INSTALL_FAILED' 70
    verify_artifact "$target" "$expected_digest" || fail 'INSTALL_FAILED' 70
}

if [[ "$#" -ne 0 ]]; then
    fail 'INVALID_ARGUMENTS' 64
fi
if [[ "$EUID" -ne 0 ]]; then
    fail 'ROOT_REQUIRED' 77
fi

INSTALLER_PATH="$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null)" \
    || fail 'INVALID_PACKAGE' 65
readonly INSTALLER_PATH
readonly ARTIFACT_DIR="${INSTALLER_PATH%/*}"
readonly RECEIVER_SOURCE="$ARTIFACT_DIR/receive-artifact.py"
readonly RUNNER_SOURCE="$ARTIFACT_DIR/runner.sh"

verify_directory "$ARTIFACT_DIR" || fail 'INVALID_PACKAGE' 65
verify_directory '/usr/local/bin' || fail 'INVALID_TARGET' 73
verify_directory '/var/lib' || fail 'INVALID_TARGET' 73
verify_artifact "$RECEIVER_SOURCE" "$RECEIVER_SHA256" || fail 'INVALID_PACKAGE' 65
verify_artifact "$RUNNER_SOURCE" "$RUNNER_SHA256" || fail 'INVALID_PACKAGE' 65

prepare_operations_root
# Publish the verified receiver before the runner can expose package commands.
install_artifact "$RECEIVER_SOURCE" "$RECEIVER_TARGET" "$RECEIVER_SHA256"
install_artifact "$RUNNER_SOURCE" "$RUNNER_TARGET" "$RUNNER_SHA256"

printf '{"status":"ok"}\n'
