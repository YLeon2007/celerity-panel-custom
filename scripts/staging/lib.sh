#!/usr/bin/env bash
set -euo pipefail

readonly CELERITY_TEST_TARGET='test'
readonly CELERITY_TEST_HOST='test.infograd.online'
readonly CELERITY_INSTALL_ROOT='/opt/hysteria-panel'
readonly CELERITY_BACKUP_ROOT='/opt/hysteria-panel-test-backups'
readonly CELERITY_COMPOSE_FILE='docker-compose.yml'
readonly CELERITY_APP_SERVICE='backend'

fail() {
    printf 'staging control refused: %s\n' "$1" >&2
    exit 64
}

require_test_target() {
    local target=${1-}
    [[ "$target" == "$CELERITY_TEST_TARGET" ]] \
        || fail 'explicit --target test is required'
}

require_test_host_identity() {
    local identity=${1-}
    [[ "$identity" == "$CELERITY_TEST_HOST" ]] \
        || fail "host identity must be exactly $CELERITY_TEST_HOST"
}

require_control_paths() {
    local install_root=${1-}
    local backup_root=${2-}
    [[ "$install_root" == "$CELERITY_INSTALL_ROOT" ]] \
        || fail "install root must be exactly $CELERITY_INSTALL_ROOT"
    [[ "$backup_root" == "$CELERITY_BACKUP_ROOT" ]] \
        || fail "backup root must be exactly $CELERITY_BACKUP_ROOT"
}

require_sha256() {
    local label=$1
    local value=${2-}
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || fail "$label must be a lowercase SHA-256"
}

require_git_oid() {
    local label=$1
    local value=${2-}
    [[ "$value" =~ ^[0-9a-f]{40}$ ]] || fail "$label must be a full lowercase Git object id"
}

require_local_regular_file() {
    local label=$1
    local file_path=${2-}
    [[ -n "$file_path" && -f "$file_path" && ! -L "$file_path" ]] \
        || fail "$label must reference a local regular file"
}

sha256_file() {
    sha256sum --binary -- "$1" | cut -d ' ' -f 1
}

require_file_checksum() {
    local label=$1
    local file_path=$2
    local expected=$3
    local actual
    actual=$(sha256_file "$file_path")
    [[ "$actual" == "$expected" ]] || fail "$label checksum mismatch"
}

resolve_control_path() {
    local logical_path=$1
    local test_root=${CELERITY_STAGING_TEST_FS_ROOT-}
    local mapped_path
    local mapped_parent
    local physical_parent
    if [[ -z "$test_root" ]]; then
        printf '%s\n' "$logical_path"
        return
    fi
    [[ ${CELERITY_STAGING_TEST_MODE-} == '1' ]] \
        || fail 'test filesystem root requires CELERITY_STAGING_TEST_MODE=1'
    [[ "$test_root" == /tmp/* && -d "$test_root" && ! -L "$test_root" ]] \
        || fail 'test filesystem root must be a real directory below /tmp'
    test_root=$(cd -- "$test_root" && pwd -P)
    [[ "$test_root" == /tmp/* ]] || fail 'test filesystem root escaped /tmp'
    [[ "$logical_path" == /* \
        && "$logical_path" != *'//'* \
        && "$logical_path" != *'/./'* \
        && "$logical_path" != *'/../'* \
        && "$logical_path" != */. \
        && "$logical_path" != */.. ]] \
        || fail 'test filesystem logical path is unsafe'
    mapped_path="$test_root$logical_path"
    mapped_parent=$(dirname -- "$mapped_path")
    [[ -d "$mapped_parent" ]] || fail 'test filesystem mapped parent is missing'
    physical_parent=$(cd -- "$mapped_parent" && pwd -P)
    [[ "$physical_parent" == "$test_root" || "$physical_parent" == "$test_root"/* ]] \
        || fail 'test filesystem path escaped its isolated root'
    printf '%s\n' "$mapped_path"
}

require_safe_git_head_metadata() {
    local repository_root=$1
    local label=$2
    local git_metadata="$repository_root/.git"
    local git_head="$git_metadata/HEAD"
    local head_value
    local head_reference
    local head_reference_path
    local head_reference_parent
    local packed_references="$git_metadata/packed-refs"
    local reference_index
    local -a head_reference_parts=()

    [[ -d "$git_metadata" && ! -L "$git_metadata" ]] \
        || fail "$label Git metadata must be a real directory"
    [[ -f "$git_head" && ! -L "$git_head" ]] \
        || fail "$label Git HEAD must be a regular file"
    head_value=$(<"$git_head")
    if [[ "$head_value" == 'ref: '* ]]; then
        head_reference=${head_value#'ref: '}
        if [[ "$head_reference" != refs/* \
            || "$head_reference" == *$'\n'* ]] \
            || ! git check-ref-format "$head_reference" >/dev/null 2>&1; then
            fail "$label Git HEAD reference is unsafe"
        fi
        IFS='/' read -r -a head_reference_parts <<< "$head_reference"
        head_reference_parent=$git_metadata
        for ((reference_index = 0; reference_index < ${#head_reference_parts[@]} - 1; reference_index++)); do
            head_reference_parent+="/${head_reference_parts[$reference_index]}"
            if [[ -L "$head_reference_parent" \
                || ( -e "$head_reference_parent" && ! -d "$head_reference_parent" ) ]]; then
                fail "$label Git HEAD reference path must use real directories"
            fi
        done
        head_reference_path="$git_metadata/$head_reference"
        if [[ -L "$head_reference_path" \
            || ( -e "$head_reference_path" && ! -f "$head_reference_path" ) ]]; then
            fail "$label Git HEAD reference must be a regular file"
        fi
        if [[ ! -e "$head_reference_path" \
            && ( -L "$packed_references" \
                || ( -e "$packed_references" && ! -f "$packed_references" ) ) ]]; then
            fail "$label Git packed references must be a regular file"
        fi
    fi
}
