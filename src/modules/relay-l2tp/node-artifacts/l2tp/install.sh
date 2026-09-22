#!/bin/bash
set -Eeuo pipefail

declare -Ar PAYLOAD_SHA256=(
    [runner.sh]='a078129a1ee7f4692cd68d4b7f803c7eae8fb87a7868a25ae8cf9f685d082ae1'
    [receive-artifact.py]='e4a107d0220284c358534ea0a7f2b8ec8a7f3952956eeebb33a7a68450988f4b'
    [apply.sh]='dfd396096bd85c2e931682f05840d2f6cce5246212288f6f2b91e2e660ccbe95'
    [preflight.sh]='a5f2c845beb4cdc781688efee00745f4edca98f7e5599a78007e411d9b2d709e'
    [backup.sh]='4aa837b461ae85627dd8f4b06fb785939b3bb6942fc85fe605c8aa7d4548b9eb'
    [compose-xray-fragment.sh]='11e4f6707bdfd6957e22af4e0ad178cccd559d9a99785c3011fba017d3bc5d02'
    [validate-xray.sh]='ee454b49fc898072f8b7a0b712c6c20f81fa51b7fe18c9e2d132460c4fc62c59'
    [validate-nft.sh]='a2bf9aa6a76371a7e42448f50c6b0bb070b0599100c6587a0b9324e3553cd970'
    [activate-xray.sh]='31abe9e6c98148e56ce449284956a298a1e04107cb734a30003a1332de4de6f1'
    [apply-firewall-policy.sh]='1d6f0ad0f1e973ea6b8c8ba9810e7237044ab95734541bc0f8c98be159dc6aba'
    [start-l2tp.sh]='2fd5026e7ddbb5e4b2f748817494edef06b33fd002012de19a1f981b17283692'
    [sync-users.sh]='49fa1c74dd16654a82363be5b639e65f512ca16f7ca0ffb848988a822127c9d3'
    [verify-users.sh]='a06942b268e0b6379ac81a9048efd203ded02953ae399765aae2eb54aef5ea61'
    [verify.sh]='82d3334f97afb9a2ce0b99991dfb8ac7d94258534c8f2d8aa917b66d1183a4ae'
    [commit.sh]='bd846dbaf50051dbdc58d9c3832a9b45b9043579598d1235a97826b231841a1b'
    [rollback.sh]='63620d8d25bc9217875738bba993febc89b6217f7c21de26b7cb2c832ba73091'
    [install-runtime.sh]='43157074ad65505ca433bd5b3365c398412c36764203fac392bf59cb49b91bb4'
    [materialize-nft-candidate.sh]='2ce54eded17460e7a4a0d53748a9f177036b4656e4b6a265f18c32f04c63f6d3'
)
readonly RECEIVER_LINK_NAME='celerity-l2tp-artifact-receiver'
readonly RUNNER_LINK_NAME='celerity-l2tp-artifact-runner'
readonly MODULE_RELATIVE_LIB='usr/local/lib/celerity/relay-l2tp'
readonly RECEIVER_LINK_TARGET='../lib/celerity/relay-l2tp/receive-artifact.py'
readonly RUNNER_LINK_TARGET='../lib/celerity/relay-l2tp/runner.sh'
readonly -a PAYLOADS=(
    runner.sh
    receive-artifact.py
    apply.sh
    preflight.sh
    backup.sh
    compose-xray-fragment.sh
    validate-xray.sh
    validate-nft.sh
    activate-xray.sh
    apply-firewall-policy.sh
    start-l2tp.sh
    sync-users.sh
    verify-users.sh
    verify.sh
    commit.sh
    rollback.sh
    install-runtime.sh
    materialize-nft-candidate.sh
)
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
        /usr/bin/rm -rf -- "$target" >/dev/null 2>&1 || true
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

verify_exact_directory() {
    local directory="$1"
    local expected_mode="$2"
    local metadata
    [[ -d "$directory" && ! -L "$directory" ]] || return 1
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$directory" 2>/dev/null)" || return 1
    [[ "$metadata" == "0:0:$expected_mode:directory" ]]
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

verify_link() {
    local link_path="$1"
    local expected_target="$2"
    local metadata

    [[ -L "$link_path" ]] || return 1
    metadata="$(/usr/bin/stat -c '%u:%g:%F' -- "$link_path" 2>/dev/null)" || return 1
    [[ "$metadata" == '0:0:symbolic link' ]] || return 1
    [[ "$(/usr/bin/readlink -- "$link_path" 2>/dev/null)" == "$expected_target" ]]
}

ensure_directory() {
    local directory="$1"
    local mode="$2"

    if [[ -e "$directory" || -L "$directory" ]]; then
        verify_directory "$directory" || fail 'INVALID_TARGET' 73
        return
    fi
    /usr/bin/install -d -o 0 -g 0 -m "$mode" -- "$directory" >/dev/null 2>&1 \
        || fail 'INSTALL_FAILED' 70
    verify_exact_directory "$directory" "${mode#0}" || fail 'INSTALL_FAILED' 70
}

install_artifact() {
    local source="$1"
    local target="$2"
    local expected_digest="$3"
    local temporary

    temporary="$(/usr/bin/mktemp --tmpdir="$MODULE_LIB_DIR" ".${target##*/}.XXXXXX" 2>/dev/null)" \
        || fail 'INSTALL_FAILED' 70
    TEMPORARY_TARGETS+=("$temporary")
    /usr/bin/install -o 0 -g 0 -m 0755 -- "$source" "$temporary" >/dev/null 2>&1 \
        || fail 'INSTALL_FAILED' 70
    verify_artifact "$temporary" "$expected_digest" || fail 'INSTALL_FAILED' 70
    /usr/bin/mv -fT -- "$temporary" "$target" >/dev/null 2>&1 \
        || fail 'INSTALL_FAILED' 70
    verify_artifact "$target" "$expected_digest" || fail 'INSTALL_FAILED' 70
}

install_link() {
    local target="$1"
    local link_target="$2"
    local temporary_directory temporary

    temporary_directory="$(/usr/bin/mktemp -d --tmpdir="$BIN_DIR" ".${target##*/}.XXXXXX" 2>/dev/null)" \
        || fail 'INSTALL_FAILED' 70
    TEMPORARY_TARGETS+=("$temporary_directory")
    temporary="$temporary_directory/link"
    /usr/bin/ln -s -- "$link_target" "$temporary" >/dev/null 2>&1 \
        || fail 'INSTALL_FAILED' 70
    verify_link "$temporary" "$link_target" || fail 'INSTALL_FAILED' 70
    /usr/bin/mv -fT -- "$temporary" "$target" >/dev/null 2>&1 \
        || fail 'INSTALL_FAILED' 70
    verify_link "$target" "$link_target" || fail 'INSTALL_FAILED' 70
    /usr/bin/rmdir -- "$temporary_directory" >/dev/null 2>&1 \
        || fail 'INSTALL_FAILED' 70
}

if [[ "$#" -ne 0 ]]; then
    fail 'INVALID_ARGUMENTS' 64
fi
if [[ "$EUID" -ne 0 ]]; then
    fail 'ROOT_REQUIRED' 77
fi

ROOT_PREFIX="${CELERITY_L2TP_ROOT:-}"
if [[ -n "$ROOT_PREFIX" ]]; then
    [[ "$ROOT_PREFIX" == /* && "$ROOT_PREFIX" != *'/../'* && "$ROOT_PREFIX" != */.. \
        && "$ROOT_PREFIX" != *'/./'* && "$ROOT_PREFIX" != */. ]] \
        || fail 'INVALID_TARGET' 73
    ROOT_PREFIX="${ROOT_PREFIX%/}"
fi
readonly ROOT_PREFIX

INSTALLER_PATH="$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null)" \
    || fail 'INVALID_PACKAGE' 65
readonly INSTALLER_PATH
readonly ARTIFACT_DIR="${INSTALLER_PATH%/*}"
readonly BIN_DIR="${ROOT_PREFIX}/usr/local/bin"
readonly MODULE_LIB_DIR="${ROOT_PREFIX}/${MODULE_RELATIVE_LIB}"
readonly OPERATIONS_ROOT="${ROOT_PREFIX}/var/lib/celerity/l2tp/operations"
readonly RECEIVER_TARGET="$BIN_DIR/$RECEIVER_LINK_NAME"
readonly RUNNER_TARGET="$BIN_DIR/$RUNNER_LINK_NAME"

verify_directory "$ARTIFACT_DIR" || fail 'INVALID_PACKAGE' 65
if [[ -n "$ROOT_PREFIX" ]]; then
    verify_directory "$ROOT_PREFIX" || fail 'INVALID_TARGET' 73
fi
for payload in "${PAYLOADS[@]}"; do
    verify_artifact "$ARTIFACT_DIR/$payload" "${PAYLOAD_SHA256[$payload]}" \
        || fail 'INVALID_PACKAGE' 65
done

if [[ -n "$ROOT_PREFIX" ]]; then
    ensure_directory "${ROOT_PREFIX}/usr" 0755
fi
ensure_directory "${ROOT_PREFIX}/usr/local" 0755
ensure_directory "$BIN_DIR" 0755
ensure_directory "${ROOT_PREFIX}/usr/local/lib" 0755
ensure_directory "${ROOT_PREFIX}/usr/local/lib/celerity" 0755
ensure_directory "$MODULE_LIB_DIR" 0755
if [[ -n "$ROOT_PREFIX" ]]; then
    ensure_directory "${ROOT_PREFIX}/var" 0755
fi
ensure_directory "${ROOT_PREFIX}/var/lib" 0755
ensure_directory "${ROOT_PREFIX}/var/lib/celerity" 0755
ensure_directory "${ROOT_PREFIX}/var/lib/celerity/l2tp" 0700
ensure_directory "$OPERATIONS_ROOT" 0700
verify_exact_directory "$MODULE_LIB_DIR" '755' || fail 'INSTALL_FAILED' 70
verify_exact_directory "${ROOT_PREFIX}/var/lib/celerity/l2tp" '700' || fail 'INSTALL_FAILED' 70
verify_exact_directory "$OPERATIONS_ROOT" '700' || fail 'INSTALL_FAILED' 70

for payload in "${PAYLOADS[@]}"; do
    install_artifact \
        "$ARTIFACT_DIR/$payload" \
        "$MODULE_LIB_DIR/$payload" \
        "${PAYLOAD_SHA256[$payload]}"
done
install_link "$RECEIVER_TARGET" "$RECEIVER_LINK_TARGET"
install_link "$RUNNER_TARGET" "$RUNNER_LINK_TARGET"

printf '{"status":"ok"}\n'
