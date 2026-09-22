#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly STATE_RELATIVE_ROOT='var/lib/celerity/topology'
readonly MAX_CANDIDATE_BYTES=4194304
TEMPORARY_FILE=''

emit_error() {
    local code="$1"
    printf '{"ok":false,"code":"%s"}\n' "$code" >&2
}

fail() {
    local code="$1"
    local status="$2"
    emit_error "$code"
    exit "$status"
}

cleanup() {
    if [[ -n "$TEMPORARY_FILE" ]]; then
        /usr/bin/rm -f -- "$TEMPORARY_FILE" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if [[ "$#" -ne 12 \
    || "$1" != '--command' \
    || "$3" != '--operation-id' \
    || "$5" != '--node-id' \
    || "$7" != '--candidate-hash' \
    || "$9" != '--backup-id' \
    || "${11}" != '--target-profile' ]]; then
    fail 'INVALID_ARGUMENTS' 64
fi

readonly COMMAND="$2"
readonly OPERATION_ID="$4"
readonly NODE_ID="$6"
readonly CANDIDATE_HASH="$8"
readonly BACKUP_ID="${10}"
readonly TARGET_PROFILE="${12}"
readonly SAFE_ID_PATTERN='^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
readonly HASH_PATTERN='^sha256:[a-f0-9]{64}$'

[[ "$COMMAND" =~ ^(prepare|commit|verify|rollback)$ ]] \
    || fail 'UNKNOWN_COMMAND' 64
[[ "$OPERATION_ID" =~ $SAFE_ID_PATTERN \
    && "$NODE_ID" =~ $SAFE_ID_PATTERN \
    && "$BACKUP_ID" =~ $SAFE_ID_PATTERN ]] \
    || fail 'INVALID_IDENTITY' 65
[[ "$CANDIDATE_HASH" =~ $HASH_PATTERN ]] \
    || fail 'INVALID_CANDIDATE_HASH' 65

ROOT_PREFIX="${CELERITY_TOPOLOGY_ROOT:-}"
if [[ -n "$ROOT_PREFIX" ]]; then
    [[ "$ROOT_PREFIX" == /* \
        && "$ROOT_PREFIX" != '/' \
        && "$ROOT_PREFIX" != *'/../'* \
        && "$ROOT_PREFIX" != */.. \
        && "$ROOT_PREFIX" != *'/./'* \
        && "$ROOT_PREFIX" != */. ]] \
        || fail 'INVALID_ROOT' 73
    ROOT_PREFIX="${ROOT_PREFIX%/}"
fi
readonly ROOT_PREFIX

case "$TARGET_PROFILE" in
    xray-main)
        readonly CONFIG_PATH="$ROOT_PREFIX/usr/local/etc/xray/config.json"
        readonly SERVICE_NAME='xray.service'
        ;;
    xray-bridge)
        readonly CONFIG_PATH="$ROOT_PREFIX/usr/local/etc/xray-bridge/config.json"
        readonly SERVICE_NAME='xray-bridge.service'
        ;;
    *)
        fail 'UNKNOWN_TARGET_PROFILE' 65
        ;;
esac

readonly STATE_ROOT="$ROOT_PREFIX/$STATE_RELATIVE_ROOT"
readonly OPERATION_DIR="$STATE_ROOT/operations/$OPERATION_ID/$TARGET_PROFILE"
readonly BACKUP_DIR="$STATE_ROOT/backups/$BACKUP_ID/$TARGET_PROFILE"
readonly CANDIDATE_PATH="$OPERATION_DIR/candidate.json"
readonly OPERATION_METADATA="$OPERATION_DIR/receipt.fields"
readonly BACKUP_METADATA="$BACKUP_DIR/receipt.fields"
readonly BACKUP_CONFIG="$BACKUP_DIR/config.json"
readonly BACKUP_ABSENT="$BACKUP_DIR/config.absent"
readonly XRAY_PATH="$ROOT_PREFIX/usr/local/bin/xray"
readonly SYSTEMCTL_PATH="$ROOT_PREFIX/usr/bin/systemctl"

emit_receipt() {
    printf '{"ok":true,"command":"%s","operationId":"%s","nodeId":"%s","candidateHash":"%s","backupId":"%s","targetProfile":"%s"}\n' \
        "$COMMAND" \
        "$OPERATION_ID" \
        "$NODE_ID" \
        "$CANDIDATE_HASH" \
        "$BACKUP_ID" \
        "$TARGET_PROFILE"
}

write_metadata() {
    local target="$1"
    {
        printf 'operationId=%s\n' "$OPERATION_ID"
        printf 'nodeId=%s\n' "$NODE_ID"
        printf 'candidateHash=%s\n' "$CANDIDATE_HASH"
        printf 'backupId=%s\n' "$BACKUP_ID"
        printf 'targetProfile=%s\n' "$TARGET_PROFILE"
    } >"$target" || fail 'STATE_WRITE_FAILED' 70
    /usr/bin/chmod 0600 -- "$target" >/dev/null 2>&1 \
        || fail 'STATE_WRITE_FAILED' 70
}

metadata_matches() {
    local target="$1"
    local -a fields=()
    [[ -f "$target" && ! -L "$target" ]] || return 1
    mapfile -t fields <"$target" || return 1
    [[ "${#fields[@]}" -eq 5 \
        && "${fields[0]}" == "operationId=$OPERATION_ID" \
        && "${fields[1]}" == "nodeId=$NODE_ID" \
        && "${fields[2]}" == "candidateHash=$CANDIDATE_HASH" \
        && "${fields[3]}" == "backupId=$BACKUP_ID" \
        && "${fields[4]}" == "targetProfile=$TARGET_PROFILE" ]]
}

file_hash_matches() {
    local target="$1"
    local digest_line digest
    [[ -f "$target" && ! -L "$target" ]] || return 1
    digest_line="$(/usr/bin/sha256sum -- "$target" 2>/dev/null)" || return 1
    digest="${digest_line%% *}"
    [[ "sha256:$digest" == "$CANDIDATE_HASH" ]]
}

ensure_fixed_state_roots() {
    local directory
    for directory in \
        "$ROOT_PREFIX/var/lib/celerity" \
        "$STATE_ROOT" \
        "$STATE_ROOT/operations" \
        "$STATE_ROOT/backups"; do
        if [[ -e "$directory" || -L "$directory" ]]; then
            [[ -d "$directory" && ! -L "$directory" ]] || fail 'INVALID_STATE_ROOT' 73
        else
            /usr/bin/mkdir -m 0700 -- "$directory" >/dev/null 2>&1 \
                || fail 'STATE_WRITE_FAILED' 70
        fi
    done
}

prepare_candidate() {
    local size digest_line digest config_parent
    ensure_fixed_state_roots
    [[ ! -e "$OPERATION_DIR" && ! -L "$OPERATION_DIR" \
        && ! -e "$BACKUP_DIR" && ! -L "$BACKUP_DIR" ]] \
        || fail 'STATE_ALREADY_EXISTS' 65

    /usr/bin/mkdir -p -m 0700 -- "$OPERATION_DIR" "$BACKUP_DIR" >/dev/null 2>&1 \
        || fail 'STATE_WRITE_FAILED' 70
    TEMPORARY_FILE="$(/usr/bin/mktemp --tmpdir="$OPERATION_DIR" '.candidate.XXXXXX')" \
        || fail 'STATE_WRITE_FAILED' 70
    /usr/bin/cat >"$TEMPORARY_FILE" || fail 'CANDIDATE_READ_FAILED' 65
    size="$(/usr/bin/stat -c '%s' -- "$TEMPORARY_FILE" 2>/dev/null)" \
        || fail 'CANDIDATE_READ_FAILED' 65
    [[ "$size" -gt 0 && "$size" -le "$MAX_CANDIDATE_BYTES" ]] \
        || fail 'INVALID_CANDIDATE' 65
    digest_line="$(/usr/bin/sha256sum -- "$TEMPORARY_FILE" 2>/dev/null)" \
        || fail 'INVALID_CANDIDATE' 65
    digest="${digest_line%% *}"
    [[ "sha256:$digest" == "$CANDIDATE_HASH" ]] \
        || fail 'CANDIDATE_HASH_MISMATCH' 65
    [[ -x "$XRAY_PATH" ]] || fail 'XRAY_UNAVAILABLE' 69
    "$XRAY_PATH" run -test -config "$TEMPORARY_FILE" >/dev/null 2>&1 \
        || fail 'CANDIDATE_INVALID' 65

    config_parent="${CONFIG_PATH%/*}"
    [[ -d "$config_parent" && ! -L "$config_parent" ]] \
        || fail 'INVALID_TARGET' 73
    if [[ -e "$CONFIG_PATH" || -L "$CONFIG_PATH" ]]; then
        [[ -f "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] \
            || fail 'INVALID_TARGET' 73
        /usr/bin/install -m 0600 -- "$CONFIG_PATH" "$BACKUP_CONFIG" >/dev/null 2>&1 \
            || fail 'BACKUP_FAILED' 70
    else
        : >"$BACKUP_ABSENT" || fail 'BACKUP_FAILED' 70
        /usr/bin/chmod 0600 -- "$BACKUP_ABSENT" >/dev/null 2>&1 \
            || fail 'BACKUP_FAILED' 70
    fi

    /usr/bin/chmod 0600 -- "$TEMPORARY_FILE" >/dev/null 2>&1 \
        || fail 'STATE_WRITE_FAILED' 70
    /usr/bin/mv -fT -- "$TEMPORARY_FILE" "$CANDIDATE_PATH" >/dev/null 2>&1 \
        || fail 'STATE_WRITE_FAILED' 70
    TEMPORARY_FILE=''
    write_metadata "$OPERATION_METADATA"
    write_metadata "$BACKUP_METADATA"
    emit_receipt
}

assert_bound_state() {
    metadata_matches "$OPERATION_METADATA" \
        && metadata_matches "$BACKUP_METADATA" \
        || fail 'RECEIPT_BINDING_MISMATCH' 65
}

commit_candidate() {
    local target_parent temporary
    assert_bound_state
    file_hash_matches "$CANDIDATE_PATH" || fail 'CANDIDATE_HASH_MISMATCH' 65
    target_parent="${CONFIG_PATH%/*}"
    [[ -d "$target_parent" && ! -L "$target_parent" ]] || fail 'INVALID_TARGET' 73
    if [[ -e "$CONFIG_PATH" || -L "$CONFIG_PATH" ]]; then
        [[ -f "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] || fail 'INVALID_TARGET' 73
    fi
    temporary="$(/usr/bin/mktemp --tmpdir="$target_parent" '.celerity-topology.XXXXXX')" \
        || fail 'ACTIVATION_FAILED' 70
    TEMPORARY_FILE="$temporary"
    /usr/bin/install -m 0644 -- "$CANDIDATE_PATH" "$temporary" >/dev/null 2>&1 \
        || fail 'ACTIVATION_FAILED' 70
    /usr/bin/mv -fT -- "$temporary" "$CONFIG_PATH" >/dev/null 2>&1 \
        || fail 'ACTIVATION_FAILED' 70
    TEMPORARY_FILE=''
    [[ -x "$SYSTEMCTL_PATH" ]] || fail 'SYSTEMCTL_UNAVAILABLE' 69
    "$SYSTEMCTL_PATH" restart "$SERVICE_NAME" >/dev/null 2>&1 \
        || fail 'ACTIVATION_FAILED' 70
    emit_receipt
}

verify_candidate() {
    assert_bound_state
    file_hash_matches "$CONFIG_PATH" || fail 'VERIFICATION_FAILED' 65
    [[ -x "$XRAY_PATH" && -x "$SYSTEMCTL_PATH" ]] \
        || fail 'VERIFICATION_UNAVAILABLE' 69
    "$XRAY_PATH" run -test -config "$CONFIG_PATH" >/dev/null 2>&1 \
        || fail 'VERIFICATION_FAILED' 65
    "$SYSTEMCTL_PATH" is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1 \
        || fail 'VERIFICATION_FAILED' 65
    emit_receipt
}

rollback_candidate() {
    local target_parent temporary
    assert_bound_state
    target_parent="${CONFIG_PATH%/*}"
    [[ -d "$target_parent" && ! -L "$target_parent" ]] || fail 'INVALID_TARGET' 73
    if [[ -f "$BACKUP_CONFIG" && ! -L "$BACKUP_CONFIG" && ! -e "$BACKUP_ABSENT" ]]; then
        if [[ -e "$CONFIG_PATH" || -L "$CONFIG_PATH" ]]; then
            [[ -f "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] || fail 'INVALID_TARGET' 73
        fi
        temporary="$(/usr/bin/mktemp --tmpdir="$target_parent" '.celerity-topology.XXXXXX')" \
            || fail 'ROLLBACK_FAILED' 70
        TEMPORARY_FILE="$temporary"
        /usr/bin/install -m 0644 -- "$BACKUP_CONFIG" "$temporary" >/dev/null 2>&1 \
            || fail 'ROLLBACK_FAILED' 70
        /usr/bin/mv -fT -- "$temporary" "$CONFIG_PATH" >/dev/null 2>&1 \
            || fail 'ROLLBACK_FAILED' 70
        TEMPORARY_FILE=''
        [[ -x "$SYSTEMCTL_PATH" ]] || fail 'SYSTEMCTL_UNAVAILABLE' 69
        "$SYSTEMCTL_PATH" restart "$SERVICE_NAME" >/dev/null 2>&1 \
            || fail 'ROLLBACK_FAILED' 70
    elif [[ -f "$BACKUP_ABSENT" && ! -L "$BACKUP_ABSENT" && ! -e "$BACKUP_CONFIG" ]]; then
        if [[ -e "$CONFIG_PATH" || -L "$CONFIG_PATH" ]]; then
            [[ -f "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] || fail 'INVALID_TARGET' 73
            /usr/bin/rm -f -- "$CONFIG_PATH" >/dev/null 2>&1 \
                || fail 'ROLLBACK_FAILED' 70
        fi
        [[ -x "$SYSTEMCTL_PATH" ]] || fail 'SYSTEMCTL_UNAVAILABLE' 69
        "$SYSTEMCTL_PATH" stop "$SERVICE_NAME" >/dev/null 2>&1 \
            || fail 'ROLLBACK_FAILED' 70
    else
        fail 'BACKUP_INVALID' 65
    fi
    emit_receipt
}

case "$COMMAND" in
    prepare) prepare_candidate ;;
    commit) commit_candidate ;;
    verify) verify_candidate ;;
    rollback) rollback_candidate ;;
esac
