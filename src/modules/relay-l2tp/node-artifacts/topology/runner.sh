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

if [[ ( "$#" -ne 12 && "$#" -ne 14 ) \
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
readonly CHECKS_TOKEN="${14-}"
readonly SAFE_ID_PATTERN='^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
readonly HASH_PATTERN='^sha256:[a-f0-9]{64}$'

[[ "$COMMAND" =~ ^(prepare|commit|verify|rollback)$ ]] \
    || fail 'UNKNOWN_COMMAND' 64
if [[ "$COMMAND" == 'verify' ]]; then
    [[ "$#" -eq 14 && "${13}" == '--checks' ]] \
        || fail 'INVALID_ARGUMENTS' 64
else
    [[ "$#" -eq 12 ]] || fail 'INVALID_ARGUMENTS' 64
fi
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
readonly XRAY_ASSET_DIR="$ROOT_PREFIX/usr/local/share/xray"
readonly SYSTEMCTL_PATH="$ROOT_PREFIX/usr/bin/systemctl"
readonly SS_PATH="$ROOT_PREFIX/usr/bin/ss"

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

# Semantic equality between the staged candidate and the live config, ignoring
# the user-managed fragment (inbounds[].settings.clients). VPN users are synced
# to portal nodes out of band by the panel's user sync, so the live portal
# config legitimately differs from the topology candidate there; treating that
# as drift would force a config swap + service restart (and a brief user
# wipeout) on every single deploy even when the tunnel wiring is unchanged.
configs_equivalent() {
    [[ -f "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] || return 1
    /usr/bin/python3 - "$CANDIDATE_PATH" "$CONFIG_PATH" >/dev/null 2>&1 <<'PY'
import json
import sys

def canonical(path):
    with open(path, 'rb') as handle:
        document = json.loads(handle.read().decode('utf-8'))
    if not isinstance(document, dict):
        raise SystemExit(1)
    for inbound in document.get('inbounds', []):
        if not isinstance(inbound, dict):
            continue
        settings = inbound.get('settings')
        if isinstance(settings, dict) and isinstance(settings.get('clients'), list):
            settings['clients'] = []
    return json.dumps(document, sort_keys=True, separators=(',', ':'))

if canonical(sys.argv[1]) != canonical(sys.argv[2]):
    raise SystemExit(1)
PY
}

candidate_structure_valid() {
    local target="$1"
    /usr/bin/python3 - "$target" >/dev/null 2>&1 <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, 'rb') as handle:
    raw = handle.read()
document = json.loads(raw.decode('utf-8'))
if not isinstance(document, dict):
    raise SystemExit(1)
if not isinstance(document.get('inbounds'), list):
    raise SystemExit(1)
if not isinstance(document.get('outbounds'), list):
    raise SystemExit(1)
canonical = json.dumps(
    document,
    ensure_ascii=False,
    separators=(',', ':'),
).encode('utf-8') + b'\n'
if raw != canonical:
    raise SystemExit(1)
PY
}

parse_checks() {
    /usr/bin/python3 - "$CHECKS_TOKEN" "$SERVICE_NAME" <<'PY'
import base64
import json
import re
import sys


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate key')
        value[key] = item
    return value


def reject_constant(_value):
    raise ValueError('invalid number')


token, service_name = sys.argv[1:]
if re.fullmatch(r'[A-Za-z0-9_-]+', token) is None:
    raise SystemExit(1)
try:
    raw = base64.b64decode(
        token + ('=' * (-len(token) % 4)),
        altchars=b'-_',
        validate=True,
    )
    if base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=') != token:
        raise ValueError('non-canonical base64url')
    checks = json.loads(
        raw.decode('utf-8'),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
if type(checks) is not list:
    raise SystemExit(1)
for check in checks:
    if type(check) is not dict or type(check.get('type')) is not str:
        raise SystemExit(1)
    if check['type'] == 'service':
        if (set(check) != {'type', 'serviceUnit', 'expectedState'}
                or check.get('serviceUnit') != service_name
                or check.get('expectedState') != 'active'):
            raise SystemExit(1)
        continue
    if check['type'] == 'port':
        port = check.get('port')
        if (set(check) != {'type', 'protocol', 'port', 'expectedState'}
                or check.get('protocol') != 'tcp'
                or type(port) is not int
                or not 1 <= port <= 65535
                or check.get('expectedState') != 'listening'):
            raise SystemExit(1)
        print(port)
        continue
    raise SystemExit(1)
PY
}

REQUIRED_TCP_PORTS=()
if [[ "$COMMAND" == 'verify' ]]; then
    checks_ports=''
    checks_ports="$(parse_checks)" || fail 'INVALID_CHECKS' 65
    if [[ -n "$checks_ports" ]]; then
        mapfile -t REQUIRED_TCP_PORTS <<<"$checks_ports"
    fi
fi
readonly -a REQUIRED_TCP_PORTS

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
    candidate_structure_valid "$TEMPORARY_FILE" \
        || fail 'INVALID_CANDIDATE' 65
    /usr/bin/chmod 0600 -- "$TEMPORARY_FILE" >/dev/null 2>&1 \
        || fail 'STATE_WRITE_FAILED' 70
    /usr/bin/mv -fT -- "$TEMPORARY_FILE" "$CANDIDATE_PATH" >/dev/null 2>&1 \
        || fail 'STATE_WRITE_FAILED' 70
    TEMPORARY_FILE=''
    [[ -x "$XRAY_PATH" ]] || fail 'XRAY_UNAVAILABLE' 69
    [[ -d "$XRAY_ASSET_DIR" && ! -L "$XRAY_ASSET_DIR" \
        && -r "$XRAY_ASSET_DIR" && -x "$XRAY_ASSET_DIR" ]] \
        || fail 'XRAY_ASSETS_UNAVAILABLE' 69
    XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" \
        "$XRAY_PATH" run -test -config "$CANDIDATE_PATH" >/dev/null 2>&1 \
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
    # No-op fast path: the live config already matches the candidate (byte for
    # byte, or semantically once the user-managed clients are ignored).
    # Skipping the swap + service restart keeps unchanged nodes fully online
    # and makes small domain-scoped changes (e.g. one link's fingerprint)
    # cheap, while verify still proves the service afterwards.
    if file_hash_matches "$CONFIG_PATH" || configs_equivalent; then
        emit_receipt
        return 0
    fi
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
    local port listeners
    assert_bound_state
    file_hash_matches "$CONFIG_PATH" || configs_equivalent || fail 'VERIFICATION_FAILED' 65
    [[ -x "$XRAY_PATH" && -x "$SYSTEMCTL_PATH" ]] \
        || fail 'VERIFICATION_UNAVAILABLE' 69
    [[ -d "$XRAY_ASSET_DIR" && ! -L "$XRAY_ASSET_DIR" \
        && -r "$XRAY_ASSET_DIR" && -x "$XRAY_ASSET_DIR" ]] \
        || fail 'XRAY_ASSETS_UNAVAILABLE' 69
    XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" \
        "$XRAY_PATH" run -test -config "$CONFIG_PATH" >/dev/null 2>&1 \
        || fail 'VERIFICATION_FAILED' 65
    "$SYSTEMCTL_PATH" is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1 \
        || fail 'VERIFICATION_FAILED' 65
    if [[ "${#REQUIRED_TCP_PORTS[@]}" -gt 0 ]]; then
        [[ -x "$SS_PATH" ]] || fail 'VERIFICATION_UNAVAILABLE' 69
        for port in "${REQUIRED_TCP_PORTS[@]}"; do
            listeners="$("$SS_PATH" -H -ltn "sport = :$port" 2>/dev/null)" \
                || fail 'VERIFICATION_UNAVAILABLE' 69
            [[ -n "$listeners" ]] || fail 'VERIFICATION_FAILED' 65
        done
    fi
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
