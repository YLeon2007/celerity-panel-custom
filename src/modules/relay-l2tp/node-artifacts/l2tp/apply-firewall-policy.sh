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
readonly CANDIDATE_PATH="$CANDIDATE_DIR/celerity-l2tp.nft"
readonly DESIRED_PATH="$OPERATION_DIR/desired.json"
readonly BACKUP_PATH="$OPERATION_DIR/backup.json"
readonly STATE_DIR="$OPERATION_DIR/state"
readonly MARKER_PATH="$STATE_DIR/firewall.applied.json"
readonly NFT_FAMILY='inet'
readonly NFT_TABLE='celerity_l2tp'
readonly RULE_PRIORITY='10077'

if [[ ! -d "$OPERATION_DIR" || -L "$OPERATION_DIR" \
    || ! -d "$CANDIDATE_DIR" || -L "$CANDIDATE_DIR" \
    || ! -f "$CANDIDATE_PATH" || -L "$CANDIDATE_PATH" \
    || ! -f "$DESIRED_PATH" || -L "$DESIRED_PATH" ]]; then
    emit_error 'FIREWALL_INPUT_MISSING'
    exit 66
fi
if [[ ! -f "$BACKUP_PATH" || -L "$BACKUP_PATH" ]]; then
    emit_error 'BACKUP_REQUIRED'
    exit 66
fi

nft_path="$(command -v nft || true)"
ip_path="$(command -v ip || true)"
if [[ -z "$nft_path" || -z "$ip_path" ]]; then
    emit_error 'RUNTIME_COMMAND_MISSING'
    exit 69
fi

parsed="$(python3 - "$OPERATION_DIR" <<'PY'
import json
import os
import re
import stat
import sys

operation_path = sys.argv[1]
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
if hasattr(os, 'O_NOFOLLOW'):
    flags |= os.O_NOFOLLOW
file_flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, 'O_NOFOLLOW'):
    file_flags |= os.O_NOFOLLOW


def read_root_file(parent, name, max_bytes):
    descriptor = os.open(name, file_flags, dir_fd=parent)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
            raise RuntimeError('invalid file')
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise RuntimeError('file too large')
            chunks.append(chunk)
        return b''.join(chunks)
    finally:
        os.close(descriptor)


operation = os.open(operation_path, flags)
try:
    if os.fstat(operation).st_uid != 0:
        raise RuntimeError('operation ownership')
    candidate_dir = os.open('candidate', flags, dir_fd=operation)
    try:
        nft_source = read_root_file(candidate_dir, 'celerity-l2tp.nft', 1024 * 1024).decode('utf-8')
    finally:
        os.close(candidate_dir)
    desired = json.loads(read_root_file(operation, 'desired.json', 1024 * 1024).decode('utf-8'))
    backup = json.loads(read_root_file(operation, 'backup.json', 8 * 1024 * 1024).decode('utf-8'))
finally:
    os.close(operation)

for field in ('fwmark', 'routeTable'):
    value = desired.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**31 - 1:
        raise RuntimeError('invalid desired routing field')

backed_up = {
    item.get('path') for item in backup.get('files', []) if isinstance(item, dict)
}
absent = set(backup.get('absent', []))
if 'etc/nftables.d/celerity-l2tp.nft' not in backed_up.union(absent):
    raise RuntimeError('nft target not backed up')

without_comments = re.sub(r'#.*$', '', nft_source, flags=re.MULTILINE)
if re.search(r'\b(?:include|flush\s+ruleset)\b', without_comments, flags=re.IGNORECASE):
    raise RuntimeError('unsafe nft directive')
tables = re.findall(
    r'\btable\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_-]+)\s*\{',
    without_comments,
)
if tables != [('inet', 'celerity_l2tp')]:
    raise RuntimeError('unexpected nft namespace')

print(f"{desired['fwmark']} {desired['routeTable']}")
PY
)" || {
    emit_error 'INVALID_FIREWALL_INPUT'
    exit 65
}
read -r fwmark route_table <<<"$parsed"

if ! "$nft_path" -c -f "$CANDIDATE_PATH" >/dev/null 2>&1; then
    emit_error 'NFT_CANDIDATE_INVALID'
    exit 65
fi

teardown_stale_namespace() {
    # Leftovers of a previous install whose marker is gone or whose live
    # state diverged (partial teardown, manual intervention, rolled-back
    # operation). The table name, rule priority and route-table id belong to
    # this module, so clearing them makes re-install idempotent instead of
    # failing with NFT_NAMESPACE_CONFLICT / FIREWALL_STATE_MISMATCH.
    "$nft_path" delete table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1 || true
    "$ip_path" -4 rule del priority "$RULE_PRIORITY" >/dev/null 2>&1 || true
    "$ip_path" -4 route flush table "$route_table" >/dev/null 2>&1 || true
}

if [[ -e "$MARKER_PATH" ]]; then
    if [[ ! -f "$MARKER_PATH" || -L "$MARKER_PATH" ]]; then
        emit_error 'FIREWALL_STATE_INVALID'
        exit 66
    fi
    marker_values="$(python3 - "$MARKER_PATH" <<'PY'
import json
import os
import stat
import sys
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, 'O_NOFOLLOW'):
    flags |= os.O_NOFOLLOW
fd = os.open(sys.argv[1], flags)
try:
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        raise RuntimeError('invalid marker')
    with os.fdopen(fd, encoding='utf-8') as handle:
        fd = -1
        marker = json.load(handle)
finally:
    if fd >= 0:
        os.close(fd)
print(f"{marker.get('fwmark')} {marker.get('routeTable')} {marker.get('priority')}")
PY
)" || {
        emit_error 'FIREWALL_STATE_INVALID'
        exit 66
    }
    if [[ "$marker_values" == "$fwmark $route_table $RULE_PRIORITY" ]] \
        && "$nft_path" list table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1 \
        && "$ip_path" -4 rule show priority "$RULE_PRIORITY" >/dev/null 2>&1 \
        && "$ip_path" -4 route show table "$route_table" type local >/dev/null 2>&1; then
        printf '%s\n' '{"status":"ok","namespace":"celerity_l2tp","changed":0}'
        exit 0
    fi
    teardown_stale_namespace
    rm -f "$MARKER_PATH"
fi

if "$nft_path" list table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1 \
    || "$ip_path" -4 rule show priority "$RULE_PRIORITY" >/dev/null 2>&1; then
    # Stale namespace without a usable marker: clear it and apply fresh.
    teardown_stale_namespace
fi
if ! "$nft_path" -f "$CANDIDATE_PATH" >/dev/null 2>&1; then
    emit_error 'NFT_APPLY_FAILED'
    exit 70
fi
if ! "$ip_path" -4 rule add priority "$RULE_PRIORITY" fwmark "$fwmark" table "$route_table" >/dev/null 2>&1; then
    "$nft_path" delete table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1 || true
    emit_error 'IP_RULE_APPLY_FAILED'
    exit 70
fi
if ! "$ip_path" -4 route add local '0.0.0.0/0' dev lo table "$route_table" >/dev/null 2>&1; then
    "$ip_path" -4 rule del priority "$RULE_PRIORITY" fwmark "$fwmark" table "$route_table" >/dev/null 2>&1 || true
    "$nft_path" delete table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1 || true
    emit_error 'IP_ROUTE_APPLY_FAILED'
    exit 70
fi

if ! python3 - "$OPERATION_DIR" "$fwmark" "$route_table" "$RULE_PRIORITY" <<'PY'
import json
import os
import secrets
import stat
import sys

operation_path, fwmark, route_table, priority = sys.argv[1:]
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
if hasattr(os, 'O_NOFOLLOW'):
    flags |= os.O_NOFOLLOW
operation = os.open(operation_path, flags)
try:
    try:
        os.mkdir('state', 0o700, dir_fd=operation)
    except FileExistsError:
        pass
    state = os.open('state', flags, dir_fd=operation)
    try:
        if os.fstat(state).st_uid != 0:
            raise RuntimeError('invalid state owner')
        payload = json.dumps({
            'fwmark': int(fwmark),
            'routeTable': int(route_table),
            'priority': int(priority),
        }, separators=(',', ':')).encode('ascii')
        temporary_name = f'.firewall.applied.{secrets.token_hex(12)}'
        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, 'O_NOFOLLOW'):
            file_flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, file_flags, 0o600, dir_fd=state)
        try:
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, 0, 0)
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(
                temporary_name,
                'firewall.applied.json',
                src_dir_fd=state,
                dst_dir_fd=state,
            )
            os.fsync(state)
        finally:
            try:
                os.unlink(temporary_name, dir_fd=state)
            except FileNotFoundError:
                pass
    finally:
        os.close(state)
finally:
    os.close(operation)
PY
then
    "$ip_path" -4 route del local '0.0.0.0/0' dev lo table "$route_table" >/dev/null 2>&1 || true
    "$ip_path" -4 rule del priority "$RULE_PRIORITY" fwmark "$fwmark" table "$route_table" >/dev/null 2>&1 || true
    "$nft_path" delete table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1 || true
    emit_error 'FIREWALL_STATE_RECORD_FAILED'
    exit 74
fi

printf '%s\n' '{"status":"ok","namespace":"celerity_l2tp","changed":1}'
