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
readonly BACKUP_PATH="$OPERATION_DIR/backup.json"
readonly STATE_DIR="$OPERATION_DIR/state"
readonly MARKER_PATH="$STATE_DIR/l2tp-services.before.json"
readonly -a L2TP_UNITS=(strongswan-starter.service xl2tpd.service)

marker_status="$(python3 - "$OPERATION_DIR" <<'PY'
import json
import os
import stat
import sys

operation_path = sys.argv[1]
dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
file_flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, 'O_NOFOLLOW'):
    dir_flags |= os.O_NOFOLLOW
    file_flags |= os.O_NOFOLLOW

operation = os.open(operation_path, dir_flags)
try:
    if os.fstat(operation).st_uid != 0:
        raise RuntimeError('operation owner')
    backup = os.open('backup.json', file_flags, dir_fd=operation)
    try:
        metadata = os.fstat(backup)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
            raise RuntimeError('backup metadata')
        with os.fdopen(backup, encoding='utf-8') as handle:
            backup = -1
            manifest = json.load(handle)
        if not isinstance(manifest, dict):
            raise RuntimeError('backup manifest')
    finally:
        if backup >= 0:
            os.close(backup)

    try:
        os.mkdir('state', 0o700, dir_fd=operation)
    except FileExistsError:
        pass
    state = os.open('state', dir_flags, dir_fd=operation)
    try:
        metadata = os.fstat(state)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise RuntimeError('state metadata')
        try:
            marker = os.open('l2tp-services.before.json', file_flags, dir_fd=state)
        except FileNotFoundError:
            print('capture')
        else:
            try:
                marker_metadata = os.fstat(marker)
                if not stat.S_ISREG(marker_metadata.st_mode) or marker_metadata.st_uid != 0:
                    raise RuntimeError('marker metadata')
                with os.fdopen(marker, encoding='utf-8') as handle:
                    marker = -1
                    value = json.load(handle)
                expected = {'strongswan-starter.service', 'xl2tpd.service'}
                if set(value) != expected or any(type(value[key]) is not bool for key in expected):
                    raise RuntimeError('marker data')
                print('existing')
            finally:
                if marker >= 0:
                    os.close(marker)
    finally:
        os.close(state)
finally:
    os.close(operation)
PY
)" || {
    emit_error 'START_STATE_INVALID'
    exit 66
}

systemctl_path="$(command -v systemctl || true)"
if [[ -z "$systemctl_path" ]]; then
    emit_error 'SYSTEMCTL_MISSING'
    exit 69
fi

if [[ "$marker_status" == 'capture' ]]; then
    strongswan_was_active=false
    xl2tpd_was_active=false
    if "$systemctl_path" is-active --quiet strongswan-starter.service >/dev/null 2>&1; then
        strongswan_was_active=true
    fi
    if "$systemctl_path" is-active --quiet xl2tpd.service >/dev/null 2>&1; then
        xl2tpd_was_active=true
    fi

    if ! python3 - "$OPERATION_DIR" "$strongswan_was_active" "$xl2tpd_was_active" <<'PY'
import json
import os
import secrets
import sys

operation_path, strongswan, xl2tpd = sys.argv[1:]
dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
if hasattr(os, 'O_NOFOLLOW'):
    dir_flags |= os.O_NOFOLLOW
operation = os.open(operation_path, dir_flags)
try:
    state = os.open('state', dir_flags, dir_fd=operation)
    try:
        payload = json.dumps({
            'strongswan-starter.service': strongswan == 'true',
            'xl2tpd.service': xl2tpd == 'true',
        }, separators=(',', ':')).encode('ascii')
        temporary = f'.l2tp-services.before.{secrets.token_hex(12)}'
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600, dir_fd=state)
        try:
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, 0, 0)
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(
                temporary,
                'l2tp-services.before.json',
                src_dir_fd=state,
                dst_dir_fd=state,
            )
            os.fsync(state)
        finally:
            try:
                os.unlink(temporary, dir_fd=state)
            except FileNotFoundError:
                pass
    finally:
        os.close(state)
finally:
    os.close(operation)
PY
    then
        emit_error 'START_STATE_RECORD_FAILED'
        exit 74
    fi
fi

for unit in "${L2TP_UNITS[@]}"; do
    if ! "$systemctl_path" restart "$unit" >/dev/null 2>&1; then
        emit_error 'L2TP_SERVICE_RESTART_FAILED'
        exit 70
    fi
    if ! "$systemctl_path" is-active --quiet "$unit" >/dev/null 2>&1; then
        emit_error 'L2TP_SERVICE_NOT_ACTIVE'
        exit 70
    fi
done

printf '%s\n' '{"status":"ok","services":2,"changed":2}'
