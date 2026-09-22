#!/usr/bin/env bash
set -Eeuo pipefail

emit_error() {
    local code="$1"
    printf '{"status":"error","code":"%s"}\n' "$code" >&2
}

if [[ "$#" -ne 2 ]]; then
    emit_error 'INVALID_ARGUMENTS'
    exit 64
fi

readonly OPERATION_DIR="$1"
readonly ROOT_PATH="$2"
readonly CANDIDATE_PATH="$OPERATION_DIR/candidate/xray.json"
if [[ ! -d "$OPERATION_DIR" || -L "$OPERATION_DIR" \
    || ! -d "$OPERATION_DIR/candidate" || -L "$OPERATION_DIR/candidate" \
    || ! -f "$CANDIDATE_PATH" || -L "$CANDIDATE_PATH" ]]; then
    emit_error 'XRAY_CANDIDATE_MISSING'
    exit 66
fi
if [[ ! -f "$OPERATION_DIR/backup.json" || -L "$OPERATION_DIR/backup.json" ]]; then
    emit_error 'BACKUP_REQUIRED'
    exit 66
fi

xray_path="$(command -v xray || true)"
systemctl_path="$(command -v systemctl || true)"
if [[ -z "$xray_path" || -z "$systemctl_path" ]]; then
    emit_error 'RUNTIME_COMMAND_MISSING'
    exit 69
fi
if ! "$xray_path" run -test -config "$CANDIDATE_PATH" >/dev/null 2>&1; then
    emit_error 'XRAY_CANDIDATE_INVALID'
    exit 65
fi

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
    operation_metadata = os.fstat(operation)
    if operation_metadata.st_uid != 0:
        raise RuntimeError('operation metadata')
    try:
        os.mkdir('state', 0o700, dir_fd=operation)
    except FileExistsError:
        pass
    state = os.open('state', dir_flags, dir_fd=operation)
    try:
        state_metadata = os.fstat(state)
        if state_metadata.st_uid != 0 or stat.S_IMODE(state_metadata.st_mode) & 0o022:
            raise RuntimeError('state metadata')
        try:
            marker = os.open('xray.before.json', file_flags, dir_fd=state)
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
                if set(value) != {'wasActive'} or type(value['wasActive']) is not bool:
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
    emit_error 'XRAY_STATE_INVALID'
    exit 66
}

if [[ "$marker_status" == 'capture' ]]; then
    xray_was_active=false
    if "$systemctl_path" is-active --quiet xray.service >/dev/null 2>&1; then
        xray_was_active=true
    fi
    if ! python3 - "$OPERATION_DIR" "$xray_was_active" <<'PY'
import json
import os
import secrets
import stat
import sys

operation_path, was_active = sys.argv[1:]
dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
if hasattr(os, 'O_NOFOLLOW'):
    dir_flags |= os.O_NOFOLLOW
operation = os.open(operation_path, dir_flags)
try:
    state = os.open('state', dir_flags, dir_fd=operation)
    try:
        state_metadata = os.fstat(state)
        if state_metadata.st_uid != 0 or stat.S_IMODE(state_metadata.st_mode) & 0o022:
            raise RuntimeError('state metadata')
        payload = json.dumps(
            {'wasActive': was_active == 'true'},
            separators=(',', ':'),
        ).encode('ascii')
        temporary_name = f'.xray.before.{secrets.token_hex(12)}'
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=state)
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
                'xray.before.json',
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
        emit_error 'XRAY_STATE_RECORD_FAILED'
        exit 74
    fi
fi

changed="$(python3 - "$OPERATION_DIR" "$ROOT_PATH" <<'PY'
import errno
import json
import os
import secrets
import stat
import sys

operation_path, root_path = sys.argv[1:]
target_relative = 'usr/local/etc/xray/config.json'


def open_dir(path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    if os.fstat(descriptor).st_uid != 0:
        os.close(descriptor)
        raise RuntimeError('ownership')
    return descriptor


def open_child(parent, name):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    return os.open(name, flags, dir_fd=parent)


def read_regular(parent, name, max_bytes=8 * 1024 * 1024):
    metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        raise RuntimeError('invalid file')
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=parent)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0:
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
        return b''.join(chunks), stat.S_IMODE(opened.st_mode)
    finally:
        os.close(descriptor)


operation = open_dir(operation_path)
root = open_dir(root_path)
try:
    candidate_dir = open_child(operation, 'candidate')
    try:
        candidate, _ = read_regular(candidate_dir, 'xray.json')
    finally:
        os.close(candidate_dir)

    backup_bytes, _ = read_regular(operation, 'backup.json')
    backup = json.loads(backup_bytes.decode('utf-8'))
    backed_up = {
        item.get('path') for item in backup.get('files', []) if isinstance(item, dict)
    }
    absent = set(backup.get('absent', []))
    if target_relative not in backed_up.union(absent):
        raise RuntimeError('target not backed up')

    parent = os.dup(root)
    try:
        for component in target_relative.split('/')[:-1]:
            child = open_child(parent, component)
            os.close(parent)
            parent = child
        target_name = target_relative.split('/')[-1]
        existing = None
        try:
            existing = read_regular(parent, target_name)
        except FileNotFoundError:
            pass
        changed = existing != (candidate, 0o644)
        if changed:
            temporary_name = f'.celerity-l2tp-xray.{secrets.token_hex(12)}'
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent)
            try:
                os.fchmod(descriptor, 0o644)
                os.fchown(descriptor, 0, 0)
                view = memoryview(candidate)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.replace(temporary_name, target_name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            finally:
                try:
                    os.unlink(temporary_name, dir_fd=parent)
                except FileNotFoundError:
                    pass
    finally:
        os.close(parent)
finally:
    os.close(root)
    os.close(operation)

print(1 if changed else 0)
PY
)" || {
    emit_error 'XRAY_ACTIVATION_FAILED'
    exit 74
}

if ! "$systemctl_path" restart xray.service >/dev/null 2>&1; then
    emit_error 'XRAY_RESTART_FAILED'
    exit 70
fi
if ! "$systemctl_path" is-active --quiet xray.service >/dev/null 2>&1; then
    emit_error 'XRAY_NOT_ACTIVE'
    exit 70
fi

if ! python3 - "$OPERATION_DIR" <<'PY'
import os
import stat
import sys

operation_path = sys.argv[1]
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
        if not stat.S_ISDIR(os.fstat(state).st_mode):
            raise RuntimeError('invalid state')
        marker_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC
        if hasattr(os, 'O_NOFOLLOW'):
            marker_flags |= os.O_NOFOLLOW
        marker = os.open('xray.activated', marker_flags, 0o600, dir_fd=state)
        try:
            os.fchmod(marker, 0o600)
            os.fchown(marker, 0, 0)
            os.write(marker, b'activated\n')
            os.fsync(marker)
        finally:
            os.close(marker)
        os.fsync(state)
    finally:
        os.close(state)
finally:
    os.close(operation)
PY
then
    emit_error 'XRAY_STATE_RECORD_FAILED'
    exit 74
fi

printf '{"status":"ok","service":"xray.service","changed":%d}\n' "$changed"
