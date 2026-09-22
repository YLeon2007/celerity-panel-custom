#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -ne 1 ]]; then
    printf '%s\n' '{"status":"error","code":"INVALID_ARGUMENTS"}' >&2
    exit 64
fi

exec python3 - "$1" <<'PY'
import json
import os
import secrets
import stat
import sys

OPERATION_PATH = sys.argv[1]


class CommitError(Exception):
    def __init__(self, code, exit_code=65):
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


def emit(payload, stream=sys.stdout):
    print(json.dumps(payload, separators=(',', ':')), file=stream)


def open_dir(path=None, parent=None, name=None):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        if parent is None:
            descriptor = os.open(path, flags)
        else:
            descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as error:
        raise CommitError('VERIFICATION_REQUIRED', 66) from error
    metadata = os.fstat(descriptor)
    if metadata.st_uid != 0:
        os.close(descriptor)
        raise CommitError('VERIFICATION_REQUIRED', 77)
    return descriptor


def read_json(parent, name, missing_ok=False):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise CommitError('VERIFICATION_REQUIRED', 66)
    except OSError as error:
        raise CommitError('VERIFICATION_REQUIRED', 66) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_size > 1024 * 1024:
            raise CommitError('VERIFICATION_REQUIRED', 77)
        with os.fdopen(descriptor, encoding='utf-8') as handle:
            descriptor = -1
            try:
                return json.load(handle)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise CommitError('VERIFICATION_REQUIRED') from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def validate_verified(value):
    expected_keys = {'fwmark', 'routeTable', 'priority', 'namespace'}
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise CommitError('VERIFICATION_REQUIRED')
    for field in ('fwmark', 'routeTable', 'priority'):
        if type(value[field]) is not int or not 1 <= value[field] <= 2**31 - 1:
            raise CommitError('VERIFICATION_REQUIRED')
    if value['priority'] != 10077 or value['namespace'] != 'celerity_l2tp':
        raise CommitError('VERIFICATION_REQUIRED')


def write_marker(state, payload):
    temporary = f'.committed.{secrets.token_hex(12)}'
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600, dir_fd=state)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 0, 0)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, 'committed.json', src_dir_fd=state, dst_dir_fd=state)
        os.fsync(state)
    finally:
        try:
            os.unlink(temporary, dir_fd=state)
        except FileNotFoundError:
            pass


def main():
    operation = open_dir(path=OPERATION_PATH)
    try:
        state = open_dir(parent=operation, name='state')
        try:
            verified = read_json(state, 'verified.json')
            validate_verified(verified)
            committed = {
                'fwmark': verified['fwmark'],
                'routeTable': verified['routeTable'],
                'priority': verified['priority'],
                'namespace': verified['namespace'],
                'committed': True,
            }
            existing = read_json(state, 'committed.json', missing_ok=True)
            if existing is not None and existing != committed:
                raise CommitError('COMMIT_STATE_CONFLICT')
            changed = existing is None
            if changed:
                payload = json.dumps(committed, separators=(',', ':')).encode('ascii')
                write_marker(state, payload)
        finally:
            os.close(state)
    finally:
        os.close(operation)
    emit({'status': 'ok', 'changed': 1 if changed else 0, 'committed': True})


try:
    main()
except CommitError as error:
    emit({'status': 'error', 'code': error.code}, sys.stderr)
    raise SystemExit(error.exit_code)
except Exception:
    emit({'status': 'error', 'code': 'COMMIT_FAILED'}, sys.stderr)
    raise SystemExit(74)
PY
