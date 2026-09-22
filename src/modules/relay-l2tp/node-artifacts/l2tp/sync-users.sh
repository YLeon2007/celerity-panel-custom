#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -ne 1 ]]; then
    printf '%s\n' '{"status":"error","code":"INVALID_ARGUMENTS"}' >&2
    exit 64
fi

readonly OPERATION_DIR="$1"
readonly ROOT_PATH="${CELERITY_L2TP_ROOT:-/}"

exec python3 - "$OPERATION_DIR" "$ROOT_PATH" <<'PY'
import errno
import ipaddress
import json
import os
import re
import secrets
import stat
import sys

OPERATION_PATH, ROOT_PATH = sys.argv[1:]
TARGET_PATH = 'etc/ppp/chap-secrets'
BEGIN = '# BEGIN CELERITY MANAGED L2TP USERS'
END = '# END CELERITY MANAGED L2TP USERS'
LOGIN = re.compile(r'^[A-Za-z0-9._@-]{1,64}$')
MAX_INPUT_BYTES = 8 * 1024 * 1024


class SyncError(Exception):
    def __init__(self, code, exit_code=65):
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


def emit(payload, stream=sys.stdout):
    print(json.dumps(payload, separators=(',', ':')), file=stream)


def open_directory(path, code):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SyncError(code, 66) from error
    metadata = os.fstat(descriptor)
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o002:
        os.close(descriptor)
        raise SyncError('ROOT_OWNERSHIP_REQUIRED', 77)
    return descriptor


def read_regular(parent, name, missing_code):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except FileNotFoundError as error:
        raise SyncError(missing_code, 66) from error
    except OSError as error:
        raise SyncError('INVALID_OPERATION_INPUT', 66) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
            raise SyncError('INVALID_OPERATION_INPUT', 77)
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_INPUT_BYTES:
                raise SyncError('INVALID_OPERATION_INPUT')
            chunks.append(chunk)
        try:
            return b''.join(chunks).decode('utf-8')
        except UnicodeDecodeError as error:
            raise SyncError('INVALID_OPERATION_INPUT') from error
    finally:
        os.close(descriptor)


def validate_backup(value):
    if not isinstance(value, dict):
        raise SyncError('INVALID_BACKUP')
    files = value.get('files')
    absent = value.get('absent')
    if not isinstance(files, list) or not isinstance(absent, list):
        raise SyncError('INVALID_BACKUP')
    file_paths = []
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get('path'), str):
            raise SyncError('INVALID_BACKUP')
        file_paths.append(item['path'])
    if any(not isinstance(path, str) for path in absent):
        raise SyncError('INVALID_BACKUP')
    if len(file_paths) != len(set(file_paths)) or len(absent) != len(set(absent)):
        raise SyncError('INVALID_BACKUP')
    if set(file_paths).intersection(absent) or TARGET_PATH not in set(file_paths).union(absent):
        raise SyncError('INVALID_BACKUP')


def validate_users(value):
    if not isinstance(value, list):
        raise SyncError('INVALID_DESIRED_USERS')
    users = []
    logins = set()
    for item in value:
        if not isinstance(item, dict):
            raise SyncError('INVALID_DESIRED_USERS')
        login = item.get('login')
        password = item.get('password')
        address = item.get('ipAddress')
        enabled = item.get('enabled')
        if (
            not isinstance(login, str)
            or LOGIN.fullmatch(login) is None
            or not isinstance(password, str)
            or not password
            or any(character in password for character in ('\r', '\n', '\0'))
            or type(enabled) is not bool
        ):
            raise SyncError('INVALID_DESIRED_USERS')
        try:
            parsed_address = ipaddress.IPv4Address(address)
        except (ipaddress.AddressValueError, TypeError) as error:
            raise SyncError('INVALID_DESIRED_USERS') from error
        if str(parsed_address) != address or login in logins:
            raise SyncError('INVALID_DESIRED_USERS')
        logins.add(login)
        users.append({
            'login': login,
            'password': password,
            'ipAddress': address,
            'enabled': enabled,
        })
    return users


def inspect_block(content):
    begins = []
    ends = []
    offset = 0
    for line in content.splitlines(keepends=True):
        plain = line.rstrip('\r\n')
        marker = (offset, offset + len(line))
        if plain == BEGIN:
            begins.append(marker)
        if plain == END:
            ends.append(marker)
        offset += len(line)
    if offset < len(content):
        plain = content[offset:]
        marker = (offset, len(content))
        if plain == BEGIN:
            begins.append(marker)
        if plain == END:
            ends.append(marker)
    if not begins and not ends:
        return None
    if len(begins) != 1 or len(ends) != 1 or begins[0][0] >= ends[0][0]:
        raise SyncError('INVALID_DESIRED_USERS')
    return begins[0][0], ends[0][1]


def quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def reconcile(existing, users):
    enabled = sorted((user for user in users if user['enabled']), key=lambda user: user['login'])
    lines = [BEGIN]
    lines.extend(
        f"{quote(user['login'])} l2tpd {quote(user['password'])} {user['ipAddress']}"
        for user in enabled
    )
    lines.extend((END, ''))
    block = '\n'.join(lines)
    existing_block = inspect_block(existing)
    if existing_block is not None:
        start, end = existing_block
        return existing[:start] + block + existing[end:], enabled
    separator = '\n' if existing and not existing.endswith(('\r', '\n')) else ''
    return existing + separator + block, enabled


def open_parent(root):
    descriptor = os.dup(root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        for component in TARGET_PATH.split('/')[:-1]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                raise SyncError('CHAP_SECRETS_TARGET_INVALID', 66) from error
            os.close(descriptor)
            descriptor = child
        if os.fstat(descriptor).st_uid != 0:
            raise SyncError('ROOT_OWNERSHIP_REQUIRED', 77)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_target(parent):
    name = TARGET_PATH.split('/')[-1]
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except FileNotFoundError:
        return '', None
    except OSError as error:
        raise SyncError('CHAP_SECRETS_TARGET_INVALID', 66) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
            raise SyncError('CHAP_SECRETS_TARGET_INVALID', 77)
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_INPUT_BYTES:
                raise SyncError('CHAP_SECRETS_TARGET_INVALID')
            chunks.append(chunk)
        try:
            content = b''.join(chunks).decode('utf-8')
        except UnicodeDecodeError as error:
            raise SyncError('CHAP_SECRETS_TARGET_INVALID') from error
        return content, stat.S_IMODE(metadata.st_mode)
    finally:
        os.close(descriptor)


def atomic_write(parent, content):
    name = TARGET_PATH.split('/')[-1]
    temporary = f'.celerity-l2tp-users.{secrets.token_hex(12)}'
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600, dir_fd=parent)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 0, 0)
        payload = content.encode('utf-8')
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def main():
    operation = open_directory(OPERATION_PATH, 'INVALID_OPERATION_DIRECTORY')
    root = open_directory(ROOT_PATH, 'INVALID_ROOT')
    try:
        try:
            backup = json.loads(read_regular(operation, 'backup.json', 'BACKUP_REQUIRED'))
        except json.JSONDecodeError as error:
            raise SyncError('INVALID_BACKUP') from error
        validate_backup(backup)
        try:
            desired = json.loads(read_regular(operation, 'desired.json', 'DESIRED_STATE_REQUIRED'))
        except json.JSONDecodeError as error:
            raise SyncError('INVALID_DESIRED_USERS') from error
        if not isinstance(desired, dict):
            raise SyncError('INVALID_DESIRED_USERS')
        users = validate_users(desired.get('users'))
        parent = open_parent(root)
        try:
            existing, mode = read_target(parent)
            rendered, enabled = reconcile(existing, users)
            changed = existing != rendered or mode != 0o600
            if changed:
                atomic_write(parent, rendered)
        finally:
            os.close(parent)
    finally:
        os.close(root)
        os.close(operation)

    emit({
        'status': 'ok',
        'changed': 1 if changed else 0,
        'managedUsers': len(enabled),
        'disabledUsers': len(users) - len(enabled),
    })


try:
    main()
except SyncError as error:
    emit({'status': 'error', 'code': error.code}, sys.stderr)
    raise SystemExit(error.exit_code)
except Exception:
    emit({'status': 'error', 'code': 'USER_SYNC_FAILED'}, sys.stderr)
    raise SystemExit(74)
PY
