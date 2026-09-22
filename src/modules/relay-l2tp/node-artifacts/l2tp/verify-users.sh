#!/usr/bin/env bash
set -Eeuo pipefail

emit_argument_error() {
    printf '%s\n' '{"ok":false,"credentialRevision":null,"enabledUserCount":0,"managedUserCount":0,"code":"INVALID_ARGUMENTS"}'
}

if [[ "$#" -ne 1 ]]; then
    emit_argument_error
    exit 64
fi

readonly OPERATION_DIR="$1"
readonly ROOT_PATH="${CELERITY_L2TP_ROOT:-/}"

exec python3 - "$OPERATION_DIR" "$ROOT_PATH" <<'PY'
import ipaddress
import json
import os
import re
import shlex
import stat
import sys

OPERATION_PATH, ROOT_PATH = sys.argv[1:]
TARGET_COMPONENTS = ('etc', 'ppp', 'chap-secrets')
BEGIN = '# BEGIN CELERITY MANAGED L2TP USERS'
END = '# END CELERITY MANAGED L2TP USERS'
LOGIN = re.compile(r'^[A-Za-z0-9._@-]{1,64}$')
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_SAFE_INTEGER = (2 ** 53) - 1


class VerificationError(Exception):
    def __init__(self, code, *, exit_code=65, revision=None, enabled=0, managed=0):
        super().__init__('L2TP user verification failed')
        self.code = code
        self.exit_code = exit_code
        self.revision = revision
        self.enabled = enabled
        self.managed = managed


def emit(ok, revision, enabled, managed, code):
    print(json.dumps({
        'ok': ok,
        'credentialRevision': revision,
        'enabledUserCount': enabled,
        'managedUserCount': managed,
        'code': code,
    }, separators=(',', ':')))


def open_directory(path, code):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError(code, exit_code=66) from error
    metadata = os.fstat(descriptor)
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o002:
        os.close(descriptor)
        raise VerificationError(code, exit_code=77)
    return descriptor


def read_regular(parent, name, code, *, exact_mode=None):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as error:
        raise VerificationError(code, exit_code=66) from error
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or (exact_mode is not None and mode != exact_mode)
        ):
            raise VerificationError(code, exit_code=77)
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_INPUT_BYTES:
                raise VerificationError(code)
            chunks.append(chunk)
        try:
            return b''.join(chunks).decode('utf-8')
        except UnicodeDecodeError as error:
            raise VerificationError(code) from error
    finally:
        os.close(descriptor)


def open_target_parent(root):
    descriptor = os.dup(root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        for component in TARGET_COMPONENTS[:-1]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                raise VerificationError('CHAP_SECRETS_INVALID', exit_code=66) from error
            os.close(descriptor)
            descriptor = child
            metadata = os.fstat(descriptor)
            if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o002:
                raise VerificationError('CHAP_SECRETS_INVALID', exit_code=77)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_desired(value):
    if not isinstance(value, dict) or set(value) != {'credentialRevision', 'users'}:
        raise VerificationError('VERIFY_USERS_INPUT_INVALID')
    revision = value['credentialRevision']
    if type(revision) is not int or not 1 <= revision <= MAX_SAFE_INTEGER:
        raise VerificationError('VERIFY_USERS_INPUT_INVALID')
    users_value = value['users']
    if not isinstance(users_value, list):
        raise VerificationError('VERIFY_USERS_INPUT_INVALID', revision=revision)

    users = []
    logins = set()
    for item in users_value:
        if not isinstance(item, dict) or set(item) != {'login', 'password', 'ipAddress', 'enabled'}:
            raise VerificationError('VERIFY_USERS_INPUT_INVALID', revision=revision)
        login = item['login']
        password = item['password']
        address = item['ipAddress']
        enabled = item['enabled']
        if (
            not isinstance(login, str)
            or LOGIN.fullmatch(login) is None
            or login in logins
            or not isinstance(password, str)
            or not password
            or any(character in password for character in ('\r', '\n', '\0'))
            or type(enabled) is not bool
        ):
            raise VerificationError('VERIFY_USERS_INPUT_INVALID', revision=revision)
        try:
            parsed_address = ipaddress.IPv4Address(address)
        except (ipaddress.AddressValueError, TypeError) as error:
            raise VerificationError('VERIFY_USERS_INPUT_INVALID', revision=revision) from error
        if str(parsed_address) != address:
            raise VerificationError('VERIFY_USERS_INPUT_INVALID', revision=revision)
        logins.add(login)
        users.append((login, password, address, enabled))
    return revision, users


def managed_lines(content, revision, enabled_count):
    lines = content.splitlines()
    begins = [index for index, line in enumerate(lines) if line == BEGIN]
    ends = [index for index, line in enumerate(lines) if line == END]
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise VerificationError(
            'MANAGED_BLOCK_INVALID',
            revision=revision,
            enabled=enabled_count,
        )
    return lines[begins[0] + 1:ends[0]]


def quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def verify_entries(lines, users, revision):
    enabled = {login: (password, address) for login, password, address, active in users if active}
    disabled = {login for login, _password, _address, active in users if not active}
    enabled_count = len(enabled)
    managed_count = len(lines)
    actual = {}

    for line in lines:
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError:
            raise VerificationError(
                'MANAGED_USERS_ALTERED',
                revision=revision,
                enabled=enabled_count,
                managed=managed_count,
            )
        if len(tokens) != 4 or tokens[1] != 'l2tpd' or LOGIN.fullmatch(tokens[0]) is None:
            raise VerificationError(
                'MANAGED_USERS_ALTERED',
                revision=revision,
                enabled=enabled_count,
                managed=managed_count,
            )
        login, _service, password, address = tokens
        if login in actual:
            raise VerificationError(
                'MANAGED_USERS_DUPLICATE',
                revision=revision,
                enabled=enabled_count,
                managed=managed_count,
            )
        actual[login] = (password, address, line)

    if disabled.intersection(actual):
        raise VerificationError(
            'DISABLED_USERS_PRESENT',
            revision=revision,
            enabled=enabled_count,
            managed=managed_count,
        )
    if set(enabled).difference(actual):
        raise VerificationError(
            'MANAGED_USERS_MISSING',
            revision=revision,
            enabled=enabled_count,
            managed=managed_count,
        )
    if set(actual).difference(enabled):
        raise VerificationError(
            'MANAGED_USERS_EXTRA',
            revision=revision,
            enabled=enabled_count,
            managed=managed_count,
        )

    for login, (password, address) in enabled.items():
        actual_password, actual_address, actual_line = actual[login]
        expected_line = f'{quote(login)} l2tpd {quote(password)} {address}'
        if (actual_password, actual_address) != (password, address) or actual_line != expected_line:
            raise VerificationError(
                'MANAGED_USERS_ALTERED',
                revision=revision,
                enabled=enabled_count,
                managed=managed_count,
            )
    return enabled_count, managed_count


def main():
    operation = open_directory(OPERATION_PATH, 'INVALID_OPERATION_DIRECTORY')
    root = open_directory(ROOT_PATH, 'INVALID_ROOT')
    try:
        try:
            desired = json.loads(read_regular(operation, 'desired.json', 'VERIFY_USERS_INPUT_INVALID', exact_mode=0o600))
        except json.JSONDecodeError as error:
            raise VerificationError('VERIFY_USERS_INPUT_INVALID') from error
        revision, users = validate_desired(desired)
        enabled_count = sum(1 for _login, _password, _address, active in users if active)
        parent = open_target_parent(root)
        try:
            content = read_regular(parent, TARGET_COMPONENTS[-1], 'CHAP_SECRETS_INVALID', exact_mode=0o600)
        finally:
            os.close(parent)
        lines = managed_lines(content, revision, enabled_count)
        enabled_count, managed_count = verify_entries(lines, users, revision)
    finally:
        os.close(root)
        os.close(operation)
    emit(True, revision, enabled_count, managed_count, 'USERS_VERIFIED')


try:
    main()
except VerificationError as error:
    emit(False, error.revision, error.enabled, error.managed, error.code)
    raise SystemExit(error.exit_code)
except Exception:
    emit(False, None, 0, 0, 'VERIFY_USERS_FAILED')
    raise SystemExit(74)
PY
