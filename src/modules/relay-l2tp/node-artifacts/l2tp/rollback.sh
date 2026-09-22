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
import subprocess
import sys

OPERATION_PATH = sys.argv[1]
ROOT_PATH = os.environ.get('CELERITY_L2TP_ROOT', '/')
MANAGED_PATHS = frozenset((
    'etc/ipsec.d/celerity-l2tp.conf',
    'etc/ipsec.secrets',
    'etc/xl2tpd/xl2tpd.conf',
    'etc/ppp/options.xl2tpd',
    'etc/ppp/chap-secrets',
    'etc/nftables.d/celerity-l2tp.nft',
    'usr/local/etc/xray/config.json',
))
SAFE_FILE_MODES = frozenset((0o600, 0o640, 0o644))
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
FILE_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC
FILE_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
if hasattr(os, 'O_NOFOLLOW'):
    DIR_FLAGS |= os.O_NOFOLLOW
    FILE_READ_FLAGS |= os.O_NOFOLLOW
    FILE_CREATE_FLAGS |= os.O_NOFOLLOW


class RollbackError(Exception):
    def __init__(self, code, exit_code=65):
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


def emit(stream, payload):
    print(json.dumps(payload, separators=(',', ':')), file=stream)


def secure_directory(path, code):
    try:
        descriptor = os.open(path, DIR_FLAGS)
    except OSError as error:
        raise RollbackError(code, 66) from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        os.close(descriptor)
        raise RollbackError(code, 66)
    return descriptor


def secure_child_directory(parent, name, code):
    try:
        descriptor = os.open(name, DIR_FLAGS, dir_fd=parent)
    except OSError as error:
        raise RollbackError(code, 66) from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        os.close(descriptor)
        raise RollbackError(code, 66)
    return descriptor


def read_regular(parent, name, code, limit=8 * 1024 * 1024):
    try:
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as error:
        raise RollbackError(code, 66) from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise RollbackError(code, 66)
    try:
        descriptor = os.open(name, FILE_READ_FLAGS, dir_fd=parent)
    except OSError as error:
        raise RollbackError(code, 66) from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or stat.S_IMODE(opened.st_mode) & 0o022:
            raise RollbackError(code, 66)
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise RollbackError(code, 66)
            chunks.append(chunk)
        return b''.join(chunks)
    finally:
        os.close(descriptor)


def parse_json(content, code):
    try:
        return json.loads(content.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RollbackError(code, 66) from error


def open_target_parent(root, relative_path):
    descriptor = os.dup(root)
    try:
        for component in relative_path.split('/')[:-1]:
            child = secure_child_directory(descriptor, component, 'ROLLBACK_FAILED')
            os.close(descriptor)
            descriptor = child
        return descriptor, relative_path.rsplit('/', 1)[1]
    except BaseException:
        os.close(descriptor)
        raise


def assert_safe_existing(parent, name):
    try:
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise RollbackError('ROLLBACK_FAILED', 74) from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        raise RollbackError('ROLLBACK_FAILED', 74)


def atomic_write(parent, name, content, mode):
    assert_safe_existing(parent, name)
    temporary = f'.celerity-l2tp-rollback.{secrets.token_hex(12)}'
    try:
        descriptor = os.open(temporary, FILE_CREATE_FLAGS, mode, dir_fd=parent)
    except OSError as error:
        raise RollbackError('ROLLBACK_FAILED', 74) from error
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, 0)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RollbackError('ROLLBACK_FAILED', 74)
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        raise
    os.close(descriptor)
    try:
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def remove_target(parent, name):
    assert_safe_existing(parent, name)
    try:
        os.unlink(name, dir_fd=parent)
        os.fsync(parent)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise RollbackError('ROLLBACK_FAILED', 74) from error
    return True


def parse_backup(value):
    if not isinstance(value, dict) or set(value) != {'files', 'absent'}:
        raise RollbackError('UNSAFE_BACKUP', 66)
    files = value['files']
    absent = value['absent']
    if not isinstance(files, list) or not isinstance(absent, list):
        raise RollbackError('UNSAFE_BACKUP', 66)
    seen = set()
    parsed_files = []
    for item in files:
        if not isinstance(item, dict) or set(item) != {'path', 'mode', 'content'}:
            raise RollbackError('UNSAFE_BACKUP', 66)
        path, mode, content = item['path'], item['mode'], item['content']
        if path not in MANAGED_PATHS or path in seen or isinstance(mode, bool) or mode not in SAFE_FILE_MODES or not isinstance(content, str):
            raise RollbackError('UNSAFE_BACKUP', 66)
        try:
            encoded = content.encode('utf-8')
        except UnicodeEncodeError as error:
            raise RollbackError('UNSAFE_BACKUP', 66) from error
        seen.add(path)
        parsed_files.append((path, mode, encoded))
    parsed_absent = []
    for path in absent:
        if not isinstance(path, str) or path not in MANAGED_PATHS or path in seen:
            raise RollbackError('UNSAFE_BACKUP', 66)
        seen.add(path)
        parsed_absent.append(path)
    return parsed_files, parsed_absent


def parse_marker(state, name, keys):
    return parse_json(read_regular(state, name, 'ROLLBACK_STATE_INVALID'), 'ROLLBACK_STATE_INVALID')


def restore_system_state(state):
    firewall = parse_marker(state, 'firewall.applied.json', {'fwmark', 'routeTable', 'priority'})
    xray = parse_marker(state, 'xray.before.json', {'wasActive'})
    services = parse_marker(state, 'l2tp-services.before.json', {'strongswan-starter.service', 'xl2tpd.service'})
    if (
        set(firewall) != {'fwmark', 'routeTable', 'priority'}
        or any(isinstance(firewall[key], bool) or not isinstance(firewall[key], int) or firewall[key] < 1 for key in firewall)
        or set(xray) != {'wasActive'} or type(xray['wasActive']) is not bool
        or set(services) != {'strongswan-starter.service', 'xl2tpd.service'}
        or any(type(value) is not bool for value in services.values())
    ):
        raise RollbackError('ROLLBACK_STATE_INVALID', 66)
    try:
        subprocess.run(['ip', '-4', 'route', 'del', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', str(firewall['routeTable'])], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['ip', '-4', 'rule', 'del', 'priority', str(firewall['priority']), 'fwmark', str(firewall['fwmark']), 'table', str(firewall['routeTable'])], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['nft', 'delete', 'table', 'inet', 'celerity_l2tp'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'restart' if xray['wasActive'] else 'stop', 'xray.service'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for service in ('strongswan-starter.service', 'xl2tpd.service'):
            subprocess.run(['systemctl', 'restart' if services[service] else 'stop', service], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as error:
        raise RollbackError('ROLLBACK_SYSTEM_FAILED', 70) from error
    return 3


def unlink_marker(state, name):
    try:
        os.unlink(name, dir_fd=state)
    except FileNotFoundError:
        raise RollbackError('ROLLBACK_STATE_INVALID', 66)
    except OSError as error:
        raise RollbackError('ROLLBACK_FAILED', 74) from error


def run():
    if not isinstance(OPERATION_PATH, str) or not os.path.isabs(OPERATION_PATH) or not isinstance(ROOT_PATH, str) or not os.path.isabs(ROOT_PATH):
        raise RollbackError('INVALID_ARGUMENTS', 64)
    operation = secure_directory(OPERATION_PATH, 'BACKUP_REQUIRED')
    root = -1
    state = -1
    try:
        backup = parse_json(read_regular(operation, 'backup.json', 'BACKUP_REQUIRED'), 'BACKUP_REQUIRED')
        files, absent = parse_backup(backup)
        root = secure_directory(ROOT_PATH, 'ROLLBACK_FAILED')
        for path, mode, content in files:
            parent, name = open_target_parent(root, path)
            try:
                atomic_write(parent, name, content, mode)
            finally:
                os.close(parent)
        for path in absent:
            parent, name = open_target_parent(root, path)
            try:
                remove_target(parent, name)
            finally:
                os.close(parent)
        state = secure_child_directory(operation, 'state', 'ROLLBACK_STATE_INVALID')
        services_reverted = restore_system_state(state)
        for marker in ('firewall.applied.json', 'xray.before.json', 'l2tp-services.before.json'):
            unlink_marker(state, marker)
        atomic_write(state, 'rolled-back.json', b'{"status":"rolled_back"}\n', 0o600)
        return {
            'status': 'ok',
            'restored': len(files),
            'removed': len(absent),
            'firewallReverted': True,
            'servicesReverted': services_reverted,
        }
    finally:
        if state >= 0:
            os.close(state)
        if root >= 0:
            os.close(root)
        os.close(operation)


try:
    emit(sys.stdout, run())
except RollbackError as error:
    emit(sys.stderr, {'status': 'error', 'code': error.code})
    raise SystemExit(error.exit_code)
except Exception:
    emit(sys.stderr, {'status': 'error', 'code': 'ROLLBACK_FAILED'})
    raise SystemExit(74)
PY
