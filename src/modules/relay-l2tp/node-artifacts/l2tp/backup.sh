#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -ne 2 ]]; then
    printf '%s\n' '{"status":"error","code":"INVALID_ARGUMENTS"}' >&2
    exit 64
fi

exec python3 - "$1" "$2" <<'PY'
import errno
import json
import os
import secrets
import stat
import sys


MANAGED_PATHS = (
    'etc/ipsec.d/celerity-l2tp.conf',
    'etc/ipsec.secrets',
    'etc/xl2tpd/xl2tpd.conf',
    'etc/ppp/options.xl2tpd',
    'etc/ppp/chap-secrets',
    'etc/nftables.d/celerity-l2tp.nft',
    'usr/local/etc/xray/config.json',
)
MAX_MANAGED_FILE_BYTES = 4 * 1024 * 1024


class BackupError(Exception):
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
        raise BackupError(code, 66) from error
    metadata = os.fstat(descriptor)
    if metadata.st_uid != 0:
        os.close(descriptor)
        raise BackupError('ROOT_OWNERSHIP_REQUIRED', 77)
    return descriptor


def open_child_directory(parent_descriptor, component):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(component, flags, dir_fd=parent_descriptor)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise BackupError('MANAGED_PATH_SYMLINK') from error
        raise BackupError('MANAGED_PATH_INVALID', 66) from error


def read_managed_file(root_descriptor, relative_path):
    components = relative_path.split('/')
    descriptor = os.dup(root_descriptor)
    try:
        for component in components[:-1]:
            child = open_child_directory(descriptor, component)
            if child is None:
                return None
            os.close(descriptor)
            descriptor = child

        name = components[-1]
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            raise BackupError('MANAGED_PATH_SYMLINK')
        if not stat.S_ISREG(metadata.st_mode):
            raise BackupError('MANAGED_PATH_INVALID', 66)
        if metadata.st_uid != 0:
            raise BackupError('MANAGED_PATH_NOT_ROOT_OWNED', 77)
        if metadata.st_size > MAX_MANAGED_FILE_BYTES:
            raise BackupError('MANAGED_PATH_TOO_LARGE')

        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        try:
            file_descriptor = os.open(name, flags, dir_fd=descriptor)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise BackupError('MANAGED_PATH_SYMLINK') from error
            raise BackupError('MANAGED_PATH_INVALID', 66) from error
        try:
            opened_metadata = os.fstat(file_descriptor)
            if not stat.S_ISREG(opened_metadata.st_mode):
                raise BackupError('MANAGED_PATH_INVALID', 66)
            if opened_metadata.st_uid != 0:
                raise BackupError('MANAGED_PATH_NOT_ROOT_OWNED', 77)
            chunks = []
            size = 0
            while True:
                chunk = os.read(file_descriptor, 65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_MANAGED_FILE_BYTES:
                    raise BackupError('MANAGED_PATH_TOO_LARGE')
                chunks.append(chunk)
        finally:
            os.close(file_descriptor)

        try:
            content = b''.join(chunks).decode('utf-8')
        except UnicodeDecodeError as error:
            raise BackupError('MANAGED_PATH_NOT_UTF8') from error
        return {
            'path': relative_path,
            'mode': stat.S_IMODE(opened_metadata.st_mode),
            'content': content,
        }
    finally:
        os.close(descriptor)


def validate_manifest(manifest):
    if not isinstance(manifest, dict):
        raise BackupError('INVALID_BACKUP_MANIFEST')
    files = manifest.get('files')
    absent = manifest.get('absent')
    if not isinstance(files, list) or not isinstance(absent, list):
        raise BackupError('INVALID_BACKUP_MANIFEST')
    file_paths = []
    for item in files:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get('path'), str)
            or item.get('path') not in MANAGED_PATHS
            or isinstance(item.get('mode'), bool)
            or not isinstance(item.get('mode'), int)
            or not isinstance(item.get('content'), str)
        ):
            raise BackupError('INVALID_BACKUP_MANIFEST')
        file_paths.append(item['path'])
    if any(not isinstance(path, str) or path not in MANAGED_PATHS for path in absent):
        raise BackupError('INVALID_BACKUP_MANIFEST')
    if len(file_paths) != len(set(file_paths)) or len(absent) != len(set(absent)):
        raise BackupError('INVALID_BACKUP_MANIFEST')
    if set(file_paths).intersection(absent) or set(file_paths).union(absent) != set(MANAGED_PATHS):
        raise BackupError('INVALID_BACKUP_MANIFEST')
    return len(files), len(absent)


def read_existing_manifest(operation_descriptor):
    try:
        metadata = os.stat('backup.json', dir_fd=operation_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode):
        raise BackupError('BACKUP_MANIFEST_SYMLINK')
    if not stat.S_ISREG(metadata.st_mode):
        raise BackupError('INVALID_BACKUP_MANIFEST_FILE', 66)
    if metadata.st_uid != 0:
        raise BackupError('BACKUP_MANIFEST_NOT_ROOT_OWNED', 77)

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open('backup.json', flags, dir_fd=operation_descriptor)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise BackupError('BACKUP_MANIFEST_SYMLINK') from error
        raise BackupError('INVALID_BACKUP_MANIFEST_FILE', 66) from error
    try:
        with os.fdopen(descriptor, encoding='utf-8') as handle:
            descriptor = -1
            try:
                return validate_manifest(json.load(handle))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise BackupError('INVALID_BACKUP_MANIFEST') from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_manifest(operation_descriptor, manifest):
    temporary_name = f'.backup.json.{secrets.token_hex(12)}'
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary_name, flags, 0o600, dir_fd=operation_descriptor)
    try:
        os.fchmod(descriptor, 0o600)
        payload = json.dumps(manifest, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_name,
            'backup.json',
            src_dir_fd=operation_descriptor,
            dst_dir_fd=operation_descriptor,
        )
        os.fsync(operation_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=operation_descriptor)
        except FileNotFoundError:
            pass


def backup(operation_path, root_path):
    if os.geteuid() != 0:
        raise BackupError('ROOT_REQUIRED', 77)
    operation_descriptor = open_directory(operation_path, 'INVALID_OPERATION_DIRECTORY')
    root_descriptor = open_directory(root_path, 'INVALID_ROOT')
    try:
        existing = read_existing_manifest(operation_descriptor)
        if existing is not None:
            backed_up, absent_count = existing
            emit({'status': 'ok', 'backedUp': backed_up, 'absent': absent_count})
            return

        files = []
        absent = []
        for path in MANAGED_PATHS:
            item = read_managed_file(root_descriptor, path)
            if item is None:
                absent.append(path)
            else:
                files.append(item)
        manifest = {'files': files, 'absent': absent}
        validate_manifest(manifest)
        write_manifest(operation_descriptor, manifest)
        emit({'status': 'ok', 'backedUp': len(files), 'absent': len(absent)})
    finally:
        os.close(root_descriptor)
        os.close(operation_descriptor)


try:
    backup(sys.argv[1], sys.argv[2])
except BackupError as error:
    emit({'status': 'error', 'code': error.code}, sys.stderr)
    raise SystemExit(error.exit_code)
except Exception:
    emit({'status': 'error', 'code': 'BACKUP_FAILED'}, sys.stderr)
    raise SystemExit(74)
PY
