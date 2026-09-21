#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -ne 2 ]]; then
    printf '%s\n' '{"status":"error","code":"INVALID_ARGUMENTS"}' >&2
    exit 64
fi

exec python3 - "$1" "$2" <<'PY'
import json
import os
import secrets
import stat
import sys


class ApplyError(Exception):
    def __init__(self, code, exit_code=65):
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


def emit(payload, stream=sys.stdout):
    print(json.dumps(payload, separators=(',', ':')), file=stream)


def read_manifest(path):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ApplyError('INVALID_MANIFEST_FILE', 66) from error

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ApplyError('INVALID_MANIFEST_FILE', 66)
        if metadata.st_uid != 0:
            raise ApplyError('MANIFEST_NOT_ROOT_OWNED', 77)
        with os.fdopen(descriptor, encoding='utf-8') as handle:
            descriptor = -1
            try:
                return json.load(handle)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ApplyError('INVALID_MANIFEST_JSON') from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


ALLOWLIST = {
    'etc/ipsec.conf': 0o644,
    'etc/ipsec.secrets': 0o600,
    'etc/xl2tpd/xl2tpd.conf': 0o644,
    'etc/ppp/options.xl2tpd': 0o600,
    'etc/ppp/chap-secrets': 0o600,
    'etc/nftables.d/celerity-l2tp.nft': 0o644,
}


def parse_entries(manifest):
    if not isinstance(manifest, dict) or not isinstance(manifest.get('files'), list):
        raise ApplyError('INVALID_MANIFEST')

    entries = []
    seen_paths = set()
    for item in manifest['files']:
        if not isinstance(item, dict):
            raise ApplyError('INVALID_MANIFEST')
        path = item.get('path')
        mode = item.get('mode')
        content = item.get('content')
        if not isinstance(path, str) or not path:
            raise ApplyError('INVALID_PATH')
        if path.startswith('/'):
            raise ApplyError('ABSOLUTE_PATH_NOT_ALLOWED')
        components = path.split('/')
        if any(component in ('', '.', '..') for component in components):
            raise ApplyError('PATH_TRAVERSAL_NOT_ALLOWED')
        if path not in ALLOWLIST:
            raise ApplyError('UNEXPECTED_PATH')
        if path in seen_paths:
            raise ApplyError('DUPLICATE_PATH')
        seen_paths.add(path)
        if isinstance(mode, bool) or not isinstance(mode, int) or mode != ALLOWLIST[path]:
            raise ApplyError('UNEXPECTED_MODE')
        if not isinstance(content, str):
            raise ApplyError('INVALID_CONTENT')
        try:
            encoded_content = content.encode('utf-8')
        except UnicodeEncodeError as error:
            raise ApplyError('INVALID_CONTENT') from error
        entries.append((path, mode, encoded_content))
    return entries


def open_root(path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path, flags)
    except OSError as error:
        raise ApplyError('INVALID_ROOT', 66) from error


def open_parent(root_descriptor, components):
    descriptor = os.dup(root_descriptor)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        for component in components:
            created = False
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o755, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                try:
                    child = os.open(component, flags, dir_fd=descriptor)
                except OSError as error:
                    raise ApplyError('INVALID_TARGET') from error
            except OSError as error:
                raise ApplyError('INVALID_TARGET') from error
            os.close(descriptor)
            descriptor = child
            if created:
                os.fchmod(descriptor, 0o755)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_existing(parent_descriptor, name):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ApplyError('INVALID_TARGET') from error

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ApplyError('INVALID_TARGET')
        chunks = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return stat.S_IMODE(metadata.st_mode), b''.join(chunks)
    finally:
        os.close(descriptor)


def stage_file(parent_descriptor, mode, content):
    name = f'.celerity-l2tp-apply.{secrets.token_hex(12)}'
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, mode, dir_fd=parent_descriptor)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        raise
    os.close(descriptor)
    return name


def apply(manifest_path, root):
    entries = parse_entries(read_manifest(manifest_path))
    root_descriptor = open_root(root)
    parent_descriptors = {}
    planned = []
    staged = []
    unchanged = 0
    try:
        for relative_path, mode, content in entries:
            components = relative_path.split('/')
            parent_key = '/'.join(components[:-1])
            if parent_key not in parent_descriptors:
                parent_descriptors[parent_key] = open_parent(root_descriptor, components[:-1])
            parent_descriptor = parent_descriptors[parent_key]
            target_name = components[-1]
            existing = read_existing(parent_descriptor, target_name)
            if existing == (mode, content):
                unchanged += 1
                continue
            planned.append((parent_descriptor, target_name, mode, content))

        for parent_descriptor, target_name, mode, content in planned:
            temporary_name = stage_file(parent_descriptor, mode, content)
            staged.append((parent_descriptor, temporary_name, target_name))
        for parent_descriptor, temporary_name, target_name in staged:
            os.replace(
                temporary_name,
                target_name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            os.fsync(parent_descriptor)
    finally:
        for parent_descriptor, temporary_name, _ in staged:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        for descriptor in parent_descriptors.values():
            os.close(descriptor)
        os.close(root_descriptor)

    emit({'status': 'ok', 'changed': len(planned), 'unchanged': unchanged})


try:
    apply(sys.argv[1], sys.argv[2])
except ApplyError as error:
    emit({'status': 'error', 'code': error.code}, sys.stderr)
    raise SystemExit(error.exit_code)
except Exception:
    emit({'status': 'error', 'code': 'APPLY_FAILED'}, sys.stderr)
    raise SystemExit(74)
PY
