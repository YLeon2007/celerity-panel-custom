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
MANIFEST_NAME = 'artifacts.json'
CANDIDATE_DIRECTORY_NAME = 'candidate'
CANDIDATE_NAME = 'celerity-l2tp.nft'
SOURCE_PATH = 'etc/nftables.d/celerity-l2tp.nft'
SOURCE_MODE = 0o644
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_CANDIDATE_BYTES = 1024 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC
WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
if hasattr(os, 'O_NOFOLLOW'):
    DIRECTORY_FLAGS |= os.O_NOFOLLOW
    READ_FLAGS |= os.O_NOFOLLOW
    WRITE_FLAGS |= os.O_NOFOLLOW


class CandidateError(Exception):
    pass


def secure_directory(metadata):
    return (
        stat.S_ISDIR(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and metadata.st_uid == 0
        and metadata.st_gid == 0
    )


def open_operation():
    try:
        descriptor = os.open(OPERATION_PATH, DIRECTORY_FLAGS)
    except OSError as error:
        raise CandidateError from error
    if not secure_directory(os.fstat(descriptor)):
        os.close(descriptor)
        raise CandidateError
    return descriptor


def read_manifest(operation):
    try:
        descriptor = os.open(MANIFEST_NAME, READ_FLAGS, dir_fd=operation)
    except OSError as error:
        raise CandidateError from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_size > MAX_MANIFEST_BYTES
        ):
            raise CandidateError
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_MANIFEST_BYTES:
                raise CandidateError
            chunks.append(chunk)
        try:
            return b''.join(chunks).decode('utf-8')
        except UnicodeDecodeError as error:
            raise CandidateError from error
    finally:
        os.close(descriptor)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise CandidateError
        value[key] = item
    return value


def parse_candidate(raw_manifest):
    try:
        manifest = json.loads(raw_manifest, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, RecursionError) as error:
        raise CandidateError from error
    if not isinstance(manifest, dict) or not isinstance(manifest.get('files'), list):
        raise CandidateError

    candidate = None
    seen_paths = set()
    for item in manifest['files']:
        if not isinstance(item, dict):
            raise CandidateError
        path = item.get('path')
        mode = item.get('mode')
        content = item.get('content')
        if (
            not isinstance(path, str)
            or not path
            or path.startswith('/')
            or '\\' in path
        ):
            raise CandidateError
        components = path.split('/')
        if any(component in ('', '.', '..') for component in components):
            raise CandidateError
        if path in seen_paths:
            raise CandidateError
        seen_paths.add(path)
        if (
            isinstance(mode, bool)
            or not isinstance(mode, int)
            or mode < 0
            or mode > 0o777
            or not isinstance(content, str)
        ):
            raise CandidateError
        try:
            encoded = content.encode('utf-8')
        except UnicodeEncodeError as error:
            raise CandidateError from error
        if path == SOURCE_PATH:
            if mode != SOURCE_MODE or candidate is not None:
                raise CandidateError
            candidate = encoded

    if candidate is None or not candidate or len(candidate) > MAX_CANDIDATE_BYTES:
        raise CandidateError
    return candidate


def open_candidate_directory(operation):
    try:
        os.mkdir(CANDIDATE_DIRECTORY_NAME, 0o700, dir_fd=operation)
    except FileExistsError:
        pass
    except OSError as error:
        raise CandidateError from error
    try:
        descriptor = os.open(CANDIDATE_DIRECTORY_NAME, DIRECTORY_FLAGS, dir_fd=operation)
    except OSError as error:
        raise CandidateError from error
    if not secure_directory(os.fstat(descriptor)):
        os.close(descriptor)
        raise CandidateError
    return descriptor


def assert_safe_target(candidate_directory):
    try:
        metadata = os.stat(
            CANDIDATE_NAME,
            dir_fd=candidate_directory,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    except OSError as error:
        raise CandidateError from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != 0
        or metadata.st_gid != 0
    ):
        raise CandidateError


def materialize(candidate_directory, content):
    assert_safe_target(candidate_directory)
    temporary_name = f'.celerity-l2tp-nft.{secrets.token_hex(12)}'
    descriptor = -1
    replaced = False
    try:
        descriptor = os.open(
            temporary_name,
            WRITE_FLAGS,
            0o600,
            dir_fd=candidate_directory,
        )
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 0, 0)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CandidateError
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        assert_safe_target(candidate_directory)
        os.replace(
            temporary_name,
            CANDIDATE_NAME,
            src_dir_fd=candidate_directory,
            dst_dir_fd=candidate_directory,
        )
        replaced = True
        os.fsync(candidate_directory)
    except OSError as error:
        raise CandidateError from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not replaced:
            try:
                os.unlink(temporary_name, dir_fd=candidate_directory)
            except FileNotFoundError:
                pass
            except OSError:
                pass


def main():
    operation = open_operation()
    candidate_directory = -1
    try:
        content = parse_candidate(read_manifest(operation))
        candidate_directory = open_candidate_directory(operation)
        materialize(candidate_directory, content)
    finally:
        if candidate_directory >= 0:
            os.close(candidate_directory)
        os.close(operation)


try:
    main()
except CandidateError:
    print('{"status":"error","code":"NFT_ARTIFACT_INVALID"}', file=sys.stderr)
    raise SystemExit(65)
except Exception:
    print('{"status":"error","code":"NFT_CANDIDATE_MATERIALIZATION_FAILED"}', file=sys.stderr)
    raise SystemExit(74)

print('{"status":"ok","candidate":"candidate/celerity-l2tp.nft"}')
PY
