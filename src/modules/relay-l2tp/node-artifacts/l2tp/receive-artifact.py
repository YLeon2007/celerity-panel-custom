#!/usr/bin/python3
"""Receive allowlisted L2TP artifacts without following remote paths."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import sys
from typing import BinaryIO


OPERATIONS_ROOT = "/var/lib/celerity/l2tp/operations"
OPERATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
ARTIFACT_NAMES = frozenset(("desired.json", "artifacts.json"))
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
READ_SIZE = 64 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class ReceiverError(Exception):
    """Sanitized protocol error suitable for the fixed receiver boundary."""

    def __init__(self, code: str):
        super().__init__("L2TP artifact receiver rejected the upload")
        self.code = code


def _is_secure(value: os.stat_result, expected_type: int, mode: int, uid: int, gid: int) -> bool:
    return (
        stat.S_IFMT(value.st_mode) == expected_type
        and stat.S_IMODE(value.st_mode) == mode
        and value.st_uid == uid
        and value.st_gid == gid
    )


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short artifact write")
        remaining = remaining[written:]


def _open_operations_root(operations_root: os.PathLike[str] | str, uid: int, gid: int) -> int:
    try:
        descriptor = os.open(os.fspath(operations_root), DIRECTORY_FLAGS)
    except OSError as error:
        raise ReceiverError("UNSAFE_OPERATIONS_ROOT") from error

    if not _is_secure(os.fstat(descriptor), stat.S_IFDIR, 0o700, uid, gid):
        os.close(descriptor)
        raise ReceiverError("UNSAFE_OPERATIONS_ROOT")
    return descriptor


def _open_operation_directory(root_descriptor: int, operation_id: str, uid: int, gid: int) -> int:
    try:
        os.mkdir(operation_id, 0o700, dir_fd=root_descriptor)
    except FileExistsError:
        pass
    except OSError as error:
        raise ReceiverError("UNSAFE_OPERATION_DIRECTORY") from error

    try:
        descriptor = os.open(operation_id, DIRECTORY_FLAGS, dir_fd=root_descriptor)
    except OSError as error:
        raise ReceiverError("UNSAFE_OPERATION_DIRECTORY") from error

    if not _is_secure(os.fstat(descriptor), stat.S_IFDIR, 0o700, uid, gid):
        os.close(descriptor)
        raise ReceiverError("UNSAFE_OPERATION_DIRECTORY")
    return descriptor


def _assert_safe_existing_target(operation_descriptor: int, artifact_name: str, uid: int, gid: int) -> None:
    try:
        target = os.stat(artifact_name, dir_fd=operation_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ReceiverError("UNSAFE_ARTIFACT_TARGET") from error

    if not _is_secure(target, stat.S_IFREG, 0o600, uid, gid):
        raise ReceiverError("UNSAFE_ARTIFACT_TARGET")


def _create_temporary_artifact(operation_descriptor: int) -> tuple[int, str]:
    for _ in range(8):
        name = f".upload-{secrets.token_hex(16)}"
        try:
            return os.open(name, FILE_FLAGS, 0o600, dir_fd=operation_descriptor), name
        except FileExistsError:
            continue
        except OSError as error:
            raise ReceiverError("UPLOAD_FAILED") from error
    raise ReceiverError("UPLOAD_FAILED")


def receive_artifact(
    source: BinaryIO,
    operation_id: str,
    artifact_name: str,
    *,
    operations_root: os.PathLike[str] | str = OPERATIONS_ROOT,
    expected_uid: int = 0,
    expected_gid: int = 0,
    expected_operation_uid: int | None = None,
    expected_operation_gid: int | None = None,
    max_artifact_bytes: int = MAX_ARTIFACT_BYTES,
) -> None:
    """Write stdin through descriptor-relative opens and an atomic replacement."""

    if not isinstance(operation_id, str) or OPERATION_ID_PATTERN.fullmatch(operation_id) is None:
        raise ReceiverError("INVALID_OPERATION_ID")
    if artifact_name not in ARTIFACT_NAMES:
        raise ReceiverError("ARTIFACT_NOT_ALLOWED")

    operation_uid = expected_uid if expected_operation_uid is None else expected_operation_uid
    operation_gid = expected_gid if expected_operation_gid is None else expected_operation_gid
    root_descriptor = _open_operations_root(operations_root, expected_uid, expected_gid)
    operation_descriptor = -1
    temporary_descriptor = -1
    temporary_name: str | None = None
    replaced = False

    try:
        operation_descriptor = _open_operation_directory(
            root_descriptor,
            operation_id,
            operation_uid,
            operation_gid,
        )
        _assert_safe_existing_target(
            operation_descriptor,
            artifact_name,
            operation_uid,
            operation_gid,
        )
        temporary_descriptor, temporary_name = _create_temporary_artifact(operation_descriptor)

        total = 0
        while True:
            chunk = source.read(READ_SIZE)
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise ReceiverError("UPLOAD_FAILED")
            total += len(chunk)
            if total > max_artifact_bytes:
                raise ReceiverError("ARTIFACT_TOO_LARGE")
            _write_all(temporary_descriptor, chunk)

        os.fchmod(temporary_descriptor, 0o600)
        os.fsync(temporary_descriptor)
        temporary = os.fstat(temporary_descriptor)
        if not _is_secure(temporary, stat.S_IFREG, 0o600, operation_uid, operation_gid):
            raise ReceiverError("UNSAFE_STAGED_ARTIFACT")

        os.close(temporary_descriptor)
        temporary_descriptor = -1
        _assert_safe_existing_target(
            operation_descriptor,
            artifact_name,
            operation_uid,
            operation_gid,
        )
        os.replace(
            temporary_name,
            artifact_name,
            src_dir_fd=operation_descriptor,
            dst_dir_fd=operation_descriptor,
        )
        replaced = True
        os.fsync(operation_descriptor)
    except ReceiverError:
        raise
    except OSError as error:
        raise ReceiverError("UPLOAD_FAILED") from error
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if temporary_name is not None and not replaced and operation_descriptor >= 0:
            try:
                os.unlink(temporary_name, dir_fd=operation_descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if operation_descriptor >= 0:
            os.close(operation_descriptor)
        os.close(root_descriptor)


def _parse_arguments(arguments: list[str]) -> tuple[str, str]:
    if (
        len(arguments) != 4
        or arguments[0] != "--operation-id"
        or arguments[2] != "--artifact-name"
    ):
        raise ReceiverError("INVALID_ARGUMENTS")
    return arguments[1], arguments[3]


def main(arguments: list[str]) -> int:
    try:
        operation_id, artifact_name = _parse_arguments(arguments)
        receive_artifact(sys.stdin.buffer, operation_id, artifact_name)
    except ReceiverError as error:
        sys.stderr.write(json.dumps({"status": "error", "code": error.code}, separators=(",", ":")) + "\n")
        return 1

    sys.stdout.write('{"status":"ok"}\n')
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
