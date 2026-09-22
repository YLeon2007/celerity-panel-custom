#!/usr/bin/env python3
"""Validate and safely extract checksum-pinned staging rollback archives."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import tarfile
from typing import NoReturn


MAX_MEMBER_SIZE = 128 * 1024 * 1024
MAX_ARCHIVE_CONTENT_SIZE = 2 * 1024 * 1024 * 1024


def refuse(message: str) -> NoReturn:
    raise SystemExit(f"staging rollback refused: {message}")


def normalized_member_name(raw_name: str, *, allow_root: bool) -> str | None:
    if not raw_name or "\x00" in raw_name or "\\" in raw_name or raw_name.startswith("/"):
        refuse("archive contains an unsafe member path")
    name = raw_name.rstrip("/")
    while name.startswith("./"):
        name = name[2:]
    if name in {"", "."}:
        if allow_root:
            return None
        refuse("archive contains an empty member path")
    if "//" in name:
        refuse("archive contains an unsafe member path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        refuse("archive contains an unsafe member path")
    return path.as_posix()


def checked_members(
    archive: tarfile.TarFile,
    *,
    required_root: str | None,
) -> dict[str, tarfile.TarInfo]:
    members: dict[str, tarfile.TarInfo] = {}
    total_size = 0
    for member in archive.getmembers():
        name = normalized_member_name(member.name, allow_root=required_root is None)
        if name is None:
            if not member.isdir():
                refuse("archive root entry must be a directory")
            continue
        if required_root is not None and name != required_root and not name.startswith(f"{required_root}/"):
            refuse("config backup contains a path outside config/test")
        if name in members:
            refuse("archive contains duplicate member paths")
        if not (member.isfile() or member.isdir()):
            refuse("archive contains links or special files")
        if member.isfile():
            if member.size < 0 or member.size > MAX_MEMBER_SIZE:
                refuse("archive member is too large")
            total_size += member.size
            if total_size > MAX_ARCHIVE_CONTENT_SIZE:
                refuse("archive content is too large")
        members[name] = member

    for name in members:
        path = PurePosixPath(name)
        for index in range(1, len(path.parts)):
            parent_name = PurePosixPath(*path.parts[:index]).as_posix()
            parent = members.get(parent_name)
            if parent is not None and not parent.isdir():
                refuse("archive places a child below a regular file")
    return members


def extract_checked_archive(
    archive_path: Path,
    output_dir: Path,
    *,
    required_root: str | None,
    private_files: bool,
) -> dict[str, tarfile.TarInfo]:
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = checked_members(archive, required_root=required_root)
            output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
            for name, member in sorted(members.items(), key=lambda item: (len(PurePosixPath(item[0]).parts), item[0])):
                destination = output_dir.joinpath(*PurePosixPath(name).parts)
                if member.isdir():
                    destination.mkdir(mode=0o700 if private_files else 0o755, parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(mode=0o700 if private_files else 0o755, parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    refuse("archive member cannot be read")
                content = stream.read(MAX_MEMBER_SIZE + 1)
                if len(content) != member.size or len(content) > MAX_MEMBER_SIZE:
                    refuse("archive member size does not match")
                destination.write_bytes(content)
                if private_files:
                    destination.chmod(0o700 if member.mode & 0o111 else 0o600)
                else:
                    destination.chmod(0o755 if member.mode & 0o111 else 0o644)
            return members
    except (tarfile.TarError, OSError) as error:
        refuse(f"backup archive cannot be validated ({type(error).__name__})")


def validate_test_config(config_env_file: Path) -> None:
    try:
        lines = config_env_file.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        refuse(f"config backup cannot be validated ({type(error).__name__})")
    panel_domains: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or "=" not in line:
            refuse("config backup must use strict KEY=value syntax")
        key, value = line.split("=", 1)
        if key == "PANEL_DOMAIN":
            panel_domains.append(value)
    if panel_domains != ["test.infograd.online"]:
        refuse("config backup PANEL_DOMAIN must match the test host exactly once")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source-archive", required=True)
    parser.add_argument("--config-env-file", required=True)
    parser.add_argument("--extract-source", required=True)
    parser.add_argument("--config-test-present", choices=("true", "false"), required=True)
    parser.add_argument("--config-test-archive")
    parser.add_argument("--extract-config-test")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    validate_test_config(Path(args.config_env_file))
    source_members = extract_checked_archive(
        Path(args.source_archive),
        Path(args.extract_source),
        required_root=None,
        private_files=False,
    )
    compose = source_members.get("docker-compose.yml")
    if compose is None or not compose.isfile():
        refuse("source backup is missing docker-compose.yml")

    if args.config_test_present == "true":
        if not args.config_test_archive or not args.extract_config_test:
            refuse("config/test backup reference is missing")
        config_members = extract_checked_archive(
            Path(args.config_test_archive),
            Path(args.extract_config_test),
            required_root="test",
            private_files=True,
        )
        root = config_members.get("test")
        if root is None or not root.isdir():
            refuse("config/test backup root is missing")
    elif args.config_test_archive or args.extract_config_test:
        refuse("unexpected config/test backup reference")


if __name__ == "__main__":
    main()
