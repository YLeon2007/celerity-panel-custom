#!/usr/bin/env python3
"""Validate and safely extract checksum-pinned staging inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
from typing import NoReturn


MANIFEST_KEYS = {
    "schema_version",
    "source_commit",
    "source_tree",
    "worktree_clean",
    "archive_root",
    "compose_file",
    "app_service",
}


def refuse(message: str) -> "NoReturn":
    raise SystemExit(f"staging input refused: {message}")


def safe_member_name(raw_name: str) -> str:
    if not raw_name or "\\" in raw_name or raw_name.startswith("/"):
        refuse("archive contains an unsafe member path")
    name = raw_name.rstrip("/")
    if not name:
        refuse("archive contains an empty member path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        refuse("archive contains an unsafe member path")
    return path.as_posix()


def checked_members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    members: dict[str, tarfile.TarInfo] = {}
    for member in archive.getmembers():
        name = safe_member_name(member.name)
        if name in members:
            refuse("archive contains duplicate member paths")
        if not (member.isfile() or member.isdir()):
            refuse("archive contains links or special files")
        members[name] = member
    return members


def read_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if not member.isfile() or member.size > limit:
        refuse("archive metadata file is missing or too large")
    stream = archive.extractfile(member)
    if stream is None:
        refuse("archive metadata file cannot be read")
    content = stream.read(limit + 1)
    if len(content) > limit:
        refuse("archive metadata file is too large")
    return content


def parse_fixed_manifest(content: bytes) -> dict[str, str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        refuse("source manifest is not UTF-8")
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            refuse("source manifest has invalid syntax")
        key, value = line.split("=", 1)
        if key in values or key not in MANIFEST_KEYS or not key:
            refuse("source manifest has duplicate or unexpected keys")
        values[key] = value
    if set(values) != MANIFEST_KEYS:
        refuse("source manifest is incomplete")
    return values


def extract_source(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    output_dir: Path,
) -> None:
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    source_names = [name for name in members if name == "source" or name.startswith("source/")]
    if not source_names:
        refuse("source archive root is missing")
    for name in sorted(source_names):
        member = members[name]
        relative = PurePosixPath(name).relative_to("source")
        if not relative.parts:
            continue
        destination = output_dir.joinpath(*relative.parts)
        if member.isdir():
            destination.mkdir(mode=0o755, parents=True, exist_ok=True)
            continue
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        content = read_member(archive, member, 128 * 1024 * 1024)
        destination.write_bytes(content)
        destination.chmod(0o755 if member.mode & 0o111 else 0o644)


def validate_source_bundle(args: argparse.Namespace) -> None:
    try:
        with tarfile.open(args.source_bundle, mode="r:gz") as archive:
            members = checked_members(archive)
            if "manifest.env" not in members:
                refuse("source manifest is missing")
            if any(name != "manifest.env" and name != "source" and not name.startswith("source/") for name in members):
                refuse("source bundle has an unexpected top-level member")
            manifest = parse_fixed_manifest(read_member(archive, members["manifest.env"], 64 * 1024))
            expected = {
                "schema_version": "1",
                "source_commit": args.expected_source_commit,
                "source_tree": args.expected_source_tree,
                "worktree_clean": "true",
                "archive_root": "source",
                "compose_file": "docker-compose.yml",
                "app_service": "backend",
            }
            if manifest != expected:
                refuse("source commit, tree, clean marker, or layout does not match")
            compose_member = members.get("source/docker-compose.yml")
            if compose_member is None or not compose_member.isfile():
                refuse("expected docker-compose.yml is missing")
            extract_source(archive, members, Path(args.extract_source))
    except (tarfile.TarError, OSError) as error:
        refuse(f"source bundle cannot be validated ({type(error).__name__})")


def validate_module_artifact(args: argparse.Namespace) -> None:
    try:
        with tarfile.open(args.module_artifact, mode="r:gz") as archive:
            members = checked_members(archive)
            manifests = [name for name in members if name.endswith("/release-manifest.json")]
            if len(manifests) != 1 or len(PurePosixPath(manifests[0]).parts) != 2:
                refuse("module release manifest is missing or ambiguous")
            content = read_member(archive, members[manifests[0]], 2 * 1024 * 1024)
            try:
                manifest = json.loads(content)
            except (UnicodeDecodeError, json.JSONDecodeError):
                refuse("module release manifest is invalid")
            source = manifest.get("source")
            if not isinstance(source, dict):
                refuse("module artifact source identity is missing or invalid")
            if source.get("commit") != args.expected_source_commit:
                refuse("module artifact source commit does not match")
            if source.get("tree") != args.expected_source_tree:
                refuse("module artifact source tree does not match")
            module = manifest.get("module")
            if not isinstance(module, dict) or module.get("id") != "relay-l2tp":
                refuse("module artifact identity does not match relay-l2tp")
            root = PurePosixPath(manifests[0]).parts[0]
            files = manifest.get("files")
            if not isinstance(files, list):
                refuse("module artifact file manifest is invalid")
            for item in files:
                if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
                    refuse("module artifact file manifest is invalid")
                relative = safe_member_name(item["path"])
                expected_hash = item["sha256"]
                if not isinstance(expected_hash, str) or len(expected_hash) != 64:
                    refuse("module artifact file hash is invalid")
                member = members.get(f"{root}/{relative}")
                if member is None or not member.isfile():
                    refuse("module artifact payload is incomplete")
                actual_hash = hashlib.sha256(read_member(archive, member, 128 * 1024 * 1024)).hexdigest()
                if actual_hash != expected_hash:
                    refuse("module artifact payload checksum mismatch")
    except (tarfile.TarError, OSError) as error:
        refuse(f"module artifact cannot be validated ({type(error).__name__})")


def validate_config_env(args: argparse.Namespace) -> None:
    config_path = Path(args.config_env_file)
    if config_path.is_symlink() or not config_path.is_file():
        refuse("test config env file must be a local regular file")
    try:
        lines = config_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        refuse(f"test config cannot be validated ({type(error).__name__})")
    allowed = {
        "PANEL_DOMAIN",
        "ACME_EMAIL",
        "L2TP_EXECUTION_ENABLED",
        "L2TP_MIGRATIONS_ENABLED",
        "TOPOLOGY_TEST_EXECUTION_ENABLED",
    }
    values: dict[str, str] = {}
    for raw_line in lines:
        if "\x00" in raw_line:
            refuse("test config must use strict KEY=value syntax")
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or "=" not in line:
            refuse("test config must use strict KEY=value syntax")
        key, value = line.split("=", 1)
        if not key or not key.replace("_", "a").isalnum() or not (key[0].isalpha() or key[0] == "_"):
            refuse("test config must use strict KEY=value syntax")
        if key not in allowed:
            refuse("unexpected test config key")
        if key in values:
            refuse("duplicate test config key")
        values[key] = value
    if values.get("PANEL_DOMAIN") != "test.infograd.online":
        refuse("test config PANEL_DOMAIN must match the test host")
    if values.get("L2TP_EXECUTION_ENABLED") != "true":
        refuse("test config requires L2TP_EXECUTION_ENABLED=true exactly")
    if values.get("L2TP_MIGRATIONS_ENABLED") != "true":
        refuse(
            "test config with L2TP_EXECUTION_ENABLED=true requires "
            "L2TP_MIGRATIONS_ENABLED=true exactly"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source-bundle", required=True)
    parser.add_argument("--module-artifact", required=True)
    parser.add_argument("--config-env-file", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-source-tree", required=True)
    parser.add_argument("--extract-source", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    validate_source_bundle(args)
    validate_module_artifact(args)
    validate_config_env(args)


if __name__ == "__main__":
    main()
