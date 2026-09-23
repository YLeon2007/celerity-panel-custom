#!/usr/bin/env python3
"""Create a private Compose env from a target env and safe test overrides."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
from typing import NoReturn


ALLOWED_OVERLAY_KEYS = frozenset({
    "PANEL_DOMAIN",
    "ACME_EMAIL",
    "L2TP_EXECUTION_ENABLED",
    "L2TP_MIGRATIONS_ENABLED",
    "TOPOLOGY_TEST_EXECUTION_ENABLED",
})
KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def refuse(message: str) -> NoReturn:
    raise SystemExit(f"staging env refused: {message}")


def require_regular_file(label: str, path: Path) -> None:
    try:
        is_symlink = path.is_symlink()
        is_file = path.is_file()
    except OSError as error:
        refuse(f"{label} cannot be checked ({type(error).__name__})")
    if is_symlink or not is_file:
        refuse(f"{label} must be a local regular file")


def read_dotenv(label: str, path: Path) -> list[tuple[str | None, str]]:
    require_regular_file(label, path)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        refuse(f"{label} cannot be validated ({type(error).__name__})")

    records: list[tuple[str | None, str]] = []
    seen: set[str] = set()
    for raw_line in lines:
        if "\x00" in raw_line:
            refuse(f"{label} must use strict KEY=value syntax")
        line = raw_line.strip()
        if not line or line.startswith("#"):
            records.append((None, raw_line))
            continue
        if line != raw_line or line.startswith("export ") or "=" not in line:
            refuse(f"{label} must use strict KEY=value syntax")
        key, _value = line.split("=", 1)
        if not KEY_PATTERN.fullmatch(key):
            refuse(f"{label} must use strict KEY=value syntax")
        if key in seen:
            refuse(f"{label} contains duplicate dotenv keys")
        seen.add(key)
        records.append((key, raw_line))
    return records


def parse_overlay(path: Path) -> tuple[list[tuple[str | None, str]], dict[str, str]]:
    records = read_dotenv("test config", path)
    values: dict[str, str] = {}
    for key, record in records:
        if key is None:
            continue
        if key not in ALLOWED_OVERLAY_KEYS:
            refuse("unexpected test config key")
        values[key] = record

    parsed_values = {key: record.split("=", 1)[1] for key, record in values.items()}
    if parsed_values.get("PANEL_DOMAIN") != "test.infograd.online":
        refuse("test config PANEL_DOMAIN must match the test host")
    if parsed_values.get("L2TP_EXECUTION_ENABLED") != "true":
        refuse("test config requires L2TP_EXECUTION_ENABLED=true exactly")
    if parsed_values.get("L2TP_MIGRATIONS_ENABLED") != "true":
        refuse(
            "test config with L2TP_EXECUTION_ENABLED=true requires "
            "L2TP_MIGRATIONS_ENABLED=true exactly"
        )
    return records, values


def merged_lines(base_path: Path, overlay_path: Path | None) -> list[str]:
    base_records = read_dotenv("target env file", base_path)
    if overlay_path is None:
        return [record for _key, record in base_records]

    overlay_records, overlay_values = parse_overlay(overlay_path)
    written_overlays: set[str] = set()
    merged: list[str] = []
    for key, record in base_records:
        if key in overlay_values:
            merged.append(overlay_values[key])
            written_overlays.add(key)
        else:
            merged.append(record)
    for key, record in overlay_records:
        if key is not None and key not in written_overlays:
            merged.append(record)
    return merged


def create_merged_env(base_path: Path, overlay_path: Path | None, output_path: Path) -> None:
    records = merged_lines(base_path, overlay_path)
    if output_path.exists() or output_path.is_symlink():
        refuse("temporary Compose env destination already exists")
    if not output_path.parent.is_dir() or output_path.parent.is_symlink():
        refuse("temporary Compose env parent must be a real directory")

    output_fd = -1
    try:
        output_fd = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(output_fd, "w", encoding="utf-8", newline="\n") as output_stream:
            output_fd = -1
            for record in records:
                output_stream.write(record)
                output_stream.write("\n")
            output_stream.flush()
            os.fchmod(output_stream.fileno(), 0o600)
    except OSError as error:
        if output_fd >= 0:
            os.close(output_fd)
        try:
            output_path.unlink()
        except OSError:
            pass
        refuse(f"temporary Compose env cannot be created ({type(error).__name__})")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--base-env-file", required=True)
    parser.add_argument("--overlay-env-file")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    create_merged_env(
        Path(args.base_env_file),
        Path(args.overlay_env_file) if args.overlay_env_file else None,
        Path(args.output),
    )


if __name__ == "__main__":
    main()
