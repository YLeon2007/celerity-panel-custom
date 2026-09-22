#!/usr/bin/env python3
"""Fixture tests for the descriptor-based root artifact receiver."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest


RECEIVER_PATH = Path(__file__).resolve().parents[1] / "node-artifacts/l2tp/receive-artifact.py"


def load_receiver():
    spec = importlib.util.spec_from_file_location("celerity_l2tp_receiver", RECEIVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load receiver fixture")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReceiveArtifactFixtureTest(unittest.TestCase):
    def setUp(self):
        self.receiver = load_receiver()
        self.temp = tempfile.TemporaryDirectory(prefix="l2tp-receiver-")
        self.root = Path(self.temp.name) / "operations"
        self.root.mkdir(mode=0o700)
        self.uid = os.getuid()
        self.gid = os.getgid()

    def tearDown(self):
        self.temp.cleanup()

    def receive(
        self,
        operation_id="operation-17",
        artifact_name="desired.json",
        content=b'{"psk":"fixture-secret"}\n',
        **overrides,
    ):
        return self.receiver.receive_artifact(
            io.BytesIO(content),
            operation_id,
            artifact_name,
            operations_root=self.root,
            expected_uid=overrides.pop("expected_uid", self.uid),
            expected_gid=overrides.pop("expected_gid", self.gid),
            **overrides,
        )

    def assert_receiver_error(self, code, callback):
        with self.assertRaises(self.receiver.ReceiverError) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)
        self.assertNotIn("fixture-secret", str(raised.exception))

    def test_creates_root_only_operation_directory_and_atomic_regular_artifact(self):
        content = b'{"psk":"fixture-secret"}\n'

        self.receive(content=content)

        operation = self.root / "operation-17"
        artifact = operation / "desired.json"
        operation_stat = operation.stat()
        artifact_stat = artifact.stat()
        self.assertTrue(stat.S_ISDIR(operation_stat.st_mode))
        self.assertEqual(stat.S_IMODE(operation_stat.st_mode), 0o700)
        self.assertEqual((operation_stat.st_uid, operation_stat.st_gid), (self.uid, self.gid))
        self.assertTrue(stat.S_ISREG(artifact_stat.st_mode))
        self.assertEqual(stat.S_IMODE(artifact_stat.st_mode), 0o600)
        self.assertEqual((artifact_stat.st_uid, artifact_stat.st_gid), (self.uid, self.gid))
        self.assertEqual(artifact.read_bytes(), content)
        self.assertEqual([path.name for path in operation.iterdir()], ["desired.json"])

    def test_replaces_only_a_secure_stale_regular_artifact(self):
        operation = self.root / "operation-stale"
        operation.mkdir(mode=0o700)
        artifact = operation / "artifacts.json"
        artifact.write_bytes(b"stale")
        artifact.chmod(0o600)

        self.receive(
            operation_id="operation-stale",
            artifact_name="artifacts.json",
            content=b"replacement",
        )

        self.assertEqual(artifact.read_bytes(), b"replacement")
        self.assertTrue(stat.S_ISREG(artifact.lstat().st_mode))
        self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)

    def test_rejects_symlinked_operation_directory_without_touching_target(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (self.root / "operation-link").symlink_to(outside, target_is_directory=True)

        self.assert_receiver_error(
            "UNSAFE_OPERATION_DIRECTORY",
            lambda: self.receive(operation_id="operation-link"),
        )
        self.assertEqual(list(outside.iterdir()), [])

    def test_rejects_non_directory_and_insecure_operation_directories(self):
        regular = self.root / "operation-file"
        regular.write_text("not a directory", encoding="utf8")
        insecure_mode = self.root / "operation-mode"
        insecure_mode.mkdir(mode=0o755)
        insecure_owner = self.root / "operation-owner"
        insecure_owner.mkdir(mode=0o700)

        self.assert_receiver_error(
            "UNSAFE_OPERATION_DIRECTORY",
            lambda: self.receive(operation_id="operation-file"),
        )
        self.assert_receiver_error(
            "UNSAFE_OPERATION_DIRECTORY",
            lambda: self.receive(operation_id="operation-mode"),
        )
        self.assert_receiver_error(
            "UNSAFE_OPERATION_DIRECTORY",
            lambda: self.receive(
                operation_id="operation-owner",
                expected_operation_uid=self.uid + 1,
            ),
        )

    def test_rejects_symlink_and_insecure_stale_artifact_targets(self):
        outside = Path(self.temp.name) / "outside-secret"
        outside.write_bytes(b"outside-must-stay")
        linked_operation = self.root / "operation-linked-artifact"
        linked_operation.mkdir(mode=0o700)
        linked_artifact = linked_operation / "desired.json"
        linked_artifact.symlink_to(outside)

        self.assert_receiver_error(
            "UNSAFE_ARTIFACT_TARGET",
            lambda: self.receive(operation_id="operation-linked-artifact"),
        )
        self.assertEqual(outside.read_bytes(), b"outside-must-stay")
        self.assertTrue(linked_artifact.is_symlink())

        insecure_operation = self.root / "operation-insecure-artifact"
        insecure_operation.mkdir(mode=0o700)
        insecure_artifact = insecure_operation / "desired.json"
        insecure_artifact.write_bytes(b"stale-public")
        insecure_artifact.chmod(0o644)

        self.assert_receiver_error(
            "UNSAFE_ARTIFACT_TARGET",
            lambda: self.receive(operation_id="operation-insecure-artifact"),
        )
        self.assertEqual(insecure_artifact.read_bytes(), b"stale-public")
        self.assertEqual(stat.S_IMODE(insecure_artifact.stat().st_mode), 0o644)

    def test_rejects_values_outside_exact_protocol_allowlists(self):
        for operation_id, artifact_name, expected_code in (
            ("../escape", "desired.json", "INVALID_OPERATION_ID"),
            ("operation-17", "other.json", "ARTIFACT_NOT_ALLOWED"),
            ("operation-17", "../desired.json", "ARTIFACT_NOT_ALLOWED"),
        ):
            with self.subTest(operation_id=operation_id, artifact_name=artifact_name):
                self.assert_receiver_error(
                    expected_code,
                    lambda operation_id=operation_id, artifact_name=artifact_name: self.receive(
                        operation_id=operation_id,
                        artifact_name=artifact_name,
                    ),
                )


if __name__ == "__main__":
    unittest.main()
