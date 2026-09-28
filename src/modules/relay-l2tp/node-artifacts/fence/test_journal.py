"""Offline contract tests; no node deployment or execution path."""
import concurrent.futures
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import journal

GEN = "generation-001"
DIGEST = "a" * 64


class JournalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Path(self.temp.name) / "private"
        self.store.mkdir(mode=0o700)

    def test_first_intent_persists_blocked_before_return(self):
        journal.initialize(self.store, GEN)
        result = journal.record_intent(self.store, GEN, "command-001", DIGEST)
        self.assertEqual(result, "blocked")
        with sqlite3.connect(self.store / "journal.sqlite3") as db:
            self.assertEqual(db.execute("SELECT generation, command_id, digest FROM intents").fetchall(),
                             [(GEN, "command-001", DIGEST)])
            self.assertEqual(db.execute("SELECT blocked FROM epoch").fetchall(), [(1,)])

    def test_no_implicit_bootstrap_or_second_epoch(self):
        with self.assertRaises(journal.JournalError):
            journal.record_intent(self.store, GEN, "command-001", DIGEST)
        journal.initialize(self.store, GEN)
        with self.assertRaises(journal.JournalError):
            journal.initialize(self.store, "generation-002")

    def test_stale_or_different_generation_never_writes(self):
        journal.initialize(self.store, GEN)
        for generation in ("generation-000", "generation-002"):
            with self.assertRaises(journal.JournalError):
                journal.record_intent(self.store, generation, "command-001", DIGEST)
        with sqlite3.connect(self.store / "journal.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM intents").fetchone()[0], 0)
        self.assertEqual(journal.record_intent(self.store, GEN, "command-001", DIGEST), "blocked")

    def test_atomic_duplicate_and_changed_digest(self):
        journal.initialize(self.store, GEN)
        self.assertEqual(journal.record_intent(self.store, GEN, "command-001", DIGEST), "blocked")
        self.assertEqual(journal.record_intent(self.store, GEN, "command-001", DIGEST), "blocked")
        with self.assertRaises(journal.JournalError):
            journal.record_intent(self.store, GEN, "command-001", "b" * 64)
        with sqlite3.connect(self.store / "journal.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM intents").fetchone()[0], 1)

    def test_concurrent_contenders_serialize_and_poison_epoch(self):
        journal.initialize(self.store, GEN)
        def attempt(command):
            try:
                return journal.record_intent(self.store, GEN, command, DIGEST)
            except journal.BlockedError:
                return "rejected"
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, [f"command-{i:03d}" for i in range(16)]))
        self.assertEqual(outcomes.count("blocked"), 1)
        self.assertEqual(outcomes.count("rejected"), 15)
        with sqlite3.connect(self.store / "journal.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM intents").fetchone()[0], 1)

    def test_multiple_processes_same_id_dedupe_at_database_boundary(self):
        journal.initialize(self.store, GEN)
        code = ("import journal,sys; print(journal.record_intent(sys.argv[1],"
                "'generation-001','command-001','" + DIGEST + "'))")
        children = [subprocess.Popen([sys.executable, "-c", code, str(self.store)],
                                     env={**os.environ, "PYTHONPATH": str(Path(__file__).parent)},
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    for _ in range(8)]
        for child in children:
            out, err = child.communicate(timeout=15)
            self.assertEqual(child.returncode, 0, err)
            self.assertEqual(out.strip(), "blocked")
        with sqlite3.connect(self.store / "journal.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM intents").fetchone()[0], 1)

    def test_corrupt_database_fails_closed(self):
        (self.store / "journal.sqlite3").write_bytes(b"not SQLite")
        (self.store / "journal.sqlite3").chmod(0o600)
        with self.assertRaises(journal.JournalError):
            journal.record_intent(self.store, GEN, "command-001", DIGEST)
        with self.assertRaises(journal.JournalError):
            journal.initialize(self.store, GEN)

    def test_unsafe_sidecar_fails_closed(self):
        journal.initialize(self.store, GEN)
        (self.store / "journal.sqlite3-wal").symlink_to(self.store / "journal.sqlite3")
        with self.assertRaises(journal.JournalError):
            journal.record_intent(self.store, GEN, "command-001", DIGEST)

    def test_reopen_after_abrupt_exit_stays_blocked_without_clear_api(self):
        journal.initialize(self.store, GEN)
        # Child exits immediately after the durable commit; there is no clean shutdown hook.
        code = ("import journal,os,sys; journal.record_intent(sys.argv[1],"
                "'generation-001','command-001','" + DIGEST + "'); os._exit(19)")
        child = subprocess.run([sys.executable, "-c", code, str(self.store)],
                               env={**os.environ, "PYTHONPATH": str(Path(__file__).parent)},
                               check=False)
        self.assertEqual(child.returncode, 19)
        self.assertEqual(journal.record_intent(self.store, GEN, "command-001", DIGEST), "blocked")
        with self.assertRaises(journal.BlockedError):
            journal.record_intent(self.store, GEN, "command-002", DIGEST)
        with self.assertRaises(journal.JournalError):
            journal.initialize(self.store, GEN)
        for name in ("clear", "release", "rotate", "dispatch", "execute", "prove_quiescence"):
            self.assertFalse(hasattr(journal, name), name)

    def test_rejects_missing_and_malformed_identifiers_before_initialization(self):
        for bad in (None, "", "../escape", "a b", "x" * 129, 3):
            with self.assertRaises(journal.JournalError):
                journal.initialize(self.store, bad)
        journal.initialize(self.store, GEN)
        for bad in (None, "", "../escape", "a b", "x" * 129, 3):
            with self.assertRaises(journal.JournalError):
                journal.record_intent(self.store, bad, "command-001", DIGEST)
            with self.assertRaises(journal.JournalError):
                journal.record_intent(self.store, GEN, bad, DIGEST)
        for bad in (None, "", "A" * 64, "f" * 63, "zz" * 32, 3):
            with self.assertRaises(journal.JournalError):
                journal.record_intent(self.store, GEN, "command-001", bad)
        with sqlite3.connect(self.store / "journal.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM intents").fetchone()[0], 0)

    def test_missing_or_invalid_epoch_fails_closed(self):
        journal.initialize(self.store, GEN)
        with sqlite3.connect(self.store / "journal.sqlite3") as db:
            db.execute("DELETE FROM epoch")
        with self.assertRaises(journal.JournalError):
            journal.record_intent(self.store, GEN, "command-001", DIGEST)
        with self.assertRaises(journal.JournalError):
            journal.initialize(self.store, GEN)

    def test_rejects_path_traversal_symlink_permissions_and_hardlink(self):
        with self.assertRaises(journal.JournalError):
            journal.initialize(Path("relative"), GEN)
        with self.assertRaises(journal.JournalError):
            journal.initialize(self.store / ".." / "private", GEN)
        link = Path(self.temp.name) / "link"
        link.symlink_to(self.store)
        with self.assertRaises(journal.JournalError):
            journal.initialize(link, GEN)
        self.store.chmod(0o755)
        with self.assertRaises(journal.JournalError):
            journal.initialize(self.store, GEN)
        self.store.chmod(0o700)
        journal.initialize(self.store, GEN)
        dbpath = self.store / "journal.sqlite3"
        dbpath.chmod(0o644)
        with self.assertRaises(journal.JournalError):
            journal.record_intent(self.store, GEN, "command-001", DIGEST)
        dbpath.chmod(0o600)
        hardlink = self.store / "copy.sqlite3"
        os.link(dbpath, hardlink)
        with self.assertRaises(journal.JournalError):
            journal.record_intent(self.store, GEN, "command-001", DIGEST)


if __name__ == "__main__":
    unittest.main()
