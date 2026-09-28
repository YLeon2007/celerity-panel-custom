"""Dormant offline intent journal. NOT a remote quiescence/enforcement proof.

There is deliberately no dispatch, epoch rotation, release, or proof-clear API.
A committed attempted intent poisons its generation permanently. The only
successful record result is 'blocked', never permission to run a command.
"""
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote


class JournalError(Exception):
    """Unsafe input, invalid store, or a state that cannot be trusted."""


class BlockedError(JournalError):
    """A second distinct intent cannot be accepted in a poisoned epoch."""


_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_DB_NAME = "journal.sqlite3"


def _token(value):
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise JournalError("invalid generation or command id")


def _digest(value):
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise JournalError("invalid SHA-256 digest")


def _directory(path):
    if os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise JournalError("ambiguous process identity")
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw.startswith("/") or ".." in Path(raw).parts:
        raise JournalError("store path must be absolute and cannot traverse")
    current = Path("/")
    for part in Path(raw).parts[1:]:
        current /= part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise JournalError("store path contains a non-directory or symlink")
        if info.st_uid not in (0, os.getuid()):
            raise JournalError("untrusted ancestor owner")
        # /tmp-style sticky directories are safe for a user-owned child.
        if info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX):
            raise JournalError("writable non-sticky ancestor")
    info = current.lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise JournalError("store directory must be private and owned by this user")
    return current


def _check_database(path):
    try:
        info = path.lstat()
    except OSError as exc:
        raise JournalError("missing or unreadable journal") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise JournalError("unsafe database file")
    for suffix in ("-wal", "-shm"):
        extra = Path(str(path) + suffix)
        try:
            info = extra.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise JournalError("unsafe SQLite sidecar")


@contextmanager
def _connect(path):
    _check_database(path)
    db = None
    try:
        db = sqlite3.connect(f"file:{quote(str(path))}?mode=rw", uri=True, timeout=10,
                             isolation_level=None)
        if db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
            raise JournalError("WAL unavailable")
        db.execute("PRAGMA synchronous=FULL")
        _check_database(path)
        yield db
    except sqlite3.Error as exc:
        raise JournalError("journal unavailable or corrupt") from exc
    finally:
        if db is not None:
            db.close()


def _sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def initialize(store, generation):
    """Create one new epoch in a new private directory; never rotate an epoch."""
    _token(generation)
    directory = _directory(store)
    path = directory / _DB_NAME
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except FileExistsError as exc:
        raise JournalError("epoch already exists; no reinitialization") from exc
    else:
        os.close(fd)
    _sync_directory(directory)
    with _connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("CREATE TABLE epoch (singleton INTEGER PRIMARY KEY CHECK (singleton=1), "
                       "generation TEXT NOT NULL, blocked INTEGER NOT NULL CHECK (blocked IN (0,1)))")
            db.execute("CREATE TABLE intents (command_id TEXT PRIMARY KEY, generation TEXT NOT NULL, "
                       "digest TEXT NOT NULL)")
            db.execute("INSERT INTO epoch VALUES (1, ?, 0)", (generation,))
            db.execute("COMMIT")
            _sync_directory(directory)
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise


def record_intent(store, generation, command_id, digest):
    """Durably record uncertainty, then return 'blocked'. NEVER dispatch."""
    _token(generation)
    _token(command_id)
    _digest(digest)
    directory = _directory(store)
    path = directory / _DB_NAME
    with _connect(path) as db:
        db.execute("BEGIN IMMEDIATE")  # serialize every contender for this node
        try:
            rows = db.execute("SELECT singleton, generation, blocked FROM epoch").fetchall()
            if len(rows) != 1 or rows[0][0] != 1 or rows[0][2] not in (0, 1):
                raise JournalError("missing or invalid epoch")
            active, blocked = rows[0][1:]
            _token(active)
            if generation != active:
                raise JournalError("generation mismatch; no epoch rotation")
            intent_count = db.execute("SELECT count(*) FROM intents").fetchone()[0]
            if intent_count > 1:
                raise JournalError("invalid epoch with multiple intents")
            existing = db.execute("SELECT generation, digest FROM intents WHERE command_id=?",
                                  (command_id,)).fetchone()
            if existing is not None:
                if existing != (generation, digest) or not blocked:
                    raise JournalError("conflicting or invalid intent")
                return "blocked"
            if blocked or intent_count != 0:
                raise BlockedError("no quiescence proof; epoch is blocked")
            db.execute("INSERT INTO intents VALUES (?, ?, ?)", (command_id, generation, digest))
            db.execute("UPDATE epoch SET blocked=1 WHERE singleton=1")
            db.execute("COMMIT")
            _sync_directory(directory)  # persist a newly created WAL directory entry
            return "blocked"
        finally:
            if db.in_transaction:
                db.execute("ROLLBACK")
