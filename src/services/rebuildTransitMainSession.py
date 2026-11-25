"""Single-use held host MAIN step. No CLI or default command runner.

The injected callbacks are trusted composition seams, not product bindings.
In particular the directory flock excludes cooperating DIRECT writers, not a
separate administrator, scheduler, or writer that does not take that lock.
The caller owns the live operation/host authority and durable mutation intent;
any lost phase acknowledgement stays unresolved. Closing this local session
only releases its descriptor; it never retries, restores MAIN or starts a unit.
"""
import fcntl
import json
import os
import stat
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import NamedTuple

from rebuildTransitMainWindow import (
    AgentWindow, CGROUP_ROOT, DIR, MAIN, MAIN_DRIFT, MAX_MAIN, TAG, UNIT, XRAY,
    MainImage, WindowError, merge_clients, parse_json, require, topology_bytes,
)

# rebuildRelayDirectHost.py takes this directory inode's flock, not a file in it.
DIRECT_LOCK = Path('/etc/systemd/system')
LOCK = 'REBUILD_MAIN_LOCK_UNPROVED'
AUTHORITY = 'REBUILD_MAIN_AUTHORITY_UNPROVED'
RUNTIME = 'REBUILD_MAIN_RUNTIME_UNPROVED'
STATE = 'REBUILD_MAIN_SESSION_STATE'
STOP = ('/usr/bin/systemctl', 'stop', '--job-mode=fail', '--', UNIT)
RESTART = ('/usr/bin/systemctl', 'restart', '--job-mode=fail', '--', XRAY)
START = ('/usr/bin/systemctl', 'start', '--job-mode=fail', '--', UNIT)


class XrayGeneration(NamedTuple):
    pid: int
    invocation_id: str


class MainSnapshot(NamedTuple):
    main: MainImage
    xray: XrayGeneration


class MainPublication(NamedTuple):
    before: MainImage
    desired: bytes


def _generation(row):
    return XrayGeneration(int(row['MainPID']), row['InvocationID'])


def _json_bytes(profile):
    try:
        return json.dumps(profile, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    except (ValueError, TypeError, RecursionError):
        raise WindowError(MAIN_DRIFT) from None


class _HeldWindow(AgentWindow):
    def __init__(self, session, **kwargs):
        super().__init__(session._run, **kwargs)
        self._session = session

    def _check_main_dir(self, parent):
        # AgentWindow calls this after staging/fsync, just before its final
        # file/stage CAS and rename, and again on publication readback.
        if self._session._state == 'captured':
            self._session._check_authority()
        super()._check_main_dir(parent)


class HostMainSession:
    """Use one lexical context on one thread, with exactly one AgentWindow.

    read() -> MainSnapshot before stop (also allowed after reconcile).
    stop() -> None; joins the original cc-agent shutdown, after a read().
    capture(expected: MainSnapshot, target: bytes) -> MainPublication;
        expected is the prior read, target is the authorized profile image.
        Only the managed clients are refreshed from the exact post-drain MAIN.
    publish(before: MainImage, desired: bytes) -> MainImage;
        use the capture's exact before/desired, reopened from durable pins by
        the caller. The returned image has the new file generation.
    restart() -> MainSnapshot; start() -> None; reconcile() -> MainSnapshot.

    run(argv, timeout) must synchronously join the fixed commands and raise on
    nonzero/timeout/truncation/uncertain completion. verify_authority() must
    return True only for the live exact host, writer scope, loaded agent config
    (including managed tags), and the operation's current fence (including
    durable intent before any mutation). verify_runtime(phase, snapshot) must
    return True only after independent read-only verification of
    the scoped runtime against the snapshot ('capture', 'restart', 'reconcile').
    Callbacks must be bounded, not reenter the session or retain its authority.
    No callback or returned snapshot replaces durable intent/artifact proofs.
    Path/clock overrides are for trusted fixtures, not request parameters.
    """

    def __init__(self, run, verify_authority, verify_runtime, managed, *,
                 main=MAIN, cgroup_root=CGROUP_ROOT, lock_dir=DIRECT_LOCK,
                 clock=time.monotonic, sleep=time.sleep):
        require(all(callable(f) for f in (run, verify_authority, verify_runtime)), STATE)
        require(type(managed) in (set, frozenset) and managed
                and all(type(tag) is str and TAG.fullmatch(tag) for tag in managed),
                'REBUILD_AGENT_MANAGED_PROFILE_UNPROVED')
        self._managed = frozenset(managed)
        self._runner = run
        self._authority = verify_authority
        self._runtime = verify_runtime
        self._lock = Path(lock_dir)
        require(self._lock.is_absolute(), LOCK)
        self._fd = None
        self._identity = None
        self._owner = None
        self._state = 'new'
        self._busy = False
        self._baseline = None
        self._baseline_topology = None
        self._publication = None
        self._written = None
        self._window = _HeldWindow(self, main=Path(main), cgroup_root=Path(cgroup_root), clock=clock, sleep=sleep)

    def __enter__(self):
        require(self._state == 'new', STATE)
        self._state = 'entering'
        self._owner = (os.getpid(), threading.get_ident())
        try:
            try:
                self._fd = os.open(self._lock, DIR)
                info = os.fstat(self._fd)
                self._identity = (info.st_dev, info.st_ino)
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise WindowError(LOCK) from None
            self._check_authority()
            self._state = 'ready'
            return self
        except BaseException as error:
            self._close(error)
            raise

    def __exit__(self, exc_type, error, traceback):
        require(self._owner == (os.getpid(), threading.get_ident()) and not self._busy
                and self._state not in ('entering', 'closed'), STATE)
        try:
            if error is None and self._state != 'failed':
                self._check_lock()
        except BaseException as lock_error:
            self._close(lock_error)
            raise
        self._close(error)

    def _close(self, error):
        self._state = 'closed'
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                if error is None:
                    raise WindowError(LOCK) from None
                error.add_note('REBUILD_MAIN_LOCK_CLOSE_UNCONFIRMED')

    def _check_lock(self):
        fd = self._fd
        if fd is None or self._state in ('failed', 'closed'):
            raise WindowError(STATE)
        try:
            held, named = os.fstat(fd), self._lock.lstat()
            require(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(named.st_mode)
                    and (held.st_dev, held.st_ino) == self._identity == (named.st_dev, named.st_ino), LOCK)
        except OSError:
            raise WindowError(LOCK) from None

    def _check_authority(self):
        self._check_lock()
        allowed = self._authority()
        self._check_lock()
        require(allowed is True, AUTHORITY)

    @contextmanager
    def _action(self, allowed, advance=None):
        require(self._owner == (os.getpid(), threading.get_ident()), STATE)
        if self._busy:
            # Reentry cannot clear the outer call's busy bit or close its FD.
            self._state = 'failed'
            raise WindowError(STATE)
        try:
            require(self._state in allowed, STATE)
            self._busy = True
            self._check_authority()
            yield
            self._check_authority()
            if advance is not None:
                self._state = advance
        except BaseException:
            # A caught error cannot revive the same capability or release the
            # lock while a caller is still disposing of the failed operation.
            if self._state != 'closed':
                self._state = 'failed'
            raise
        finally:
            self._busy = False

    def _run(self, argv, timeout):
        self._check_lock()
        command = tuple(argv)
        if command in (STOP, RESTART, START):
            self._check_authority()
            if command == STOP:
                require(self._baseline is not None and self._window._xray is not None
                        and _generation(self._window._xray) == self._baseline.xray, RUNTIME)
                self._check_baseline_image(self._window.read_main())
            else:
                require(self._written is not None and self._window.read_main() == self._written, MAIN_DRIFT)
            self._check_lock()
        result = self._runner(argv, timeout)
        self._check_lock()
        return result

    def _sample(self, *, xray=None, main=None):
        row = self._window._main_unit()
        require(xray is None or row == xray, RUNTIME)
        image = self._window.read_main()
        require(self._window._main_unit() == row, RUNTIME)
        require(main is None or image == main, MAIN_DRIFT)
        return MainSnapshot(image, _generation(row))

    def _check_baseline_image(self, image):
        require(topology_bytes(parse_json(image.data), self._managed) == self._baseline_topology, MAIN_DRIFT)

    def _check_started(self):
        window = self._window
        require(window._new is not None and window._unit() == window._new and window._cgroup_populated()
                and window._unit() == window._new, RUNTIME)

    def _prove_runtime(self, phase, snapshot):
        self._check_authority()
        allowed = self._runtime(phase, snapshot)
        self._check_authority()
        require(allowed is True, RUNTIME)
        if phase == 'reconcile':
            self._check_started()
        else:
            self._window.require_quiet()
        require(self._sample(xray=self._window._xray, main=snapshot.main) == snapshot, RUNTIME)

    def read(self):
        with self._action(('ready', 'reconciled')):
            if self._state == 'reconciled':
                self._check_started()
                return self._sample(xray=self._window._xray, main=self._written)
            baseline = self._sample()
            self._baseline_topology = topology_bytes(parse_json(baseline.main.data), self._managed)
            self._baseline = baseline
            return baseline

    def stop(self):
        with self._action(('ready',), 'quiet'):
            require(self._baseline is not None, STATE)
            self._window.quiesce()

    def capture(self, expected, target):
        with self._action(('quiet',), 'captured'):
            require(type(expected) is MainSnapshot and expected == self._baseline
                    and type(target) is bytes and 0 < len(target) <= MAX_MAIN, MAIN_DRIFT)
            self._window.require_quiet()
            fresh = self._sample(xray=self._window._xray)
            require(fresh.xray == expected.xray, RUNTIME)
            self._check_baseline_image(fresh.main)
            candidate = parse_json(target)
            merged = _json_bytes(merge_clients(candidate, parse_json(fresh.main.data), self._managed))
            desired = target if merged == _json_bytes(candidate) else merged
            require(len(desired) <= MAX_MAIN, MAIN_DRIFT)
            self._prove_runtime('capture', fresh)
            self._publication = MainPublication(fresh.main, desired)
            return self._publication

    def publish(self, before, desired):
        with self._action(('captured',), 'published'):
            publication = self._publication
            if publication is None:
                raise WindowError(STATE)
            require(type(before) is MainImage and type(desired) is bytes
                    and publication == (before, desired), MAIN_DRIFT)
            self._written = self._window.publish_main(*publication)
            return self._written

    def restart(self):
        with self._action(('published',), 'restarted'):
            self._window.require_quiet()
            try:
                self._run(list(RESTART), 25)
            except (OSError, subprocess.SubprocessError):
                raise WindowError('REBUILD_MAIN_RESTART_UNCONFIRMED') from None
            self._window.join_xray_restart()
            current = self._sample(xray=self._window._xray, main=self._written)
            self._prove_runtime('restart', current)
            return current

    def start(self):
        with self._action(('restarted',), 'started'):
            self._window.resume()
            self._sample(xray=self._window._xray, main=self._written)

    def reconcile(self):
        with self._action(('started',), 'reconciled'):
            self._window.wait_reconciled()
            self._check_started()
            current = self._sample(xray=self._window._xray, main=self._written)
            self._prove_runtime('reconcile', current)
            return current
