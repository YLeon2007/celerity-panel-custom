"""Fixed native adapter for a trusted, already admitted held MAIN session.

This is not an SSH entry point. The installer/receiver must separately pin
host and agent enrollment, the safe plan and the live panel writer authority.
No peer-controlled argv, timeout, filesystem path or observer is accepted.
"""
import math
import subprocess
import time

from rebuildTransitMainRuntime import MainRuntimeObserver, _exchange
from rebuildTransitMainSession import AUTHORITY, DIRECT_LOCK, LOCK, START, STOP, RESTART, HostMainFlock, HostMainSession
from rebuildTransitMainWindow import INVOCATION, PROPERTIES, UNIT, XRAY, XRAY_PROPS, WindowError, require


def _show(unit, properties):
    return ('/usr/bin/systemctl', 'show', '--all', *('--property=' + key for key in properties), '--', unit)


_SHOW = frozenset((_show(UNIT, PROPERTIES), _show(XRAY, XRAY_PROPS)))
_JOURNAL = ('/usr/bin/journalctl', '--quiet', '--no-pager', '--output=cat', '--lines=128', '_SYSTEMD_UNIT=' + UNIT)
_INVOCATION = '_SYSTEMD_INVOCATION_ID='
_LIMITS = {STOP: (25, 0), RESTART: (25, 0), START: (15, 0)}


def _command(argv):
    args = tuple(argv)
    if args in _LIMITS:
        return args, _LIMITS[args]
    if args in _SHOW:
        return args, (4, 16384)
    if (len(args) == len(_JOURNAL) + 1 and args[:-1] == _JOURNAL and args[-1].startswith(_INVOCATION)
            and INVOCATION.fullmatch(args[-1][len(_INVOCATION):])):
        return args, (4, 65536)
    raise WindowError(AUTHORITY)


def _run(deadline, argv, timeout):
    require(type(argv) in (list, tuple) and 0 < len(argv) < 64 and all(type(arg) is str for arg in argv), AUTHORITY)
    args, (cap, size) = _command(argv)
    require(type(timeout) in (int, float) and 0 < timeout <= cap, AUTHORITY)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.SubprocessError()
        value = _exchange(args, b'', timeout=min(timeout, remaining), limit=size, end=deadline).decode('utf-8')
        if time.monotonic() < deadline:
            return value
    except (OSError, subprocess.SubprocessError, UnicodeError, WindowError):
        pass
    # Do not attach journal, manager output or child argv. A killed local
    # systemctl is NOT a cancelled remote manager job; callers must not retry.
    raise subprocess.SubprocessError('REBUILD_MAIN_NATIVE_UNCONFIRMED')


def create_main_session(deadline, flock, *, managed, verify_authority, verify_manager_scope, routes_for):
    """Join the supplied original held flock and clip all native commands."""
    require(type(deadline) in (int, float) and math.isfinite(deadline)
            and all(callable(cb) for cb in (verify_authority, verify_manager_scope)), AUTHORITY)
    require(type(flock) is HostMainFlock and flock.path == DIRECT_LOCK, LOCK)
    flock.check()

    def run(argv, timeout):
        if tuple(argv) in _LIMITS:
            # Stock argv does not itself restrict the systemd transaction.
            # Prove all units affected by the proposed window and exclude
            # outside activation, including a side unit with PartOf=.
            require(verify_manager_scope(deadline) is True and verify_authority() is True, AUTHORITY)
            flock.check()
        return _run(deadline, argv, timeout)

    observer = MainRuntimeObserver(managed, routes_for, deadline=deadline)
    return HostMainSession(run, verify_authority, observer, managed, flock=flock, deadline=deadline)
