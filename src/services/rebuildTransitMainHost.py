"""Fixed native adapter for a trusted, already admitted held MAIN session.

This is not an SSH entry point. The installer/receiver must separately pin
host and agent enrollment, the safe plan and the live panel writer authority.
No peer-controlled argv, timeout, filesystem path or observer is accepted.
"""
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from rebuildTransitMainRuntime import MainRuntimeObserver, _exchange
from rebuildTransitMainSession import AUTHORITY, DIRECT_LOCK, LOCK, START, STOP, RESTART, HostMainFlock, HostMainSession
from rebuildTransitMainWindow import (
    AGENT_EMPTY, EXPECTED_EXEC, INVOCATION, PROPERTIES, SMALL_FILE, UNIT, XRAY, XRAY_EXEC, XRAY_PROPS,
    WindowError, _file_generation, _file_metadata, _state_fields, require,
)


def _show(unit, properties):
    return ('/usr/bin/systemctl', 'show', '--all', *('--property=' + key for key in properties), '--', unit)


_SCOPE_EMPTY = tuple(('Requisite RequisiteOf RequiredBy BindsTo BoundBy PartOf ConsistsOf '
                      'PropagatesStopTo StopPropagatedFrom Upholds UpheldBy Triggers TriggeredBy '
                      'OnFailure OnSuccess ExecCondition ExecStartPre ExecStartPost ExecStop ExecStopPost '
                      'ExecReload Environment EnvironmentFiles PassEnvironment UnsetEnvironment RootDirectory '
                      'RootImage SourcePath').split())
_SCOPE_NONE = ('FailureAction', 'SuccessAction', 'StartLimitAction', 'JobTimeoutAction')
_SCOPE_PROPS = ('Id', 'LoadState', 'NeedDaemonReload', 'Job', 'ActiveState', 'SubState', 'MainPID', 'InvocationID',
                'Requires', 'Wants', 'Conflicts', 'ConflictedBy', 'Type', 'KillMode', 'ExecStart', 'FragmentPath',
                'DropInPaths', 'PrivateNetwork', 'WorkingDirectory', 'StopWhenUnneeded', 'ControlPID')
_SCOPE_PROPS += _SCOPE_EMPTY + _SCOPE_NONE
_ANCHORS = frozenset(('-.mount', 'system.slice', 'sysinit.target', 'basic.target', 'network-online.target'))
_SHUTDOWN = 'shutdown.target'
_PULLS = ('Requires', 'Wants', 'Requisite', 'BindsTo', 'Upholds')
_STOP_EDGES = ('RequiredBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo')
_ANCHOR_PROPS = ('Id', 'LoadState', 'NeedDaemonReload', 'Job', 'ActiveState', 'StopWhenUnneeded', 'Conflicts',
                 'ConflictedBy', 'OnFailure', 'OnSuccess', *_PULLS, *_STOP_EDGES)
_MANAGER_UNIT = re.compile(r'(?:[A-Za-z0-9_.:@-]|\\x[0-9a-f]{2}){1,240}\.(?:service|mount|automount|target|slice|socket|device|swap|path|timer|scope)')
_MAX_DEPENDENCIES = 96
_JOBS = ('/usr/bin/systemctl', 'list-jobs', '--no-legend', '--plain', '--no-pager')
_SHOW = frozenset((_show(UNIT, PROPERTIES), _show(XRAY, XRAY_PROPS), _show(UNIT, _SCOPE_PROPS),
                   _show(XRAY, _SCOPE_PROPS), *(_show(name, _ANCHOR_PROPS) for name in _ANCHORS | {_SHUTDOWN})))
_UNIT_DIR = Path('/etc/systemd/system')
_XRAY_DROP = '10-donot_touch_single_conf.conf'
_SETUP_DROPS = {
    '90-celerity-config-access.conf': b'# Managed by Celerity Xray setup\n[Service]\nSupplementaryGroups=xray\n',
    '90-celerity-logs-directory.conf': b'# Managed by Celerity Xray setup\n[Service]\nLogsDirectory=xray\n',
}
_JOURNAL = ('/usr/bin/journalctl', '--quiet', '--no-pager', '--output=cat', '--lines=128', '_SYSTEMD_UNIT=' + UNIT)
_INVOCATION = '_SYSTEMD_INVOCATION_ID='
_LIMITS = {STOP: (25, 0), RESTART: (25, 0), START: (15, 0)}


def _dependencies_show(names):
    return (*_show('', _ANCHOR_PROPS)[:-1], *names)


def _command(argv):
    args = tuple(argv)
    if args in _LIMITS:
        return args, _LIMITS[args]
    if args in _SHOW:
        return args, (4, 16384)
    prefix = _dependencies_show(())
    names = args[len(prefix):]
    if (args[:len(prefix)] == prefix and 0 < len(names) <= 32 and len(set(names)) == len(names)
            and all(_MANAGER_UNIT.fullmatch(name) for name in names)):
        return args, (4, 256 << 10)
    if args == _JOBS:
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


def _trusted_file(path, limit):
    """Read a fixed root-controlled file and return its exact local identity."""
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, AUTHORITY)
    with os.fdopen(os.open(path, SMALL_FILE), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o7022 and 0 < info.st_size <= limit, AUTHORITY)
        data = stream.read(info.st_size + 1)
        pin = _file_generation(info), _file_metadata(info)
        require(len(data) == info.st_size and all((_file_generation(row), _file_metadata(row)) == pin
                for row in (os.fstat(stream.fileno()), path.lstat())), AUTHORITY)
        return data, pin


def _layout(name, row):
    fragment = _UNIT_DIR / name
    require(row['FragmentPath'] == str(fragment), AUTHORITY)
    _trusted_file(fragment, 16384)
    if name == UNIT:
        require(not row['DropInPaths'] and EXPECTED_EXEC.fullmatch(row['ExecStart'])
                and not row['Wants'] and set(row['Requires'].split()) <= {'system.slice', 'sysinit.target'}
                and not any(row[k] for k in AGENT_EMPTY if k in row), AUTHORITY)
        return
    require(XRAY_EXEC.fullmatch(row['ExecStart']), AUTHORITY)
    folder = _UNIT_DIR / (XRAY + '.d')
    try:
        info = folder.lstat()
    except FileNotFoundError:
        names = []
    else:
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, AUTHORITY)
        with os.scandir(folder) as entries:
            names = []
            for i, entry in enumerate(entries):
                require(i < 64, AUTHORITY)
                if entry.name.endswith('.conf'):
                    names.append(entry.name)
    require(set(row['DropInPaths'].split()) == {str(folder / n) for n in names}
            and all(n == _XRAY_DROP or n in _SETUP_DROPS for n in names), AUTHORITY)
    for name in names:
        data, _ = _trusted_file(folder / name, 16384)
        if name != _XRAY_DROP:
            require(data == _SETUP_DROPS[name], AUTHORITY)
        else:
            lines = [line.removesuffix(b'\r').strip(b' \t') for line in data.split(b'\n')]
            argv = row['ExecStart'].partition(' ; argv[]=')[2].partition(' ; ')[0].encode('ascii')
            require(all(b'\0' not in line and b'\r' not in line and not line.endswith(b'\\') for line in lines)
                    and [line for line in lines if line and not line.startswith((b'#', b';'))]
                    == [b'[Service]', b'ExecStart=', b'ExecStart=' + argv], AUTHORITY)


def _check_dependencies(deadline, anchors):
    # An already-active target can still have pull-ins of its own. Follow
    # only manager-reported forward edges of these named dependencies, never
    # a peer pattern, and refuse any transaction that could start a new unit.
    seen = set()
    todo = set(anchors) | {_SHUTDOWN}
    while todo:
        require(len(seen | todo) <= _MAX_DEPENDENCIES, AUTHORITY)
        batch = sorted(todo)[:32]
        todo.difference_update(batch)
        seen.update(batch)
        raw = _run(deadline, _dependencies_show(batch), 4)
        require(raw.endswith('\n'), AUTHORITY)
        found = set()
        for block in raw.rstrip('\n').split('\n\n'):
            ids = [line[3:] for line in block.split('\n') if line.startswith('Id=')]
            require(len(ids) == 1 and ids[0] in batch and ids[0] not in found, AUTHORITY)
            name = ids[0]
            found.add(name)
            row = _state_fields(block, _ANCHOR_PROPS, name)
            require(row['ActiveState'] == ('inactive' if name == _SHUTDOWN else 'active'), AUTHORITY)
            if name == _SHUTDOWN:
                require(not any(row[key] for key in (*_STOP_EDGES, 'OnFailure', 'OnSuccess')), AUTHORITY)
                continue  # Already-inactive stock conflict; not a start edge.
            conflicts = set(row['Conflicts'].split()) | set(row['ConflictedBy'].split())
            pulls = {unit for prop in _PULLS for unit in row[prop].split()}
            require(row['StopWhenUnneeded'] == 'no' and not row['OnSuccess'] and not row['OnFailure']
                    and conflicts <= {_SHUTDOWN} and not pulls & {_SHUTDOWN, UNIT, XRAY}, AUTHORITY)
            todo.update(pulls - seen)
        require(found == set(batch), AUTHORITY)


def verify_manager_scope(deadline):
    """Check effective named-unit scope inside the existing writer authority.

    Ordering edges (e.g. DIRECT NET After=xray) are not pull-in edges. A
    pending job, activation hook, or reverse stop dependency is not stock.
    These observations do not lock systemd or an independent administrator.
    """
    try:
        def unit(name, props):
            return _state_fields(_run(deadline, _show(name, props), 4), props, name)

        require(_run(deadline, _JOBS, 4) == '', AUTHORITY)
        rows = {name: unit(name, _SCOPE_PROPS) for name in (UNIT, XRAY)}
        anchors = set()
        for name, row in rows.items():
            _layout(name, row)
            require(row['Type'] == 'simple' and row['KillMode'] == 'control-group' and row['ControlPID'] == '0'
                    and row['PrivateNetwork'] == row['StopWhenUnneeded'] == 'no'
                    and row['WorkingDirectory'] in ('', '/')
                    and not any(row[k] for k in _SCOPE_EMPTY)
                    and all(row[k] == 'none' for k in _SCOPE_NONE)
                    and all(set(row[k].split()) <= {_SHUTDOWN} for k in ('Conflicts', 'ConflictedBy')), AUTHORITY)
            running = (row['ActiveState'], row['SubState']) == ('active', 'running')
            # AgentWindow joins the cgroup and successful shutdown separately.
            # An inactive service can have a manager-specific SubState.
            require(running or (name == UNIT and row['ActiveState'] == 'inactive' and row['MainPID'] == '0'), AUTHORITY)
            pull = set(row['Requires'].split()) | set(row['Wants'].split())
            require(pull <= _ANCHORS, AUTHORITY)
            anchors.update(pull)
        _check_dependencies(deadline, anchors)
        require(all(unit(name, _SCOPE_PROPS) == row for name, row in rows.items())
                and _run(deadline, _JOBS, 4) == '', AUTHORITY)
    except (OSError, subprocess.SubprocessError, UnicodeError, WindowError):
        raise WindowError(AUTHORITY) from None
    return rows[UNIT]


def create_main_session(deadline, flock, *, managed, verify_authority, verify_manager_scope, routes_for,
                        packaged_proof=None):
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
            # The potentially longer dependency observation must not rebase
            # the window onto a replacement invocation before native handoff.
            window = session._window
            require(window._unit() == (window._old if tuple(argv) == STOP else window._quiet)
                    and window._main_unit() == window._xray, AUTHORITY)
            flock.check()
        return _run(deadline, argv, timeout)

    observer = MainRuntimeObserver(managed, routes_for, deadline=deadline, packaged_proof=packaged_proof)
    session = HostMainSession(run, verify_authority, observer, managed, flock=flock, deadline=deadline)
    return session
