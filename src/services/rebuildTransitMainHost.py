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
    AGENT_EMPTY, EXPECTED_EXEC, INVOCATION, MAIN_SYSTEMD_DEPENDENCIES, PROPERTIES, SMALL_FILE, UNIT, XRAY,
    XRAY_EXEC, XRAY_PROPS, ManagerScopeError, WindowError, _file_generation, _file_metadata, _state_fields, require,
)


def _show(unit, properties):
    return ('/usr/bin/systemctl', 'show', '--all', *('--property=' + key for key in properties), '--', unit)


_EDGE_EMPTY = tuple(('RequiredBy RequisiteOf BoundBy UpheldBy ConsistsOf TriggeredBy PropagatesStopTo '
                     'PropagatesReloadTo StopPropagatedFrom OnSuccess OnFailure PartOf Triggers Upholds Requisite').split())
_SCOPE_EMPTY = tuple(('ExecCondition ExecStartPre ExecStartPost ExecStop ExecStopPost '
                      'ExecReload Environment EnvironmentFiles PassEnvironment UnsetEnvironment RootDirectory '
                      'RootImage SourcePath').split())
_SCOPE_NONE = ('FailureAction', 'SuccessAction', 'StartLimitAction', 'JobTimeoutAction')
_SCOPE_NO = ('StopWhenUnneeded', 'RefuseManualStart', 'RefuseManualStop')
_PULLS = ('Requires', 'BindsTo', 'Wants')
_SCOPE_PROPS = ('Id', 'LoadState', 'NeedDaemonReload', 'Job', 'ActiveState', 'SubState', 'MainPID', 'InvocationID',
                'Conflicts', 'ConflictedBy', 'Type', 'KillMode', 'ExecStart', 'FragmentPath',
                'DropInPaths', 'PrivateNetwork', 'WorkingDirectory', 'ControlPID')
_SCOPE_PROPS += _PULLS + _EDGE_EMPTY + _SCOPE_EMPTY + _SCOPE_NONE + _SCOPE_NO
_SHUTDOWN = 'shutdown.target'
_DEPENDENCY_PROPS = ('Id', 'LoadState', 'NeedDaemonReload', 'Job', 'ActiveState')
_ACTIVE_PROPS = ('Id', 'LoadState', 'ActiveState', 'InvocationID')
# systemctl show with a glob matches loaded manager units, not unit files.
_ACTIVE_SHOW = ('/usr/bin/systemctl', 'show', '--all', '--state=active', '--no-pager',
                *('--property=' + key for key in _ACTIVE_PROPS), '--', '*')
_MANAGER_UNIT = re.compile(r'(?:[A-Za-z0-9_.:@-]|\\x[0-9a-f]{2}){1,240}\.(?:service|mount|automount|target|slice|socket|device|swap|path|timer|scope)')
_JOBS = ('/usr/bin/systemctl', 'list-jobs', '--no-legend', '--plain', '--no-pager')
_SHOW = frozenset((_show(UNIT, PROPERTIES), _show(XRAY, XRAY_PROPS), _show(UNIT, _SCOPE_PROPS),
                   _show(XRAY, _SCOPE_PROPS), *(_show(name, _DEPENDENCY_PROPS)
                                              for name in MAIN_SYSTEMD_DEPENDENCIES | {_SHUTDOWN})))
_UNIT_DIR = Path('/etc/systemd/system')
_XRAY_DROP = '10-donot_touch_single_conf.conf'
_SETUP_DROPS = {
    '90-celerity-config-access.conf': b'# Managed by Celerity Xray setup\n[Service]\nSupplementaryGroups=xray\n',
    '90-celerity-logs-directory.conf': b'# Managed by Celerity Xray setup\n[Service]\nLogsDirectory=xray\n',
}
_JOURNAL = ('/usr/bin/journalctl', '--quiet', '--no-pager', '--output=cat', '--lines=128', '_SYSTEMD_UNIT=' + UNIT)
_INVOCATION = '_SYSTEMD_INVOCATION_ID='
_LIMITS = {STOP: (25, 0), RESTART: (25, 0), START: (15, 0)}


def _command(argv):
    args = tuple(argv)
    if args in _LIMITS:
        return args, _LIMITS[args]
    if args in _SHOW:
        return args, (4, 16384)
    if args == _ACTIVE_SHOW:
        return args, (4, 1 << 20)
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


def _require_idle(deadline):
    if _run(deadline, _JOBS, 4) != '':
        raise ManagerScopeError(('list-jobs',))


def _unit(deadline, name, props):
    return _state_fields(_run(deadline, _show(name, props), 4), props, name)


def verify_manager_scope(deadline):
    """Check effective named-unit scope inside the existing writer authority.

    Ordering edges (e.g. DIRECT NET After=xray) are not pull-in edges. A
    pending job, activation hook, or reverse stop dependency is not stock.
    These observations do not lock systemd or an independent administrator.
    """
    try:
        _require_idle(deadline)
        rows = {name: _unit(deadline, name, _SCOPE_PROPS) for name in (UNIT, XRAY)}
        dependencies = {}
        issues = set()
        conflicts = set()
        for name, row in rows.items():
            issues.update(f'{name}:{k}' for k in _EDGE_EMPTY if row[k])
            issues.update(f'{name}:{k}' for k in _SCOPE_NO if row[k] != 'no')
            for key in ('Conflicts', 'ConflictedBy'):
                values = set(row[key].split())
                if values - {_SHUTDOWN}:
                    issues.add(f'{name}:{key}')
                conflicts.update(values & {_SHUTDOWN})
            for key in _PULLS:
                values = set(row[key].split())
                if values - MAIN_SYSTEMD_DEPENDENCIES:
                    issues.add(f'{name}:{key}')
                for dependency in values & MAIN_SYSTEMD_DEPENDENCIES:
                    dependencies.setdefault(dependency, set()).add(f'{name}:{key}')
            running = (row['ActiveState'], row['SubState']) == ('active', 'running')
            # AgentWindow joins the cgroup and successful shutdown separately.
            # An inactive service can have a manager-specific SubState.
            if not (running or (name == UNIT and row['ActiveState'] == 'inactive' and row['MainPID'] == '0')):
                issues.add(f'{name}:ActiveState')
        if issues:
            raise ManagerScopeError(issues)
        # Observe only direct dependencies' state. Never traverse sysinit's
        # Wants, emergency conflicts, conditions or any other boot edges.
        for name, checks in sorted(dependencies.items()):
            if _unit(deadline, name, _DEPENDENCY_PROPS)['ActiveState'] != 'active':
                issues.update(checks)
        if conflicts and _unit(deadline, _SHUTDOWN, _DEPENDENCY_PROPS)['ActiveState'] != 'inactive':
            issues.add('shutdown.target:ActiveState')
        if issues:
            raise ManagerScopeError(issues)
        for name, row in rows.items():
            _layout(name, row)
            require(row['Type'] == 'simple' and row['KillMode'] == 'control-group' and row['ControlPID'] == '0'
                    and row['PrivateNetwork'] == 'no' and row['WorkingDirectory'] in ('', '/')
                    and not any(row[k] for k in _SCOPE_EMPTY)
                    and all(row[k] == 'none' for k in _SCOPE_NONE), AUTHORITY)
            require(_unit(deadline, name, _SCOPE_PROPS) == row, AUTHORITY)
        _require_idle(deadline)
    except ManagerScopeError:
        raise
    except (OSError, subprocess.SubprocessError, UnicodeError, WindowError):
        raise WindowError(AUTHORITY) from None
    return rows[UNIT]


def _active_invocations(deadline, states, *, changed):
    """A bounded, read-only roster; no unrelated unit names leave the host."""
    try:
        text = _run(deadline, _ACTIVE_SHOW, 4)
        require(text.endswith('\n'), AUTHORITY)
        active = {}
        seen = set()
        for block in text.rstrip('\n').split('\n\n'):
            row = {}
            for line in block.split('\n'):
                key, sep, value = line.partition('=')
                require(sep and key in _ACTIVE_PROPS and key not in row, AUTHORITY)
                row[key] = value
            require(row.keys() == set(_ACTIVE_PROPS), AUTHORITY)
            name, invocation, load = row['Id'], row['InvocationID'], row['LoadState']
            require(_MANAGER_UNIT.fullmatch(name) and name not in seen and row['ActiveState'] == 'active'
                    and (not invocation or INVOCATION.fullmatch(invocation)), AUTHORITY)
            seen.add(name)
            if load == 'loaded':
                active[name] = invocation
            else:
                require(load in ('stub', 'not-found', 'bad-setting', 'error', 'merged', 'masked'), AUTHORITY)
        require(all((name in active) == expected for name, expected in states.items()), AUTHORITY)
        active.pop(changed, None)
        return active
    except (OSError, subprocess.SubprocessError, UnicodeError, WindowError):
        raise ManagerScopeError(('active-invocations',)) from None


def create_main_session(deadline, flock, *, managed, verify_authority, verify_manager_scope, routes_for,
                        packaged_proof=None):
    """Join the supplied original held flock and clip all native commands."""
    require(type(deadline) in (int, float) and math.isfinite(deadline)
            and all(callable(cb) for cb in (verify_authority, verify_manager_scope)), AUTHORITY)
    require(type(flock) is HostMainFlock and flock.path == DIRECT_LOCK, LOCK)
    flock.check()

    def run(argv, timeout):
        action = tuple(argv)
        if action not in _LIMITS:
            return _run(deadline, argv, timeout)
        changed = XRAY if action == RESTART else UNIT
        require(verify_manager_scope(deadline) is True and verify_authority() is True, AUTHORITY)
        before = _active_invocations(deadline, {UNIT: action == STOP, XRAY: True}, changed=changed)
        # Do not rebase onto a replacement invocation after the scope read.
        window = session._window
        require(window._unit() == (window._old if action == STOP else window._quiet)
                and window._main_unit() == window._xray, AUTHORITY)
        _require_idle(deadline)
        flock.check()
        result = _run(deadline, argv, timeout)
        _require_idle(deadline)
        expected = 'active' if action == START else 'inactive'
        checks = [f'{name}:ActiveState' for name, props, state in ((UNIT, PROPERTIES, expected), (XRAY, XRAY_PROPS, 'active'))
                  if _unit(deadline, name, props)['ActiveState'] != state]
        if checks:
            raise ManagerScopeError(checks)
        after = _active_invocations(deadline, {UNIT: action == START, XRAY: True}, changed=changed)
        if after != before:
            raise ManagerScopeError(('active-invocations',))
        _require_idle(deadline)
        return result

    observer = MainRuntimeObserver(managed, routes_for, deadline=deadline, packaged_proof=packaged_proof)
    session = HostMainSession(run, verify_authority, observer, managed, flock=flock, deadline=deadline)
    return session
