"""Host-side cc-agent exclusion for a serial MAIN step (no CLI).

The caller must hold the node writer lock and durable mutation intent from
before quiesce() through post-resume MAIN verification. This excludes the
stock agent, not an administrator launching another writer or manager job.
An unconfirmed manager command is not replayable, including on SSH loss.
"""
import copy
import json
import os
import pathlib
import re
import stat
import subprocess
import time
from typing import NamedTuple
from uuid import uuid4

UNIT = 'cc-agent.service'
XRAY = 'xray.service'
GROUP = '/system.slice/' + UNIT
MAIN = pathlib.Path('/usr/local/etc/xray/config.json')
CGROUP_ROOT = pathlib.Path('/sys/fs/cgroup/system.slice')
AGENT_EMPTY = tuple('DropInPaths SourcePath ExecCondition ExecStartPre ExecStartPost ExecStop ExecStopPost '
                    'TriggeredBy Triggers BindsTo BoundBy PartOf ConsistsOf PropagatesStopTo StopPropagatedFrom '
                    'Upholds UpheldBy Wants'.split())
PROPERTIES = tuple('Id LoadState NeedDaemonReload Type KillMode ExecStart FragmentPath Requires Conflicts ConflictedBy '
                   'ActiveState SubState Job ControlGroup MainPID InvocationID Result '
                   'ExecMainCode ExecMainStatus InactiveEnterTimestampMonotonic'.split()) + AGENT_EMPTY
XRAY_PROPS = tuple('Id LoadState NeedDaemonReload ActiveState SubState Job MainPID InvocationID ExecStart'.split())
EXPECTED_EXEC = re.compile(r'\{ path=/usr/local/bin/cc-agent ; argv\[\]=/usr/local/bin/cc-agent ; '
                           r'ignore_errors=no ; [^{}]*\}')
XRAY_EXEC = re.compile(r'\{ path=/usr/local/bin/xray ; argv\[\]=/usr/local/bin/xray run (?:-config|-c) '
                       r'/usr/local/etc/xray/config\.json ; ignore_errors=no ; [^{}]*\}')
INVOCATION = re.compile(r'[a-f0-9]{32}')
PID = re.compile(r'[1-9][0-9]{0,9}')
TAG = re.compile(r'[A-Za-z0-9_.:-]{1,128}')
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
SMALL_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
MAX_MAIN = 8 * 1024 * 1024
MAIN_DRIFT = 'REBUILD_MAIN_CAS_UNPROVED'


class MainImage(NamedTuple):
    data: bytes
    metadata: tuple[int, int, int]  # mode, uid, gid
    generation: tuple[int, int, int]  # dev, inode, ctime_ns


class WindowError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(ok, code='REBUILD_AGENT_EXCLUSION_UNPROVED'):
    if not ok:
        raise WindowError(code)


def parse_json(raw):
    code = 'REBUILD_AGENT_MANAGED_PROFILE_UNPROVED'

    def unique(pairs):
        obj = dict(pairs)
        require(len(obj) == len(pairs), code)
        return obj

    def reject(_):
        raise WindowError(code)

    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=reject)
    except (ValueError, UnicodeError, RecursionError):
        raise WindowError(code) from None


def managed_inbounds(cfg):
    """Configured tag ownership: same fields/default as cc-agent LoadConfig.

    Refuse malformed, ambiguous or unsupported inputs, not a guessed roster.
    Caller pins the agent's loaded config generation as a prerequisite.
    """
    code = 'REBUILD_AGENT_MANAGED_PROFILE_UNPROVED'
    require(isinstance(cfg, dict), code)
    keys = {'inbounds', 'inbound_tag'}
    require(all(k.casefold() not in keys or k in keys for k in cfg), code)
    entries = cfg.get('inbounds')
    require(entries is None or isinstance(entries, list), code)
    if not entries:
        entries = [{'tag': cfg.get('inbound_tag', 'vless-in')}]
    tags = set()
    for row in entries:
        require(isinstance(row, dict) and all(k.casefold() != 'tag' or k == 'tag' for k in row), code)
        tag = row.get('tag')
        require(isinstance(tag, str) and TAG.fullmatch(tag) and tag not in tags, code)
        tags.add(tag)
    return frozenset(tags)


def client_settings(profile, managed):
    code = 'REBUILD_AGENT_MANAGED_PROFILE_UNPROVED'
    require(isinstance(profile, dict) and isinstance(profile.get('inbounds'), list) and managed, code)
    tags, settings = set(), {}
    for row in profile['inbounds']:
        require(isinstance(row, dict), code)
        tag = row.get('tag')
        require(isinstance(tag, str) and tag and tag not in tags, code)
        tags.add(tag)
        if tag in managed:
            value = row.get('settings')
            require(row.get('protocol') == 'vless' and isinstance(value, dict)
                    and isinstance(value.get('clients'), list)
                    and all(isinstance(c, dict) for c in value['clients']), code)
            settings[tag] = value
    require(set(settings) == managed, code)
    return settings


def topology_bytes(profile, managed):
    projected = copy.deepcopy(profile)
    for value in client_settings(projected, managed).values():
        del value['clients']
    try:
        return json.dumps(projected, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    except (ValueError, TypeError, RecursionError):
        raise WindowError('REBUILD_AGENT_MANAGED_PROFILE_UNPROVED') from None


def merge_clients(target, current, managed):
    """Fresh clients after the writer was joined, in either direction."""
    result = copy.deepcopy(target)
    live = client_settings(current, managed)
    for tag, value in client_settings(result, managed).items():
        value['clients'] = copy.deepcopy(live[tag]['clients'])
    return result


def _state_fields(text, props, service):
    require(isinstance(text, str) and len(text) <= 16384)
    data = {}
    for line in text.splitlines():
        k, separator, v = line.partition('=')
        require(separator and k in props and k not in data)
        data[k] = v
    require(data.keys() == set(props) and data['Id'] == service and data['LoadState'] == 'loaded'
            and data['NeedDaemonReload'] == 'no' and data['Job'] in ('', '0'))
    return data


def _generation(row):
    return (row['ActiveState'] == 'active' and row['SubState'] == 'running'
            and PID.fullmatch(row['MainPID'])
            and INVOCATION.fullmatch(row['InvocationID']) and row['InvocationID'] != '0' * 32)


def _running(row):
    return (_generation(row) and row['ControlGroup'] == GROUP
            and row['Result'] == 'success')


def _file_generation(info):
    return info.st_dev, info.st_ino, info.st_ctime_ns


def _file_metadata(info):
    return stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid


def _read_main(parent, name):
    fd = os.open(name, SMALL_FILE, dir_fd=parent)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= MAX_MAIN
                and not before.st_mode & 0o7000 and not os.listxattr(fd), MAIN_DRIFT)
        data = source.read(before.st_size + 1)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(len(data) == before.st_size and before.st_size == after.st_size == named.st_size
                and _file_generation(before) == _file_generation(after) == _file_generation(named)
                and _file_metadata(before) == _file_metadata(after) == _file_metadata(named), MAIN_DRIFT)
    return MainImage(data, _file_metadata(before), _file_generation(before))


class AgentWindow:
    """Single-use process-local capability; never resumed from old receipts.

    `run` accepts only the fixed argv below and a positive timeout, and raises
    on nonzero, timeout, truncated output or a detached local command. The
    caller journals phase and error code, never command output. The cgroup
    root must be the host system.slice on unified cgroup v2.
    """

    def __init__(self, run, *, main=MAIN, cgroup_root=CGROUP_ROOT,
                 clock=time.monotonic, sleep=time.sleep):
        self._run = run
        self._main = main
        self._cgroup_root = cgroup_root
        self._clock = clock
        self._sleep = sleep
        self._old = None
        self._new = None
        self._quiet = None
        self._xray = None
        self._xray_joined = False
        self._publication_entered = False
        self._slice_id = None
        self.phase = 'initial'

    def _show(self, name, props, timeout):
        return _state_fields(self._run(['/usr/bin/systemctl', 'show', '--all',
                                       *('--property=' + k for k in props), '--', name], timeout), props, name)

    def _unit(self, timeout=4):
        row = self._show(UNIT, PROPERTIES, timeout)
        require(row['FragmentPath'] == '/etc/systemd/system/' + UNIT
                and row['Type'] == 'simple' and row['KillMode'] == 'control-group'
                and not any(row[k] for k in AGENT_EMPTY)
                and set(row['Requires'].split()) <= {'system.slice', 'sysinit.target'}
                and all(set(row[k].split()) <= {'shutdown.target'} for k in ('Conflicts', 'ConflictedBy'))
                and EXPECTED_EXEC.fullmatch(row['ExecStart']))
        return row

    def _main_unit(self, timeout=4):
        row = self._show(XRAY, XRAY_PROPS, timeout)
        require(_generation(row) and XRAY_EXEC.fullmatch(row['ExecStart']))
        return row

    def _journal(self, invocation, timeout=4):
        text = self._run(['/usr/bin/journalctl', '--quiet', '--no-pager', '--output=cat', '--lines=128',
                          '_SYSTEMD_UNIT=' + UNIT, '_SYSTEMD_INVOCATION_ID=' + invocation], timeout)
        require(isinstance(text, str) and len(text) <= 65536 and (not text or text.endswith('\n')))
        return text.splitlines()

    def _cgroup_populated(self):
        # A missing service cgroup is admissible only beneath a readable
        # system.slice that was checked while the original incarnation ran.
        parent = os.open(self._cgroup_root, DIR)
        try:
            inode = os.fstat(parent)
            identity = (inode.st_dev, inode.st_ino)
            if self._slice_id is None:
                self._slice_id = identity
            require(self._slice_id == identity)
            try:
                group = os.open(UNIT, DIR, dir_fd=parent)
            except FileNotFoundError:
                return False
            try:
                events = os.open('cgroup.events', SMALL_FILE, dir_fd=group)
                try:
                    text = os.read(events, 1025).decode('ascii')
                    count = re.findall(r'^populated ([01])$', text, re.M)
                    require(len(text) <= 1024 and text.endswith('\n') and len(count) == 1)
                    return count == ['1']
                finally:
                    os.close(events)
            finally:
                os.close(group)
        finally:
            os.close(parent)

    def _stopped(self):
        row = self._unit()
        require(row['ActiveState'] == 'inactive' and row['SubState'] == 'dead' and row['MainPID'] == '0'
                and row['ControlGroup'] in ('', GROUP)
                and re.fullmatch(r'[1-9][0-9]{0,19}', row['InactiveEnterTimestampMonotonic']))
        require(not self._cgroup_populated())
        parent = os.open(self._main.parent, DIR)
        try:
            names = os.listdir(parent)
            require(not any(n.startswith('.' + self._main.name + '-') and n.endswith('.tmp') for n in names))
        finally:
            os.close(parent)
        # Detect manager churn across file and cgroup observations. A separate
        # administrator or scheduler is outside this window's authority.
        require(self._unit() == row)
        return row

    def quiesce(self):
        require(self.phase == 'initial', 'REBUILD_AGENT_WINDOW_STATE')
        try:
            row = self._unit()
            require(_running(row) and self._cgroup_populated() and self._unit() == row)
            self._xray = self._main_unit()
        except (OSError, UnicodeError, subprocess.SubprocessError, WindowError):
            raise WindowError('REBUILD_AGENT_EXCLUSION_UNPROVED') from None
        self._old = row
        self.phase = 'stop-unconfirmed'  # latch before the synchronous manager handoff
        try:
            self._run(['/usr/bin/systemctl', 'stop', '--job-mode=fail', '--', UNIT], 25)
        except (OSError, subprocess.SubprocessError):
            raise WindowError('REBUILD_AGENT_STOP_UNCONFIRMED') from None
        try:
            stopped = self._stopped()
            require(stopped['Result'] == 'success' and stopped['ExecMainCode'] == '1'
                    and stopped['ExecMainStatus'] == '0')
            journal = self._journal(row['InvocationID'])
            require(any(msg.endswith('[main] Shutdown complete') for msg in journal)
                    and not any('[config] Final flush:' in msg or '[store] Final save:' in msg for msg in journal))
            require(self._stopped() == stopped and self._main_unit() == self._xray)
        except (OSError, UnicodeError, subprocess.SubprocessError, WindowError):
            self.phase = 'exclusion-lost'
            raise WindowError('REBUILD_AGENT_EXCLUSION_UNPROVED') from None
        self._quiet = stopped
        self.phase = 'quiet'

    def _check_quiet(self, xray):
        require(self.phase == 'quiet', 'REBUILD_AGENT_WINDOW_STATE')
        try:
            require(self._stopped() == self._quiet)
            current = self._main_unit()
            if xray == 'same':
                require(current == self._xray)
            else:
                require(not self._xray_joined and self._xray is not None
                        and all(current[k] != self._xray[k] for k in ('MainPID', 'InvocationID')))
            require(self._unit() == self._quiet)
            return current
        except (OSError, UnicodeError, subprocess.SubprocessError, WindowError):
            self.phase = 'exclusion-lost'
            raise WindowError('REBUILD_AGENT_EXCLUSION_UNPROVED') from None

    def require_quiet(self):
        self._check_quiet('same')

    def _check_main_dir(self, parent):
        held, named = os.fstat(parent), self._main.parent.lstat()
        require(stat.S_ISDIR(named.st_mode) and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino), MAIN_DRIFT)

    def read_main(self):
        """Bounded descriptor-based read addressed to the fixed MAIN."""
        try:
            parent = os.open(self._main.parent, DIR)
            try:
                result = _read_main(parent, self._main.name)
                self._check_main_dir(parent)
                return result
            finally:
                os.close(parent)
        except OSError:
            raise WindowError(MAIN_DRIFT) from None

    def publish_main(self, before, desired):
        """One exact-generation CAS using reopened, journal-bound image bytes.

        Caller must authenticate both artifacts and still own host authority.
        A post-rename failure can never authorize a second publication.
        """
        require(self.phase == 'quiet' and not self._publication_entered and not self._xray_joined,
                'REBUILD_AGENT_WINDOW_STATE')
        self._publication_entered = True
        require(type(before) is MainImage and type(desired) is bytes and 0 < len(desired) <= MAX_MAIN, MAIN_DRIFT)
        self.require_quiet()
        renamed = False
        try:
            parent = os.open(self._main.parent, DIR)
            try:
                name, scratch = self._main.name, '.c3-main-' + uuid4().hex
                require(_read_main(parent, name) == before, MAIN_DRIFT)
                stage = os.open(scratch, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o600, dir_fd=parent)
                stage_id = None
                try:
                    with os.fdopen(stage, 'wb') as output:
                        stage_id = _file_generation(os.fstat(stage))[:2]
                        output.write(desired)
                        output.flush()
                        mode, uid, gid = before.metadata
                        if _file_metadata(os.fstat(stage))[1:] != (uid, gid):
                            os.fchown(stage, uid, gid)
                        os.fchmod(stage, mode)
                        os.fsync(stage)
                        staged = MainImage(desired, before.metadata, _file_generation(os.fstat(stage)))
                    self.require_quiet()
                    self._check_main_dir(parent)
                    require(_read_main(parent, scratch) == staged and _read_main(parent, name) == before, MAIN_DRIFT)
                    renamed = True
                    os.replace(scratch, name, src_dir_fd=parent, dst_dir_fd=parent)
                    os.fsync(parent)
                    result = _read_main(parent, name)
                    self._check_main_dir(parent)
                    require(result.generation[:2] == stage_id and result.metadata == before.metadata
                            and result.data == desired, MAIN_DRIFT)
                    return result
                finally:
                    if not renamed and stage_id is not None:
                        info = os.stat(scratch, dir_fd=parent, follow_symlinks=False)
                        require(_file_generation(info)[:2] == stage_id, MAIN_DRIFT)
                        os.unlink(scratch, dir_fd=parent)
                        os.fsync(parent)
            finally:
                os.close(parent)
        except (OSError, WindowError) as error:
            if renamed:
                self.phase = 'publication-unconfirmed'
                raise WindowError('REBUILD_MAIN_PUBLICATION_UNCONFIRMED') from None
            if isinstance(error, WindowError):
                raise
            raise WindowError(MAIN_DRIFT) from None

    def join_xray_restart(self):
        """Accept the new generation only after the caller joins its restart."""
        self._xray = self._check_quiet('new')
        self._xray_joined = True

    def resume(self):
        self.require_quiet()
        self.phase = 'start-unconfirmed'
        try:
            self._run(['/usr/bin/systemctl', 'start', '--job-mode=fail', '--', UNIT], 15)
            row = self._unit()
            require(_running(row) and self._old is not None
                    and row['InvocationID'] != self._old['InvocationID'] and self._cgroup_populated()
                    and self._main_unit() == self._xray)
        except (OSError, UnicodeError, subprocess.SubprocessError, WindowError):
            raise WindowError('REBUILD_AGENT_START_UNCONFIRMED') from None
        self._new = row
        self.phase = 'started'

    def wait_reconciled(self):
        require(self.phase == 'started' and self._new is not None, 'REBUILD_AGENT_WINDOW_STATE')
        self.phase = 'reconcile-unconfirmed'
        terminal = '[main] Startup stats discarded (cold-start reset)'
        denied = ('[main] Preserving Xray config and runtime', '[main] Startup config flush:',
                  '[main] Startup config reflush:', '[main] Stale Xray config on startup, restarting',
                  '[store] Preserving users and Xray config until full /sync',
                  '[main] Startup stats discard failed:')
        # The known agent waits 3 s + 15 s before the reflush, with up to 60 s
        # for the final RPC. An active unit or a 5–10 s sleep is not settlement.
        deadline = self._clock() + 85
        try:
            while self._clock() < deadline:
                def timeout():
                    remaining = deadline - self._clock()
                    require(remaining > 0)
                    return min(4, remaining)

                require(self._unit(timeout()) == self._new and self._main_unit(timeout()) == self._xray)
                lines = self._journal(self._new['InvocationID'], timeout())
                require(len(lines) < 128 and not any(msg in line for line in lines for msg in denied))
                receipts = sum(line.endswith(terminal) for line in lines)
                if receipts:
                    require(receipts == 1 and self._main_unit(timeout()) == self._xray
                            and self._unit(timeout()) == self._new and self._clock() < deadline)
                    self.phase = 'reconciled'
                    return
                self._sleep(max(0, min(0.25, deadline - self._clock())))
        except (OSError, UnicodeError, subprocess.SubprocessError, WindowError):
            pass
        raise WindowError('REBUILD_AGENT_RECONCILE_UNPROVED') from None
