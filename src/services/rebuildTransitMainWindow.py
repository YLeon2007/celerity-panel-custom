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
import subprocess
import time

UNIT = 'cc-agent.service'
GROUP = '/system.slice/' + UNIT
MAIN = pathlib.Path('/usr/local/etc/xray/config.json')
CGROUP_ROOT = pathlib.Path('/sys/fs/cgroup/system.slice')
PROPERTIES = tuple('Id LoadState NeedDaemonReload Type KillMode TriggeredBy ExecStart '
                   'ActiveState SubState Job ControlGroup MainPID InvocationID Result '
                   'ExecMainCode ExecMainStatus'.split())
EXPECTED_EXEC = re.compile(r'\{ path=/usr/local/bin/cc-agent ; argv\[\]=/usr/local/bin/cc-agent ; '
                           r'ignore_errors=no ; [^{}]*\}')
INVOCATION = re.compile(r'[a-f0-9]{32}')
PID = re.compile(r'[1-9][0-9]{0,9}')
TAG = re.compile(r'[A-Za-z0-9_.:-]{1,128}')
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
SMALL_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


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


def _state_fields(text):
    require(isinstance(text, str) and len(text) <= 16384)
    data = {}
    for line in text.splitlines():
        k, separator, v = line.partition('=')
        require(separator and k in PROPERTIES and k not in data)
        data[k] = v
    require(data.keys() == set(PROPERTIES) and data['Id'] == UNIT and data['LoadState'] == 'loaded'
            and data['NeedDaemonReload'] == 'no' and data['Type'] == 'simple'
            and data['KillMode'] == 'control-group' and data['TriggeredBy'] == ''
            and EXPECTED_EXEC.fullmatch(data['ExecStart']) and data['Job'] in ('', '0'))
    return data


def _running(row):
    return (row['ActiveState'] == 'active' and row['SubState'] == 'running'
            and row['ControlGroup'] == GROUP and PID.fullmatch(row['MainPID'])
            and INVOCATION.fullmatch(row['InvocationID']) and row['InvocationID'] != '0' * 32
            and row['Result'] == 'success')


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
        self._slice_id = None
        self.phase = 'initial'

    def _unit(self, timeout=4):
        return _state_fields(self._run(['/usr/bin/systemctl', 'show', '--all',
                                       *('--property=' + k for k in PROPERTIES), '--', UNIT], timeout))

    def _journal(self, invocation, timeout=4):
        return self._run(['/usr/bin/journalctl', '--quiet', '--no-pager', '--output=cat', '--lines=128',
                          '_SYSTEMD_UNIT=' + UNIT, '_SYSTEMD_INVOCATION_ID=' + invocation], timeout).splitlines()

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
        require(row['ActiveState'] in ('inactive', 'failed') and row['MainPID'] == '0'
                and row['ControlGroup'] in ('', GROUP))
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
        except (OSError, UnicodeError, subprocess.SubprocessError, WindowError):
            raise WindowError('REBUILD_AGENT_EXCLUSION_UNPROVED') from None
        self._old = row
        self.phase = 'stop-unconfirmed'  # latch before the synchronous manager handoff
        try:
            self._run(['/usr/bin/systemctl', 'stop', '--', UNIT], 25)
        except (OSError, subprocess.SubprocessError):
            raise WindowError('REBUILD_AGENT_STOP_UNCONFIRMED') from None
        try:
            stopped = self._stopped()
            require(stopped['Result'] == 'success' and stopped['ExecMainCode'] == '1'
                    and stopped['ExecMainStatus'] == '0')
            journal = self._journal(row['InvocationID'])
            require(any(msg.endswith('[main] Shutdown complete') for msg in journal)
                    and not any('[config] Final flush:' in msg or '[store] Final save:' in msg for msg in journal))
        except (OSError, UnicodeError, subprocess.SubprocessError, WindowError):
            self.phase = 'exclusion-lost'
            raise WindowError('REBUILD_AGENT_EXCLUSION_UNPROVED') from None
        self.phase = 'quiet'

    def require_quiet(self):
        require(self.phase == 'quiet', 'REBUILD_AGENT_WINDOW_STATE')
        try:
            self._stopped()
        except (OSError, UnicodeError, subprocess.SubprocessError, WindowError):
            self.phase = 'exclusion-lost'
            raise WindowError('REBUILD_AGENT_EXCLUSION_UNPROVED') from None

    def resume(self):
        self.require_quiet()
        self.phase = 'start-unconfirmed'
        try:
            self._run(['/usr/bin/systemctl', 'start', '--', UNIT], 15)
            row = self._unit()
            require(_running(row) and self._old is not None
                    and row['InvocationID'] != self._old['InvocationID'] and self._cgroup_populated())
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

                require(self._unit(timeout()) == self._new)
                lines = self._journal(self._new['InvocationID'], timeout())
                require(not any(msg in line for line in lines for msg in denied))
                if any(line.endswith(terminal) for line in lines):
                    require(self._unit(timeout()) == self._new and self._clock() < deadline)
                    self.phase = 'reconciled'
                    return
                self._sleep(max(0, min(0.25, deadline - self._clock())))
        except (OSError, UnicodeError, subprocess.SubprocessError, WindowError):
            pass
        raise WindowError('REBUILD_AGENT_RECONCILE_UNPROVED') from None
