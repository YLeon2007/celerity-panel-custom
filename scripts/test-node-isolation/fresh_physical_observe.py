#!/usr/bin/python3 -I
"""Fixed bounded read-only natural watcher release OBSERVATION, never acceptance.

No resource cleanup, signaling, Coordinator, protocol dispatch or service actions.
Programmatic injection is only a local test seam; main selects no paths/callbacks.
"""
import hashlib
import os
from pathlib import Path
import select
import stat
import sys
import time
import types
sys.dont_write_bytecode = True

# Reviewed source closure; separate from immutable legacy source-pack acceptance.
SOURCE_PINS = {
    '/usr/local/libexec/c3-test-fresh-physical.py': 'f2d0622c796a6e4e549d76bf3a6abb36218ee0402005957bfb7c6cc4b7877d6f',
    '/usr/local/libexec/c3-test-fresh-physical-exec.py': '05e17f363e52e0c7cb0010999fbd4f8157de8ac95e74dad618f6e0f18a281fda',
    '/usr/local/libexec/c3-test-fresh-physical-watch.py': 'edd33f724b390aeb763bf4c8125a287367657019463946675d5eebdbb4aa4b0e',
    '/usr/local/libexec/c3-test-coordinated-restore.py': '651c3f6d5acd63c06ec55408d7a0ac47fc17d3f43ccee692de5156699aed8b6c',
    '/usr/local/libexec/c3-test-fresh-classic.py': '440139f44dda102b2de75e637eff12cdeb7b3c11efc3b585131c828635466cdd',
    '/etc/systemd/system/c3-test-fresh-prepare-watch.service': '97b16b9583f7da3a59ae0569e05006384a07aaa7bac6973c43052350505e92f7',
    '/etc/systemd/system/c3-test-fresh-classic.service': '03009f943c76e1675c7f2488962c9a223c9ba0901d302fa11fc4873f63812c6d',
}
PHYSICAL = '/usr/local/libexec/c3-test-fresh-physical.py'
COORDINATED = '/usr/local/libexec/c3-test-coordinated-restore.py'
FRESH = '/usr/local/libexec/c3-test-fresh-classic.py'


class Observation:
    def __init__(self, m, prepared, source_check=lambda: None):
        self.m, self.prepared, self.source_check = m, prepared, source_check
        self.watcher = self.supervisor = None
        try:
            self.run = m.RunPlan()
            source_check()
            self.inputs = {p: m.input_snapshot(p, 8*1024*1024) for p in
                (m.RESOURCE+'/generation.json', m.POLICY, m.INPUT+'/resource-plan.json')}
            self.generation = g = m.decode(self.inputs[m.RESOURCE+'/generation.json'][0])
            m.need(type(g) is dict and set(g) == {'version', 'context', 'generation', 'supervisor',
                   'filesSha256', 'accepted', 'watcherObservation'} and
                   type(g['version']) is int and g['version'] == 1 and g['context'] == m.CONTEXT and
                   g['accepted'] is False and self.hex(g['generation'], 64) and
                   self.hex(g['filesSha256'], 64), 'EXACT_UNACCEPTED_GENERATION_REQUIRED')
            w = g['watcherObservation']
            m.need(type(w) is dict and set(w) == {'pid', 'start', 'bootId', 'invocationId',
                   'deadlineMonotonicNs', 'runPlanSha256'} and
                   type(w['pid']) is int and w['pid'] > 0 and self.start(w['start']) and
                   self.hex(w['invocationId'], 32) and w['bootId'] == self.run.boot and
                   type(w['deadlineMonotonicNs']) is int and w['deadlineMonotonicNs'] == self.run.deadline_ns and
                   w['runPlanSha256'] == self.run.digest, 'EXACT_WATCHER_BINDING_REQUIRED')
            s = g['supervisor']
            m.need(type(s) is dict and set(s) == {'pid', 'start'} and type(s['pid']) is int and
                   s['pid'] > 0 and self.start(s['start']) and s['pid'] != w['pid'],
                   'EXACT_SUPERVISOR_REQUIRED')
            self.binding = w
            self.watcher = m.ProcessLease(w['pid'])  # must open while original is alive
            m.need(self.watcher.start == w['start'], 'WATCHER_START_DRIFT')
            self.supervisor = m.ProcessLease(s['pid'])
            m.need(self.supervisor.start == s['start'], 'SUPERVISOR_START_DRIFT')
            self.policy = m.decode(self.inputs[m.POLICY][0])
            plan = m.decode(self.inputs[m.INPUT+'/resource-plan.json'][0])
            m.need(type(plan) is dict and set(plan) == {'version', 'context', 'files', 'networkNamespace'} and
                   type(plan['version']) is int and plan['version'] == 1 and plan['context'] == m.CONTEXT and
                   type(plan['files']) is dict and type(plan['networkNamespace']) is dict and
                   set(plan['networkNamespace']) == {'device', 'inode'} and
                   all(type(v) is int and v > 0 for v in plan['networkNamespace'].values()),
                   'EXACT_OBSERVED_RESOURCE_PLAN_REQUIRED')
            m.need(type(self.policy) is dict and self.policy.get('context') == m.CONTEXT and
                   type(plan) is dict and m.encode(plan.get('files')) == m.encode(self.policy.get('files')) and
                   g['filesSha256'] == m.sha(m.encode(self.policy.get('files'))), 'GENERATION_FILES_DRIFT')
            self.control_inode = (Path('/proc')/str(s['pid'])/'fd/3').stat().st_ino
            self.paths = self.resource_paths()
            self.check()
            self.running(m.watcher_properties(self.run.deadline))
            self.watcher.check(); self.run.check()
        except BaseException:
            self.close(); raise

    @staticmethod
    def hex(value, length):
        return type(value) is str and len(value) == length and all(c in '0123456789abcdef' for c in value)

    @staticmethod
    def start(value):
        return type(value) is str and value.isascii() and value.isdigit() and int(value) > 0

    def resource_paths(self):
        # No connect/bind/flock or file write. Identity is observation only, not
        # independent physical acceptance. Parent traversal is already checked by
        # the pinned generation file; the socket leaf must remain the same inode.
        m = self.m
        fd = m.trusted_open(m.RESOURCE, directory=True)
        try: root = os.fstat(fd)
        finally: os.close(fd)
        control = os.lstat(m.CONTROL)
        m.need(stat.S_ISDIR(root.st_mode) and stat.S_ISSOCK(control.st_mode),
               'OBSERVED_RESOURCE_PATH_DRIFT')
        return tuple((s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid) for s in (root, control))

    def check(self):
        m = self.m
        self.run.check(); self.source_check()
        m.need(self.resource_paths() == self.paths, 'OBSERVED_RESOURCE_PATH_DRIFT')
        m.need(all(m.input_snapshot(p, 8*1024*1024) == value for p, value in self.inputs.items()),
               'OBSERVATION_INPUT_DRIFT')
        self.supervisor.check(stopped=True)
        self.prepared(self.policy, self.supervisor.pid)  # existing read-only consumer predicates
        self.supervisor.check(stopped=True)
        m.need((Path('/proc')/str(self.supervisor.pid)/'fd/3').stat().st_ino == self.control_inode,
               'OBSERVED_CONTROL_DRIFT')
        self.run.check(); self.source_check()

    def association(self, values):
        self.m.need(values['InvocationID'] == self.binding['invocationId'] and
                    values['ExecMainPID'] == str(self.watcher.pid), 'WATCHER_INVOCATION_DRIFT')

    def running(self, values):
        self.association(values)
        self.m.need(values['MainPID'] == str(self.watcher.pid) and
                    values['ActiveState'] == 'active' and values['SubState'] == 'running',
                    'ORIGINAL_LIVE_WATCHER_REQUIRED')

    def wait(self):
        m = self.m
        while True:
            self.check()
            values = m.watcher_properties(self.run.deadline)
            self.run.check(); self.association(values)
            dead = bool(select.select([self.watcher.fd], [], [], 0)[0])
            if dead and values['ActiveState'] == 'active' and values['SubState'] == 'running':
                # Death can follow the property snapshot (or precede PID1's
                # terminal publication). Reobserve ONLY the already pinned same
                # invocation under the original deadline, never infer success.
                self.running(values)
                time.sleep(min(.01, max(0, self.run.deadline-time.monotonic())))
                self.run.check()
                continue
            if not dead:
                try: self.watcher.check()
                except (m.Refusal, FileNotFoundError) as error:
                    # Only an independently observed original pidfd death may
                    # cross into the terminal query path; start/reuse faults
                    # remain refusal and never authorize replacement adoption.
                    if (isinstance(error, m.Refusal) and str(error) != 'PREPARATION_PROCESS_LOST') or not \
                            select.select([self.watcher.fd], [], [], 0)[0]:
                        raise
                    self.run.check()
                    continue
                self.running(values)
            else:
                # Result=success while RUNNING is not completion. PID1's numeric
                # CLD_EXITED=1, original pidfd death and active/exited are all required.
                m.need(all(values[k] == v for k, v in {'MainPID': '0', 'ActiveState': 'active',
                    'SubState': 'exited', 'ExecMainCode': '1', 'ExecMainStatus': '0',
                    'Result': 'success'}.items()), 'NATURAL_WATCHER_SUCCESS_UNKNOWN')
                self.check()
                # Pinned watch_main only returns naturally after its finally has
                # completed checked disposal. Verify its observable retained state.
                m.need(not os.path.lexists(m.REGISTER) and os.path.isdir(m.RESOURCE) and
                       stat.S_ISSOCK(os.lstat(m.CONTROL).st_mode), 'WATCHER_FINALLY_STATE_UNKNOWN')
                acceptance = m.decode(m.trusted_read(m.ACCEPTANCE, 16384))
                expected = {k: self.generation[k] for k in
                            ('version', 'context', 'generation', 'supervisor', 'filesSha256')}
                expected['policySha256'] = m.sha(m.encode(self.policy))
                m.need(m.encode(acceptance) == m.encode(expected), 'INDEPENDENT_ACCEPTANCE_DRIFT')
                self.check()
                again = m.watcher_properties(self.run.deadline)
                m.need(again == values, 'WATCHER_TERMINAL_DRIFT')
                self.run.check()
                return dict(code='WATCHER_NATURAL_RELEASE_OBSERVED_UNACCEPTED',
                            physicalAccepted=False, operationalGO=False, generation=self.generation['generation'],
                            watcherObservation=dict(self.binding), supervisor=dict(self.generation['supervisor']))
            # Same independently fixed ceiling, no relative timeout restart.
            select.select([self.watcher.fd], [], [], min(.02, max(0, self.run.deadline-time.monotonic())))
            self.run.check()

    def close(self):
        errors = []
        for name in ('watcher', 'supervisor'):
            item = getattr(self, name, None); setattr(self, name, None)
            if item is not None:
                try: item.close()
                except BaseException as error: errors.append(error)
        if errors: raise errors[0]

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def source_snapshot(path):
    fd = os.open('/', os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        parts = Path(path).parts[1:]
        for index, part in enumerate(parts):
            child = os.open(part, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC|
                            (os.O_DIRECTORY if index < len(parts)-1 else 0), dir_fd=fd)
            os.close(fd); fd = child; info = os.fstat(fd)
            if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022 or os.listxattr(fd):
                raise RuntimeError('UNTRUSTED_OBSERVER_SOURCE')
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        identity = tuple(getattr(info, k) for k in fields)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024*1024:
            raise RuntimeError('UNTRUSTED_OBSERVER_SOURCE')
        raw = os.pread(fd, 1024*1024+1, 0)
        if len(raw) != info.st_size or identity != tuple(getattr(os.fstat(fd), k) for k in fields):
            raise RuntimeError('OBSERVER_SOURCE_DRIFT')
        return raw, identity
    finally: os.close(fd)


def main():
    if len(sys.argv) != 1 or (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
        raise RuntimeError('FIXED_ROOT_NO_ARGUMENT_ENTRY_REQUIRED')
    for ns in ('pid', 'mnt', 'net', 'user'):
        if os.readlink('/proc/self/ns/'+ns) != os.readlink('/proc/1/ns/'+ns):
            raise RuntimeError('HOST_OBSERVER_VIEW_REQUIRED')
    if not SOURCE_PINS: raise RuntimeError('INDEPENDENT_REVIEWED_SOURCE_CLOSURE_REQUIRED')
    inputs = {p: source_snapshot(p) for p in SOURCE_PINS}
    if any(hashlib.sha256(raw).hexdigest() != SOURCE_PINS[p] for p, (raw, _) in inputs.items()):
        raise RuntimeError('OBSERVATION_SOURCE_PIN_REQUIRED')
    def sources():
        if any(source_snapshot(p) != v for p, v in inputs.items()):
            raise RuntimeError('OBSERVATION_SOURCE_DRIFT')
    def module(name, path, injected=None):
        obj = types.ModuleType(name); obj.__file__ = path
        if injected: obj.__dict__.update(injected)
        exec(compile(inputs[path][0], path, 'exec'), obj.__dict__)
        return obj
    m = module('physical', PHYSICAL)
    c = module('coordinated_restore', COORDINATED)
    fresh = module('fresh_classic', FRESH, {'c': c})
    def prepared(policy, pid):
        fresh.validate(policy)
        fresh.Platform().prepared(policy, pid)
        fd3 = (Path('/proc')/str(pid)/'fd/3').stat().st_ino
        with m.ProcessLease(pid) as lease: m.check_prepared_resources(lease, fd3)
    with Observation(m, prepared, sources) as observation:
        result = observation.wait()
    sources()
    observation.run.check()
    print(m.encode(result).decode(), end='')


if __name__ == '__main__':
    try: main()
    except BaseException:
        print('REFUSAL WATCHER_RELEASE_UNKNOWN_RETAINED', file=sys.stderr)
        raise SystemExit(75)
