#!/usr/bin/env python3
"""TEST-only host cgroup freezer. No remote-node authority is emitted."""
import copy
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import time
import uuid

TEST_MACHINE_ID = '7fa266f995fe4aa69e96cf7d01359e34'
CONTROL = ['/system.slice/docker.service', '/system.slice/containerd.service']
NAMES = {'hysteria-backend', 'hysteria-updater', 'hysteria-mongo',
         'hysteria-redis', 'hysteria-caddy'}
RUNTIME = ('dockerd', 'containerd', 'runc', 'buildkit', 'docker-proxy')
HEX64 = re.compile(r'^[0-9a-f]{64}$')


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def walk_error(error):
    raise error


def events(path):
    return {k: int(v) for k, v in (line.split() for line in path.read_text().splitlines())}


class SystemdRelaunchBarrier:
    """Manager-enforced launch refusal while original kernel roots stay frozen.

    Service-only freezer state can disappear on main-PID death. Prevent automatic
    restart AND socket/dependency activation without freezing PID1's fork path.
    Root administration of these unit files remains in the trusted boundary.
    """
    CONTENT = '[Unit]\nConditionPathExists=!/run\n[Service]\nRestart=no\nExecCondition=\nExecCondition=/usr/bin/false\n'

    def __init__(self, units=None):
        self.units = units or ['docker.service', 'containerd.service']

    def run(self, *args):
        return subprocess.run(['/usr/bin/systemctl', *args], check=True, timeout=10,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout

    def show(self, unit):
        keys = ['Slice', 'ControlGroup', 'Restart', 'KillMode', 'ActiveState', 'ExecCondition']
        text = self.run('show', '--all', unit, *['--property=' + k for k in keys])
        result = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
        # systemctl omits empty command arrays even with --all; installation is
        # accepted only after the nonempty exact false command is read back.
        result.setdefault('ExecCondition', '')
        return result

    def conditions(self, unit):
        def bus(*args):
            result = subprocess.run(['/usr/bin/busctl', '--json=short', *args],
                                    check=True, timeout=10, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
            return json.loads(result.stdout)
        address = bus('call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1',
                      'org.freedesktop.systemd1.Manager', 'GetUnit', 's', unit)
        need(address['type'] == 'o' and len(address['data']) == 1, 'invalid supervisor object')
        result = bus('get-property', 'org.freedesktop.systemd1', address['data'][0],
                     'org.freedesktop.systemd1.Unit', 'Conditions')
        need(result['type'] == 'a(sbbsi)', 'invalid supervisor conditions')
        return result['data']

    def original(self):
        return {u: self.show(u) for u in self.units}

    def verify(self, expected):
        for row in expected['relaunch']['dropins']:
            path = Path(row['path'])
            need(not path.is_symlink() and path.read_text() == self.CONTENT, 'relaunch dropin changed')
        for service in self.units:
            row = self.show(service)
            conditions = self.conditions(service)
            need(any(len(c) == 5 and c[:4] == ['ConditionPathExists', False, True, '/run']
                     for c in conditions), 'prefork activation refusal not loaded')
            condition = row['ExecCondition']
            need(row['Restart'] == 'no' and condition.count('path=') == 1
                 and condition.startswith('{ path=/usr/bin/false ; argv[]=/usr/bin/false ; ignore_errors=no ; '),
                 'supervisor launch refusal not loaded')
            need(row['ControlGroup'] == expected['supervisors'][service]['ControlGroup'],
                 'supervisor executor group drift')

    def prepare(self, expected, kernel, owner, persist):
        need(self.original() == expected['supervisors'], 'supervisor identity/configuration drift')
        need(all(row['ExecCondition'] == '' for row in expected['supervisors'].values()), 'preexisting supervisor condition')
        expected['relaunch'] = {'owner': owner, 'dropins': []}
        for service in self.units:
            directory = Path('/run/systemd/system') / (service + '.d')
            made = not directory.exists()
            path = directory / '90-c3-test-host-isolation.conf'
            persist('intent', action='write-relaunch-refusal', file=str(path), content=self.CONTENT)
            directory.mkdir(mode=0o755, exist_ok=True)
            need(directory.resolve() == directory, 'aliased systemd runtime directory')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as out:
                out.write(self.CONTENT)
                out.flush()
                os.fsync(out.fileno())
            expected['relaunch']['dropins'].append({'path': str(path), 'createdDirectory': made})
        self.run('daemon-reload')
        self.verify(expected)
        return None

    def restore(self, expected, kernel, persist):
        self.verify(expected)
        for row in expected['relaunch']['dropins']:
            path = Path(row['path'])
            persist('intent', action='remove-relaunch-refusal', file=str(path))
            path.unlink()
            if row['createdDirectory']:
                path.parent.rmdir()
        self.run('daemon-reload')
        need(self.original() == expected['supervisors'], 'original supervisor configuration not restored')
        del expected['relaunch']
        return None


class LinuxKernel:
    """Real proc/cgroup-v2 operations; no Docker command after arm begins."""
    def __init__(self, proc='/proc', cgroup='/sys/fs/cgroup', machine='/etc/machine-id', timeout=5):
        self.proc, self.root, self.machine = Path(proc), Path(cgroup), Path(machine)
        self.timeout = timeout
        self.pins = {}
        self.barrier = None

    def prepare_relaunch(self, expected, owner, persist):
        return self.barrier.prepare(expected, self, owner, persist) if self.barrier else None

    def restore_relaunch(self, expected, persist):
        return self.barrier.restore(expected, self, persist) if self.barrier and 'relaunch' in expected else None

    def host(self):
        return {'machineId': self.machine.read_text().strip(),
                'bootId': (self.proc / 'sys/kernel/random/boot_id').read_text().strip()}

    def group(self, name):
        need(name.startswith('/') and '..' not in Path(name).parts and name != '/', 'unsafe cgroup')
        path = self.root / name.lstrip('/')
        need(path.resolve() == path and not path.is_symlink(), 'aliased cgroup')
        return path

    def pid(self, pid):
        p = self.proc / str(pid)
        text = (p / 'stat').read_text()
        fields = text[text.rfind(')') + 2:].split()
        cg = (p / 'cgroup').read_text().strip()
        need(cg.startswith('0::/') and '\n' not in cg, 'not unified cgroup v2')
        return {'pid': int(pid), 'startTicks': fields[19], 'cgroup': cg[3:],
                'session': int(fields[3]),
                'exe': os.readlink(p / 'exe'), 'comm': (p / 'comm').read_text().strip()}

    def members(self, name):
        path = self.group(name)
        result = []
        count = 0
        for base, dirs, files in os.walk(path, onerror=walk_error):
            count += 1
            need(count <= 4096 and len(result) <= 4096, 'cgroup inventory limit')
            need(all(not (Path(base) / d).is_symlink() for d in dirs), 'aliased descendant')
            result.extend(int(x) for x in (Path(base) / 'cgroup.procs').read_text().split())
        need(len(result) <= 4096, 'cgroup process inventory limit')
        need(len(set(result)) == len(result), 'moving process inventory')
        rows = [self.pid(pid) for pid in sorted(result)]
        need(all(p['cgroup'] == name or p['cgroup'].startswith(name + '/') for p in rows), 'escaped PID')
        return rows

    def pin(self, name):
        path = self.group(name)
        need((path / 'cgroup.type').read_text().strip() == 'domain', 'threaded cgroup unsupported')
        return {'inode': path.stat().st_ino, 'members': self.members(name)}

    def runtime(self):
        result = []
        for p in self.proc.iterdir():
            if not p.name.isdigit():
                continue
            comm = ''
            try:
                comm = (p / 'comm').read_text().strip()
                try:
                    exe = Path(os.readlink(p / 'exe')).name.removesuffix(' (deleted)')
                except FileNotFoundError:
                    need(not comm.startswith(RUNTIME), 'runtime lost executable')
                    continue
                if comm.startswith(RUNTIME) or exe.startswith(RUNTIME):
                    row = self.pid(int(p.name))
                    if exe.startswith('containerd-shim'):
                        args = (p / 'cmdline').read_bytes().split(b'\0')
                        need(b'-id' in args and b'-namespace' in args, 'unaccounted shim protocol')
                        row['containerId'] = args[args.index(b'-id') + 1].decode()
                        need(args[args.index(b'-namespace') + 1] == b'moby', 'foreign shim namespace')
                    result.append(row)
            except (FileNotFoundError, ProcessLookupError):
                # A disappearing runtime invalidates the inventory, unlike an
                # unrelated short-lived host process.
                need(not locals().get('comm', '').startswith(RUNTIME), 'runtime disappeared')
        need(len(result) <= 4096, 'runtime inventory limit')
        return sorted(result, key=lambda x: x['pid'])

    def docker_groups(self):
        groups = []
        self.runtime_groups = []
        count = 0
        for base, dirs, files in os.walk(self.root, onerror=walk_error):
            count += 1
            need(count <= 16384, 'host cgroup inventory limit')
            for d in dirs:
                path = Path(base) / d
                relative = '/' + str(path.relative_to(self.root))
                if (any(part.startswith(('docker', 'containerd', 'runc', 'buildkit')) for part in Path(relative).parts)
                        and (path / 'cgroup.events').is_file() and events(path / 'cgroup.events')['populated']):
                    self.runtime_groups.append(relative)
                if d.startswith('docker-') and d.endswith('.scope'):
                    groups.append('/' + str((Path(base) / d).relative_to(self.root)))
        return sorted(groups)

    def parent_identity(self, pid):
        text = (self.proc / str(pid) / 'stat').read_text()
        fields = text[text.rfind(')') + 2:].split()
        return {'pid': int(pid), 'startTicks': fields[19], 'ppid': int(fields[1]),
                'session': int(fields[3])}

    def survivor_descendants(self, group, init):
        # Allow ordinary fork/exit churn, but never accept an incomplete walk.
        # Each retry starts a new full proof; ancestry/session violations are
        # not retryable. Persistent churn is bounded and refuses the hold.
        for _ in range(3):
            try:
                rows = self.survivor_snapshot(group, init)
                if rows is not None:
                    return rows
            except (FileNotFoundError, ProcessLookupError):
                continue
        raise RuntimeError('unproven survivor membership unstable')

    def survivor_snapshot(self, group, init):
        # A Docker exec can already be inside an unfrozen payload while its
        # shim/runc parent is frozen elsewhere. Membership in an accepted cgroup
        # is not authority. Prove every member's current chain to this exact init,
        # including members already present at capture and detached/orphaned work.
        rows = {r['pid']: r for r in self.members(group)}
        need(rows.get(init['pid']) == init, 'survivor init identity drift')
        # Runc launches init and exec into separate sessions. An exec child may
        # be adopted by container PID1 after its parent exits, so PPID ancestry
        # alone is insufficient. Linux cannot join another existing session:
        # setsid creates only the caller's own session. Require the pinned live
        # init to lead the inherited session; independently daemonized children
        # are unproven and refuse rather than being frozen/adopted.
        need(init['session'] == init['pid']
             and all(row['session'] == init['session'] for row in rows.values()),
             'unproven survivor session')
        parents = {pid: self.parent_identity(pid) for pid in rows}
        need(all(parents[pid]['startTicks'] == row['startTicks']
                 and parents[pid]['session'] == row['session'] for pid, row in rows.items()),
             'unproven survivor process identity')
        for pid in rows:
            current, seen = pid, set()
            while current != init['pid']:
                need(current in parents and current not in seen, 'unproven survivor ancestry')
                seen.add(current)
                child = parents[current]
                current = child['ppid']
                need(current in parents
                     and int(parents[current]['startTicks']) <= int(child['startTicks']),
                     'unproven survivor ancestry')
        # Do not stitch a proof across PID reuse, reparenting, or moving members.
        need(all(self.parent_identity(pid) == row for pid, row in parents.items()),
             'unproven survivor ancestry changed')
        if self.members(group) != sorted(rows.values(), key=lambda r: r['pid']):
            return None
        return rows

    def escaped_descendants(self, expected, survivors):
        # Account for generic accepted-work children too, not just executables
        # whose basename happens to say runc/buildkit. Runtime roots are already
        # frozen before this can establish the held result.
        parents = {}
        for p in self.proc.iterdir():
            if not p.name.isdigit():
                continue
            try:
                text = (p / 'stat').read_text()
                fields = text[text.rfind(')') + 2:].split()
                parents[int(p.name)] = int(fields[1])
            except (FileNotFoundError, ProcessLookupError):
                continue
        roots = {r['pid'] for g in expected['controls'] for r in expected['groups'][g]['members']}
        held_groups = [g for g in expected['groups'] if g in expected['controls']
                       or g in expected['freezeOrder'] or g == expected.get('proxyGroup')]
        survivor_containers = [c for c in expected['containers'] if c['cgroup'] not in held_groups]
        for pid in parents:
            current, seen = pid, set()
            while current in parents and current not in seen and current not in roots:
                seen.add(current)
                current = parents[current]
            if current in roots:
                try:
                    cg = (self.proc / str(pid) / 'cgroup').read_text().strip()[3:]
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if any(cg == g or cg.startswith(g + '/') for g in held_groups):
                    continue
                try:
                    row = self.pid(pid)
                    if survivors.get(pid) != row:
                        # A survivor may fork after its first snapshot. Reprove
                        # the entire payload rather than exempt its cgroup.
                        container = next((c for c in survivor_containers
                                          if cg == c['cgroup'] or cg.startswith(c['cgroup'] + '/')), None)
                        if container:
                            survivors.update(self.survivor_descendants(container['cgroup'], container['init']))
                            row = self.pid(pid)
                    need(survivors.get(pid) == row,
                         'accepted-work descendant escaped accounted cgroups')
                except (FileNotFoundError, ProcessLookupError):
                    continue

    def verify(self, expected, frozen, dead=False):
        need(self.host() == expected['host'], 'host/boot identity drift')
        if self.barrier and 'relaunch' in expected:
            self.barrier.verify(expected)
        need(self.docker_groups() == sorted(c['cgroup'] for c in expected['containers']), 'unknown/missing Docker cgroup or replica')
        for group in self.runtime_groups:
            need(any(group == known or group.startswith(known + '/') for known in expected['groups']),
                 'unaccounted runtime cgroup/payload')
        runtime = self.runtime()
        need(runtime == expected['runtime'], 'runtime identity/inventory drift')
        controls = expected['controls']
        ids = {c['id'] for c in expected['containers']}
        for row in runtime:
            proxy = (row['cgroup'] == expected.get('proxyGroup')
                     and Path(row['exe']).name == 'docker-proxy'
                     and any({**original, 'cgroup': row['cgroup']} == row for original in expected.get('proxyOriginals', [])))
            need(proxy or any(row['cgroup'] == g or row['cgroup'].startswith(g + '/') for g in controls), 'runtime helper outside frozen launch roots')
            if 'containerId' in row:
                need(row['containerId'] in ids, 'unaccounted replica shim')
        survivors = {}
        for group, pin in expected['groups'].items():
            path = self.group(group)
            need(path.stat().st_ino == pin['inode'], 'cgroup replaced')
            want = int(group in frozen)
            need(int((path / 'cgroup.freeze').read_text()) == want and events(path / 'cgroup.events')['frozen'] == want, 'freezer not acknowledged')
            if dead and group == expected['backend']:
                need(events(path / 'cgroup.events')['populated'] == 0 and not self.members(group), 'old backend still populated')
                for row in pin['members']:
                    try:
                        text = (self.proc / str(row['pid']) / 'stat').read_text()
                    except (FileNotFoundError, ProcessLookupError):
                        continue
                    fields = text[text.rfind(')') + 2:].split()
                    # A frozen shim cannot reap its dead child. A zombie has no
                    # execution capability; do not claim its /proc row vanished.
                    need(fields[19] != row['startTicks'] or fields[0] == 'Z', 'old process still exists')
            elif group in controls or group in expected['freezeOrder'] or group == expected.get('proxyGroup') or group == expected.get('relaunch', {}).get('cgroup'):
                need(self.members(group) == pin['members'], 'pinned executor tree drift')
            else:
                # Unfrozen payload children may vary, but cgroup membership alone
                # never admits an extra shim/exec child as legitimate data plane.
                init = next(c['init'] for c in expected['containers'] if c['cgroup'] == group)
                need(self.pid(init['pid']) == init, 'survivor init identity drift')
                survivors.update(self.survivor_descendants(group, init))
                if group == expected.get('candidateClosure', {}).get('group'):
                    need(group in frozen and self.members(group) == pin['members'],
                         'closed candidate tree drift')
        self.escaped_descendants(expected, survivors)
        if self.barrier and 'relaunch' in expected:
            self.barrier.verify(expected)
        for group in expected['freezeOrder']:
            need(any(group == g for g in expected['groups']), 'unaccounted freeze root')
        # Re-read identity/freezer after the process walk, not just before it.
        need(self.host() == expected['host'], 'host identity changed during check')
        for group in frozen:
            need(events(self.group(group) / 'cgroup.events')['frozen'] == 1, 'fence thawed during check')

    def proxy_path(self, owner):
        return '/system.slice/c3-test-host-proxies-' + owner + '.scope'

    def split_proxies(self, expected, owner, persist):
        proxies = [r for r in expected['runtime'] if Path(r['exe']).name == 'docker-proxy']
        if not proxies:
            return
        need(str(uuid.UUID(owner)) == owner, 'proxy owner UUID required')
        group = self.proxy_path(owner)
        persist('intent', action='create-proxy-group', group=group)
        path = self.group(group)
        path.mkdir()
        self.pins[group] = path.stat().st_ino
        expected['proxyGroup'] = group
        expected['proxyOriginals'] = copy.deepcopy(proxies)
        expected['groups'][group] = self.pin(group)
        for proxy in proxies:
            self.move_proxy(expected, proxy, group, persist)
        self.verify(expected, expected['freezeOrder'])

    def move_proxy(self, expected, proxy, target, persist):
        source = proxy['cgroup']
        persist('intent', action='move-proxy', pid=proxy['pid'], source=source, target=target)
        # Only immutable, pinned docker-proxy data-plane helpers may leave the
        # freezer. Never move a shim, daemon, runc, buildkit or generic child.
        need(Path(proxy['exe']).name == 'docker-proxy' and self.pid(proxy['pid']) == proxy, 'proxy identity drift')
        need(self.group(target).stat().st_ino == self.pins[target], 'proxy target changed')
        (self.group(target) / 'cgroup.procs').write_text(str(proxy['pid']))
        changed = {**proxy, 'cgroup': target}
        need(self.pid(proxy['pid']) == changed, 'proxy move unconfirmed')
        expected['runtime'] = [changed if r['pid'] == proxy['pid'] else r for r in expected['runtime']]
        expected['groups'][source]['members'] = [r for r in expected['groups'][source]['members'] if r['pid'] != proxy['pid']]
        expected['groups'][target]['members'].append(changed)
        expected['groups'][target]['members'].sort(key=lambda r: r['pid'])
        persist('arming')

    def restore_proxies(self, expected, persist):
        group = expected.get('proxyGroup')
        if not group:
            return
        for original in expected['proxyOriginals']:
            row = next(r for r in expected['runtime'] if r['pid'] == original['pid'])
            self.move_proxy(expected, row, original['cgroup'], persist)
        persist('intent', action='remove-proxy-group', group=group)
        need(not self.members(group), 'proxy group not empty')
        self.group(group).rmdir()
        del expected['groups'][group]
        del expected['proxyGroup']
        del expected['proxyOriginals']
        persist('arming')

    def await_event(self, name, key, value):
        end = time.monotonic() + self.timeout
        while time.monotonic() < end:
            if events(self.group(name) / 'cgroup.events')[key] == value:
                return
            time.sleep(.01)
        raise TimeoutError('kernel cgroup acknowledgement timeout')

    def freeze(self, name, value):
        path = self.group(name)
        if name in self.pins:
            need(path.stat().st_ino == self.pins[name], 'cgroup changed before freeze write')
        (path / 'cgroup.freeze').write_text('1' if value else '0')
        self.await_event(name, 'frozen', int(value))

    def kill(self, name):
        path = self.group(name)
        need(path.stat().st_ino == self.pins[name], 'cgroup changed before kill')
        need(events(path / 'cgroup.events')['frozen'] == 1, 'kill requires frozen exact group')
        (path / 'cgroup.kill').write_text('1')
        self.await_event(name, 'populated', 0)


def docker_read(args):
    cmd = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', *args]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=10, check=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
    need(len(result.stdout) <= 4 * 1024 * 1024, 'Docker inventory limit')
    return result.stdout


def capture(kernel):
    ids = docker_read(['container', 'ls', '--all', '--quiet', '--no-trunc']).decode().split()
    need(5 <= len(ids) <= 6 and all(HEX64.fullmatch(x) for x in ids), 'unknown container count')
    inspected = json.loads(docker_read(['container', 'inspect', *sorted(ids)]))
    containers = []
    for c in inspected:
        name = c['Name'].lstrip('/')
        need(name in NAMES or name == 'c3-test-candidate', 'unexpected container/replica')
        cfg, s = c['HostConfig'], c['State']
        labels = c['Config'].get('Labels') or {}
        project, service = labels.get('com.docker.compose.project'), labels.get('com.docker.compose.service')
        if name in NAMES:
            need(isinstance(project, str) and re.fullmatch('[a-z0-9_-]{1,64}', project), 'missing Compose project')
            need(service == name.removeprefix('hysteria-'), 'unexpected service label')
        need(s['Running'] and not any(s.get(x) for x in ('Paused', 'Restarting', 'Dead')), 'non-running/paused container')
        need(not cfg['Privileged'] and cfg.get('PidMode') != 'host' and cfg.get('CgroupnsMode') != 'host', 'privileged container')
        need(not cfg.get('CapAdd'), 'added container capabilities')
        for mount in c.get('Mounts', []):
            src = mount.get('Source', '')
            need(src not in ('/', '/proc', '/sys', '/sys/fs/cgroup', '/run', '/var/run') and not src.startswith('/sys/'), 'host control mount')
            if 'docker.sock' in src or 'containerd.sock' in src:
                need(name == 'hysteria-updater', 'unfenced runtime socket mount')
        cg = '/system.slice/docker-' + c['Id'] + '.scope'
        init = kernel.pid(s['Pid'])
        need(init['cgroup'] == cg, 'unexpected container cgroup driver')
        need(re.fullmatch('sha256:[0-9a-f]{64}', c['Image']), 'unfixed image identity')
        containers.append({'id': c['Id'], 'name': name, 'image': c['Image'], 'imageRef': c['Config']['Image'],
                           'cgroup': cg, 'init': init, 'project': project, 'service': service, 'startedAt': s['StartedAt'],
                           'restartCount': c['RestartCount'], 'restartPolicy': cfg['RestartPolicy']})
    containers.sort(key=lambda c: c['id'])
    need(NAMES <= {c['name'] for c in containers} and len({c['name'] for c in containers}) == len(containers), 'missing/duplicate role')
    backend = next(c['cgroup'] for c in containers if c['name'] == 'hysteria-backend')
    updater = next(c['cgroup'] for c in containers if c['name'] == 'hysteria-updater')
    need((kernel.group(backend) / 'cgroup.kill').is_file(), 'exact cgroup.kill interface unavailable')
    allgroups = CONTROL + [c['cgroup'] for c in containers]
    need(all(a == b or not (a.startswith(b + '/') or b.startswith(a + '/')) for a in allgroups for b in allgroups), 'payload/control cgroups not independent')
    groups = {g: kernel.pin(g) for g in allgroups}
    runtime = kernel.runtime()
    shims = [r['containerId'] for r in runtime if 'containerId' in r]
    need(sorted(shims) == sorted(c['id'] for c in containers), 'exact per-container shim inventory required')
    for binary, group in [('dockerd', CONTROL[0]), ('containerd', CONTROL[1])]:
        rows = [r for r in runtime if Path(r['exe']).name == binary]
        need(len(rows) == 1 and rows[0]['cgroup'] == group, 'exact control daemon inventory required')
    result = {'schema': 1, 'host': kernel.host(), 'controls': CONTROL[:],
              'backend': backend, 'freezeOrder': [updater, *CONTROL, backend],
              'containers': containers, 'groups': groups, 'runtime': runtime}
    if kernel.barrier:
        result['supervisors'] = kernel.barrier.original()
        for service, group in zip(kernel.barrier.units, CONTROL):
            need(result['supervisors'][service] == {'Slice': 'system.slice', 'ControlGroup': group, 'Restart': 'always', 'KillMode': 'process', 'ActiveState': 'active', 'ExecCondition': ''}, 'unexpected supervisor configuration')
    kernel.verify(result, [])
    return result


class Journal:
    """Private durable journal. flock only prevents duplicate controllers;
    actual dispatch exclusion is cgroup.freeze, never this lock."""
    def __init__(self, directory):
        path = Path(directory)
        path.mkdir(mode=0o700)  # Exclusive creation; never adopt a previous hold.
        parent_fd = os.open(path.parent, os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self.fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW)
        s = os.fstat(self.fd)
        need(s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700, 'unsafe state directory')
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.path = path

    def save(self, row):
        data = (json.dumps(row, sort_keys=True) + '\n').encode()
        fd = os.open('next.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            os.rename('next.json', 'hold.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
            check = os.open('hold.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
            with os.fdopen(check, 'rb') as inp:
                need(inp.read() == data, 'journal readback mismatch')
        except BaseException:
            # An unfinished next.json deliberately blocks further writes/reuse.
            raise


class Fence:
    def __init__(self, expected, kernel, journal, owner):
        self.original = copy.deepcopy(expected)
        self.expected = copy.deepcopy(expected)
        self.kernel = kernel
        self.journal = journal
        self.owner = owner
        self.frozen = []
        self.dead = False
        self.phase = 'new'
        self.pending = None

    def record(self, phase, **extra):
        self.phase = phase
        if phase == 'intent':
            self.pending = copy.deepcopy(extra)
        elif phase != 'unknown':
            self.pending = None
        self.journal.save({'phase': phase, 'owner': self.owner, 'pending': self.pending,
                           'originalExpected': self.original, 'expected': self.expected, 'frozen': self.frozen[:],
                           'dead': self.dead, **extra})

    def unknown(self):
        # Never thaw in any failure path, including signals, EOF or journal failure.
        self.phase = 'unknown'
        self.record('unknown')

    def require(self, phases, owner=None):
        if self.phase not in phases or (owner is not None and owner != self.owner):
            raise RuntimeError('phase/owner refuses operation')

    def arm(self):
        self.require(('new',))
        try:
            self.kernel.verify(self.expected, self.frozen, self.dead)
            replacement = self.kernel.prepare_relaunch(self.expected, self.owner, self.record)
            if replacement:
                self.frozen.append(replacement)
            if replacement or 'relaunch' in self.expected:
                self.record('arming')
            for group in self.expected['freezeOrder']:
                self.record('intent', action='freeze', group=group)
                self.kernel.freeze(group, True)
                self.frozen.append(group)
                self.kernel.verify(self.expected, self.frozen, self.dead)
                self.record('arming')
            self.kernel.split_proxies(self.expected, self.owner, self.record)
            self.record('held')
            return self.check()
        except BaseException:
            self.unknown()
            raise

    def check(self):
        self.require(('held', 'empty'))
        try:
            self.kernel.verify(self.expected, self.frozen, self.dead)
        except BaseException:
            self.unknown()
            raise
        return {'hostFence': 'held', 'oldExecutor': 'empty' if self.dead else 'frozen',
                'nodeState': 'unknown', 'owner': self.owner,
                **({'candidate': 'closed'} if 'candidateClosure' in self.expected else {})}

    def close_candidate(self, owner):
        """One-way exact payload freeze. External effects remain a node-side gate."""
        self.require(('held', 'empty'), owner)
        self.check()
        if 'candidateClosure' in self.expected:
            return self.check()
        candidates = [c for c in self.expected['containers'] if c['name'] == 'c3-test-candidate']
        need(len(candidates) == 1, 'exact candidate required')
        candidate = candidates[0]; group = candidate['cgroup']
        try:
            # Old fences and launch refusal have just been read back. Accepted
            # descendants may fork until freeze acknowledgement; prove the entire
            # final tree's pinned init/session/ancestry AFTER it is kernel-held.
            self.record('intent', action='freeze-candidate', group=group)
            self.kernel.freeze(group, True)
            self.frozen.append(group)
            members = self.kernel.survivor_descendants(group, candidate['init'])
            self.expected['groups'][group]['members'] = sorted(members.values(), key=lambda r: r['pid'])
            self.expected['candidateClosure'] = {'group': group}
            self.kernel.verify(self.expected, self.frozen, self.dead)
            self.record('empty' if self.dead else 'held')
            return self.check()
        except BaseException:
            self.unknown()
            raise

    def terminate(self, owner, ack):
        self.require(('held',), owner)
        if ack != 'KILL_EXACT_OLD_BACKEND':
            raise RuntimeError('explicit exact backend kill acknowledgement required')
        self.check()
        try:
            self.record('intent', action='kill', group=self.expected['backend'])
            self.kernel.kill(self.expected['backend'])
            self.dead = True
            self.kernel.verify(self.expected, self.frozen, self.dead)
            self.record('empty')
            return self.check()
        except BaseException:
            self.unknown()
            raise

    def restore(self, owner):
        need('candidateClosure' not in self.expected, 'candidate closure forbids restore')
        self.require(('held',), owner)
        self.check()
        try:
            # Control-plane APIs can resume pending work once thawed; restoration
            # is allowed ONLY before destructive work / node mutation.
            self.kernel.restore_proxies(self.expected, self.record)
            replacement = self.kernel.restore_relaunch(self.expected, self.record)
            if replacement:
                self.frozen.remove(replacement)
            need(self.expected == self.original, 'original state projection mismatch')
            for group in reversed(self.expected['freezeOrder']):
                self.record('intent', action='thaw', group=group)
                self.kernel.freeze(group, False)
                self.frozen.remove(group)
                self.kernel.verify(self.expected, self.frozen, self.dead)
            self.record('restored')
            return {'hostFence': 'released', 'nodeState': 'unknown', 'owner': self.owner}
        except BaseException:
            self.unknown()
            raise


def host_precheck(kernel):
    need(os.geteuid() == 0, 'host root required')
    need(kernel.host()['machineId'] == TEST_MACHINE_ID, 'TEST host identity required; PROD not supported')
    for ns in ('mnt', 'pid', 'cgroup'):
        need(os.readlink('/proc/self/ns/' + ns) == os.readlink('/proc/1/ns/' + ns), 'host namespace required')
    need((kernel.root / 'cgroup.controllers').is_file(), 'cgroup v2 required')


def read_expected(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as inp:
        need(stat.S_ISREG(os.fstat(inp.fileno()).st_mode), 'expected is not a regular file')
        data = inp.read(4 * 1024 * 1024 + 1)
    need(len(data) <= 4 * 1024 * 1024, 'expected file limit')
    return json.loads(data)


def serve(fence, infd=0):
    """Held live pipe, bounded frames; EOF/signal/lost guard never thaws.

    Caller must keep this process alive AND request fresh checks at each use.
    Historical JSON/journal rows are observations, not bearer capabilities.
    """
    def emit(row):
        print(json.dumps(row, sort_keys=True), flush=True)

    def interrupted(signum, frame):
        raise InterruptedError('guard interrupted')

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    buffer = b''
    try:
        emit(fence.arm())
        while True:
            fence.check()
            ready, _, _ = select.select([infd], [], [], .2)
            if not ready:
                continue
            chunk = os.read(infd, 4096)
            need(chunk, 'controller EOF; kernel hold retained')
            buffer += chunk
            need(len(buffer) <= 8192, 'control frame limit')
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                request = json.loads(line)
                need(type(request) is dict and request.get('owner') == fence.owner, 'foreign control owner')
                cmd = request.get('command')
                if cmd == 'check' and set(request) == {'owner', 'command'}:
                    emit(fence.check())
                elif cmd == 'kill' and set(request) == {'owner', 'command', 'ack'}:
                    emit(fence.terminate(request['owner'], request['ack']))
                elif cmd == 'restore' and set(request) == {'owner', 'command', 'ack'}:
                    need(request['ack'] == 'NO_DESTRUCTIVE_OR_NODE_MUTATION', 'nondestructive restore acknowledgement required')
                    emit(fence.restore(request['owner']))
                    return 0
                else:
                    raise RuntimeError('unknown control operation')
    except BaseException as error:
        fence.unknown()
        reason = str(error) if type(error) is RuntimeError else type(error).__name__
        emit({'hostFence': 'unknown', 'holdRequired': True, 'nodeState': 'unknown', 'owner': fence.owner, 'reason': reason})
        return 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('capture', help='read-only exact TEST inventory; review independently')
    hold = sub.add_parser('hold', help='hold kernel fence until explicit nondestructive restore')
    hold.add_argument('--expected', required=True)
    hold.add_argument('--state-dir', required=True)
    hold.add_argument('--owner', required=True)
    args = parser.parse_args(argv)
    kernel = LinuxKernel()
    kernel.barrier = SystemdRelaunchBarrier()
    try:
        host_precheck(kernel)
        if args.action == 'capture':
            print(json.dumps(capture(kernel), sort_keys=True))
            return 0
        need(str(uuid.UUID(args.owner)) == args.owner, 'canonical owner UUID required')
        expected = read_expected(args.expected)
        # Never infer approval from live state; full independent acceptance must
        # match two fresh inventories before creating a real hold.
        need(capture(kernel) == expected and capture(kernel) == expected, 'independent expected inventory drift')
        kernel.pins = {g: p['inode'] for g, p in expected['groups'].items()}
        journal = Journal(args.state_dir)
        fence = Fence(expected, kernel, journal, args.owner)
        return serve(fence)
    except (Exception, KeyboardInterrupt) as error:
        # Only our fixed RuntimeError messages are public; never raw transport,
        # credential-bearing input, subprocess stderr or arbitrary exception text.
        reason = str(error) if type(error) is RuntimeError else type(error).__name__
        print(json.dumps({'hostFence': 'unknown', 'holdRequired': True, 'nodeState': 'unknown', 'reason': reason}), flush=True)
        return 2


if __name__ == '__main__':
    sys.exit(main())
