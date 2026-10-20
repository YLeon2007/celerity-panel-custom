#!/usr/bin/env python3
"""Disposable LOCAL Docker26/kernel drill, never run against a panel host.

Run only as root inside hermes-heavy + an unshared mount namespace. Uses explicit
local static Docker binaries, cgroupfs payloads and private daemon state/socket.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess as sp
import sys
import tarfile
import time
import traceback

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bin-dir', required=True)
parser.add_argument('--workspace', required=True)
parser.add_argument('--restore-only', action='store_true')
parser.add_argument('--survivor-exec', choices=('before-capture', 'after-capture', 'orphan-after-capture'),
                    help='prove refusal after real exec has entered an unfrozen payload')
a = parser.parse_args()
assert not (a.restore_only and a.survivor_exec), 'choose restore or survivor-exec drill'
P, B = Path(a.workspace).resolve(), Path(a.bin_dir).resolve()
assert os.geteuid() == 0 and 'hermes-heavy-' in Path('/proc/self/cgroup').read_text()
assert str(P).startswith('/home/leon/.hermes/cache/scratch/') and not P.exists()
P.mkdir(mode=0o700)
spec = importlib.util.spec_from_file_location('freezer', Path(__file__).parents[1] / 'panel-host-freezer.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
E = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER', 'CONTAINERD'))}
E.update(PATH=str(P / 'bin') + ':' + str(B) + ':/usr/sbin:/usr/bin:/sbin:/bin', GOMAXPROCS='2')
D = [str(B / 'docker'), '-H', 'unix://' + str(P / 'd.sock')]
C = [str(B / 'ctr'), '--address', str(P / 'c.sock'), '--namespace', 'moby']
logs, jobs, clients, groups = [], [], [], []
success = False
fence = None
cg = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().strip()[4:]
cg = cg / ('c3-freezer-' + str(os.getpid()))


def emit(event, **data):
    row = {'event': event, **data}
    logs.append(row)
    print(json.dumps(row), flush=True)


def run(args, timeout=20, check=True):
    return sp.run([str(x) for x in args], env=E, stdout=sp.PIPE, stderr=sp.PIPE,
                  timeout=timeout, check=check, text=True)


def wait(fn, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if fn():
                return
        except (OSError, sp.SubprocessError):
            pass
        time.sleep(.05)
    raise TimeoutError('drill readiness')


def launch(args, group=None, name='client', proxy_status=False):
    if proxy_status:
        ready_r, ready_w = os.pipe()
    def enter():
        if group:
            (group / 'cgroup.procs').write_text(str(os.getpid()))
        if proxy_status:
            os.dup2(ready_w, 3)
    f = open(P / (name + '.log'), 'a')
    q = sp.Popen([str(x) for x in args], env=E, stdout=f, stderr=sp.STDOUT,
                 preexec_fn=enter if group or proxy_status else None,
                 pass_fds=tuple({ready_w, 3}) if proxy_status else ())
    if proxy_status:
        os.close(ready_w)
        import select
        assert select.select([ready_r], [], [], 3)[0], 'proxy status timeout'
        assert os.read(ready_r, 128).startswith(b'0\n'), 'proxy start failed'
        os.close(ready_r)
    jobs.append(q)
    return q


def connect(path):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(.3)
    s.connect(str(path))
    clients.append(s)
    return s


def blocked(s, payload):
    s.sendall(payload)
    try:
        value = s.recv(4096)
        raise AssertionError('frozen API returned data or closed: ' + repr(value))
    except socket.timeout:
        return True


class PipeFence:
    """Exercise the actual held guard protocol in a separate real process."""
    def __init__(self, expected, kernel):
        import select
        self.owner = '11111111-2222-3333-4444-555555555555'
        self.kernel = kernel
        self.state = P / 'journal/hold.json'
        child_in, parent_out = os.pipe()
        parent_in, child_out = os.pipe()
        sys.stdout.flush()
        pid = os.fork()
        if pid == 0:
            os.close(parent_out)
            os.close(parent_in)
            os.dup2(child_in, 0)
            os.dup2(child_out, 1)
            os.close(child_in)
            os.close(child_out)
            f = m.Fence(expected, kernel, m.Journal(P / 'journal'), self.owner)
            os._exit(m.serve(f))
        os.close(child_in)
        os.close(child_out)
        self.pid = pid
        self.send = os.fdopen(parent_out, 'w', buffering=1)
        self.recv = os.fdopen(parent_in, 'r', buffering=1)
        self.expected = expected
        self.phase = 'new'

    def reply(self):
        import select
        assert select.select([self.recv], [], [], 20)[0], 'real guard reply timeout'
        line = self.recv.readline(8193)
        assert line and len(line) <= 8192, 'real guard lost/truncated'
        row = json.loads(line)
        state = json.loads(self.state.read_text())
        self.expected = state['expected']
        self.phase = state['phase']
        self.kernel.pins = {g: p['inode'] for g, p in self.expected['groups'].items()}
        if row['hostFence'] == 'unknown':
            raise RuntimeError('real guard refused/retained unknown hold: ' + str(row.get('reason')))
        return row

    def request(self, command, **args):
        self.send.write(json.dumps({'owner': self.owner, 'command': command, **args}) + '\n')
        self.send.flush()
        return self.reply()

    def arm(self):
        return self.reply()
    def check(self):
        return self.request('check')
    def terminate(self, owner, ack):
        assert owner == self.owner
        return self.request('kill', ack=ack)
    def restore(self, owner):
        assert owner == self.owner
        return self.request('restore', ack='NO_DESTRUCTIVE_OR_NODE_MUTATION')
    def close(self):
        try:
            self.send.close()  # EOF -> sticky unknown; NEVER release a kernel fence.
        except BrokenPipeError:
            pass  # Guard may already have refused; disposable cleanup must still run.
        for _ in range(50):
            done, status = os.waitpid(self.pid, os.WNOHANG)
            if done:
                self.recv.close()
                return
            time.sleep(.02)
        os.kill(self.pid, 9)
        os.waitpid(self.pid, 0)
        self.recv.close()


class LocalKernel(m.LinuxKernel):
    # The TEST entrypoint never exposes these local-only discovery adapters.
    # Actual freezer, identity, membership and kill routines are unchanged.
    def proxy_path(self, owner):
        return '/' + str((cg / ('proxies-' + owner)).relative_to(self.root))
    def docker_groups(self):
        super().docker_groups()
        return sorted('/' + str(x.relative_to(self.root)) for x in (cg / 'payload').iterdir() if x.is_dir())
    def runtime(self):
        return [r for r in super().runtime() if r['exe'].startswith((str(B) + '/', str(P / 'bin') + '/'))]


try:
    assert not Path('/var/run/docker.sock').exists(), 'host Docker must be absent'
    assert os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'), 'private mount namespace required'
    (P / 'run').mkdir()
    run(['mount', '--bind', P / 'run', '/run'])
    cg.mkdir()
    for name in ('dockerd', 'containerd', 'updater', 'payload'):
        d = cg / name
        d.mkdir()
        groups.append(d)
    (P / 'bin').mkdir()
    # Gate real runc exec AFTER Docker/containerd/shim accepted the request.
    # A compiled executable retains runtime identity instead of hiding a shell.
    wrapper = r'''#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
int main(int n,char **v){
 for(int i=1;i<n;i++) if(!strcmp(v[i],"exec")){
  int fd=open("GATE.entered",O_CREAT|O_WRONLY,0600); if(fd>=0)close(fd);
  while(access("GATE",F_OK)==0)usleep(10000);
 }
 v[0]="REAL"; execv(v[0],v); perror("execv"); return 127;
}
'''.replace('GATE', str(P / 'gate')).replace('REAL', str(B / 'runc'))
    (P / 'runc.c').write_text(wrapper)
    run(['gcc', '-O0', '-o', P / 'bin/runc', P / 'runc.c'])
    (P / 'c.toml').write_text(f'version=2\nroot="{P}/cr"\nstate="{P}/cs"\ndisabled_plugins=["io.containerd.grpc.v1.cri", "io.containerd.snapshotter.v1.aufs"]\n[grpc]\n address="{P}/c.sock"\n[plugins."io.containerd.internal.v1.opt"]\n path="{P}/opt"\n')
    config = {'hosts': ['unix://' + str(P / 'd.sock')], 'data-root': str(P / 'data'),
              'exec-root': str(P / 'exec'), 'pidfile': str(P / 'd.pid'),
              'containerd': str(P / 'c.sock'), 'bridge': 'none', 'iptables': False,
              'ip-forward': False, 'ip-masq': False, 'userland-proxy': False,
              'storage-driver': 'vfs', 'live-restore': False, 'log-driver': 'none',
              'exec-opts': ['native.cgroupdriver=cgroupfs'],
              'cgroup-parent': '/' + str((cg / 'payload').relative_to('/sys/fs/cgroup')),
              'runtimes': {'gated': {'path': str(P / 'bin/runc')}}, 'default-runtime': 'gated'}
    (P / 'd.json').write_text(json.dumps(config))
    launch([B / 'containerd', '--config', P / 'c.toml'], cg / 'containerd', 'containerd')
    wait(lambda: run(C + ['version'], timeout=1, check=False).returncode == 0)
    launch([B / 'dockerd', '--config-file', P / 'd.json'], cg / 'dockerd', 'dockerd')
    wait(lambda: run(D + ['info'], timeout=1, check=False).returncode == 0)
    paths = {'/usr/bin/busybox'}
    for line in run(['ldd', '/usr/bin/busybox']).stdout.splitlines():
        paths.update(t for t in line.split() if t.startswith('/') and Path(t).is_file())
    with tarfile.open(P / 'rootfs.tar', 'w', dereference=True) as t:
        for path in paths:
            t.add(path, arcname=path.lstrip('/'), recursive=False)
    run(D + ['import', P / 'rootfs.tar', 'local-freezer:only'])
    (P / 'heartbeat').mkdir(mode=0o777)
    (P / 'heartbeat/index.html').write_text('survivor-proxy-ok')
    def free_port():
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        return port
    target_port, proxy_port = free_port(), free_port()
    old = run(D + ['run', '-d', '--network', 'none', '--restart', 'always', '--name', 'old',
                   'local-freezer:only', '/usr/bin/busybox', 'sleep', '600']).stdout.strip()
    survivor = run(D + ['run', '-d', '--network', 'host', '--name', 'survivor', '-v', str(P / 'heartbeat') + ':/out',
                        'local-freezer:only', '/usr/bin/busybox', 'sh', '-c',
                        f'/usr/bin/busybox httpd -f -p 127.0.0.1:{target_port} -h /out & while true; do /usr/bin/busybox date +%s%N >> /out/ticks; /usr/bin/busybox sleep .05; done']).stdout.strip()
    launch(['/usr/bin/sleep', '600'], cg / 'updater', 'updater')
    wait(lambda: (P / 'heartbeat/ticks').exists())
    launch([B / 'docker-proxy', '-proto', 'tcp', '-host-ip', '127.0.0.1', '-host-port', str(proxy_port),
            '-container-ip', '127.0.0.1', '-container-port', str(target_port)], cg / 'dockerd', 'docker-proxy', proxy_status=True)
    def proxy_ok():
        with socket.create_connection(('127.0.0.1', proxy_port), timeout=.5) as s:
            s.sendall(b'GET /index.html HTTP/1.0\r\nHost: localhost\r\n\r\n')
            response = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            return b'survivor-proxy-ok' in response
    wait(proxy_ok)
    docker_old = connect(P / 'd.sock')
    docker_old.sendall(b'GET /_ping HTTP/1.1\r\nHost: localhost\r\n\r\n')
    assert b'200' in docker_old.recv(4096)
    containerd_old = connect(P / 'c.sock')
    containerd_old.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + b'\x00\x00\x00\x04\x00\x00\x00\x00\x00')
    assert containerd_old.recv(4096)
    try:
        while containerd_old.recv(4096):
            pass
    except socket.timeout:
        pass
    def launch_survivor_exec():
        # No userspace gate: Docker returns only after the extra process is
        # actually running in the unfrozen survivor cgroup.
        command = ('/usr/bin/busybox sleep 600 >/dev/null 2>&1 & echo started > /out/exec-ticks'
                   if a.survivor_exec == 'orphan-after-capture' else
                   'echo started > /out/exec-ticks; exec /usr/bin/busybox sleep 600')
        run(D + ['exec', '-d', survivor, '/usr/bin/busybox', 'sh', '-c', command])
        wait(lambda: (P / 'heartbeat/exec-ticks').exists())

    if a.survivor_exec == 'before-capture':
        launch_survivor_exec()
    if not a.survivor_exec:
        (P / 'gate').touch()
        launch(D + ['exec', old, '/usr/bin/busybox', 'touch', '/accepted-exec'], name='accepted-exec')
        wait(lambda: (P / 'gate.entered').exists())
    kernel = LocalKernel(timeout=5)
    cs = []
    for cid in (old, survivor):
        c = json.loads(run(D + ['inspect', cid]).stdout)[0]
        init = kernel.pid(c['State']['Pid'])
        cs.append({'id': cid, 'cgroup': init['cgroup'], 'init': init})
    oldcg = next(c['cgroup'] for c in cs if c['id'] == old)
    controls = ['/' + str((cg / n).relative_to(kernel.root)) for n in ('dockerd', 'containerd')]
    updater = '/' + str((cg / 'updater').relative_to(kernel.root))
    allgroups = controls + [updater] + [c['cgroup'] for c in cs]
    expected = {'host': kernel.host(), 'containers': cs, 'controls': controls,
                'backend': oldcg, 'freezeOrder': [updater, *controls, oldcg],
                'groups': {g: kernel.pin(g) for g in allgroups}, 'runtime': kernel.runtime()}
    kernel.pins = {g: p['inode'] for g, p in expected['groups'].items()}
    if a.survivor_exec in ('after-capture', 'orphan-after-capture'):
        launch_survivor_exec()
        wait(lambda: kernel.runtime() == expected['runtime'])
    if a.survivor_exec:
        survivorcg = next(c['cgroup'] for c in cs if c['id'] == survivor)
        survivorinit = next(c['init'] for c in cs if c['id'] == survivor)
        payload = kernel.members(survivorcg)
        shims = {r['pid'] for r in expected['runtime'] if r.get('containerId') == survivor}
        exec_rows = [r for r in payload if r['pid'] != survivorinit['pid']
                     and (kernel.parent_identity(r['pid'])['ppid'] in shims
                          if a.survivor_exec != 'orphan-after-capture' else
                          (Path('/proc') / str(r['pid']) / 'cmdline').read_bytes().split(b'\0')[:3]
                          == [b'/usr/bin/busybox', b'sleep', b'600'])]
        assert exec_rows, 'real entered exec must be observed inside survivor'
        if a.survivor_exec == 'orphan-after-capture':
            wait(lambda: all(kernel.parent_identity(r['pid'])['ppid'] == survivorinit['pid']
                             for r in exec_rows))
        emit('real-survivor-exec-entered', timing=a.survivor_exec, exec_rows=exec_rows,
             parents=[kernel.parent_identity(r['pid']) for r in exec_rows],
             init_stat=(Path('/proc') / str(survivorinit['pid']) / 'stat').read_text(),
             exec_stats=[(Path('/proc') / str(r['pid']) / 'stat').read_text() for r in exec_rows])
    fence = PipeFence(expected, kernel)
    before = (P / 'heartbeat/ticks').stat().st_size
    if not a.survivor_exec:
        held = fence.arm()
        assert proxy_ok()
        emit('held', result=held, runtime=fence.expected['runtime'], groups=fence.expected['groups'], proxy_functional=True)
    if a.survivor_exec:
        try:
            fence.arm()
            raise AssertionError('real entered survivor exec was admitted')
        except RuntimeError as error:
            assert 'unproven survivor' in str(error), str(error)
        state = json.loads(fence.state.read_text())
        assert state['phase'] == 'unknown'
        assert kernel.group(survivorcg).joinpath('cgroup.freeze').read_text().strip() == '0'
        time.sleep(.2)
        growth = (P / 'heartbeat/ticks').stat().st_size - before
        assert growth > 0 and proxy_ok()
        emit('entered-survivor-exec-refused', timing=a.survivor_exec,
             phase=state['phase'], survivor_frozen=0, survivor_heartbeat_growth=growth,
             proxy_functional=True)
        success = True
    elif a.restore_only:
        result = fence.restore('11111111-2222-3333-4444-555555555555')
        assert fence.expected == expected and fence.phase == 'restored'
        kernel.verify(expected, [])
        assert run(D + ['inspect', old]).returncode == 0 and proxy_ok()
        emit('nondestructive-exact-restore', result=result, proxy_functional=True,
             original_state_equal=True, daemon_api_resumed=True)
        success = True
    else:
        # Release the accepted exec's userspace gate; kernel freeze must still stop it.
        (P / 'gate').unlink()
        payload = b'POST /containers/' + old.encode() + b'/restart HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n'
        assert blocked(docker_old, payload)
        assert blocked(connect(P / 'd.sock'), b'POST /containers/create?name=queued-new HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}')
        ping = b'\x00\x00\x08\x06\x00\x00\x00\x00\x00abcdefgh'
        assert blocked(containerd_old, ping)
        assert blocked(connect(P / 'c.sock'), b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + b'\x00\x00\x00\x04\x00\x00\x00\x00\x00')
        fence.check()
        emit('apis-and-preaccepted-helper-suspended', old_and_new_docker=True, old_and_new_containerd=True,
             accepted_exec_gate_released=True)
        result = fence.terminate('11111111-2222-3333-4444-555555555555', 'KILL_EXACT_OLD_BACKEND')
        for _ in range(10):
            fence.check()
            time.sleep(.1)
        after = (P / 'heartbeat/ticks').stat().st_size
        assert after > before and proxy_ok()
        emit('old-empty-no-restart', result=result, cgroup_events=m.events(kernel.group(oldcg) / 'cgroup.events'),
             survivor_heartbeat_growth=after - before, observation_s=1,
             accepted_exec_marker_exists=bool(list((P / 'data').rglob('accepted-exec'))))
        assert not list((P / 'data').rglob('accepted-exec'))
        try:
            fence.restore('11111111-2222-3333-4444-555555555555')
            raise AssertionError('destructive restore was allowed')
        except RuntimeError:
            pass
        # Never thaw a destructive hold. Kill all owned groups while frozen, THEN
        # terminate their exact daemon identities; only disposable drill cleanup.
        success = True
except BaseException:
    emit('error', traceback=traceback.format_exc())
finally:
    if fence is not None:
        fence.close()
    for s in clients:
        s.close()
    if cg.exists():
        # Destructive disposable test teardown, not the mechanism's restore path.
        for child in cg.iterdir():
            if child.is_dir():
                try:
                    (child / 'cgroup.kill').write_text('1')
                except OSError:
                    pass
    for q in jobs:
        try:
            q.kill()
            q.wait(timeout=3)
        except (OSError, sp.TimeoutExpired):
            pass
    time.sleep(.2)
    if cg.exists():
        for child in sorted(cg.rglob('*'), key=lambda p: len(p.parts), reverse=True):
            if child.is_dir():
                try:
                    child.rmdir()
                except OSError:
                    pass
        try:
            cg.rmdir()
        except OSError:
            pass
    mounted = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        p = line.split()[4]
        if p.startswith(str(P) + '/'):
            mounted.append(p)
    for path in sorted(mounted, key=len, reverse=True):
        run(['umount', '-l', path], check=False)
    run(['umount', '/run'], check=False)
    for path in ('data', 'exec', 'cr', 'cs', 'run'):
        shutil.rmtree(P / path, ignore_errors=True)
    emit('cleanup', success=success, cgroup_remaining=cg.exists())
    (P / 'result.json').write_text(json.dumps(logs, indent=2))
    for base, ds, fs in os.walk(P):
        os.chown(base, 1000, 1000)
        for name in fs:
            os.chown(Path(base) / name, 1000, 1000)
    if not success or cg.exists():
        sys.exit(1)
