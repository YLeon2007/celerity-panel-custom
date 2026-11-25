"""Opt-in native cc-agent/Xray, modeled systemd job/cgroup; never uses host systemd."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid

from rebuildTransitMainWindowHost import System, m

XRAY = '/tools/xray'
AGENT = '/usr/local/bin/cc-agent'
BOOT = m.MAIN
CONF = Path('/etc/cc-agent/config.json')
ROOT = Path('/work')
TOKEN = 'synthetic-main-window-token'
TAG = 'vless-in'


def loopback_only():
    own = os.readlink('/proc/self/ns/net')
    parent = os.environ.get('C3_CUTOVER_PARENT_NETNS', '')
    assert parent.startswith('net:[') and own != parent
    assert [name for _, name in socket.if_nameindex()] == ['lo']
    assert not os.path.lexists('/etc/resolv.conf') and not os.path.lexists('/run/systemd/private')
    with open(XRAY, 'rb') as binary:
        digest = hashlib.file_digest(binary, 'sha256').hexdigest()
    assert digest in {
        '8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed',
        'e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d'}
    assert BOOT.parent.is_dir() and CONF.parent.is_dir() and not BOOT.exists() and not CONF.exists()


def ports():
    sockets = [socket.socket() for _ in range(3)]
    try:
        for s in sockets:
            s.bind(('127.0.0.1', 0))
        return [s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:
            s.close()


def readback(executable, port):
    data = json.loads(subprocess.check_output([executable, 'api', 'inbounduser',
                      f'--server=127.0.0.1:{port}', '-t=1', '-tag=' + TAG], timeout=3))
    return sorted((u['email'], u['account']['id'], u['account'].get('flow', '')) for u in data.get('users', []))


def publish(path, data):
    publish_bytes(path, json.dumps(data).encode())


def publish_bytes(path, data):
    tmp = path.with_name(path.name + '.fixture-new')
    with tmp.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def profile(api, user_port, target):
    return {'log': {'loglevel': 'none'}, 'stats': {},
            'api': {'tag': 'api', 'services': ['HandlerService', 'RoutingService', 'StatsService']},
            'inbounds': [{'tag': 'local-api', 'listen': '127.0.0.1', 'port': api, 'protocol': 'dokodemo-door',
                          'settings': {'address': '127.0.0.1'}},
                         {'tag': TAG, 'listen': '127.0.0.1', 'port': user_port, 'protocol': 'vless',
                          'settings': {'decryption': 'none', 'clients': []}}],
            'outbounds': [{'tag': name, 'protocol': 'blackhole'} for name in ('a', 'b')],
            'routing': {'rules': [{'type': 'field', 'ruleTag': 'api', 'inboundTag': ['local-api'], 'outboundTag': 'api'},
                                  {'type': 'field', 'ruleTag': 'select', 'inboundTag': [TAG], 'outboundTag': target}]}}


class Native(System):
    def __init__(self, root, agent_port, current_core):
        super().__init__(root)
        self.port = agent_port
        self.current_core = current_core
        self.agent = None
        self.logs = {}
        self.stop_timeout = False
        self.root.mkdir(exist_ok=True)
        self.start_agent()

    def start_agent(self):
        log = self.root / ('agent-' + self.inv + '.log')
        self.logs[self.inv] = log
        with log.open('x') as output:
            self.agent = subprocess.Popen([AGENT], stdout=output, stderr=output, stdin=subprocess.DEVNULL,
                                          start_new_session=True)
        self.ready()

    def call(self, path, method='GET', data=None):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=1)
        try:
            c.request(method, path, json.dumps(data) if data is not None else None,
                      {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'})
            status = c.getresponse()
            assert status.status == 200, f'fixture agent {method} {path}: HTTP {status.status}'
            return json.loads(status.read(1 << 20))
        finally:
            c.close()

    def ready(self):
        until = time.monotonic() + 5
        while time.monotonic() < until:
            assert self.agent is not None and self.agent.poll() is None
            if 'starting on' in self.logs[self.inv].read_text():
                try:
                    if self.call('/health').get('status') == 'ok':
                        return
                except OSError:
                    pass
            time.sleep(.05)
        raise AssertionError('fixture agent not ready')

    def __call__(self, argv, timeout):
        if argv[0] == '/usr/bin/journalctl':
            assert argv[-1].startswith('_SYSTEMD_INVOCATION_ID=')
            lines = self.logs[argv[-1].split('=', 1)[1]].read_text().splitlines(keepends=True)
            return ''.join(lines[-128:])
        if argv[-1] == m.XRAY:
            core = self.current_core()
            assert core.poll() is None
            return super().__call__(argv, timeout).replace(f'MainPID={self.xray_generation + 500}\n',
                                                           f'MainPID={core.pid}\n')
        assert self.agent is not None
        if argv[1] == 'show':
            row = super().__call__(argv, timeout)
            if self.active:
                assert self.agent.poll() is None
                row = row.replace(f'MainPID={100+self.generation}\n', f'MainPID={self.agent.pid}\n')
            else:
                assert self.agent.poll() == 0
            return row
        if argv[1] == 'stop':
            assert argv[-1] == m.UNIT and self.agent.poll() is None
            self.agent.terminate()
            # A real pending TERM while SIGSTOP'ed, with a test-only shorter wait.
            assert self.agent.wait(timeout=.25 if self.stop_timeout else min(timeout, 8)) == 0
            return super().__call__(argv, timeout)
        if argv[1] == 'start':
            super().__call__(argv, timeout)
            self.inv = uuid.uuid4().hex
            self.start_agent()
            return ''
        raise AssertionError('unexpected command')

    def close(self):
        if self.agent is not None and self.agent.poll() is None:
            self.agent.send_signal(signal.SIGCONT)
            self.agent.terminate()
            try:
                self.agent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.agent.kill()
                self.agent.wait(timeout=3)
                raise


def main():
    loopback_only()
    os.umask(0o077)
    api, user_port, agent_port = ports()
    store = ROOT / 'store'
    store.mkdir()
    cfg = {'listen': f'127.0.0.1:{agent_port}', 'xray_api': f'127.0.0.1:{api}', 'token': TOKEN,
           'data_dir': str(store), 'inbounds': [{'tag': TAG, 'flow': ''}]}
    publish(CONF, cfg)
    managed = m.managed_inbounds(cfg)
    past, goal = [profile(api, user_port, tag) for tag in 'ab']
    publish(BOOT, past)
    cores = []

    def start_core():
        proc = subprocess.Popen([XRAY, 'run', '-c', str(BOOT)], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        cores.append(proc)
        return proc

    def stop_core(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                assert proc.wait(timeout=4) == 0
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
                raise

    def observed():
        until = time.monotonic() + 4
        while time.monotonic() < until:
            try:
                return readback(XRAY, api)
            except subprocess.CalledProcessError:
                time.sleep(.05)
        raise AssertionError('fixture HandlerService not ready')

    def route():
        out = subprocess.check_output([XRAY, 'api', 'lsrules', f'--server=127.0.0.1:{api}', '-t=1'], timeout=3)
        return json.loads(out)['rules'][1]['tag']

    def disk():
        return m.parse_json(BOOT.read_bytes())

    def assert_profile(target):
        assert m.topology_bytes(disk(), managed) == m.topology_bytes(target, managed)

    def new_user(n):
        return {'id': str(uuid.uuid4()), 'email': f'fixture-{n}@example.invalid'}

    mgr = None
    core = start_core()
    try:
        assert observed() == [] and route() == 'a'
        cgroot = ROOT / 'fake-system.slice'
        cgroot.mkdir()
        mgr = Native(cgroot, agent_port, lambda: core)
        # Stock first boot lacks users.json and only admits a full panel sync.
        assert mgr.call('/sync', 'POST', {'users': []})['errors'] == 0
        user = new_user(1)
        mgr.call('/users', 'POST', user)
        assert observed() == [(user['email'], user['id'], '')]
        wnd = m.AgentWindow(mgr, cgroup_root=cgroot)
        mode, = sys.argv[1:]
        timeout = mode == 'timeout'
        if timeout:
            mgr.stop_timeout = True
            assert mgr.agent is not None
            mgr.agent.send_signal(signal.SIGSTOP)
            pid, status = os.waitpid(mgr.agent.pid, os.WUNTRACED)
            if not os.WIFSTOPPED(status):
                mgr.agent.returncode = os.waitstatus_to_exitcode(status)
                raise AssertionError('fixture agent exited before Stop timeout test')
            assert pid == mgr.agent.pid
        assert mode in ('full', 'timeout')

        def image(data):
            return {'raw': data.hex(), 'topology': hashlib.sha256(m.topology_bytes(m.parse_json(data), managed)).hexdigest()}

        def snapshot():
            raw = BOOT.read_bytes()
            st = BOOT.stat()
            return {**image(raw), 'pid': core.pid, 'file': {'ino': str(st.st_ino), 'mode': st.st_mode,
                    'uid': st.st_uid, 'gid': st.st_gid}, 'generation': mgr.xray_generation}

        original = snapshot()
        identities = []
        trace = []

        def handle(f):
            nonlocal core, wnd, identities
            action = f['action']
            tag = 'a' if f.get('direction') == 'rollback' else 'b'
            target = past if tag == 'a' else goal
            trace.append((action, tag))
            if action == 'manifest':
                return {'before': original, 'desired': image(json.dumps(goal).encode())}
            if action == 'capture':
                return snapshot()
            if action == 'agent-stop':
                assert_profile(goal if tag == 'a' else past)
                wnd.quiesce()
            elif action == 'drained-capture':
                wnd.require_quiet()
                fresh = snapshot()
                expected = f['expected']
                assert all(fresh[k] == expected[k] for k in ('pid', 'generation', 'topology'))
                identities = observed()
                assert len(identities) == (1 if tag == 'b' else 2)
                actual = m.merge_clients(m.parse_json(bytes.fromhex(f['target']['raw'])), disk(), managed)
                return {'before': fresh, 'desired': image(json.dumps(actual).encode())}
            elif action == 'main-publication':
                assert snapshot() == f['before']
                wnd.require_quiet()
                publish_bytes(BOOT, bytes.fromhex(f['desired']['raw']))
                assert image(BOOT.read_bytes()) == f['desired']
            elif action == 'xray-restart':
                wnd.require_quiet()
                stop_core(core)
                prev, core = core, start_core()
                mgr.xray_generation += 1
                assert core.pid != prev.pid and observed() == identities and route() == tag
                wnd.join_xray_restart()
            elif action == 'agent-start':
                wnd.resume()
            elif action in ('agent-reconcile', 'verify', 'terminal'):
                if action == 'agent-reconcile':
                    wnd.wait_reconciled()
                assert wnd.phase == 'reconciled'
                assert_profile(target)
                assert observed() == identities and route() == tag
                assert mgr.call('/info')['users_count'] == len(identities)
                verified = snapshot()
                if action == 'terminal' and tag == 'b':
                    mgr.call('/users', 'POST', new_user(2))
                    wnd = m.AgentWindow(mgr, cgroup_root=cgroot)
                return verified
            elif action == 'observe':
                assert timeout and wnd.phase == 'stop-unconfirmed' and snapshot() == original and route() == 'a'
                return 'before'
            else:
                raise AssertionError('unexpected fixture action')
            return True

        with subprocess.Popen(['/tools/node', '/scripts/main-window-journal.cjs', 'timeout' if timeout else 'rollback'],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE) as worker:
            reader, writer = worker.stdout, worker.stdin
            assert reader is not None and writer is not None
            # One reply per request. Only the overall isolated runner may kill these children.
            try:
                for frame in iter(lambda: reader.readline(16384), b''):
                    f = json.loads(frame)
                    if f['action'] == 'done':
                        assert f['status'] == ('unknown' if timeout else 'rolled-back')
                        break
                    try:
                        reply = {'ok': True, 'value': handle(f)}
                    except m.WindowError as e:
                        if not (timeout and f['action'] == 'agent-stop' and e.code == 'REBUILD_AGENT_STOP_UNCONFIRMED'):
                            raise
                        reply = {'ok': False}
                    writer.write(json.dumps(reply).encode() + b'\n')
                    writer.flush()
                else:
                    raise AssertionError('MAIN journal worker ended without terminal witness')
                writer.close()
                assert worker.wait(timeout=3) == 0
            finally:
                if worker.poll() is None:
                    worker.kill()
                    worker.wait(timeout=3)
        if timeout:
            assert [action for action, _ in trace] == ['manifest', 'capture', 'agent-stop', 'observe']
            print('PASS retained stop phase, no publication or restart and no replay', flush=True)
        else:
            assert [tag for action, tag in trace if action == 'agent-reconcile'] == ['b', 'a']
            print('PASS journalled A→B→A with real agent drain, post-resume checks and new user retained', flush=True)
    finally:
        if mgr is not None:
            mgr.close()
        for child in reversed(cores):
            stop_core(child)


if __name__ == '__main__':
    main()
