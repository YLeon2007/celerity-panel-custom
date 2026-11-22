"""Only run via run.sh. Raw core diagnostics and JSON stay on private tmpfs."""

import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

LO = '127.0.0.1'
XRAY = '/tools/xray'
XRAY_SHA = 'e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d'


class Failure(Exception):
    """Only fixed, non-secret fixture diagnostics may escape as Failure."""


def need(condition, message):
    if not condition:
        raise Failure(message)


def output(*argv, data=None):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    need(result.returncode == 0, f'{Path(argv[0]).name} exited {result.returncode} (raw output withheld)')
    return result.stdout


def wait_for(check, alive, message):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        for child in alive:
            child.check()
        if check():
            return
        time.sleep(.1)
    raise Failure(message)


def reserve_ports(*names):
    with contextlib.ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in names]
        for sock in sockets:
            sock.bind((LO, 0))
        return dict(zip(names, (s.getsockname()[1] for s in sockets)))


class Core:
    def __init__(self, stack, work, name, config):
        self.name = name
        self.log = work / f'{name}.log'
        config_path = work / f'{name}.json'
        config_path.write_text(json.dumps(config))
        test = subprocess.run([XRAY, 'run', '-test', '-c', config_path],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=5)
        need(test.returncode == 0, f'{name}: Xray config test failed (raw output withheld)')
        with self.log.open('wb') as log:
            self.proc = subprocess.Popen([XRAY, 'run', '-c', config_path], stdin=subprocess.DEVNULL,
                                         stdout=log, stderr=subprocess.STDOUT)
        stack.callback(self.stop)

    def check(self):
        need(self.proc.poll() is None, f'{self.name}: Xray exited (raw output withheld)')

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=3)

    def lines(self):
        return self.log.read_text(errors='replace').splitlines()


class Origin(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self):
        self.lock = threading.Lock()
        self.hits = 0
        self.bytes = 0
        super().__init__((LO, 0), Echo)

    def get_request(self):
        request = super().get_request()
        with self.lock:
            self.hits += 1
        return request

    def snapshot(self):
        with self.lock:
            return self.hits, self.bytes


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        origin = self.server
        if not isinstance(origin, Origin):
            return
        self.request.settimeout(2)
        try:
            while data := self.request.recv(1024):
                with origin.lock:
                    origin.bytes += len(data)
                self.request.sendall(data)
        except OSError:
            pass


def recv_exact(sock, count):
    data = b''
    while len(data) < count:
        fragment = sock.recv(count - len(data))
        if not fragment:
            break
        data += fragment
    return data


def echo(socks, dest):
    """Return received bytes, and whether the SOCKS request reached the send step."""
    payload = secrets.token_bytes(32)
    got = b''
    sent = False
    try:
        with socket.create_connection((LO, socks), timeout=.7) as conn:
            conn.sendall(b'\x05\x01\x00')
            if recv_exact(conn, 2) != b'\x05\x00':
                return False, got, sent
            conn.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(LO) + struct.pack('!H', dest))
            reply = recv_exact(conn, 10)
            if len(reply) != 10 or reply[:4] != b'\x05\x00\x00\x01':
                return False, got, sent
            conn.sendall(payload)
            sent = True
            while len(got) < len(payload):
                part = conn.recv(len(payload) - len(got))
                if not part:
                    break
                got += part
    except OSError:
        pass
    return got == payload, got, sent


def matches(config, collection, port):
    entries = [row for row in config[collection] if row.get('port', row.get('settings', {}).get('port')) == port]
    need(len(entries) == 1, f'expected one composer-generated endpoint in {collection}')
    return entries[0]


def exit_fixture(dial, origin):
    # The stock exit excludes geoip:private. Keep the generated dialer verbatim,
    # but allow solely this fixture origin in an isolated test-only exit wrapper.
    return {'outbounds': [{'tag': 'block', 'protocol': 'blackhole'}, dial,
                          {'tag': 'echo', 'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow'}]}}],
            'routing': {'rules': [{'type': 'field', 'inboundTag': [dial['settings']['reverse']['tag']],
                                  'ip': [LO], 'port': str(origin), 'outboundTag': 'echo'}]}}


def logged(config):
    # Observe auth and access without editing any emitted wire or routing field.
    return {**config, 'log': {'loglevel': 'info'}}


def decoded_requests(lines, destination):
    # A native reverse control connection is not logged like ordinary
    # dispatched traffic. This inbound message is emitted after VLESS auth.
    marker = f'proxy/vless/inbound: received request for {destination}'
    return sum(marker in line for line in lines)


def reverse_requests(lines):
    return decoded_requests(lines, 'tcp:v1.rvs.cool:0')


def regress(work, stack, origin):
    ports = reserve_ports('subscriber', 'portalApi', 'relayClient', 'relayApi', 'bridgeApi',
                          'reused', 'downstream', 'socks')
    dest = origin.server_address[1]
    profiles = json.loads(output('/tools/node', '/panel/compose.cjs', data=json.dumps(ports).encode()))
    before, after, retired = (profiles[k] for k in ('before', 'after', 'retired'))
    old_dial = matches(retired, 'outbounds', ports['reused'])
    new_dial = profiles['afterExit']
    old_in, new_in = (matches(config, 'inbounds', ports['reused']) for config in (before, after))
    old_client, new_client = old_in['settings']['clients'], new_in['settings']['clients']
    old_id, new_id = old_dial['settings']['id'], new_dial['settings']['id']
    need(old_id != new_id and [c['id'] for c in old_client] == [old_id]
         and [c['id'] for c in new_client] == [new_id], 'composer credential membership differs from fixture')
    for dial, inbound in ((old_dial, old_in), (new_dial, new_in)):
        need(dial['protocol'] == inbound['protocol'] == 'vless' and inbound['listen'] == '0.0.0.0'
             and dial['settings']['address'] == LO and dial['settings']['port'] == ports['reused']
             and dial['settings']['encryption'] == inbound['settings']['decryption'] == 'none'
             and dial['streamSettings'] == inbound['streamSettings'] == old_dial['streamSettings']
             and dial['streamSettings']['security'] == 'none',
             'composer tunnel transport or endpoint changed')
    sub = matches(before, 'inbounds', ports['subscriber'])
    need(sub == matches(after, 'inbounds', ports['subscriber']), 'subscriber config changed across cutover')
    subscriber = sub['settings']['clients'][0]
    client = {'inbounds': [{'tag': 'probe', 'listen': LO, 'port': ports['socks'], 'protocol': 'socks',
                            'settings': {'auth': 'noauth'}}],
              'outbounds': [{'tag': 'portal', 'protocol': 'vless', 'streamSettings': sub['streamSettings'],
                             'settings': {'address': LO, 'port': sub['port'], 'id': subscriber['id'],
                                          'encryption': 'none'}}]}

    def core(name, config):
        return Core(stack, work, name, config)

    def exchange():
        return echo(ports['socks'], dest)[0]

    previous = core('before-portal', logged(before))
    stale = core('retired-relay', retired)
    old_exit = core('before-exit', exit_fixture(profiles['beforeExit'], dest))
    subscriber_core = core('subscriber', client)
    baseline = [previous, stale, old_exit, subscriber_core]
    wait_for(exchange, baseline, 'OLD dialer: no nonce echo through original two-hop path')
    wait_for(lambda: reverse_requests(previous.lines()), baseline,
             'OLD dialer: no authenticated reverse request in receiver log')
    print(f'PASS before OLD: nonce echo through portal -> relay -> bridge; '
          f'authenticated reverse requests={reverse_requests(previous.lines())}', flush=True)

    # Reap the old receiver; leave the exact retired relay process and its
    # working downstream exit running, so this is a real reconnect attempt.
    previous.stop()
    current = core('after-portal', logged(after))
    after_live = [current, stale, old_exit, subscriber_core]

    def refusals(lines):
        return sum(' rejected ' in line and f'proxy/vless/encoding: invalid request user id: {old_id}' in line
                   for line in lines)

    wait_for(lambda: refusals(current.lines()), after_live,
             'OLD dialer: no receiver-side VLESS rejection matching the retired UUID')
    hits = origin.snapshot()
    attempts = 3
    for _ in range(attempts):
        ok, received, sent = echo(ports['socks'], dest)
        need(sent and not ok and not received, 'OLD window: missing test request or unexpected response bytes')
    wait_for(lambda: decoded_requests(current.lines(), f'tcp:{LO}:{dest}') >= attempts, after_live,
             'OLD window: surviving subscriber ingress did not decode all origin requests')
    lines = current.lines()
    need(origin.snapshot() == hits, 'OLD dialer: origin accepted a connection or payload')
    need(not reverse_requests(lines), 'OLD dialer: receiver authenticated a reverse request')
    print(f'PASS after OLD: same endpoint {LO}:{ports["reused"]}; '
          f'VLESS invalid-user rejections={refusals(lines)}; reverse accepts=0; '
          f'origin probes={attempts}, connections=0, payload bytes=0, response bytes=0', flush=True)

    # Same post-delete listener and subscriber; the rejected process stays
    # alive even while the valid surviving dialer proves service recovery.
    survivor = core('after-exit', exit_fixture(new_dial, dest))
    after_live.append(survivor)
    wait_for(exchange, after_live, 'valid surviving dialer: no nonce echo through replacement link')
    wait_for(lambda: reverse_requests(current.lines()), after_live,
             'valid surviving dialer: no authenticated reverse request in receiver log')
    rejects_at_echo = refusals(current.lines())
    wait_for(lambda: refusals(current.lines()) > rejects_at_echo, after_live,
             'valid surviving dialer: OLD dialer did not retry while survivor was active')
    need(exchange(), 'valid surviving dialer: echo failed after concurrent OLD retry')
    print(f'PASS after VALID: same receiver process/endpoint, OLD process still running; '
          f'nonce echo via surviving bridge before/after concurrent OLD refusal; '
          f'authenticated reverse requests={reverse_requests(current.lines())}',
          flush=True)


def main():
    os.umask(0o077)
    need(os.readlink('/proc/self/ns/net') != os.environ['PARENT_NETNS'], 'missing private network namespace')
    links = json.loads(output('/tools/ip', '-j', 'link'))
    need([row['ifname'] for row in links] == ['lo'] and 'UP' in links[0]['flags'], 'expected only loopback, up')
    for family in ('-4', '-6'):
        need(not json.loads(output('/tools/ip', '-j', family, 'route', 'show', 'default')), 'unexpected default route')
    with open(XRAY, 'rb') as binary:
        need(hashlib.file_digest(binary, 'sha256').hexdigest() == XRAY_SHA, 'unexpected offline Xray binary digest')
    need(output(XRAY, 'version').startswith(b'Xray 26.11.9 '), 'unexpected Xray version')
    print(f'ISOLATED private netns, lo only, no default route; Xray 26.11.9 sha256={XRAY_SHA}', flush=True)
    with tempfile.TemporaryDirectory(dir='/tmp') as tmp, Origin() as origin, contextlib.ExitStack() as stack:
        worker = threading.Thread(target=origin.serve_forever)
        worker.start()
        stack.callback(worker.join, 3)
        stack.callback(origin.shutdown)
        regress(Path(tmp), stack, origin)
    print('PASS retired reverse dialer regression; owned Xray children reaped', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Failure as exc:
        sys.exit(f'FAIL: {exc}')
    except Exception as exc:
        sys.exit(f'FAIL: fixture setup/runtime exception ({type(exc).__name__}); raw output withheld')
