"""Replay the real reverse-observation endpoint via local-check (see .md)."""
import concurrent.futures
import contextlib
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

LO = '127.0.0.1'
SNI = 'decoy.fixture.invalid'
LINK = '00000000000000000123abcd'
CONN = 'rebuild-rp-conn-' + LINK[-8:]
TAG = 'rebuild-rp-egress-' + LINK[-8:]
OTHER_TAG = 'anonymous-native-egress'
PIN = 'e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d'
PANEL = Path(__file__).with_name('reverse_evidence_panel.cjs').resolve()


def output(*argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=6).stdout


def guard(parent, xray):
    ns = os.readlink('/proc/self/ns/net')
    if not parent or parent == ns:
        raise RuntimeError('run via local-check in a fresh network namespace')
    links = json.loads(output('ip', '-j', 'link'))
    if len(links) != 1 or links[0]['ifname'] != 'lo' or 'UP' not in links[0]['flags']:
        raise RuntimeError('expected only a live loopback interface')
    for family in ('-4', '-6'):
        for row in json.loads(output('ip', '-j', family, 'route', 'show', 'table', 'all')):
            if (row.get('dev') != 'lo' or row.get('table') != 'local' or 'gateway' in row
                    or row.get('type') not in ('local', 'broadcast')
                    or row.get('dst') not in ('127.0.0.0/8', '127.0.0.1', '127.255.255.255', '::1')):
                raise RuntimeError(f'unexpected route {family} {row}')
    with xray.open('rb') as binary:
        if hashlib.file_digest(binary, 'sha256').hexdigest() != PIN:
            raise RuntimeError('unexpected Xray binary')
    print(f'ISOLATION {ns} != {parent}: lo only, local routes only; {output(xray, "version").splitlines()[0]} sha256={PIN}', flush=True)


def until(predicate):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError('fixture transition not observed')


def ports(count):
    with contextlib.ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for sock in sockets:
            sock.bind((LO, 0))
        return [sock.getsockname()[1] for sock in sockets]


@contextlib.contextmanager
def child(log, *argv, shutdown=signal.SIGKILL, show_failure_log=True):
    with log.open('wb') as out:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT)
        try:
            yield proc
            if proc.poll() is not None:
                detail = log.read_text()[-2000:] if show_failure_log else f'status={proc.returncode}'
                raise AssertionError(f'{log.name} exited early: {detail}')
        finally:
            if proc.poll() is None:
                proc.send_signal(shutdown)
            try:
                status = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=4)
                raise
            if shutdown == signal.SIGTERM and status != 0:
                raise AssertionError(f'{log.name} exited with status {status}')


@contextlib.contextmanager
def decoy(work):
    cert, key = work / 'decoy.pem', work / 'decoy.key'
    output('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
           '-days', '1', '-subj', f'/CN={SNI}', '-addext', f'subjectAltName=DNS:{SNI}', '-keyout', key, '-out', cert)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    ctx.load_cert_chain(cert, key)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(4)
            try:
                with ctx.wrap_socket(self.request, server_side=True) as tls:
                    while data := tls.recv(4096):
                        tls.sendall(data)
            except OSError:
                pass

    with socketserver.ThreadingTCPServer((LO, 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield server.server_address[1], cert
        finally:
            server.shutdown()
            thread.join()


def main(work, parent, agent, xray, mongod, decoy_port, cert):
    rp, api_port, subscriber_port, bridge_api, mongo_port, traffic_port = ports(6)
    keys = dict(row.split(': ', 1) for row in output(xray, 'x25519').splitlines() if ': ' in row)
    good, wrong, other, subscriber = (str(uuid.uuid4()) for _ in range(4))
    portal = dict(_id='a' * 24, name='receiver', cascadeRole='portal', active=True, ip=LO, type='xray',
                  port=subscriber_port, xray=dict(apiPort=api_port, security='none', transport='tcp'))
    bridge = dict(_id='b' * 24, name='dialer', cascadeRole='bridge', active=True, ip=LO, type='xray',
                  xray=dict(apiPort=bridge_api))
    link = dict(_id=LINK, name='synthetic reverse', active=True, mode='reverse', portalNode=portal['_id'],
                bridgeNode=bridge['_id'], tunnelUuid=good, tunnelPort=rp, tunnelProtocol='vless', tunnelTransport='tcp',
                tunnelSecurity='reality', tunnelEncryption='none', realityDest=f'{LO}:{decoy_port}', realitySni=[SNI],
                realityPrivateKey=keys['PrivateKey'], realityPublicKey=keys['Password (PublicKey)'],
                realityShortIds=[secrets.token_hex(8)], realityFingerprint='chrome')
    fixture = work / 'panel-input.json'
    fixture.write_text(json.dumps(dict(portal=portal, bridge=bridge, link=link, wrong=wrong, other=other,
                                       subscriber=dict(userId='client-fixture', xrayUuid=subscriber))))
    profiles = json.loads(output('node', PANEL, 'compose', fixture))
    print('COMPOSER receiver MAIN and reverse dialer generated; explicit fingerprint=chrome', flush=True)

    # DIRECT's read-only relay inventory must still recognize exactly this
    # composer-owned account and reject lookalikes with the same tag suffix.
    import copy
    import runpy
    host = runpy.run_path(str(PANEL.parents[2] / 'src/services/rebuildRelayDirectHost.py'))
    descriptor = [{'linkId': LINK, 'mode': 'reverse', 'port': rp, 'uuid': good}]
    def transit(row, edges=descriptor):
        return host['transit_inbounds']({'inbounds': [row]}, edges)
    tagged = next(i for i in profiles['receiver']['inbounds'] if i['tag'] == CONN)
    legacy = next(i for i in profiles['old']['inbounds'] if i['tag'] == CONN)
    assert transit(legacy) == transit(tagged) == {CONN: rp}
    for kind in ('wrong-id-same-suffix', 'wrong-uuid', 'subscriber-email', 'other-account', 'wrong-security'):
        row = copy.deepcopy(tagged)
        edges = copy.deepcopy(descriptor)
        if kind == 'wrong-id-same-suffix': edges[0]['linkId'] = 'f' + LINK[1:]
        if kind == 'wrong-uuid': edges[0]['uuid'] = wrong
        if kind == 'subscriber-email': row['settings']['clients'][0]['email'] = 'ordinary-user'
        if kind == 'other-account': row['settings']['clients'].append({'id': other})
        if kind == 'wrong-security': row['streamSettings']['security'] = 'tls'
        try:
            transit(row, edges)
        except host['Refusal'] as error:
            assert str(error) == 'PROFILE_USERS'
        else:
            raise AssertionError('foreign account admitted: ' + kind)

    def core(name, config):
        file = work / f'{name}.json'
        file.write_text(json.dumps(config))
        return child(work / f'{name}.log', xray, 'run', '-c', file, show_failure_log=mongod is not None)

    def dial(name, choice='dial'):
        # Run the exact emitted outbound without the exit policy's geoip asset.
        return core(name, {'outbounds': [{'protocol': 'blackhole', 'tag': 'block'}, profiles[choice]]})

    def api(verb, *args):
        return output(xray, 'api', verb, f'--server={LO}:{api_port}', '-t=1', *args)

    def tags():
        try:
            return {item['tag'] for item in json.loads(api('lso'))['outbounds']}
        except subprocess.CalledProcessError:
            return set()

    def counter():
        stat = json.loads(api('stats', f'-name=inbound>>>{CONN}>>>traffic>>>downlink'))['stat']
        return stat.get('value', 0)

    def check(phase, *, collect=False):
        env = os.environ | dict(C3_REVERSE_PHASE=phase, C3_REVERSE_PARENT_NETNS=parent,
                                C3_REVERSE_PORT=str(rp), C3_REVERSE_API=f'{LO}:{api_port}',
                                C3_REVERSE_IDENTITY=hashlib.sha256(good.encode()).hexdigest(),
                                C3_REVERSE_FIXTURE=str(fixture), C3_REVERSE_MONGO_PORT=str(mongo_port),
                                C3_REVERSE_PANEL_HELPER=str(PANEL), C3_REVERSE_ANONYMOUS=other,
                                C3_REVERSE_TRAFFIC=f'{LO}:{traffic_port}')
        return subprocess.run([agent, '-test.v', '-test.timeout=25s', '-test.run=^TestRealReverseObservation$'],
                              env=env, timeout=27, check=not collect).returncode

    if mongod is None:
        # Exercise real subscriber traffic, but do not open any arbitrary exit:
        # the exact emitted dialer can reach only the fixture's echo socket.
        class Echo(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                if self.headers.get('Content-Length') != str(64 << 10):
                    self.send_error(400)
                    return
                self.connection.settimeout(2)
                body = self.rfile.read(64 << 10)
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        def tcp_ready(port):
            try:
                with socket.create_connection((LO, port), timeout=.25):
                    return True
            except OSError:
                return False

        with http.server.ThreadingHTTPServer((LO, 0), Echo) as origin:
            thread = threading.Thread(target=origin.serve_forever)
            thread.start()
            dest = origin.server_port
            block = {'protocol': 'blackhole', 'tag': 'block'}
            client = {'inbounds': [{'listen': LO, 'port': traffic_port, 'protocol': 'dokodemo-door',
                                    'settings': {'address': LO, 'port': dest, 'network': 'tcp'}}],
                      'outbounds': [{'protocol': 'vless', 'settings': {
                          'address': LO, 'port': subscriber_port, 'id': subscriber, 'encryption': 'none'}}]}
            transit = profiles['dial']['settings']['reverse']['tag']
            bridge_config = {'outbounds': [block, profiles['dial'], {
                'protocol': 'freedom', 'tag': 'echo',
                'settings': {'finalRules': [{'action': 'allow', 'ip': [LO + '/32']}, {'action': 'block'}]}}],
                'routing': {'rules': [{'type': 'field', 'inboundTag': [transit], 'ip': [LO + '/32'],
                                       'port': dest, 'outboundTag': 'echo'}]}}
            try:
                with core('stats-receiver', profiles['receiver']), core('stats-subscriber', client):
                    until(lambda: 'block' in tags())
                    until(lambda: tcp_ready(traffic_port))
                    with core('stats-dialer', bridge_config):
                        until(lambda: TAG in tags())
                        print('PHASE connected-with-stats', flush=True)
                        live = check('connected-with-stats', collect=True)
                        # Re-prime with genuine bytes before stopping the only
                        # dialer. The cut test must not start on empty counters.
                        payload = b'x' * (64 << 10)
                        conn = http.client.HTTPConnection(LO, traffic_port, timeout=2)
                        try:
                            conn.request('POST', '/', payload)
                            res = conn.getresponse()
                            assert res.status == 200 and res.read() == payload
                        finally:
                            conn.close()
                    time.sleep(.5)  # Drain the killed dialer's in-flight bytes.
                    assert TAG in tags(), 'dynamic handler must survive the cut'
                    print('PHASE cut-with-stats (dialer reaped, receiver and dynamic egress retained)', flush=True)
                    cut = check('cut-with-stats', collect=True)
            finally:
                origin.shutdown()
                thread.join()
        print(f'RESULT connected-with-stats={live} cut-with-stats={cut}', flush=True)
        return int(bool(live or cut))

    def check_decoy():
        trust = ssl.create_default_context(cafile=cert)
        with socket.create_connection((LO, rp), timeout=3) as conn, trust.wrap_socket(conn, server_hostname=SNI) as tls:
            assert tls.getpeercert(True) == ssl.PEM_cert_to_DER_cert(cert.read_text())
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
                result = worker.submit(check, 'decoy-after-cut')
                echoed = 0
                while not result.done():
                    token = secrets.token_bytes(16)
                    tls.sendall(token)
                    data = b''
                    while len(data) < len(token):
                        part = tls.recv(len(token) - len(data))
                        assert part
                        data += part
                    assert data == token
                    echoed += 1
                    time.sleep(.2)
                result.result()
                assert echoed > 0
        print(f'DECOY certificate verified, echoed {echoed} requests during sample', flush=True)

    with core('old-receiver', profiles['old']):
        until(lambda: 'block' in tags())
        with dial('old-dialer'):
            until(lambda: TAG in tags())
            check('old-profile-connected')

    db = work / 'db'
    db.mkdir()
    with child(work / 'mongod.log', mongod, '--dbpath', db, '--bind_ip', LO, '--port', str(mongo_port),
               '--nounixsocket', '--quiet', shutdown=signal.SIGTERM):
        # Only diagnostics differ from composed MAIN; never change its wire fields.
        with core('receiver', {**profiles['receiver'], 'log': {'loglevel': 'debug', 'access': 'none'}}) as receiver:
            until(lambda: 'block' in tags())
            # Exercise the DIRECT inventory reader against the same real
            # HandlerService. Only the systemd PID/socket lookups are fixtures.
            pid = str(receiver.pid)
            reader = host['xray_users']
            reader.__globals__.update(XRAY=str(xray), xray_argv=lambda info: pid)
            sockets = [('tcp', LO, api_port, [pid]), ('tcp', '0.0.0.0', rp, [pid])]
            config = host['entry'](json.dumps(profiles['receiver']).encode())
            assert reader(config, {}, sockets, descriptor) == host['owned_sockets'](sockets, pid)
            print('DIRECT inventory: exact composed and live named transit account matched', flush=True)
            assert TAG not in tags()
            check('before')
            with dial('positive'):
                until(lambda: TAG in tags())
                check('connected')
                for phase in ('wrong-full-id', 'wrong-identity', 'wrong-port'):
                    check(phase)
            time.sleep(.5)  # Let in-flight bytes from the killed dialer drain.
            assert TAG in tags(), 'dynamic handler must survive the cut'
            check('cut')
            check_decoy()
            with dial('wrong-dialer', 'wrong'):
                until(lambda: 'invalid request user id' in (work / 'receiver.log').read_text().lower())
                check('wrong-uuid-after-cut')
            check('add-anonymous-account')
            with dial('anonymous', 'other'):
                until(lambda: {TAG, OTHER_TAG} <= tags())
                before = counter()
                check('anonymous-account-traffic')
                assert counter() > before
                print('ANONYMOUS account advanced aggregate downlink without proof', flush=True)
            with dial('reconnected'):
                check('reconnected')
        check('api-unavailable')


if __name__ == '__main__':
    parent, agent, xray, mode = sys.argv[1:]
    agent, xray = (Path(path).resolve(strict=True) for path in (agent, xray))
    mongod = None if mode == '--stats-only' else Path(mode).resolve(strict=True)
    guard(parent, xray)
    os.umask(0o077)

    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    with tempfile.TemporaryDirectory(dir=Path.cwd(), prefix='synthetic-') as temp:
        work = Path(temp)
        with decoy(work) as (port, cert):
            result = main(work, parent, agent, xray, mongod, port, cert)
    assert not work.exists()
    print('COMPLETE: fixture children reaped and generated files removed', flush=True)
    sys.exit(result)
