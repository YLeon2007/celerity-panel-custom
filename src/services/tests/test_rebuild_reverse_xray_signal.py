"""Real Xray 26.11.9 signal regression. Run only in a fresh loopback-only netns.

Pass the local release binary in C3_XRAY_26_11_9. The SOCKS/echo route and
REALITY fallback certificate are synthetic controls, not production probes.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

LO = '127.0.0.1'
TAG = 'rebuild-rp-egress-aabbccdd'
INGRESS = 'rebuild-rp-ingress-aabbccdd'
SNI = 'decoy.fixture.invalid'


def output(*argv):
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=4).stdout


def until(predicate):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError('expected fixture transition not observed')


@contextlib.contextmanager
def listener(handle):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            handle(self.request)

    with socketserver.ThreadingTCPServer((LO, 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join()


def ports(count):
    with contextlib.ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for sock in sockets:
            sock.bind((LO, 0))
        return [sock.getsockname()[1] for sock in sockets]


class ReverseSignal(unittest.TestCase):
    def test_real_certificate_fresh_reverse_disconnect_and_reconnect(self):
        if [row['ifname'] for row in json.loads(output('ip', '-j', 'link'))] != ['lo']:
            self.fail('run in a fresh loopback-only netns')
        xray = Path(os.environ['C3_XRAY_26_11_9']).resolve(strict=True)
        with xray.open('rb') as binary:
            self.assertEqual(hashlib.file_digest(binary, 'sha256').hexdigest(),
                             'e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d')
        with tempfile.TemporaryDirectory(prefix='reverse-signal-') as tmp, contextlib.ExitStack() as stack:
            work = Path(tmp)
            cert, key = work / 'cert.pem', work / 'key.pem'
            output('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                   '-days', '1', '-subj', f'/CN={SNI}', '-addext', f'subjectAltName=DNS:{SNI}', '-keyout', key, '-out', cert)
            decoy = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            decoy.minimum_version = ssl.TLSVersion.TLSv1_3
            decoy.set_alpn_protocols(['h2', 'http/1.1'])
            decoy.load_cert_chain(cert, key)

            def accept_tls(conn):
                try:
                    with decoy.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(1)
                except OSError:
                    pass

            decoy_port = stack.enter_context(listener(accept_tls))
            echo_port = stack.enter_context(listener(lambda conn: conn.sendall(conn.recv(128))))
            api_port, reverse_port, socks_port = ports(3)
            keys = dict(line.split(': ', 1) for line in output(xray, 'x25519').splitlines() if ': ' in line)
            short, identity = secrets.token_hex(8), str(uuid.uuid4())
            block = {'tag': 'block', 'protocol': 'blackhole'}

            def inbound(tag, port, proto, settings, **extra):
                return dict(tag=tag, listen=LO, port=port, protocol=proto, settings=settings, **extra)

            def rule(tag, outbound):
                return {'type': 'field', 'inboundTag': [tag], 'outboundTag': outbound}

            def stream(**settings):
                return dict(network='tcp', security='reality', realitySettings=settings)

            @contextlib.contextmanager
            def core(name, **config):
                profile, log = work / (name + '.json'), work / (name + '.log')
                profile.write_text(json.dumps(config))
                with log.open('wb') as capture:
                    proc = subprocess.Popen([xray, 'run', '-c', profile], stdin=subprocess.DEVNULL,
                                            stdout=capture, stderr=subprocess.STDOUT)
                    try:
                        yield proc, log
                        self.assertIsNone(proc.poll(), name + ' exited before cleanup')
                    finally:
                        if proc.poll() is None:
                            proc.kill()
                        proc.wait(timeout=4)

            def dialer(name, user):
                return core(name, log={'loglevel': 'warning', 'access': 'none'},
                            outbounds=[block, {'protocol': 'vless', 'tag': 'dial', 'settings': {
                                'address': LO, 'port': reverse_port, 'id': user, 'encryption': 'none',
                                'reverse': {'tag': INGRESS},
                            }, 'streamSettings': stream(serverName=SNI, publicKey=keys['Password (PublicKey)'],
                                                        shortId=short, fingerprint='chrome')},
                                {'tag': 'echo-exit', 'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow'}]}}],
                            routing={'rules': [rule(INGRESS, 'echo-exit')]})

            stack.enter_context(core('receiver', log={'loglevel': 'info', 'access': 'none'},
                                     api={'tag': 'api', 'services': ['HandlerService']},
                                     inbounds=[inbound('api-in', api_port, 'dokodemo-door', {'address': LO}),
                                               inbound('reverse', reverse_port, 'vless', {
                                                   'decryption': 'none', 'clients': [{'id': identity, 'reverse': {'tag': TAG}}],
                                               }, streamSettings=stream(dest=f'{LO}:{decoy_port}', serverNames=[SNI],
                                                                        privateKey=keys['PrivateKey'], shortIds=[short])),
                                               inbound('test-socks', socks_port, 'socks', {'auth': 'noauth'})],
                                     outbounds=[block], routing={'rules': [rule('api-in', 'api'), rule('test-socks', TAG)]}))

            def handlers():
                return json.loads(output(xray, 'api', 'lso', f'--server={LO}:{api_port}', '-t=1'))['outbounds']

            def api_ready():
                try:
                    return bool(handlers())
                except subprocess.CalledProcessError:
                    return False

            def has_reverse():
                return any(row['tag'] == TAG for row in handlers())

            def echo_through_reverse():
                nonce = secrets.token_bytes(16)
                try:
                    with socket.create_connection((LO, socks_port), timeout=.5) as conn, conn.makefile('rb') as response:
                        conn.sendall(b'\x05\x01\x00')
                        if response.read(2) != b'\x05\x00':
                            return False
                        conn.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(LO) + echo_port.to_bytes(2, 'big'))
                        if response.read(10)[:2] != b'\x05\x00':
                            return False
                        conn.sendall(nonce)
                        return response.read(len(nonce)) == nonce
                except OSError:
                    return False

            until(api_ready)
            # Static routing reference + real TCP and a validated certificate
            # from fallback, all without an authenticated VLESS reverse worker.
            client_tls = ssl.create_default_context(cafile=cert)
            with socket.create_connection((LO, reverse_port), timeout=2) as conn, client_tls.wrap_socket(conn, server_hostname=SNI) as tls:
                self.assertEqual(tls.getpeercert(binary_form=True), ssl.PEM_cert_to_DER_cert(cert.read_text()))
                self.assertFalse(has_reverse())
                self.assertFalse(echo_through_reverse())
            with dialer('wrong-user', str(uuid.uuid4())):
                until(lambda: 'invalid request user id' in (work / 'receiver.log').read_text().lower())
                self.assertFalse(has_reverse())
            with dialer('authenticated', identity):
                until(echo_through_reverse)
                self.assertTrue(has_reverse())
            self.assertTrue(has_reverse(), 'registered handler survives dialer loss')
            self.assertFalse(echo_through_reverse())
            with dialer('reconnected', identity):
                until(echo_through_reverse)
                self.assertTrue(has_reverse())


if __name__ == '__main__':
    unittest.main()
