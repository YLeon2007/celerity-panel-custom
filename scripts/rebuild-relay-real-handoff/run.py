#!/usr/bin/env python3
"""Opt-in native SOCKS handoff regression; never runs Xray outside the sandbox."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import runpy
import shutil
import socket
import struct
import subprocess
import sys
import sysconfig
import tempfile
import time


PINS = {  # Linux amd64, verified against the repository's existing offline pins.
    '26.11.9': 'e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d',
    '26.3.27': '8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed',
}
IP = '/usr/sbin/ip'
SS = '/usr/bin/ss'
XRAY = '/bin/xray'
LOOPBACK = '127.0.0.1'
ENV = {'LC_ALL': 'C', 'HOME': '/work', 'GOMAXPROCS': '2'}


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def say(event, **facts):
    print(json.dumps(dict(event=event, **facts), sort_keys=True), flush=True)


def output(*argv):
    return subprocess.check_output(argv, stdin=subprocess.DEVNULL, env=ENV, timeout=3, text=True)


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot(src, dest):
    # Cache and checkout inputs are read only; execute/mount only the snapshot.
    with open(src, 'rb', opener=lambda p, f: os.open(p, f | os.O_NOATIME)) as source:
        with dest.open('xb') as target:
            shutil.copyfileobj(source, target)


def runtime_mounts():
    stdlib = Path(sysconfig.get_path('stdlib'))
    python = Path(sys.executable).resolve(strict=True)
    ip = Path(IP).resolve(strict=True)
    ss = Path(SS).resolve(strict=True)
    files = {str(python): python, IP: ip, SS: ss}
    # Mount only the standard library and its ELF dependencies, not host /usr
    # or /etc. -I -B -S prevents site loading and bytecode writes.
    for binary in [python, ip, ss, *sorted((stdlib / 'lib-dynload').glob('*.so'))]:
        for line in output('/usr/bin/ldd', str(binary)).splitlines():
            check('not found' not in line, f'missing runtime dependency for {binary.name}')
            match = re.search(r'(?:=>\s*|^\s*)(/\S+)\s+\(', line)
            if match:
                target = match[1]
                files[target] = Path(target).resolve(strict=True)
    mounts = ['--ro-bind', str(stdlib.resolve(strict=True)), str(stdlib)]
    for target, source in sorted(files.items()):
        mounts.extend(('--ro-bind', str(source), target))
    return str(python), mounts


def launch(args):
    check(os.getuid() != 0, 'run as an unprivileged user, not root')
    check(os.uname().machine == 'x86_64', 'offline binaries are Linux amd64')
    runner = Path(__file__).resolve()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryDirectory(prefix='c3-real-handoff.') as tmp:
        stage = Path(tmp)
        binary = stage / 'xray'
        snapshot(args.xray, binary)
        check(digest(binary) == PINS[args.version], 'binary does not match the pinned SHA-256')
        binary.chmod(0o500)
        python, mounts = runtime_mounts()
        cmd = ['/usr/bin/bwrap', '--unshare-all', '--unshare-user', '--disable-userns',
               '--new-session', '--die-with-parent', '--cap-drop', 'ALL', '--clearenv',
               '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/work', '--chdir', '/work',
               '--ro-bind', str(binary), XRAY, '--ro-bind', str(runner), '/runner.py', *mounts]
        if not args.core_only:
            product = stage / 'rebuildRelayDirectHost.py'
            snapshot(runner.parents[2] / 'src/services/rebuildRelayDirectHost.py', product)
            cmd.extend(('--ro-bind', str(product), '/rebuildRelayDirectHost.py'))
        cmd += ['--', python, '-I', '-B', '-S', '/runner.py', '--sandbox',
                os.readlink('/proc/self/ns/net'), args.version, 'core-only' if args.core_only else 'product']
        status = subprocess.run(cmd, env={}, stdin=subprocess.DEVNULL, timeout=30).returncode
        say('sandbox_exit', status=status)
        return status if status >= 0 else 128 - status


def isolated(parent_netns):
    current = os.readlink('/proc/self/ns/net')
    check(current != parent_netns, 'refusing to use the launcher network namespace')
    interfaces = json.loads(output(IP, '-j', 'address', 'show'))
    check(len(interfaces) == 1 and interfaces[0]['ifname'] == 'lo'
          and {'LOOPBACK', 'UP'} <= set(interfaces[0]['flags']), 'namespace is not loopback-only')
    addresses = {row['local'] for row in interfaces[0]['addr_info']}
    check(LOOPBACK in addresses and addresses <= {LOOPBACK, '::1'}, 'unexpected loopback addresses')
    for family in ('-4', '-6'):
        routes = json.loads(output(IP, '-j', family, 'route', 'show', 'table', 'all'))
        check(all(row.get('dev') == 'lo' and row.get('dst') != 'default' for row in routes),
              'unexpected non-loopback or default route')
    # bubblewrap supplies PWD; CPython may coerce the default C locale.
    check(all((key, value) in {('PWD', '/work'), ('LC_CTYPE', 'C.UTF-8')}
              for key, value in os.environ.items()), 'launcher environment leaked into sandbox')
    say('isolated', netns=current, parent_netns=parent_netns, interfaces=['lo'],
        ipv4_default=False, ipv6_default=False)


def listeners():
    rows = []
    for line in output(SS, '-H', '-lntup').splitlines():
        proto, _, _, _, local, _, *rest = line.split(maxsplit=6)
        address, port = local.rsplit(':', 1)
        rows.append((proto, address, int(port), sorted({int(pid) for pid in
                     re.findall(r'\bpid=(\d+),', ' '.join(rest))})))
    return rows


def until(predicate, message, child=None):
    end = time.monotonic() + 4
    while time.monotonic() < end:
        if child is not None:
            check(child.poll() is None, f'Xray exited before {message}: status={child.returncode}')
        if predicate() and time.monotonic() < end:
            return
        time.sleep(0.025)
    raise AssertionError(message)


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        block = sock.recv(size - len(data))
        check(block, 'unexpected EOF during SOCKS5 handshake')
        data.extend(block)
    return bytes(data)


def independent_associate(port, child, legacy):
    # RFC 1928 no-auth handshake and UDP ASSOCIATE with unknown client endpoint.
    with socket.create_connection((LOOPBACK, port), timeout=2) as control:
        control.sendall(bytes.fromhex('05 01 00'))
        check(recv_exact(control, 2) == bytes.fromhex('05 00'), 'no-auth negotiation failed')
        control.sendall(bytes.fromhex('05 03 00 01 00 00 00 00 00 00'))
        check(recv_exact(control, 4) == bytes.fromhex('05 00 00 01'), 'bad UDP ASSOCIATE response')
        address, udp_port = struct.unpack('!4sH', recv_exact(control, 6))
        check(socket.inet_ntoa(address) == LOOPBACK and udp_port > 0,
              'UDP ASSOCIATE did not return a numeric loopback port')
        check((udp_port == port) == legacy, 'unexpected fixed/ephemeral UDP ASSOCIATE endpoint')
        row = ('udp', LOOPBACK, udp_port, [child.pid])
        check(row in listeners(), 'UDP ASSOCIATE endpoint is not owned by the original Xray process')
        check(output(SS, '-Hnt', 'state', 'established').strip(), 'no live TCP control connection')
        say('associate', address=LOOPBACK, udp_port=udp_port, fixed=legacy, owned=True)
    check(control.fileno() == -1, 'independent control descriptor did not close')
    return udp_port


def no_control_connection():
    return not output(SS, '-Hnt', 'state', 'established').strip()


def verify_product(port, child, legacy):
    source = Path('/rebuildRelayDirectHost.py')
    product = runpy.run_path(str(source))
    rows = product['sock_rows']()  # Real product ss(8) census, no synthetic rows.
    opened = []
    observing = False

    def audit(event, args):
        if observing and event == 'socket.connect':
            sock, address = args
            check(address == (LOOPBACK, port), 'product attempted an unexpected connection')
            opened.append(sock)

    # Hold the actual socket object across return so refcount disposal cannot
    # mask a missing explicit close. No network or parser calls are replaced.
    sys.addaudithook(audit)
    try:
        observing = True
        product['verify_socks_handoff'](rows, port, str(child.pid))
        observing = False
        check(len(opened) == (0 if legacy else 1), 'unexpected product TCP connect count')
        check(all(sock.fileno() == -1 for sock in opened), 'product leaked the control socket')
    finally:
        observing = False
        for sock in opened:
            if sock.fileno() != -1:
                sock.close()
    return {'source_sha256': digest(source), 'connections': len(opened),
            'control_closed': True if opened else None, 'fixed_udp': legacy}


def exercise(version, mode):
    sha = digest(XRAY)
    check(sha == PINS[version], 'sandbox binary digest mismatch')
    version_line = output(XRAY, 'version').splitlines()[0]
    check(version_line.startswith(f'Xray {version} '), 'Xray version mismatch')
    say('xray', version=version_line, sha256=sha)
    check(not listeners(), 'namespace was not empty before the fixture')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind((LOOPBACK, 0))
        port = reservation.getsockname()[1]
    config = Path('/work/socks.json')
    config.write_text(json.dumps({
        'log': {'loglevel': 'warning'},
        'inbounds': [{'tag': 'rebuild-relay-ingress', 'listen': LOOPBACK, 'port': port,
                      'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}],
        'outbounds': [{'protocol': 'blackhole'}],
    }), encoding='ascii')
    argv = [XRAY, 'run', '-config', str(config)]
    say('start', argv=argv)
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, env=ENV)
    legacy = version == '26.3.27'
    try:
        tcp = ('tcp', LOOPBACK, port, [child.pid])
        baseline = [tcp] + ([('udp', LOOPBACK, port, [child.pid])] if legacy else [])
        until(lambda: tcp in listeners(), 'TCP listener readiness', child)
        check(sorted(listeners()) == sorted(baseline), 'unexpected startup listeners or owners')
        say('startup', tcp_port=port, exclusive_tcp=True, fixed_udp=legacy, xray_pid=child.pid)
        udp_port = independent_associate(port, child, legacy)
        until(lambda: no_control_connection() and sorted(listeners()) == sorted(baseline),
              'control connection or per-session UDP endpoint still present', child)
        say('associate_closed', udp_port=udp_port, fixed_udp_retained=legacy)
        if mode == 'product':
            verified = verify_product(port, child, legacy)
            until(lambda: no_control_connection() and sorted(listeners()) == sorted(baseline),
                  'product left a control connection or unexpected UDP endpoint', child)
            say('product_verified', helper='verify_socks_handoff', **verified)
        check(child.poll() is None, 'Xray died before fixture teardown')
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            status = child.wait(timeout=4)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=4)
            raise
        say('xray_reaped', status=status)
    check(status in (0, -15), 'unexpected Xray shutdown status')
    check(not listeners(), 'socket listener remained after reaping Xray')
    say('pass', mode=mode, version=version)


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '--sandbox' and sys.argv[0] == '/runner.py':
        os.umask(0o077)
        isolated(sys.argv[2])
        exercise(sys.argv[3], sys.argv[4])
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('xray', type=Path, help='pinned local Xray executable (no downloads)')
    parser.add_argument('--version', choices=PINS, default='26.11.9')
    parser.add_argument('--core-only', action='store_true', help='omit the product verifier (native wire test only)')
    return launch(parser.parse_args())


if __name__ == '__main__':
    sys.exit(main())
