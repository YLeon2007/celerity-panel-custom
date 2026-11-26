"""Opt-in real observer + real helper/Xray matrix (only in private unshare -Urn).

Use the same launcher as scripts/native-xray-main-proof/README.md, replacing
its Python test entrypoint with this file. Only systemd show is modeled.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from unittest.mock import patch

HERE = Path(__file__).resolve()
sys.path[:0] = [str(HERE.parents[1]), str(HERE.parents[3] / 'scripts/native-xray-main-proof')]
import test_native as reference  # pyright: ignore[reportMissingImports]
import rebuildTransitMainRuntime as rt
from rebuildTransitMainSession import MainSnapshot, XrayGeneration
from rebuildTransitMainWindow import AgentWindow, WindowError

INV = '1234567890abcdef' * 2
SCOPE = frozenset({reference.IN, reference.EXTRA})


def route_plan():
    return tuple(rt.RouteCheck(c['inboundTag'], c['network'], c['targetPort'], row['outboundTag'],
                               c.get('targetDomain'), c.get('targetIP'))
                 for row in reference.frame()['routes'] for c in [row['context']])


def check_core(version, core, proof, work):
    with core.open('rb') as source:
        assert hashlib.file_digest(source, 'sha256').hexdigest() == reference.PINS[version]
    env = {'HOME': str(work), 'TMPDIR': str(work), 'XRAY_LOCATION_ASSET': str(work)}
    assert subprocess.check_output([core, 'version'], env=env, timeout=4).splitlines()[0].split()[:2] == [
        b'Xray', version.encode('ascii'),
    ]
    main = work / 'config.json'
    cases, waits, native_statuses = [], [], []
    popen = subprocess.Popen

    def assert_absent():
        assert not subprocess.check_output(['/usr/bin/ss', '-H', '-ltn', 'sport', '=', ':61000'], timeout=2)

    def publish_fixture(cfg):
        main.write_text(json.dumps(cfg), encoding='ascii')

    @contextmanager
    def daemon(label, cfg, *, ready=True, argv0=core, other_netns=False):
        assert_absent()
        publish_fixture(cfg)
        argv, executable = [argv0, 'run', '-config', main], core
        if other_netns:
            assert argv0 == core and not ready
            executable = '/usr/bin/unshare'
            argv = [executable, '-n', '/bin/sh', '-ec', '/usr/bin/ip link set lo up; exec "$@"', 'fixture', *argv]
        with (work / (label + '.log')).open('xb') as log:
            p = popen(argv, executable=executable, env=env, cwd=work,
                      stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            try:
                if other_netns:
                    until = time.monotonic() + 3
                    while p.poll() is None and time.monotonic() < until:
                        proc = Path(f'/proc/{p.pid}')
                        if (proc / 'exe').readlink() == core and any(
                            line.split()[1:4:2] == [b'0100007F:EE48', b'0A']
                            for line in (proc / 'net/tcp').read_bytes().splitlines()[1:]
                        ):
                            break
                        time.sleep(0.02)
                    else:
                        raise AssertionError('fixture listener not ready in secondary netns')
                    assert not (proc / 'ns/net').samefile('/proc/thread-self/ns/net')
                elif ready:
                    reference.owned_listener(p, core)
                else:
                    until = time.monotonic() + 3
                    while p.poll() is None and time.monotonic() < until:
                        rows = subprocess.check_output(['/usr/bin/ss', '-H', '-ltnp', 'sport', '=', ':20001'],
                                                       timeout=2)
                        if f'pid={p.pid},'.encode() in rows:
                            break
                        time.sleep(0.02)
                    else:
                        raise AssertionError('fixture VLESS listener not ready')
                yield p
            finally:
                if p.poll() is None:
                    p.terminate()
                try:
                    code = p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=3)
                    raise
                assert code == 0, (label, code)
                waits.append(code)
        assert_absent()

    def observe(name, pid, expected_status=None, *, want=True, routes=None, after_receipt=None, xray=core):
        manager_reads, children = [], []
        original_exchange = rt._exchange
        image = AgentWindow(None, main=main).read_main()
        snapshot = MainSnapshot(image, XrayGeneration(pid, INV))

        def manager(argv, timeout):
            assert argv == ['/usr/bin/systemctl', 'show', '--all',
                            *('--property=' + k for k in rt.XRAY_PROPS), '--', 'xray.service']
            assert timeout == 4
            manager_reads.append('show')
            props = dict(Id='xray.service', LoadState='loaded', NeedDaemonReload='no', ActiveState='active',
                         SubState='running', Job='', MainPID=str(pid), InvocationID=INV,
                         ExecStart=f'{{ path={xray} ; argv[]={xray} run -config {main} ; ignore_errors=no ; }}')
            return ''.join(f'{k}={v}\n' for k, v in props.items())

        observer = rt.MainRuntimeObserver(SCOPE, lambda phase, snap: route_plan() if routes is None else routes,
                                          _fixture_paths=(proof, xray, main), _fixture_show=manager)

        def only_proof(argv, **kw):
            assert tuple(argv) == (str(proof),)
            p = popen(argv, **kw)
            children.append(p)
            return p

        def receipt_boundary(argv, data, **kw):
            assert len(manager_reads) == 2
            reply = original_exchange(argv, data, **kw)
            if after_receipt:
                after_receipt()
            return reply

        with patch.object(rt.subprocess, 'Popen', side_effect=only_proof), \
             patch.object(rt, '_exchange', side_effect=receipt_boundary):
            try:
                assert observer('baseline', snapshot) is True
            except WindowError as e:
                assert not want and e.code == rt.RUNTIME and e.__context__ is None, name
            else:
                assert want, name
                assert len(manager_reads) == 4
        assert [p.returncode for p in children] == ([] if expected_status is None else [expected_status]), name
        assert all(p.stdin.closed and p.stdout.closed and p.stderr.closed for p in children), name
        assert AgentWindow(None, main=main).read_main() == image, name
        cases.append(name)
        native_statuses.append(expected_status)

    with daemon('base', reference.config()) as p:
        observe('scoped-named-and-six-routes', p.pid, 0)
        routes = route_plan()
        observe('wrong-concrete-outbound', p.pid, 1, want=False,
                routes=(routes[0]._replace(outbound_tag='default'), *routes[1:]))
        # Deliberately add a new IPv6 LISTEN after a real valid child receipt.
        with socket.socket(socket.AF_INET6) as competitor:
            competitor.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            competitor.bind(('::1', 61000))
            observe('post-receipt-competing-listener', p.pid, 0, want=False,
                    after_receipt=lambda: competitor.listen())
        changed = reference.config()
        changed['inbounds'][1]['settings']['clients'][0]['id'] = reference.ANONYMOUS
        publish_fixture(changed)  # Same count, different UUID than the live generation.
        observe('named-uuid-drift', p.pid, 1, want=False)
        publish_fixture(reference.config())
        observe('xray-death-after-receipt', p.pid, 0, want=False,
                after_receipt=lambda: (p.terminate(), p.wait(timeout=3)))

    with daemon('anonymous', reference.config(anonymous=True)) as p:
        observe('anonymous-not-part-of-proof', p.pid, 0)

    with daemon('predicate', reference.config(changed_predicate=True)) as p:
        observe('changed-predicate-rejects-old-plan', p.pid, 1, want=False)
        routes = route_plan()
        observe('changed-predicate-matches-new-plan', p.pid, 0,
                routes=(routes[0]._replace(outbound_tag='default'), routes[1]._replace(outbound_tag='selected'), *routes[2:]))

    stock = reference.config(routing_api=False)
    stock['api']['services'].append('StatsService')
    with daemon('stock', stock) as p:
        observe('stock-missing-routing-declaration', p.pid, want=False)
        publish_fixture(reference.config())
        observe('live-routing-rpc-actually-absent', p.pid, 1, want=False)

    foreign = work / 'different-xray'
    foreign.write_bytes(b'not the running executable')
    foreign.chmod(0o700)
    with daemon('exe', reference.config(), argv0=foreign) as p:
        observe('argv-spelling-with-foreign-exe', p.pid, want=False, xray=foreign)

    with daemon('other-netns', reference.config(), ready=False, other_netns=True) as p:
        assert_absent()
        observe('serving-xray-in-different-netns', p.pid, want=False)

    no_api = reference.config()
    no_api['inbounds'].pop(0)
    with daemon('no-api', no_api, ready=False) as p:
        publish_fixture(reference.config())  # Valid on disk, deliberately not the boot image.
        observe('absent-listener', p.pid, want=False)
        for name, address in (('foreign-listener', '127.0.0.1'), ('wildcard-listener', '0.0.0.0')):
            with socket.socket(socket.AF_INET) as foreign_socket:
                foreign_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                foreign_socket.bind((address, 61000))
                foreign_socket.listen()
                observe(name, p.pid, want=False)

    assert len(cases) == len(set(cases)) == len(native_statuses) == 15 and waits == [0] * 7
    print(json.dumps({'core': version, 'checks': cases, 'count': len(cases), 'proofWaits': native_statuses,
                      'xrayWaits': waits}), flush=True)


def main():
    assert len(sys.argv) == 4 and not sys.flags.optimize
    reference.isolated()  # Refuse before starting a binary or binding a socket.
    scratch = Path(os.environ['TMPDIR']).resolve(strict=True)
    assert scratch.is_relative_to('/home/leon/.hermes/cache/scratch')
    proof, *cores = [Path(x).resolve(strict=True) for x in sys.argv[1:]]
    with tempfile.TemporaryDirectory(prefix='main-runtime-', dir=scratch) as tmp:
        for version, core in zip(reference.PINS, cores, strict=True):
            work = Path(tmp) / version
            work.mkdir(mode=0o700)
            check_core(version, core, proof, work)


if __name__ == '__main__':
    main()
