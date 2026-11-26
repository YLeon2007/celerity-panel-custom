"""Opt-in matrix; run only after creating a fresh, loopback-only netns."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


PINS = {
    '26.3.27': '8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed',
    '26.11.9': 'e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d',
}
VERSION = 'native-xray-main-proof/v1'
IN = 'vless-in'
EXTRA = 'vless-extra'
API = '127.0.0.1:61000'
SELECTED = 'choice.example.invalid'
FALLBACK = 'fallback.example.invalid'
VISION = 'xtls-rprx-vision'
U1 = {'email': 'synthetic@main.invalid', 'uuid': '00000000-0000-4000-8000-000000000001', 'flow': VISION, 'level': 0}
U2 = {'email': 'other@main.invalid', 'uuid': '00000000-0000-4000-8000-000000000002', 'flow': '', 'level': 2}
ANONYMOUS = '00000000-0000-4000-8000-000000000003'


def isolated():
    assert os.readlink('/proc/self/ns/net') != os.environ['C3_PROOF_PARENT_NETNS']
    link = subprocess.check_output(['/usr/bin/ip', '-o', 'link', 'show']).decode().splitlines()
    assert len(link) == 1 and link[0].split(': ')[1] == 'lo' and 'LOWER_UP' in link[0]
    for family in ('-4', '-6'):
        assert not subprocess.check_output(['/usr/bin/ip', family, 'route', 'show', 'table', 'main'])


def config(anonymous=False, changed_predicate=False, routing_api=True):
    def vless(tag, port, clients):
        return {'tag': tag, 'port': port, 'listen': '127.0.0.1', 'protocol': 'vless',
                'settings': {'clients': clients, 'decryption': 'none'}}

    clients = [dict(id=u['uuid'], email=u['email'], flow=u['flow'], level=u['level']) for u in (U1, U2)]
    if anonymous:
        clients.append({'id': ANONYMOUS})
    return {
        'log': {'loglevel': 'none'},
        'api': {'tag': 'api', 'services': ['HandlerService'] + (['RoutingService'] if routing_api else [])},
        'inbounds': [
            {'tag': 'API_INBOUND', 'port': 61000, 'listen': '127.0.0.1', 'protocol': 'dokodemo-door',
             'settings': {'address': '127.0.0.1'}},
            vless(IN, 20001, clients), vless(EXTRA, 20002, []),
        ],
        'outbounds': [dict(tag=t, protocol='blackhole') for t in ('default', 'selected', 'ip-picked')],
        'routing': {'domainStrategy': 'AsIs', 'rules': [
            dict(type='field', inboundTag=['API_INBOUND'], outboundTag='api'),
            dict(type='field', ruleTag='domain', inboundTag=[IN], network='tcp', port='443',
                 domain=['full:' + (FALLBACK if changed_predicate else SELECTED)], outboundTag='selected'),
            dict(type='field', ruleTag='ip', inboundTag=[IN], network='udp', port='53',
                 ip=['192.0.2.8', '2001:db8::8'], outboundTag='ip-picked'),
            dict(type='field', ruleTag='default', inboundTag=[IN], outboundTag='default'),
        ]},
    }


def frame():
    def route(outbound, network, port, **target):
        return {'context': {'inboundTag': IN, 'network': network, 'targetPort': port, **target},
                'outboundTag': outbound}

    return {'version': VERSION,
            'namedInbounds': [{'tag': IN, 'users': [U2.copy(), U1.copy()]}, {'tag': EXTRA, 'users': []}],
            'routes': [route('selected', 'tcp', 443, targetDomain=SELECTED),
                       route('default', 'tcp', 443, targetDomain=FALLBACK),
                       route('default', 'tcp', 8443, targetDomain=SELECTED),
                       route('ip-picked', 'udp', 53, targetIP='192.0.2.8', targetDomain=FALLBACK),
                       route('ip-picked', 'udp', 53, targetIP='2001:db8::8'),
                       route('default', 'udp', 53, targetIP='192.0.2.9')]}


def owned_listener(child, core):
    until = time.monotonic() + 3
    while child.poll() is None and time.monotonic() < until:
        output = subprocess.check_output(['/usr/bin/ss', '-H', '-ltnp', 'sport', '=', ':61000'], timeout=2)
        rows = output.decode().splitlines()
        if rows:
            assert len(rows) == 1 and rows[0].split()[3] == API, rows
            if 'pid=' in rows[0]:
                assert f'pid={child.pid},' in rows[0], rows
                assert os.path.samefile(f'/proc/{child.pid}/exe', core)
                return
        time.sleep(0.02)
    raise AssertionError('owned Xray API listener not ready')


def test_core(version, core, proof, work):
    with core.open('rb') as f:
        assert hashlib.file_digest(f, 'sha256').hexdigest() == PINS[version]
    env = {'HOME': str(work), 'TMPDIR': str(work), 'XRAY_LOCATION_ASSET': str(work)}
    v = subprocess.check_output([core, 'version'], env=env, timeout=5).splitlines()[0].split()
    assert v[:2] == [b'Xray', version.encode()]
    good = {'version': VERSION, 'userScope': 'named-vless-email-index',
            'namedInbounds': [{'handlerCount': 2, 'enumeratedNamed': 2}, {'handlerCount': 0, 'enumeratedNamed': 0}],
            'routesVerified': 6}
    cases, waits = [], []

    def check(name, data, result=None, error=None):
        p = subprocess.run([proof], input=json.dumps(data).encode(), capture_output=True, env=env, timeout=10)
        if error is None:
            assert p.returncode == 0 and p.stderr == b'', (name, p.returncode, p.stderr)
            assert json.loads(p.stdout) == result, name
        else:
            assert p.returncode == 1 and p.stdout == b'' and p.stderr == (error + '\n').encode(), (name, p.returncode, p.stderr)
        cases.append(name)

    def with_core(name, cfg, checks):
        path = work / f'{name}.json'
        path.write_text(json.dumps(cfg), encoding='ascii')
        with (work / f'{name}.log').open('xb') as log:
            p = subprocess.Popen([core, 'run', '-config', path], cwd=work, env=env,
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            try:
                owned_listener(p, core)
                checks()
                owned_listener(p, core)
            finally:
                if p.poll() is None:
                    p.terminate()
                try:
                    code = p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=3)
                    raise
                assert code == 0, (name, code)
                waits.append(code)
        assert not subprocess.check_output(['/usr/bin/ss', '-H', '-ltn', 'sport', '=', ':61000'], timeout=2)

    def check_base():
        check('base', frame(), result=good)
        for key, wrong in [('uuid', ANONYMOUS), ('email', U1['email'].upper()), ('flow', ''), ('level', 1)]:
            bad = frame()
            bad['namedInbounds'][0]['users'][1][key] = wrong
            check('wrong-' + key, bad, error='NAMED_USERS_MISMATCH 0')
        bad = frame()
        bad['namedInbounds'][0]['users'].pop()
        check('missing-named', bad, error='USER_COUNT_MISMATCH 0')
        # No global union: a second, separately empty inbound must stay empty.
        bad = frame()
        bad['namedInbounds'][1]['users'].append(U1.copy())
        check('wrong-extra-inbound', bad, error='USER_COUNT_MISMATCH 1')
        bad = frame()
        bad['routes'][0]['context']['network'] = 'udp'
        check('wrong-network', bad, error='TEST_ROUTE_MISMATCH 0')
        bad = frame()
        bad['routes'][0]['context']['inboundTag'] = EXTRA
        check('no-match-no-default-assumption', bad, error='TEST_ROUTE_UNAVAILABLE 0')

    def check_changed_predicate():
        check('changed-predicate-refuses-old-proof', frame(), error='TEST_ROUTE_MISMATCH 0')
        changed = frame()
        changed['routes'][0]['outboundTag'], changed['routes'][1]['outboundTag'] = 'default', 'selected'
        check('changed-predicate-confirms-new-proof', changed, result=good)

    with_core('base', config(), check_base)
    with_core('anonymous', config(anonymous=True), lambda: check('anonymous-unobservable', frame(), result=good))
    with_core('predicate', config(changed_predicate=True), check_changed_predicate)
    with_core('no-route-api', config(routing_api=False),
              lambda: check('missing-routing-service', frame(), error='TEST_ROUTE_UNAVAILABLE 0'))
    check('listener-absent', frame(), error='USER_COUNT_UNAVAILABLE 0')
    print(json.dumps({'core': version, 'checks': cases, 'count': len(cases), 'childWaits': waits}), flush=True)


def main():
    assert len(sys.argv) == 4 and not sys.flags.optimize
    isolated()  # Refuse before subprocess binds or Xray version/start.
    proof, *cores = [Path(x).resolve(strict=True) for x in sys.argv[1:]]
    with tempfile.TemporaryDirectory(prefix='native-proofs-', dir=os.environ['TMPDIR']) as temp:
        for version, core in zip(PINS, cores, strict=True):
            work = Path(temp) / version
            work.mkdir(mode=0o700)
            test_core(version, core, proof, work)


if __name__ == '__main__':
    main()
