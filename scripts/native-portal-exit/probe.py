#!/usr/bin/env python3
"""Run only through verify-portal-exits.sh, inside its private namespaces."""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import dataclass
from hashlib import file_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess as sp
import sys
import threading
import time

LO = '127.0.0.1'
VIRTUAL_IP = '127.0.0.42'  # No listener here; only a synthetic destination before egress.
VIRTUAL_PORT = 18080
GEO = 'fixture.invalid'
SNI = 'cover.fixture.invalid'
XRAY = '/tools/xray'
BRIDGE_XRAY = '/tools/bridge-xray'
BRIDGES = ('A', 'B')
COMPOSER_INPUTS = ('services/rebuildTopologyComposer.js', 'domain/rebuildTopologyCompiler.js',
                   'domain/rebuildPortalExit.js')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def cmd(argv, **kwargs):
    return sp.run(argv, capture_output=True, text=True, timeout=10, **kwargs)


def checked(argv, **kwargs):
    return cmd(argv, check=True, **kwargs).stdout


def dump(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + '\n')


def namespace(parent_net):
    live = os.readlink('/proc/self/ns/net')
    require(live != parent_net and os.getcwd() == '/work' and (os.getpid() == 1 or os.getppid() == 1),
            'missing fresh netns, private workdir or PID isolation')
    require(socket.if_nameindex() == [(1, 'lo')], 'netns must have only lo')
    require(not checked(['ip', '-4', 'route']) and not checked(['ip', '-6', 'route']),
            'netns must have no non-local routes')
    require(not Path('/etc/resolv.conf').exists(), 'host resolver must not be mounted')
    print(f'ISOLATED {live}: lo only, no non-local routes, no mounted resolver')
    return live


def ports_for(names):
    # Hold all allocations until the complete distinct roster is allocated.
    # Closing these sockets cannot race an unrelated process in this netns.
    with ExitStack() as stack:
        ports = {}
        for name in names:
            sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            sock.bind((LO, 0))
            ports[name] = sock.getsockname()[1]
        return ports


def version(binary):
    return checked([binary, 'version']).splitlines()[0]


def digest(file):
    with open(file, 'rb') as inp:
        return file_digest(inp, 'sha256').hexdigest()


def source_digests():
    base = Path('/source/src/modules/relay-l2tp')
    return {leaf: digest(base / leaf) if (base / leaf).is_file() else None for leaf in COMPOSER_INPUTS}


def reality_keys(reality_count, cover_port):
    short_ids = set()
    keys = []
    for _ in range(reality_count):
        fields = [row.split(':', 1)[1].strip() for row in checked([XRAY, 'x25519']).splitlines() if ':' in row]
        require(len(fields) >= 2 and all(len(value) == 43 for value in fields[:2]), 'unexpected Xray x25519 output')
        short_id = secrets.token_hex(8)
        require(short_id not in short_ids, 'random short ID collision')
        short_ids.add(short_id)
        keys.append({'realityDest': f'{LO}:{cover_port}', 'realitySni': [SNI],
                     'realityPrivateKey': fields[0], 'realityPublicKey': fields[1],
                     'realityShortIds': [short_id]})
    return keys


class Origins:
    def __init__(self):
        self.marker = {name: f'{name}:{secrets.token_hex(16)}' for name in BRIDGES}
        self.receipts = {}
        self.lock = threading.Lock()

    def handler(self, name):
        origins = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                host = self.headers.get('Host')
                if not self.path.startswith('/proof-') or host not in (GEO, f'{GEO}:{VIRTUAL_PORT}',
                                                                          f'{VIRTUAL_IP}:{VIRTUAL_PORT}'):
                    self.send_error(404)
                    return
                with origins.lock:
                    origins.receipts.setdefault(self.path, []).append((name, host))
                body = origins.marker[name].encode('ascii')
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass
        return Handler

    def start(self, stack, name, port):
        server = ThreadingHTTPServer((LO, port), self.handler(name))
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            require(not thread.is_alive(), f'origin {name} failed to stop')

        stack.callback(stop)


def fixture_config(profile, sink_port, label):
    config = deepcopy(profile)
    config['log'] = {'loglevel': 'info', 'access': f'/work/{label}.access.log'}
    if sink_port is None:
        return config
    # Select the composer's existing exit rules and retain the exact transit
    # inbound tags and freedom outbound. Only replace the internet policy here.
    rules = config['routing']['rules']
    permits = [rule for rule in rules if rule.get('outboundTag') == 'freedom']
    require(len(rules) == 2 and len(permits) == 1 and permits[0].get('inboundTag')
            and config['outbounds'][0]['protocol'] == 'blackhole', f'unexpected exit profile: {label}')
    transit = permits[0]['inboundTag']
    freedom = next(o for o in config['outbounds'] if o.get('tag') == 'freedom')
    require(freedom['protocol'] == 'freedom', f'unexpected exit protocol: {label}')
    config['routing'] = {'domainStrategy': 'AsIs', 'rules': [
        {**permits[0], 'port': str(VIRTUAL_PORT), **selector}
        for selector in ({'domain': [f'full:{GEO}']}, {'ip': [f'{VIRTUAL_IP}/32']})
    ]}
    freedom['settings'] = {'redirect': f'{LO}:{sink_port}', 'domainStrategy': 'AsIs',
                           'finalRules': [{'action': 'allow', 'ip': [f'{LO}/32']}, {'action': 'block'}]}
    require(all(rule['inboundTag'] == transit for rule in config['routing']['rules']), 'lost transit scope')
    return config


def subscriber_config(users, ports):
    return {
        'log': {'loglevel': 'info'},
        'inbounds': [{'listen': LO, 'port': ports[f'socks-{name}'], 'tag': f'socks-{name}', 'protocol': 'socks'}
                     for name in users],
        'outbounds': [{'tag': 'block', 'protocol': 'blackhole'}] + [
            {'tag': name, 'protocol': 'vless', 'settings': {'vnext': [
                {'address': LO, 'port': ports[name], 'users': [{'id': user['xrayUuid'], 'encryption': 'none'}]}
            ]}} for name, user in users.items()],
        'routing': {'domainStrategy': 'AsIs', 'rules': [
            {'type': 'field', 'inboundTag': [f'socks-{name}'], 'outboundTag': name} for name in users
        ]},
    }


def start(stack, label, argv, reaped):
    with open(f'{label}.run.log', 'w') as log:
        child = sp.Popen(argv, stdin=sp.DEVNULL, stdout=log, stderr=sp.STDOUT)

    def stop():
        before = child.poll()
        forced = False
        if before is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except sp.TimeoutExpired:
                forced = True
                child.kill()
                child.wait(timeout=3)
        else:
            child.wait(timeout=3)
        reaped[label] = {'pid': child.pid, 'status': child.returncode, 'early_exit': before, 'forced_kill': forced}

    stack.callback(stop)
    return child


def wait_until(description, children, condition, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        dead = {name: child.returncode for name, child in children.items() if child.poll() is not None}
        require(not dead, f'child exited waiting for {description}: {dead}')
        if condition():
            return
        time.sleep(0.12)
    raise RuntimeError(f'timeout waiting for {description}')


def sockets(port, proc, *, established=False):
    if established:
        # Xray can accept these IPv4 peers on a dual-stack AF_INET6 listener.
        args = ['ss', '-Htnp', 'state', 'established', f'( sport = :{port} )']
    else:
        args = ['ss', '-Hltnp', f'( sport = :{port} )']
    return [ln for ln in checked(args).splitlines() if f'pid={proc.pid},' in ln]


@dataclass(frozen=True)
class Probe:
    portal: str
    kind: str
    want: str
    edge: int

    @property
    def name(self):
        return f'{self.portal}/{self.kind}'


def tunnel_tag(link, incoming):
    if link['mode'] == 'reverse':
        prefix = 'rebuild-rp-ingress' if incoming else 'rebuild-rp-egress'
    else:
        prefix = 'fwd-hop' if incoming else 'fwd'
    return f"{prefix}-{link['id'][-8:]}"


def probe(case, ports, origins, links):
    host = GEO if case.kind == 'domain' else VIRTUAL_IP
    args = [] if case.kind != 'sniff' else ['--header', f'Host: {GEO}']
    attempts = []
    access = Path('gateway-main.access.log')
    offset = access.stat().st_size if access.exists() else 0
    ingress = next(link for link in links.values() if link['source'] == case.portal)
    inbound = tunnel_tag(ingress, incoming=True)
    outbound = tunnel_tag(links[case.edge], incoming=False)
    for _ in range(4):
        path = f'/proof-{case.portal}-{case.kind}-{secrets.token_hex(12)}'
        res = cmd(['curl', '-q', '--silent', '--show-error', '--fail', '--max-time', '2',
                   '--noproxy', '', '--socks5-hostname', f'{LO}:{ports[f"socks-{case.portal}"]}', *args,
                   f'http://{host}:{VIRTUAL_PORT}{path}'])
        with origins.lock:
            sinks = [list(row) for row in origins.receipts.get(path, [])]
        attempts.append({'path': path, 'curl_status': res.returncode, 'curl_error': res.stderr, 'sinks': sinks})
        if res.returncode == 0:
            got = next((name for name, marker in origins.marker.items() if marker == res.stdout), None)
            host_header = GEO if case.kind == 'sniff' else f'{host}:{VIRTUAL_PORT}'
            require(got is not None and sinks == [[got, host_header]], f'{case.name}: missing/invalid origin proof: {sinks}')
            # Distinguish two channels to the same backend using the live
            # relay access log, not just the backend's HTTP marker.
            with access.open('rb') as log:
                log.seek(offset)
                routes = [row for row in log.read().decode().splitlines()
                          if f'[{inbound} ' in row and any(f'accepted tcp:{addr}:{VIRTUAL_PORT} ' in row
                                                          for addr in (VIRTUAL_IP, GEO))]
            require(routes and all(row.endswith(f'[{inbound} -> {outbound}]') for row in routes),
                    f'{case.name}: expected relay channel {outbound}, got {routes}')
            return {'case': case.name, 'expected': case.want, 'actual': got, 'egress': outbound, 'attempts': attempts}
        time.sleep(0.2)
    return {'case': case.name, 'expected': case.want, 'actual': None, 'attempts': attempts}


def run(parent_net, mode, preferred, evidence):
    evidence['netns'] = namespace(parent_net)
    evidence['source_sha256'] = source_digests()
    evidence['actors_sha256'] = {bin: digest(bin) for bin in (XRAY, BRIDGE_XRAY, '/tools/cover')}
    vx, vb = version(XRAY), version(BRIDGE_XRAY)
    print(f'CORE: {vx} | bridges: {vb}')
    evidence['versions'] = [vx, vb]
    clients = ['p1', 'p2', 'p3']
    server_labels = clients + ['gateway'] + list(BRIDGES)
    n_links = 7 if preferred else 6
    ports = ports_for(['cover', *clients, 'gateway', *(f'api-{n}' for n in server_labels),
                       *(f'link-{i}' for i in range(n_links)), *(f'socks-{n}' for n in clients),
                       *(f'sink-{n}' for n in BRIDGES)])
    evidence['ports'] = ports
    cert, key = '/work/cover.crt', '/work/cover.key'
    checked(['openssl', 'req', '-config', '/dev/null', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', f'/CN={SNI}',
             '-addext', f'subjectAltName=DNS:{SNI}', '-out', cert, '-keyout', key])
    fixture = dict(ports=ports, version=vx.split()[1], bridgeVersion=vb.split()[1], mode=mode, preferred=preferred,
                   reality=reality_keys(n_links, ports['cover']))
    raw = checked(['node', '/scripts/compose.cjs'], input=json.dumps(fixture))
    Path('composer-output.json').write_text(raw + '\n')
    generated = json.loads(raw)
    evidence['links'] = generated['links']
    configs, run_configs = {}, {}
    for item in generated['profiles']:
        label, profile = item['name'], item['profile']
        key = f'{label}-{profile}'
        require(key not in configs and label in server_labels, f'unexpected composer output {key}')
        live = profile == ('bridge' if label in BRIDGES else 'main')
        configs[key] = fixture_config(item['config'], ports[f'sink-{label}'] if live and label in BRIDGES else None,
                                      key) if live else item['config']
        if live:
            run_configs[label] = key
    require(set(run_configs) == set(server_labels) and len(configs) == 2 * len(server_labels), 'incomplete profile roster')
    configs['subscriber'] = subscriber_config(generated['users'], ports)
    run_configs['subscriber'] = 'subscriber'
    binary = lambda label: BRIDGE_XRAY if label.split('-')[0] in BRIDGES else XRAY
    evidence['config_tests'] = {}
    for key, config in configs.items():
        dump(f'{key}.json', config)
        res = cmd([binary(key), 'run', '-test', '-c', f'{key}.json'])
        Path(f'{key}.test.log').write_text(res.stdout + res.stderr)
        evidence['config_tests'][key] = res.returncode
        require(res.returncode == 0, f'{key}: xray run -test failed; see {key}.test.log')
    print(f'CONFIG OK {len(configs)}/{len(configs)} (all emitted profiles + synthetic subscriber)')

    b = 6 if preferred else 3
    cases = [Probe('p1', 'numeric', 'B', b), Probe('p2', 'numeric', 'B', b),
             Probe('p1', 'domain', 'A', 4), Probe('p2', 'domain', 'B', b),
             Probe('p1', 'sniff', 'A', 4), Probe('p2', 'sniff', 'B', b),
             Probe('p3', 'numeric', 'A', 2), Probe('p3', 'domain', 'A', 4)]
    links = {link['index']: link for link in generated['links']}
    origins = Origins()
    evidence['probes'] = []
    reaped = evidence['reaped'] = {}
    with ExitStack() as stack:
        for label in BRIDGES:
            origins.start(stack, label, ports[f'sink-{label}'])
        cover = start(stack, 'cover', ['/tools/cover', str(ports['cover']), cert, '/work/cover.key'], reaped)
        children = {'cover': cover}
        wait_until('cover listener', children, lambda: sockets(ports['cover'], cover), 4)
        for label in ['gateway', *clients, *BRIDGES, 'subscriber']:
            key = run_configs[label]
            children[label] = start(stack, key, [binary(key), 'run', '-c', f'{key}.json'], reaped)
        listens = [(ln['source'] if ln['mode'] == 'reverse' else ln['target'], ln['port']) for ln in generated['links']]
        listens += [(n, ports[n]) for n in clients] + [('subscriber', ports[f'socks-{n}']) for n in clients]
        wait_until('PID-owned tunnel/portal/SOCKS listeners', children,
                   lambda: all(sockets(port, children[owner]) for owner, port in listens), 6)
        reverse = [ln for ln in generated['links'] if ln['mode'] == 'reverse']
        reverse_owners = {owner: sum(ln['source'] == owner for ln in reverse)
                          for owner in {ln['source'] for ln in reverse}}

        def reverse_ready():
            return all(sockets(ln['port'], children[ln['source']], established=True) for ln in reverse) and all(
                Path(f'{run_configs[owner]}.run.log').read_text().count(
                    'proxy/vless/inbound: received request for tcp:v1.rvs.cool:0') >= count
                for owner, count in reverse_owners.items())

        wait_until('native reverse authentication records and PID-owned TCP sessions on every reverse port',
                   children, reverse_ready, 18)
        evidence['reverse_readiness'] = {'socket_paths': [f"{ln['source']}->{ln['target']}" for ln in reverse],
                                         'minimum_auth_records_per_listener_process': reverse_owners}
        print(f'REVERSE READY {len(reverse)}/{len(reverse)}')
        for case in cases:
            result = probe(case, ports, origins, links)
            evidence['probes'].append(result)
            print(f'{case.name}: HTTP {result["actual"] or "NO MARKER"} (want {case.want})')
        require(all(child.poll() is None for child in children.values()), 'child exited during HTTP probes')
    require(set(reaped) == set(run_configs.values()) | {'cover'} and all(
        r['early_exit'] is None and not r['forced_kill'] and r['status'] in (0, -signal.SIGTERM) for r in reaped.values()),
        f'unexpected child wait/cleanup: {reaped}')
    require(not checked(['ss', '-Hltun']).strip(), 'unexpected listeners left after fixture cleanup')
    print(f'REAPED {len(reaped)} children; no TCP/UDP listeners remain')
    require(evidence['source_sha256'] == source_digests(), 'composer inputs changed during the run')
    rows = evidence['probes']
    if all(row['actual'] == row['expected'] for row in rows):
        print(f'PASS {len(rows)}/{len(cases)} HTTP markers and exact relay channels')
        evidence['result'] = 'PASS'
        return 0
    evidence['result'] = 'ASSERTION_FAILED'
    print('FAIL: HTTP marker matrix differs from expected policy')
    return 1


def stop(signum, _frame):
    raise KeyboardInterrupt(f'signal {signum}')


if __name__ == '__main__':
    os.umask(0o077)
    signal.signal(signal.SIGTERM, stop)
    parent_net, mode, preferred, source = sys.argv[1:]
    evidence = {'source_root': source, 'mode': mode, 'preferred': preferred == 'yes'}
    status = 2
    try:
        status = run(parent_net, mode, preferred == 'yes', evidence)
    except (Exception, KeyboardInterrupt) as exc:
        evidence.update(result='INFRA_ERROR', error=str(exc))
        print(f'ERROR: {exc}', file=sys.stderr)
        if isinstance(exc, sp.CalledProcessError):
            # All subprocess input for this harness is synthetic.
            print(exc.stderr, file=sys.stderr)
        status = 2
    finally:
        if os.getcwd() == '/work':
            dump('result.json', {**evidence, 'status': status})
    sys.exit(status)
