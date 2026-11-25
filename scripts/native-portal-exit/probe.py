#!/usr/bin/env python3
"""Run only through verify-portal-exits.sh, inside its private namespaces."""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import dataclass
from hashlib import file_digest
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_network
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
OTHER_GEO = 'other.invalid'
PPP_IP = '198.51.100.42'  # Documentation-only, never bound or sent outside the fixture.
RU_IP = '198.51.100.43'  # Synthetic RU /32; adjacent PPP_IP is deliberately outside it.
SNI = 'cover.fixture.invalid'
XRAY = '/tools/xray'
RELAY_XRAY = '/tools/relay-xray'
BRIDGE_XRAY = '/tools/bridge-xray'
BRIDGES = ('A', 'B')
PORTALS = ('p1', 'p2', 'p3')
RELAYS = ('gateway', 'tail', 'island')
ROLES = {**dict.fromkeys(PORTALS, 'portal'), **dict.fromkeys(RELAYS, 'relay'),
         **dict.fromkeys(BRIDGES, 'bridge'), 'subscriber': 'subscriber'}
ROLE_BINARIES = {'portal': XRAY, 'subscriber': XRAY, 'relay': RELAY_XRAY, 'bridge': BRIDGE_XRAY}
COMPOSER_INPUTS = ('services/rebuildTopologyComposer.js', 'domain/rebuildTopologyCompiler.js',
                   'domain/rebuildPortalExit.js', 'domain/routePolicy.js', 'services/rebuildTransitChannels.js',
                   'services/l2tpFollowRelay.js', '../../services/configGenerator.js', '../../services/rebuildLinkKeys.js',
                   '../../services/rebuildTunnelTls.js', '../../services/rebuildRealityFingerprint.js',
                   '../../services/rebuildReverseIdentity.js', '../../utils/cascadeTransport.js')


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


def geoip_fixture():
    # Xray's GeoIPList (field 1: GeoIP), GeoIP (1: country_code, 2: CIDR),
    # CIDR (1: packed network address, 2: prefix). All values/lengths here
    # fit in one protobuf varint byte. Do not read any installed geodata.
    def field(number, value):
        return bytes([(number << 3) | 2, len(value)]) + value

    entries = {'PRIVATE': '127.0.0.0/8', 'RU': f'{RU_IP}/32'}
    payload = b''
    for code, cidr in entries.items():
        network = ip_network(cidr)
        subnet = field(1, network.network_address.packed) + bytes([2 << 3, network.prefixlen])
        payload += field(1, field(1, code.encode('ascii')) + field(2, subnet))
    path = Path('/work/assets/geoip.dat')
    with path.open('xb') as stream:
        stream.write(payload)
    return {'file': str(path), 'entries': entries, 'sha256': digest(path)}


def actor(owner, evidence):
    role = ROLES[owner]
    binary = ROLE_BINARIES[role]
    return {'owner': owner, 'role': role, 'binary': binary, 'version': evidence['xray_binaries'][binary],
            'sha256': evidence['actors_sha256'][binary]}


def test_xray(label, owner, config, evidence):
    spec = actor(owner, evidence)
    dump(f'{label}.json', config)
    res = cmd([spec['binary'], 'run', '-test', '-c', f'{label}.json'])
    Path(f'{label}.test.log').write_text(res.stdout + res.stderr)
    evidence['config_tests'][label] = res.returncode
    evidence['config_test_actors'][label] = spec
    require(res.returncode == 0, f'{label}: xray run -test failed; see {label}.test.log')


def start_xray(stack, label, owner, evidence, *, boot=None):
    spec = actor(owner, evidence)
    child = start(stack, label, [spec['binary'], 'run', '-c', f'{boot or label}.json'], evidence['reaped'])
    # Popen returns after exec, so this verifies the actual mounted executable,
    # including when two mounts refer to the same host inode.
    exe = os.readlink(f'/proc/{child.pid}/exe')
    evidence['live_actors'][label] = {**spec, 'pid': child.pid, 'proc_exe': exe}
    require(exe == spec['binary'], f'{label}: unexpected running binary {exe}')
    return child


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
                        f'{OTHER_GEO}:{VIRTUAL_PORT}', f'{VIRTUAL_IP}:{VIRTUAL_PORT}', f'{PPP_IP}:{VIRTUAL_PORT}',
                        f'{RU_IP}:{VIRTUAL_PORT}'):
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
        for selector in ({'domain': [f'full:{GEO}', f'full:{OTHER_GEO}']},
                         {'ip': [f'{addr}/32' for addr in (VIRTUAL_IP, PPP_IP, RU_IP)]})
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


def reap(label, child, reaped):
    if label in reaped:
        return
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


def start(stack, label, argv, reaped):
    with open(f'{label}.run.log', 'w') as log:
        child = sp.Popen(argv, stdin=sp.DEVNULL, stdout=log, stderr=sp.STDOUT)
    stack.callback(reap, label, child, reaped)
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
    want: str | None
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


def probe(case, ports, origins, links, chain=False, matrix=False, staged=False):
    hosts = {'domain': GEO, 'other': OTHER_GEO, 'control': 'panel.fixture.invalid', 'geoip-ru': RU_IP}
    ppp = case.portal in ('ppp', 'ppp-island')
    host = hosts.get(case.kind, PPP_IP if ppp else VIRTUAL_IP)
    args = [] if case.kind != 'sniff' else ['--header', f'Host: {GEO}']
    attempts = []
    checks = []
    if matrix and ppp:
        sock = ports['ppp-island' if case.portal == 'ppp-island' else 'ppp-gateway']
        if case.want is not None:
            middle = links[7]
            checks = [(Path('gateway-main.access.log'), 'rebuild-relay-ingress', tunnel_tag(middle, False)),
                      (Path('tail-main.access.log'), tunnel_tag(middle, True), tunnel_tag(links[case.edge], False))]
    elif matrix and case.portal in ('stage-p1', 'stage-p2'):
        sock = ports[case.portal]
        middle = next(link for link in links.values() if link.get('selectedBy') == case.portal.removeprefix('stage-'))
        checks = [(Path('gateway-main.access.log'), case.portal, tunnel_tag(middle, False)),
                  (Path('tail-main.access.log'), tunnel_tag(middle, True), tunnel_tag(links[case.edge], False))]
    else:
        sock = ports[f'socks-{case.portal}']
        ingress = next(link for link in links.values() if link['source'] == case.portal)
        if matrix:
            middle = next((link for link in links.values() if link.get('selectedBy') == case.portal), None)
            if middle and staged:
                middle = links[7]
        else:
            middle = links[7 if case.portal == 'p1' else 8] if chain and case.portal != 'p3' else None
        if case.want is not None:
            hops = [(ingress, middle), (middle, links[case.edge])] if middle else [(ingress, links[case.edge])]
            checks = [(Path(f"{first['target']}-main.access.log"), tunnel_tag(first, True), tunnel_tag(second, False))
                      for first, second in hops]
    for _ in range(4):
        offsets = [access.stat().st_size if access.exists() else 0 for access, _, _ in checks]
        path = f'/proof-{case.portal}-{case.kind}-{secrets.token_hex(12)}'
        res = cmd(['curl', '-q', '--silent', '--show-error', '--fail', '--max-time', '2',
                   '--noproxy', '', '--socks5-hostname', f'{LO}:{sock}', *args,
                   f'http://{host}:{VIRTUAL_PORT}{path}'])
        with origins.lock:
            sinks = [list(row) for row in origins.receipts.get(path, [])]
        attempts.append({'path': path, 'curl_status': res.returncode, 'curl_error': res.stderr, 'sinks': sinks})
        if case.want is None:
            require(res.returncode in (28, 52, 56) and not sinks, f'{case.name}: expected block, got exit {res.returncode} and {sinks}')
            return {'case': case.name, 'destination': host, 'expected': None, 'actual': None, 'attempts': attempts}
        if res.returncode == 0:
            got = next((name for name, marker in origins.marker.items() if marker == res.stdout), None)
            host_header = GEO if case.kind == 'sniff' else f'{host}:{VIRTUAL_PORT}'
            require(got is not None and sinks == [[got, host_header]], f'{case.name}: missing/invalid origin proof: {sinks}')
            # Distinguish two channels to the same backend using the live
            # relay access log, not just the backend's HTTP marker.
            route_lines = {}
            destinations = (host, GEO) if case.kind == 'sniff' else (host,)
            deadline = time.monotonic() + 1.0
            for (access, inbound, hop_outbound), offset in zip(checks, offsets, strict=True):
                # Origin data can arrive before Xray's async logger flushes.
                # Wait only for the evidence, never replay a successful probe.
                while True:
                    new_rows = []
                    if access.exists():
                        with access.open('rb') as log:
                            log.seek(offset)
                            new_rows = log.read().decode().split('\n')[:-1]
                    routes = [row for row in new_rows
                              if f'[{inbound} ' in row and any(f'accepted tcp:{addr}:{VIRTUAL_PORT} ' in row
                                                              for addr in destinations)]
                    if routes or time.monotonic() >= deadline:
                        break
                    time.sleep(0.02)
                require(routes and all(row.endswith(f'[{inbound} -> {hop_outbound}]') for row in routes),
                        f'{case.name}: {access} expected {inbound} -> {hop_outbound}, got {routes}')
                route_lines[access.name] = routes
            return {'case': case.name, 'destination': host, 'expected': case.want, 'actual': got,
                    'marker': res.stdout, 'exit_edge': case.edge, 'egress': tunnel_tag(links[case.edge], False),
                    'relay_hops': [[p.name, i, o] for p, i, o in checks], 'route_lines': route_lines, 'attempts': attempts}
        time.sleep(0.2)
    return {'case': case.name, 'destination': host, 'expected': case.want, 'actual': None, 'attempts': attempts}


def scoped_proofs(proofs, cert, cover_port, evidence):
    require(len(proofs) == 2 and len({p['listenerPort'] for p in proofs}) == 2,
            'expected two independently allocated channels on one physical link')
    require(len({p['channel']['physicalId'] for p in proofs}) == 1, 'scoped proofs do not share a physical link')
    answers = {}
    receipt_lock = threading.Lock()
    reaped = evidence['reaped']
    results = evidence['scoped_proofs'] = []
    with ExitStack() as stack:
        def handler(channel, key):
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    path = self.path
                    if not path.startswith('/proof-') or len(path) != 39:
                        self.send_error(404)
                        return
                    with receipt_lock:
                        answers.setdefault(path, []).append(channel)
                    result = hmac.digest(key, (channel + path).encode('ascii'), 'sha256').hex().encode('ascii')
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(result)))
                    self.end_headers()
                    self.wfile.write(result)

                def log_message(self, format, *args):
                    pass
            return Handler

        cover = start(stack, 'cover', ['/tools/cover', str(cover_port), cert, '/work/cover.key'], reaped)
        children = {'cover': cover}
        wait_until('cover listener', children, lambda: sockets(cover_port, cover), 4)
        keys = {}
        for proof in proofs:
            channel = proof['channel']['id']
            keys[channel] = secrets.token_bytes(32)
            server = ThreadingHTTPServer((LO, proof['responderPort']), handler(channel, keys[channel]))
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
            thread.start()

            def stop(responder=server, runner=thread):
                responder.shutdown()
                responder.server_close()
                runner.join(timeout=2)
                require(not runner.is_alive(), 'proof responder failed to stop')

            stack.callback(stop)
            for side in ('request', 'response'):
                label = f'{channel}-{side}'
                cfg = {**proof[side], 'log': {'access': f'/work/{label}.access.log', 'loglevel': 'info'}}
                owner = proof['channel']['source' if side == 'request' else 'target']
                test_xray(label, owner, cfg, evidence)
                children[label] = start_xray(stack, label, owner, evidence)

        for proof in proofs:
            channel, mode = proof['channel']['id'], proof['channel']['mode']
            request = children[f'{channel}-request']
            listener = request if mode == 'reverse' else children[f'{channel}-response']
            wait_until('PID-owned exact proof ports', children, lambda: sockets(proof['requestPort'], request)
                       and sockets(proof['listenerPort'], listener), 6)
            if mode == 'reverse':
                wait_until('reverse control and authenticated TCP session', children,
                           lambda: sockets(proof['listenerPort'], listener, established=True)
                           and 'received request for tcp:v1.rvs.cool:0' in Path(f'{channel}-request.run.log').read_text(), 18)

        def perform(proof, expected):
            channel, mode = proof['channel']['id'], proof['channel']['mode']
            request = children[f'{channel}-request']
            require(request.poll() is None and sockets(proof['requestPort'], request), 'no live requester before proof')
            path = '/proof-' + secrets.token_hex(16)
            logs = [Path(f'{channel}-{side}.access.log') for side in ('request', 'response')]
            offsets = [log.stat().st_size if log.exists() else 0 for log in logs]
            response = cmd(['curl', '-q', '--noproxy', '*', '--silent', '--show-error', '--fail',
                            '--max-time', '3', f'http://{LO}:{proof["requestPort"]}{path}'])
            with receipt_lock:
                got = answers.get(path)
            if expected:
                want = hmac.digest(keys[channel], (channel + path).encode('ascii'), 'sha256').hex()
                require(response.returncode == 0 and hmac.compare_digest(response.stdout, want) and got == [channel],
                        f'{mode}: end-to-end proof missing; see private logs')
                suffix = channel[-8:]
                inbound = ('rebuild-rp-ingress-' if mode == 'reverse' else 'fwd-hop-') + suffix
                outbound = ('rebuild-rp-egress-' if mode == 'reverse' else 'fwd-') + suffix
                tags = [('rebuild-proof-request', outbound), (inbound, 'rebuild-proof-response')]
                for log, offset, ends in zip(logs, offsets, tags, strict=True):
                    with log.open('rb') as stream:
                        stream.seek(offset)
                        access = stream.read().decode().splitlines()
                    require(any(f'accepted tcp:{LO}:{proof["responderPort"]} ' in row
                                and row.endswith(f'[{ends[0]} -> {ends[1]}]') for row in access),
                            f'{mode}: expected proof tags not used in {log.name}')
            else:
                require(response.returncode in (28, 52, 56) and got is None, f'{mode}: expected failure through the live requester')
            require(request.poll() is None and sockets(proof['requestPort'], request), 'requester failed during proof')
            results.append({'mode': mode, 'id': channel, 'expected': 'marker' if expected else 'closed', 'verified': True})

        for proof in proofs:
            perform(proof, True)
        # Cut only the response-side process, keeping both local requesters
        # and both responders alive: the other policy must not carry its probe.
        dead = children.pop(f'{proofs[0]["channel"]["id"]}-response')
        dead.terminate()
        require(dead.wait(timeout=3) in (0, -signal.SIGTERM), 'failed to terminate response process')
        perform(proofs[0], False)
        perform(proofs[1], True)
    require(len(reaped) == 5 and all(not result['forced_kill'] and result['status'] in (0, -signal.SIGTERM)
            and (label == f'{proofs[0]["channel"]["id"]}-response' or result['early_exit'] is None)
            for label, result in reaped.items()), 'proof child cleanup incomplete')
    require(not checked(['ss', '-Hltun']).strip(), 'proof left listeners behind')
    require(len(results) == 4 and len(evidence['config_tests']) == 4, 'incomplete scoped wire proof')



def run(parent_net, mode, preferred, evidence, chain=False, proof=False, matrix=False, stage=False):
    evidence['netns'] = namespace(parent_net)
    evidence['source_sha256'] = source_digests()
    if proof:
        evidence['proof_source_sha256'] = digest('/scripts/transit-proof.cjs')
    if stage:
        evidence['switch_source_sha256'] = digest('/scripts/stage-switch.cjs')
        evidence['journal_source_sha256'] = digest('/source/src/services/rebuildTransitCutoverJournal.js')
        evidence['planner_source_sha256'] = digest('/source/src/services/rebuildTransitActivationPlan.js')
    if matrix:
        evidence['geoip_fixture'] = geoip_fixture()
    binaries = (XRAY, RELAY_XRAY, BRIDGE_XRAY)
    evidence['actors_sha256'] = {binary: digest(binary) for binary in (*binaries, '/tools/cover')}
    evidence['xray_binaries'] = {binary: version(binary) for binary in binaries}
    for field in ('config_tests', 'config_test_actors', 'live_actors', 'reaped'):
        evidence[field] = {}
    evidence['api_calls'] = []
    evidence['versions'] = [evidence['xray_binaries'][binary] for binary in (XRAY, BRIDGE_XRAY)]
    for role, binary in ROLE_BINARIES.items():
        print(f'CORE {role}: {binary} | {evidence["xray_binaries"][binary]}')
    relays = RELAYS if matrix else RELAYS[:2] if chain else RELAYS[:1]
    server_labels = [*PORTALS, *relays, *BRIDGES]
    n_links = 9 if chain else 7 if preferred else 6
    ports = ports_for(['cover', *PORTALS, *relays, *(f'api-{n}' for n in server_labels),
                       *(f'link-{i}' for i in range(n_links)), *(f'socks-{n}' for n in PORTALS),
                       *(f'sink-{n}' for n in BRIDGES), *(['ppp-gateway', 'ppp-island'] if matrix else []),
                       *(['stage-p1', 'stage-p2'] if stage else []),
                       *((f'proof-{side}-{i}' for side in ('request', 'origin') for i in range(2)) if proof else ())])
    evidence['ports'] = ports
    cert, key = '/work/cover.crt', '/work/cover.key'
    checked(['openssl', 'req', '-config', '/dev/null', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', f'/CN={SNI}',
             '-addext', f'subjectAltName=DNS:{SNI}', '-out', cert, '-keyout', key])
    versions_by_node = evidence['dialer_versions_by_node'] = {
        name: actor(name, evidence)['version'].split()[1] for name in server_labels}
    fixture = dict(ports=ports, versionsByNode=versions_by_node, mode=mode, preferred=preferred,
                   chain=chain, proof=proof, matrix=matrix, stage=stage,
                   reality=reality_keys(n_links, ports['cover']))
    raw = checked(['node', '/scripts/compose.cjs'], input=json.dumps(fixture))
    Path('composer-output.json').write_text(raw + '\n')
    generated = json.loads(raw)
    evidence['links'] = generated['links']
    evidence['wire_endpoints'] = {}
    for ln in generated['links'] + [item['channel'] for item in generated.get('proofs', [])]:
        listener, dialer = (ln['source'], ln['target']) if ln['mode'] == 'reverse' else (ln['target'], ln['source'])
        evidence['wire_endpoints'][ln['id']] = {'listener': actor(listener, evidence), 'dialer': actor(dialer, evidence)}
    if proof:
        scoped_proofs(generated['proofs'], cert, ports['cover'], evidence)
        require(evidence['source_sha256'] == source_digests()
                and evidence['proof_source_sha256'] == digest('/scripts/transit-proof.cjs'),
                'proof profile sources changed during the run')
        print('PASS 4/4 scoped wire probe receipts (separate fixture processes, not MAIN activation)')
        evidence['result'] = 'PASS'
        return 0
    configs, run_configs, config_owners = {}, {}, {}
    for item in generated['profiles']:
        label, profile = item['name'], item['profile']
        key = f'{label}-{profile}'
        require(key not in configs and label in server_labels, f'unexpected composer output {key}')
        live = profile == ('bridge' if label in BRIDGES else 'main')
        configs[key] = fixture_config(item['config'], ports[f'sink-{label}'] if live and label in BRIDGES else None,
                                      key) if live else item['config']
        config_owners[key] = label
        if live:
            run_configs[label] = key
    require(set(run_configs) == set(server_labels) and len(configs) == 2 * len(server_labels), 'incomplete profile roster')
    configs['subscriber'] = subscriber_config(generated['users'], ports)
    run_configs['subscriber'] = 'subscriber'
    config_owners['subscriber'] = 'subscriber'
    for key, config in configs.items():
        test_xray(key, config_owners[key], config, evidence)
    if matrix:
        # The emitted TPROXY config above is parsed unchanged. At runtime use a
        # loopback SOCKS adapter at its exact tag/port instead of kernel PPP.
        # No routing decisions or local handoff rules are replaced.
        for node, tag in generated['pppTags'].items():
            config = configs[f'{node}-main']
            ppp, = [row for row in config['inbounds'] if row['tag'] == tag]
            port = ports[f'ppp-{node}']
            require(ppp['protocol'] == 'dokodemo-door' and ppp['port'] == port
                    and ppp['settings']['followRedirect'], 'fixture lost the generated TPROXY identity')
            ppp.clear()
            ppp.update(tag=tag, listen=LO, port=port, protocol='socks', settings={'auth': 'noauth'})
            dump(f'{node}-main.json', config)
    scoped_rule_tags = []
    plan = generated['transition']['plan'] if stage else None
    added = [(step['owner'], step['config']['port']) for step in plan['listeners']] if plan is not None else []
    delivery_owner = ''
    delivery_rule_tags = []
    restarts = {}
    if plan is not None:
        transition = generated['transition']
        require([len(plan[key]) for key in ('listeners', 'dialers', 'transit', 'ingress')] == [2, 2, 1, 1],
                'unexpected staged activation plan')
        evidence['main_restarts'] = []
        stock = {item['name']: fixture_config(item['config'], None, f'{item["name"]}-main') for item in transition['before']}
        require(set(stock) == {'gateway', 'tail'}, 'missing stock MAIN')
        for owner, original in stock.items():
            original['api']['services'].append('RoutingService')
            for i, row in enumerate(original['inbounds']):
                if row['tag'] == generated['pppTags'].get(owner):
                    original['inbounds'][i] = next(copy for copy in configs[f'{owner}-main']['inbounds'] if copy['tag'] == row['tag'])
        gateway = stock['gateway']
        switch, = plan['ingress']
        delivery, = plan['transit']
        delivery_owner = delivery['owner']
        delivery_rule_tags = [rule['ruleTag'] for rule in delivery['append']]
        require(switch['owner'] == 'gateway' and delivery['owner'] == 'tail'
                and gateway['routing'] == switch['before'] and stock['tail']['routing'] == delivery['before'],
                'wrong selector preimages')
        desired = switch['after']
        scoped_rule_tags = [rule['ruleTag'] for rule in desired['rules'] if rule.get('ruleTag', '').startswith('rebuild-policy-portal-')]
        require(len(set(scoped_rule_tags)) == len(scoped_rule_tags) == 2, 'fixture needs exactly two scoped ingress selectors')
        probes = []
        for ln in generated['links']:
            if 'selectedBy' not in ln:
                continue
            tag = f'stage-{ln["selectedBy"]}'
            gateway['inbounds'].append({'tag': tag, 'listen': LO, 'port': ports[tag], 'protocol': 'socks'})
            probes.append({'type': 'field', 'ruleTag': tag, 'inboundTag': [tag], 'outboundTag': tunnel_tag(ln, False)})
        require(len(probes) == 2, 'missing staged probe inputs')
        gateway['routing'] = {**switch['before'], 'rules': [*probes, *switch['before']['rules']]}
        for owner, original in stock.items():
            dump(f'{owner}-main.json', original)
        for phase in ('preparation', 'portals'):
            for op in plan[phase]:
                owner = op['owner']
                key = run_configs[owner]
                require(owner not in restarts, 'duplicate restart owner')
                old = stock.get(owner, fixture_config(op['before'], None, key))
                new = deepcopy(old)
                for tag in op['tags']:
                    have, = [row for row in new['inbounds'] if row['tag'] == tag]
                    was, = [row for row in op['before']['inbounds'] if row['tag'] == tag]
                    want, = [row for row in op['after']['inbounds'] if row['tag'] == tag]
                    require(have == was, 'restart input is not the stock inbound')
                    have['sniffing']['routeOnly'] = want['sniffing']['routeOnly']
                    require(have == want, 'restart changed more than its allowed sniffing flag')
                restarts[owner] = {direction: f'{key}-boot-{direction}' for direction in ('before', 'after')}
                test_xray(restarts[owner]['before'], owner, old, evidence)
                test_xray(restarts[owner]['after'], owner, new, evidence)
                dump(f'{key}.json', old)
        dump('staged-routes.json', {'routing': gateway['routing']})
        dump('desired-routes.json', {'routing': desired})
        dump('delivery-before.json', {'routing': delivery['before']})
        dump('delivery-append.json', {'routing': {**delivery['before'], 'rules': delivery['append']}})
        dump('delivery-appended.json', {'routing': {**delivery['before'], 'rules': [*delivery['before']['rules'], *delivery['append']]}})
        for phase, field in (('listeners', 'inbounds'), ('dialers', 'outbounds')):
            for step in plan[phase]:
                dump(f'{phase}-{step["channelId"]}.json', {field: [step['config']]})
    config_count = len(configs) + 2 * len(restarts)
    print(f'CONFIG OK {len(evidence["config_tests"])}/{config_count} (including fixture boot candidates)')

    b = 6 if preferred else 3
    cases = [Probe('p1', 'numeric', 'B', b), Probe('p2', 'numeric', 'B', b),
             Probe('p1', 'domain', 'A', 4), Probe('p2', 'domain', 'B', b),
             Probe('p1', 'sniff', 'A', 4), Probe('p2', 'sniff', 'B', b),
             Probe('p3', 'numeric', 'A', 2), Probe('p3', 'domain', 'A', 4)]
    if matrix:
        cases = [Probe('p1', 'numeric', 'B', 3), Probe('p1', 'geoip-ru', 'A', 4),
                 Probe('p1', 'domain', 'A', 4), Probe('p1', 'sniff', 'A', 4),
                 Probe('p2', 'numeric', 'A', 2), Probe('p2', 'geoip-ru', 'A', 2),
                 Probe('p2', 'other', 'A', 2), Probe('p2', 'sniff', 'A', 2),
                 Probe('p3', 'numeric', 'A', 2), Probe('p3', 'other', 'B', 6),
                 Probe('ppp', 'numeric', 'A', 2), Probe('ppp', 'other', 'B', 6), Probe('ppp', 'control', None, 0),
                 Probe('ppp-island', 'numeric', None, 0)]
    elif chain:
        cases = [Probe(case.portal, case.kind, 'A', 2) if case.portal == 'p2' else case for case in cases]
    links = {link['index']: link for link in generated['links']}
    origins = Origins()
    evidence['probes'] = []
    expected_count = len(cases) + (5 if matrix else 0) + (13 if stage else 0)
    xray_count = len(run_configs) + 3 * len(restarts)
    evidence['expected_counts'] = {'config_tests': config_count, 'http_probes': expected_count,
                                   'live_xray': xray_count, 'children': xray_count + 1}
    reaped = evidence['reaped']
    with ExitStack() as stack:
        for label in BRIDGES:
            origins.start(stack, label, ports[f'sink-{label}'])
        cover = start(stack, 'cover', ['/tools/cover', str(ports['cover']), cert, '/work/cover.key'], reaped)
        children = {'cover': cover}
        wait_until('cover listener', children, lambda: sockets(ports['cover'], cover), 4)
        for label in [*relays, *PORTALS, *BRIDGES, 'subscriber']:
            children[label] = start_xray(stack, run_configs[label], label, evidence)
        active_runs = dict(run_configs)
        initial_links = [ln for ln in generated['links'] if not stage or 'selectedBy' not in ln]
        scoped_links = [ln for ln in generated['links'] if stage and 'selectedBy' in ln]
        listens = [(ln['source'] if ln['mode'] == 'reverse' else ln['target'], ln['port']) for ln in initial_links]
        listens += [(n, ports[n]) for n in PORTALS] + [('subscriber', ports[f'socks-{n}']) for n in PORTALS]
        if matrix:
            listens += [(node, ports[f'ppp-{node}']) for node in generated['pppTags']]
        if stage:
            listens += [('gateway', ports[tag]) for tag in ('stage-p1', 'stage-p2')]
        wait_until('PID-owned tunnel/portal/SOCKS listeners', children,
                   lambda: all(sockets(port, children[owner]) for owner, port in listens), 6)
        reverse = [ln for ln in initial_links if ln['mode'] == 'reverse']
        reverse_owners = {owner: sum(ln['source'] == owner for ln in reverse)
                          for owner in {ln['source'] for ln in reverse}}

        def reverse_ready():
            return all(sockets(ln['port'], children[ln['source']], established=True) for ln in reverse) and all(
                Path(f'{active_runs[owner]}.run.log').read_text().count(
                    'proxy/vless/inbound: received request for tcp:v1.rvs.cool:0') >= count
                for owner, count in reverse_owners.items())

        wait_until('native reverse authentication records and PID-owned TCP sessions on every reverse port',
                   children, reverse_ready, 18)
        evidence['reverse_readiness'] = {'socket_paths': [f"{ln['source']}->{ln['target']}" for ln in reverse],
                                         'minimum_auth_records_per_listener_process': reverse_owners}
        print(f'REVERSE READY {len(reverse)}/{len(reverse)}')

        def api_actor(owner, operation):
            spec = evidence['live_actors'][active_runs[owner]]
            port = ports[f'api-{owner}']
            require(sockets(port, children[owner]), f'{operation}: API socket not owned by {owner}')
            return {**spec, 'operation': operation, 'port': port}

        def api(owner, operation, *args):
            spec = api_actor(owner, operation)
            result = cmd([spec['binary'], 'api', operation, f'--server={LO}:{spec["port"]}', *args])
            evidence['api_calls'].append({**spec, 'status': result.returncode})
            result.check_returncode()
            return result.stdout

        def verify_live_rules(owner, filename):
            expected = json.loads(Path(filename).read_text())['routing']['rules']
            live = json.loads(api(owner, 'lsrules'))['rules']
            # The API reports ordered tags and actions, not the predicates.
            require([(r.get('ruleTag', ''), r.get('tag', '')) for r in live]
                    == [(r.get('ruleTag', ''), r.get('outboundTag', '')) for r in expected],
                    f'{owner}: live rule order or outbound differs from {filename}')

        def drain_fixture_sessions(owner, port):
            # Only in this private fixture namespace, on the scoped port.
            if sockets(port, children[owner], established=True):
                result = cmd(['ss', '-Ktn', 'state', 'established', f'( sport = :{port} )'])
                require(result.returncode == 0 and not result.stderr, 'fixture could not close the exact TCP sessions')
            wait_until('scoped sessions drained', children,
                       lambda: not sockets(port, children[owner], established=True), 6)

        def verify_case(case, staged=False):
            result = probe(case, ports, origins, links, chain, matrix, staged=staged)
            evidence['probes'].append(result)
            print(f'{case.name}: HTTP {result["actual"] or "NO MARKER"} (want {case.want})'
                  + (f' via {result["egress"]}' if 'egress' in result else ''))
            require(result['actual'] == case.want, f'{case.name}: wrong origin')

        def restart_mains(steps, direction, expected_listens):
            ordered = reversed(steps) if direction == 'before' else steps
            for operation in ordered:
                owner = operation['owner']
                previous = 'before' if direction == 'after' else 'after'
                boot = Path(f'{run_configs[owner]}.json')
                expected = Path(f'{restarts[owner][previous]}.json').read_bytes()
                candidate = Path(f'{restarts[owner][direction]}.json').read_bytes()
                require(boot.read_bytes() == expected and candidate != expected, 'MAIN boot preimage changed')
                stage_file = boot.with_suffix('.next')
                with stage_file.open('xb') as stream:
                    stream.write(candidate)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(stage_file, boot)
                directory = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                require(boot.read_bytes() == candidate, 'published MAIN boot bytes differ')
                retained = {node: proc for node, proc in children.items() if node != owner}
                old = children[owner]
                reap(active_runs[owner], old, reaped)
                label = f'{run_configs[owner]}-start-{len(evidence["main_restarts"])}'
                children[owner] = start_xray(stack, label, owner, evidence, boot=run_configs[owner])
                active_runs[owner] = label
                wait_until('restarted MAIN owns listeners', children, lambda: all(
                    sockets(port, children[node]) for node, port in expected_listens), 6)
                wait_until('original reverse paths reestablished', children, reverse_ready, 18)
                require(children[owner].pid != old.pid and all(children[node] is proc and proc.poll() is None
                        for node, proc in retained.items()) and boot.read_bytes() == candidate, 'MAIN restart generation mismatch')
                evidence['main_restarts'].append({'owner': owner, 'previous_pid': old.pid,
                    'current_pid': children[owner].pid, 'direction': direction, 'boot_sha256': digest(boot)})

        def stage_channels(steps, verify_baseline):
            require(all(not sockets(port, children[owner]) and not sockets(port, children[owner], established=True)
                        for owner, port in added), 'scoped listeners or old sessions already present')
            for step in steps['listeners']:
                api(step['owner'], 'adi', f'listeners-{step["channelId"]}.json')
            wait_until('new listeners before any dialer is installed', children,
                       lambda: all(sockets(port, children[owner]) for owner, port in added), 6)
            require(all(not sockets(port, children[owner], established=True) for owner, port in added),
                    'new channel has a session before its dialer is installed')
            for step in steps['dialers']:
                api(step['owner'], 'ado', f'dialers-{step["channelId"]}.json')
            api(delivery_owner, 'adrules', '-append', 'delivery-append.json')
            verify_live_rules(delivery_owner, 'delivery-appended.json')
            wait_until('staged reverse control sockets', children, lambda: all(
                sockets(ln['port'], children[ln['source']], established=True)
                for ln in scoped_links if ln['mode'] == 'reverse'), 18)
            if verify_baseline:
                verify_case(Probe('p1', 'numeric', 'A', 2), staged=True)
                verify_case(Probe('p2', 'other', 'B', 6), staged=True)
            verify_case(Probe('stage-p1', 'numeric', 'B', 3), staged=True)
            verify_case(Probe('stage-p2', 'other', 'A', 2), staged=True)

        if plan is not None:
            verify_case(Probe('p1', 'numeric', 'A', 2), staged=True)
            verify_case(Probe('p2', 'other', 'B', 6), staged=True)
            restart_mains(plan['preparation'], 'after', listens)
            # Install listeners first into the original processes, then dialers
            # and the downstream policy. Subscriber selectors are still old.
            stage_channels(plan, True)
            api('gateway', 'adrules', 'desired-routes.json')
            verify_live_rules('gateway', 'desired-routes.json')
            restart_mains(plan['portals'], 'after', [*listens, *added])
            wait_until('original staged process and all listeners retained', children,
                       lambda: all(sockets(port, children[owner]) for owner, port in [*listens, *added]), 4)
        for case in cases:
            verify_case(case)
        if plan is not None:
            restart_mains(plan['portals'], 'before', [*listens, *added])
            api('gateway', 'adrules', 'staged-routes.json')
            verify_live_rules('gateway', 'staged-routes.json')
            api(delivery_owner, 'rmrules', *reversed(delivery_rule_tags))
            verify_live_rules(delivery_owner, 'delivery-before.json')
            for step in reversed(plan['dialers']):
                api(step['owner'], 'rmo', step['tag'])
            for step in reversed(plan['listeners']):
                api(step['owner'], 'rmi', step['tag'])
            wait_until('new listeners absent after inverse plan', children,
                       lambda: all(not sockets(port, children[owner]) for owner, port in added)
                       and all(sockets(port, children[owner]) for owner, port in listens), 6)
            for step in plan['dialers']:
                require(f'"{step["tag"]}"' not in api(step['owner'], 'lso'), 'dialer remained after inverse plan')
            for owner, port in added:
                drain_fixture_sessions(owner, port)
            restart_mains(plan['preparation'], 'before', listens)
            verify_case(Probe('p1', 'numeric', 'A', 2), staged=True)
            verify_case(Probe('p2', 'other', 'B', 6), staged=True)
            # A separate explicit fixture operation after confirmed rollback.
            restart_mains(plan['preparation'], 'after', listens)
            stage_channels(plan, False)
            api('gateway', 'adrules', 'desired-routes.json')
            restart_mains(plan['portals'], 'after', [*listens, *added])
            verify_case(Probe('p1', 'numeric', 'B', 3))
            listens.extend(added)
        if matrix:
            # Remove one incoming listener in the actual, still-running MAIN.
            # Do not remove its route or damage the neighboring/shared policy.
            cut, = [ln for ln in links.values() if ln.get('selectedBy') == 'p1']
            owner = cut['source'] if cut['mode'] == 'reverse' else cut['target']
            tag = ('rebuild-rp-conn-' if cut['mode'] == 'reverse' else 'fwd-hop-') + cut['id'][-8:]
            previous, = [row for row in configs[run_configs[owner]]['inbounds'] if row['tag'] == tag]
            require(previous['port'] == cut['port'], 'wrong original channel listener')
            dump('cut-preimage.json', {'inbounds': [previous]})
            reply = api(owner, 'rmi', tag)
            wait_until('cut listener absent, peer listeners retained', children,
                       lambda: not sockets(cut['port'], children[owner]) and all(
                           sockets(port, children[node]) for node, port in listens if port != cut['port']), 4)
            if cut['mode'] == 'reverse':
                # Unbinding a reverse connector alone does not close its
                # established workers. Cut only this tuple in our private netns.
                drain_fixture_sessions(owner, cut['port'])
            evidence['cut'] = {'id': cut['id'], 'owner': owner, 'mode': cut['mode'], 'tag': tag, 'api': reply.strip()}
            verify_case(Probe('p1', 'cut', None, 0))
            verify_case(Probe('p2', 'numeric', 'A', 2))
            verify_case(Probe('ppp', 'other', 'B', 6))
            api(owner, 'adi', 'cut-preimage.json')
            wait_until('restored listener in the original process', children,
                       lambda: sockets(cut['port'], children[owner]) and (
                           cut['mode'] != 'reverse' or sockets(cut['port'], children[owner], established=True)), 18)
            verify_case(Probe('p1', 'domain', 'A', 4))
            verify_case(Probe('p1', 'numeric', 'B', 3))
        if stage:
            # A fresh writer dies after a real routing update. The observer
            # must read the live result and leave the unacknowledged intent;
            # it has no permission to send that write a second time.
            api('gateway', 'adrules', 'staged-routes.json')
            verify_case(Probe('p1', 'numeric', 'A', 2), staged=True)
            before = api('gateway', 'lsrules')
            spec = api_actor('gateway', 'adrules (lost reply)')
            writer_argv = ['node', '/scripts/stage-switch.cjs']
            pinned = [str(spec['port']), str(spec['pid']), parent_net, spec['binary']]
            writer = cmd([*writer_argv, 'lost', *pinned])
            evidence['api_calls'].append({**spec, 'writer_status': writer.returncode})
            require(writer.returncode == -signal.SIGKILL and not writer.stdout and not writer.stderr,
                    'expected lost reply after real switch')
            record, = Path('selector-journal').glob('cutover-*.jsonl')
            original = record.read_bytes()
            events = [json.loads(row)['event'] for row in original.splitlines()]
            require([row['type'] for row in events] == ['start', 'proved', 'intent'], 'unexpected durable events')
            observer = cmd([*writer_argv, 'observe', *pinned])
            require(observer.returncode == 0 and not observer.stderr, 'fresh journal observer refused')
            outcome = json.loads(observer.stdout)
            require(outcome == {'observation': 'after', 'retryAllowed': False, 'pending': 'switch_ingress',
                                'acknowledged': False, 'head': json.loads(original.splitlines()[-1])['sha256']},
                    'unknown cutover was not observed as desired without replay')
            after = api('gateway', 'lsrules')
            require(before != after and all(tag not in before and tag in after for tag in scoped_rule_tags), 'live rule readback did not change')
            verify_case(Probe('p1', 'numeric', 'B', 3))
            require(record.read_bytes() == original, 'read-only reconciliation changed journal bytes')
            evidence['lost_reply'] = {**outcome, 'writer_status': writer.returncode}
        require(all(child.poll() is None for child in children.values()), 'child exited during HTTP probes')
    require(len(evidence['live_actors']) == xray_count and set(reaped) == set(evidence['live_actors']) | {'cover'} and all(
        r['early_exit'] is None and not r['forced_kill'] and r['status'] in (0, -signal.SIGTERM) for r in reaped.values()),
        f'unexpected child wait/cleanup: {reaped}')
    require(not checked(['ss', '-Hltun']).strip(), 'unexpected listeners left after fixture cleanup')
    print(f'REAPED {len(reaped)} children; no TCP/UDP listeners remain')
    require(evidence['source_sha256'] == source_digests(), 'composer inputs changed during the run')
    if stage:
        require(evidence['switch_source_sha256'] == digest('/scripts/stage-switch.cjs'), 'stage writer changed during the run')
        require(evidence['journal_source_sha256'] == digest('/source/src/services/rebuildTransitCutoverJournal.js'),
                'cutover journal changed during the run')
        require(evidence['planner_source_sha256'] == digest('/source/src/services/rebuildTransitActivationPlan.js'), 'planner changed during the run')
    rows = evidence['probes']
    if len(rows) == expected_count and all(row['actual'] == row['expected'] for row in rows):
        print(f'PASS {len(rows)}/{len(rows)} HTTP marker/block checks and exact relay channels')
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
    parent_net, mode, preferred, source, chain = sys.argv[1:]
    evidence = {'source_root': source, 'mode': mode, 'preferred': preferred == 'yes', 'chain_probe': chain == 'yes',
                'scoped_proof': chain == 'proof', 'scoped_matrix': chain == 'matrix', 'staged_matrix': chain == 'stage'}
    status = 2
    try:
        status = run(parent_net, mode, preferred == 'yes', evidence, chain != 'no',
                     chain == 'proof', chain in ('matrix', 'stage'), chain == 'stage')
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
