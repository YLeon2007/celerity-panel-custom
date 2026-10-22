#!/usr/bin/python3 -I
"""Fixed TEST private point-to-point construction. Never an acceptance/GO producer.

No Docker writes, bridge/IPAM allocation, host routes, NAT or public-address ARP.
The only endpoint mutations are newly owned veths plus one private Caddy table/rule.
CLI entry is separate; injected seams below are for unprivileged tests only.
"""
import ctypes
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import time

CONTEXT = 'test.infograd.online'
TEST_MACHINE = '7fa266f995fe4aa69e96cf7d01359e34'
NETNS = '/run/netns/c3-test-fresh-classic'
INPUT = '/etc/c3-test-fresh-network.json'
LEASE = '/etc/c3-test-fresh-network-lease.json'
STATE = '/var/lib/c3-test-fresh-network'
SOCKET = '/run/c3-test-fresh-network.sock'
LIB = '/usr/local/libexec/c3-test-fresh-network.py'
IP = '/usr/sbin/ip'
NFT = '/usr/sbin/nft'
DOCKER = '/run/docker.sock'
PUBLIC = '212.119.42.100'
READY = b'c3-classic-ready-v1\n'
ROLES = ('caddy', 'mongo', 'redis')
PORTS = {'mongo': 27017, 'redis': 6379}
NAMES = {'caddy': ('c3nc', 'c3pc'), 'mongo': ('c3nm', 'c3pm'), 'redis': ('c3nr', 'c3pr')}
TABLE = '39303'
PRIORITY = '10303'
LIMIT = 1024 * 1024
CLONE_NEWNET = 0x40000000


class Refusal(RuntimeError):
    pass


def need(ok, code):
    if not ok:
        raise Refusal(code)


def held_dispatch_required(*args):
    raise Refusal('HELD_DISPATCH_REQUIRED')


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'DUPLICATE_KEY')
            out[key] = value
        return out
    try:
        need(len(raw) <= LIMIT, 'FRAME_TOO_LARGE')
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: need(False, 'NONFINITE_JSON'))
    except (ValueError, UnicodeError):
        raise Refusal('INVALID_JSON') from None


def keys(value, expected):
    need(type(value) is dict and set(value) == set(expected.split()), 'CLOSED_SCHEMA_REQUIRED')


def pin(value):
    need(type(value) is str and re.fullmatch('[a-f0-9]{64}', value), 'DIGEST_REQUIRED')


def integer(value):
    need(type(value) is int and value > 0, 'POSITIVE_INTEGER_REQUIRED')


def identity(path):
    s = os.stat(path)
    return [s.st_dev, s.st_ino]


def proc_start(pid):
    raw = Path('/proc', str(pid), 'stat').read_text()
    return raw[raw.rindex(')')+2:].split()[19]


def trusted_fd(path, directory=False):
    need(str(Path(path)) == path and path.startswith('/') and '..' not in Path(path).parts,
         'CANONICAL_ROOT_PATH_REQUIRED')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = Path(path).parts[1:]
        for i, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if directory or i < len(parts)-1:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            s = os.fstat(fd)
            need(s.st_uid == s.st_gid == 0 and not s.st_mode & 0o022 and not os.listxattr(fd),
                 'UNTRUSTED_ROOT_PATH')
        return fd
    except BaseException:
        os.close(fd)
        raise


def trusted_read(path):
    fd = trusted_fd(path)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= LIMIT,
             'TRUSTED_REGULAR_FILE_REQUIRED')
        raw = os.read(fd, LIMIT+1)
        after = os.fstat(fd)
        need(before == after and len(raw) <= LIMIT, 'INPUT_DRIFT')
        return raw
    finally:
        os.close(fd)


def validate_plan(p):
    keys(p, 'version context machine boot hostNetns generation deadline daemon peers executables hostsSha256 oldConfig newConfig')
    need(type(p['version']) is int and p['version'] == 1 and p['context'] == CONTEXT,
         'FIXED_TEST_ONLY')
    need(p['machine'] == TEST_MACHINE and type(p['boot']) is str and
         re.fullmatch('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', p['boot']), 'FIXED_TEST_MACHINE_BOOT_REQUIRED')
    need(type(p['generation']) is str and re.fullmatch('[a-f0-9]{32}', p['generation']), 'GENERATION_REQUIRED')
    integer(p['deadline'])
    need(type(p['hostNetns']) is list and len(p['hostNetns']) == 2, 'HOST_NS_REQUIRED')
    for n in p['hostNetns']:
        integer(n)
    keys(p['daemon'], 'socket id root')
    need(type(p['daemon']['socket']) is list and len(p['daemon']['socket']) == 2 and
         all(type(x) is int and x > 0 for x in p['daemon']['socket']) and
         type(p['daemon']['id']) is str and p['daemon']['id'] and
         type(p['daemon']['root']) is str and p['daemon']['root'].startswith('/'), 'DAEMON_PINS_REQUIRED')
    need(type(p['executables']) is dict and set(p['executables']) == {IP, NFT}, 'FIXED_EXECUTABLES_REQUIRED')
    for x in p['executables'].values():
        pin(x)
    pin(p['hostsSha256'])
    keys(p['peers'], 'caddy mongo redis')
    networks = []
    containers = set()
    for role in ROLES:
        peer = p['peers'][role]
        keys(peer, 'id inspectSha256 subnet address')
        pin(peer['id']); pin(peer['inspectSha256'])
        need(peer['id'] not in containers, 'DISTINCT_CONTAINERS_REQUIRED')
        containers.add(peer['id'])
        try:
            net = ipaddress.IPv4Network(peer['subnet'], strict=True)
            address = ipaddress.IPv4Address(peer['address'])
        except (ValueError, TypeError):
            raise Refusal('INVALID_IP_INPUT') from None
        private = any(net.subnet_of(ipaddress.IPv4Network(x)) for x in
                      ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
        need(net.prefixlen == 30 and private and str(net) == peer['subnet'] and
             str(address) == peer['address'] and address != ipaddress.IPv4Address(PUBLIC), 'PRIVATE_P2P_REQUIRED')
        need(not any(net.overlaps(x) for x in networks), 'P2P_OVERLAP')
        networks.append(net)
    # Full independently accepted config bytes, never a URL/command selected by a request.
    old = encode(p['oldConfig']); new = encode(p['newConfig'])
    need(old != new and len(old) <= LIMIT and len(new) <= LIMIT, 'DISTINCT_CONFIGS_REQUIRED')
    transformed = json.loads(old)
    count = [0]
    def visit(value):
        if type(value) is dict:
            if value.get('handler') == 'reverse_proxy':
                upstreams = value.get('upstreams')
                if type(upstreams) is list:
                    for upstream in upstreams:
                        if type(upstream) is dict and upstream.get('dial') == 'backend:3000':
                            upstream['dial'] = PUBLIC+':3000'
                            count[0] += 1
            for child in value.values():
                visit(child)
        elif type(value) is list:
            for child in value:
                visit(child)
    visit(transformed)
    need(count == [1] and encode(transformed) == new, 'EXACT_ONE_CADDY_UPSTREAM_CHANGE_REQUIRED')
    return p


def link_commands(role, subnet, generation):
    """Host-side creation only, while still down. No replace, flush or adoption."""
    own, peer = NAMES[role]
    return [('link', 'add', own, 'type', 'veth', 'peer', 'name', peer),
            ('link', 'set', own, 'alias', 'c3:'+generation+':'+role+':fresh'),
            ('link', 'set', peer, 'alias', 'c3:'+generation+':'+role+':peer')]


def addresses(p, role):
    net = ipaddress.IPv4Network(p['peers'][role]['subnet'])
    return str(net.network_address+1), str(net.network_address+2)


def nft_policy(p):
    caddy_fresh, caddy_peer = addresses(p, 'caddy')
    lines = ['table inet c3fresh {',
             'chain input { type filter hook input priority 0; policy drop;',
             'iifname "lo" accept', 'ct state established,related accept',
             f'iifname "c3nc" ip saddr {caddy_peer} ip daddr {PUBLIC} tcp dport 3000 accept', '}',
             'chain forward { type filter hook forward priority 0; policy drop; }',
             'chain output { type filter hook output priority 0; policy drop;',
             'oifname "lo" accept', 'ct state established,related accept']
    for role in ('mongo', 'redis'):
        lines.append(f'oifname "{NAMES[role][0]}" ip daddr {p["peers"][role]["address"]} tcp dport {PORTS[role]} accept')
    return ('\n'.join(lines+['}', '}'])+'\n').encode()


def move_message(index, namespace_fd, sequence):
    integer(index); integer(namespace_fd); integer(sequence)
    payload = struct.pack('BBHiII', 0, 0, 0, index, 0, 0) + struct.pack('HHi', 8, 28, namespace_fd)
    return struct.pack('IHHII', 16+len(payload), 16, 5, sequence, 0)+payload


def parse_move_ack(reply, sender, raw):
    need(type(sender) is tuple and len(sender) == 2 and sender == (0, 0) and
         len(reply) >= 36, 'NETLINK_KERNEL_ACK_REQUIRED')
    length, kind, flags, seq, pid = struct.unpack_from('IHHII', reply)
    expected_seq = struct.unpack_from('I', raw, 8)[0]
    # No extended-ACK options were enabled: success carries only nlmsgerr+echoed header.
    need(length == len(reply) == 36 and flags in (0, 0x100) and kind == 2 and seq == expected_seq and
         reply[20:36] == raw[:16] and struct.unpack_from('i', reply, 16)[0] == 0,
         'VETH_MOVE_UNKNOWN')
    return True


def move_link(index, namespace_fd, before_send=lambda: None):
    raw = move_message(index, namespace_fd, 1)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.settimeout(3)
        channel.bind((0, 0))
        before_send()
        need(channel.sendto(raw, (0, 0)) == len(raw), 'VETH_MOVE_UNKNOWN')
        reply, sender = channel.recvfrom(65536)
        return parse_move_ack(reply, sender, raw)


def require_listener(pid, ip, port):
    before = proc_start(pid)
    owned = set()
    for fd in Path('/proc', str(pid), 'fd').iterdir():
        try:
            link = os.readlink(fd)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r'socket:\[([0-9]+)\]', link)
        if match:
            owned.add(match[1])
    endpoint = socket.inet_aton(ip)[::-1].hex().upper()+f':{port:04X}'
    rows = [x.split() for x in Path('/proc', str(pid), 'net/tcp').read_text().splitlines()[1:]]
    listeners = {x[9] for x in rows if x[1] == endpoint and x[3] == '0A'}
    need(len(owned & listeners) == 1 and proc_start(pid) == before, 'EXACT_TARGET_LISTENER_REQUIRED')


def bound_probe(pid, expected_start, ip=PUBLIC, port=3000):
    """Actual keepalive tuple intersects the independently pinned PID's socket FDs."""
    need(proc_start(pid) == expected_start, 'SERVING_PID_REUSED')
    def endpoint(address, number):
        return socket.inet_aton(address)[::-1].hex().upper()+f':{number:04X}'
    def owned():
        result = set()
        for fd in Path('/proc', str(pid), 'fd').iterdir():
            try:
                link = os.readlink(fd)
            except FileNotFoundError:
                continue
            match = re.fullmatch(r'socket:\[([0-9]+)\]', link)
            if match:
                result.add(match[1])
        return result
    def rows():
        return [x.split() for x in Path('/proc', str(pid), 'net/tcp').read_text().splitlines()[1:]]
    listeners = {r[9] for r in rows() if r[1] == endpoint(ip, port) and r[3] == '0A'}
    need(len(listeners & owned()) == 1, 'EXACT_SERVING_LISTENER_REQUIRED')
    conn = http.client.HTTPConnection(ip, port, timeout=2)
    try:
        conn.request('GET', '/classic-ready', headers={'Connection': 'keep-alive'})
        reply = conn.getresponse(); body = reply.read(65537)
        need(reply.status == 200 and body == READY and conn.sock is not None, 'ACTUAL_KEEPALIVE_READINESS_REQUIRED')
        client_ip, client_port = conn.sock.getsockname()
        tuples = {r[9] for r in rows() if r[1] == endpoint(ip, port) and
                  r[2] == endpoint(client_ip, client_port) and r[3] == '01'}
        need(len(tuples & owned()) == 1 and proc_start(pid) == expected_start,
             'READINESS_NOT_BOUND_TO_PINNED_PID')
        return {'pid': pid, 'start': expected_start, 'bodySha256': digest(body)}
    finally:
        conn.close()


def docker_backend_addresses():
    """Ask Docker's namespace-local embedded DNS, not the host resolv.conf."""
    token = os.urandom(2)
    question = b'\x07backend\x00\x00\x01\x00\x01'
    query = token+struct.pack('!HHHHH', 0x0100, 1, 0, 0, 0)+question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.settimeout(2)
        channel.connect(('127.0.0.11', 53))
        channel.send(query)
        raw = channel.recv(4096)
    return parse_backend_dns(raw, token)


def parse_backend_dns(raw, token):
    need(len(raw) >= 12 and raw[:2] == token, 'DOCKER_DNS_REPLY_REFUSED')
    flags, questions, answers, authority, additional = struct.unpack_from('!HHHHH', raw, 2)
    need(flags & 0x8000 and not flags & 0x020f and questions == 1 and 0 < answers <= 16 and
         authority == additional == 0, 'DOCKER_DNS_REPLY_REFUSED')
    question = b'\x07backend\x00\x00\x01\x00\x01'
    need(raw[12:12+len(question)] == question, 'DOCKER_DNS_QUESTION_DRIFT')
    offset = 12+len(question)
    addresses_ = set()
    for _ in range(answers):
        # Docker's direct A answer must own this exact question name. CNAME or
        # unexpected formats refuse instead of falling back to host DNS.
        if raw[offset:offset+2] == b'\xc0\x0c':
            offset += 2
        else:
            need(raw[offset:offset+9] == b'\x07backend\x00', 'DOCKER_DNS_OWNER_DRIFT')
            offset += 9
        need(len(raw) >= offset+14, 'TRUNCATED_DOCKER_DNS')
        kind, klass, ttl, length = struct.unpack_from('!HHIH', raw, offset)
        offset += 10
        need(kind == klass == 1 and length == 4, 'DOCKER_DNS_A_ONLY')
        addresses_.add(socket.inet_ntoa(raw[offset:offset+4])); offset += 4
    need(offset == len(raw), 'DOCKER_DNS_TRAILING_BYTES')
    return sorted(addresses_)


def syscall(name, *args):
    libc = ctypes.CDLL(None, use_errno=True)
    result = getattr(libc, name)(*args)
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, name)


def in_namespace(fd, fn, timeout=8):
    """One bounded fork, held namespace FD, never PID-selected command execution."""
    readfd, writefd = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        os.close(readfd)
        try:
            syscall('setns', fd, CLONE_NEWNET)
            raw = encode({'ok': True, 'value': fn()})
        except BaseException:
            raw = encode({'ok': False})
        try:
            # Parent drains while child writes; fixed maximum avoids pipe deadlock.
            view = memoryview(raw)
            while view:
                view = view[os.write(writefd, view):]
        finally:
            os._exit(0)
    os.close(writefd)
    raw = b''
    end = time.monotonic()+timeout
    complete = False
    try:
        while time.monotonic() < end:
            ready, _, _ = select.select([readfd], [], [], max(0, end-time.monotonic()))
            if not ready:
                break
            block = os.read(readfd, 65536)
            if not block:
                complete = True
                break
            raw += block
            need(len(raw) <= LIMIT, 'NAMESPACE_REPLY_OVERFLOW')
        need(complete, 'NAMESPACE_OPERATION_UNKNOWN')
        result = decode(raw)
        need(result.get('ok') is True, 'NAMESPACE_OPERATION_REFUSED')
        return result['value']
    finally:
        os.close(readfd)
        if not complete:
            # The child remains our unreaped child: PID cannot have been reused.
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
        os.waitpid(pid, 0)


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect(DOCKER)


def request(conn, method, path, raw=None):
    try:
        conn.request(method, path, body=raw, headers={'Content-Type': 'application/json', 'Connection': 'close'})
        response = conn.getresponse()
        body = response.read(LIMIT+1)
        need(200 <= response.status < 300 and len(body) <= LIMIT, 'HTTP_REFUSED')
        return body
    finally:
        conn.close()


class Linux:
    """Real privileged seam. Source tests never instantiate this against a daemon."""
    def __init__(self, p):
        self.p = p
        self.fds = {}
        self.pids = {}
        self.pidfds = {}
        self.netns_fd = None
        self.sealed = None
        self.firewall_seal = None
        self.path_identity = None
        self.path_state = 'absent'
        self.owned = {}
        self.target_hold = None
        self.dispatch = held_dispatch_required
        self.boundary = held_dispatch_required
        self.host_fd = os.open('/proc/1/ns/net', os.O_RDONLY | os.O_CLOEXEC)
        self.fds['host'] = self.host_fd
        self.check_host()
        for role in ROLES:
            current = self.inspect(role)
            self.pids[role] = current['pid']
            pidfd = os.pidfd_open(current['pid'])
            self.pidfds[role] = pidfd
            fd = os.open('/proc/'+str(current['pid'])+'/ns/net', os.O_RDONLY | os.O_CLOEXEC)
            self.fds[role] = fd
            self.check_peer(role)
        need(len({tuple(identity('/proc/'+str(x)+'/ns/net')) for x in self.pids.values()}) == 3,
             'SHARED_PEER_NAMESPACES_UNSUPPORTED')

    def check_host(self):
        need(Path('/etc/machine-id').read_text().strip() == self.p['machine'] and
             Path('/proc/sys/kernel/random/boot_id').read_text().strip() == self.p['boot'] and
             identity('/proc/1/ns/net') == self.p['hostNetns'] and
             identity('/proc/self/ns/net') == self.p['hostNetns'] and
             identity('/proc/self/ns/mnt') == identity('/proc/1/ns/mnt'), 'WRONG_TEST_HOST_OR_NAMESPACE')
        need(identity(DOCKER) == self.p['daemon']['socket'] and stat.S_ISSOCK(os.lstat(DOCKER).st_mode) and
             os.stat(DOCKER).st_uid == 0 and not os.stat(DOCKER).st_mode & 0o002, 'DOCKER_SOCKET_DRIFT')
        info = decode(request(UnixHTTP('localhost'), 'GET', '/info'))
        need(identity(DOCKER) == self.p['daemon']['socket'] and info.get('ID') == self.p['daemon']['id'] and info.get('DockerRootDir') == self.p['daemon']['root'],
             'WRONG_DOCKER_DAEMON')
        for path, pin_ in self.p['executables'].items():
            fd = trusted_fd(path)
            try:
                s = os.fstat(fd)
                need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and not s.st_mode & 0o6022,
                     'UNTRUSTED_EXECUTABLE')
                h = hashlib.sha256()
                while True:
                    b = os.read(fd, 65536)
                    if not b:
                        break
                    h.update(b)
                need(h.hexdigest() == pin_, 'EXECUTABLE_DRIFT')
            finally:
                os.close(fd)

    def inspect(self, role):
        c = decode(request(UnixHTTP('localhost'), 'GET', '/containers/'+self.p['peers'][role]['id']+'/json'))
        need(c.get('Id') == self.p['peers'][role]['id'] and c['State']['Running'] is True and
             c['State']['Paused'] is False and c['State']['Restarting'] is False, 'CONTAINER_NOT_STABLE')
        pid = c['State']['Pid']
        integer(pid)
        projection = {'id': c['Id'], 'pid': pid, 'start': proc_start(pid),
                      'netns': identity('/proc/'+str(pid)+'/ns/net'), 'image': c['Image'],
                      'restartCount': c['RestartCount'], 'networks': c['NetworkSettings']['Networks']}
        need(digest(encode(projection)) == self.p['peers'][role]['inspectSha256'], 'CONTAINER_IDENTITY_DRIFT')
        need(self.p['peers'][role]['address'] in
             {x.get('IPAddress') for x in c['NetworkSettings']['Networks'].values()}, 'DATA_ENDPOINT_ADDRESS_DRIFT')
        return projection

    def check_peer(self, role):
        current = self.inspect(role)
        fd = self.fds[role]
        s = os.fstat(fd)
        need(current['pid'] == self.pids[role] and current['netns'] == [s.st_dev, s.st_ino] and
             not select.select([self.pidfds[role]], [], [], 0)[0] and
             current['netns'] != self.p['hostNetns'], 'PEER_NAMESPACE_DRIFT')

    def check(self):
        self.check_host()
        self.check_targets()

    def check_targets(self):
        self.check_hold()
        if self.path_state == 'underlay':
            need(identity(NETNS) == self.path_identity, 'NETNS_MOUNTPOINT_REPLACED')
        for role in ROLES:
            self.check_peer(role)
        if self.sealed is not None:
            need(encode({x: self.snapshot(x) for x in ('host', 'fresh', *ROLES)}) == encode(self.sealed),
                 'CONSTRUCTED_NETWORK_DRIFT')
            need(encode(self.nft_observation()) == encode(self.firewall_seal), 'PRIVATE_FIREWALL_DRIFT')
        if self.netns_fd is not None:
            s = os.fstat(self.netns_fd)
            expected = [s.st_dev, s.st_ino] if self.path_state == 'mounted' else self.path_identity
            need((not os.path.lexists(NETNS)) if self.path_state == 'absent' else
                 identity(NETNS) == expected, 'OWNED_NETNS_REPLACED')
            need([s.st_dev, s.st_ino] != self.p['hostNetns'], 'OWNED_NETNS_REPLACED')
        for (where, name), expected in self.owned.items():
            rows = [x for x in self.snapshot(where)['links'] if x['ifname'] == name]
            need(len(rows) == 1 and all(encode(rows[0].get(k)) == encode(v)
                                       for k, v in expected.items()), 'OWNED_VETH_IDENTITY_LOST')

    def step(self, label, fn, after=lambda: None):
        def operation():
            value = fn()
            after()  # Checked expected-state transition, never a new blanket seal.
            return value
        return self.dispatch(label, operation)

    def write_ip(self, where, *args, after=lambda: None):
        return self.step('ip:'+where+':'+':'.join(args), lambda: self.ip(where, *args), after)

    def invoke(self, where, fn):
        def operation():
            self.boundary()  # In the joined child, immediately before the external write.
            return fn()
        return in_namespace(self.fds[where], operation)


    def ip(self, where, *args):
        # No shell, PATH, inherited user environment, Docker CLI/context or request argv.
        def call():
            if not any(x in args for x in ('show', 'list')):
                self.boundary()
            c = subprocess.run([IP, '-j', '-4', *args], env={'LC_ALL': 'C'},
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=3, check=True)
            need(len(c.stdout) <= LIMIT, 'IP_REPLY_OVERFLOW')
            return c.stdout.decode()
        return in_namespace(self.fds[where], call)

    def snapshot(self, where):
        return {kind: decode(self.ip(where, *args).encode()) for kind, args in
                {'links': ('-details', 'link', 'show'), 'addresses': ('address', 'show'),
                 'routes': ('route', 'show', 'table', 'all'), 'rules': ('rule', 'show')}.items()}

    def preflight(self):
        self.check()
        need(not os.path.lexists(NETNS), 'EXISTING_NETNS_REFUSED')
        snapshots = {role: self.snapshot(role) for role in ('host', *ROLES)}
        public = [(a['ifname'], x.get('prefixlen')) for a in snapshots['host']['addresses']
                  for x in a.get('addr_info', []) if x.get('family') == 'inet' and x.get('local') == PUBLIC]
        need(public == [('eth0', 24)], 'FIXED_TEST_PUBLIC_ADDRESS_REQUIRED')
        names = {n for pair in NAMES.values() for n in pair}
        for role, snap in snapshots.items():
            need(not names.intersection(x['ifname'] for x in snap['links']), 'EXISTING_INTERFACE_REFUSED')
            for route in snap['routes']:
                dst = route.get('dst', 'default')
                if dst == 'default':
                    continue
                try:
                    net = ipaddress.IPv4Network(dst, strict=False)
                except ValueError:
                    raise Refusal('UNSUPPORTED_ROUTE') from None
                need(not any(net.overlaps(ipaddress.IPv4Network(self.p['peers'][x]['subnet'])) for x in ROLES),
                     'EXISTING_P2P_ROUTE_OVERLAP')
        c = snapshots['caddy']
        need(not any(str(x.get('table')) == TABLE for x in c['routes']) and
             not any(str(x.get('priority')) == PRIORITY or str(x.get('table')) == TABLE for x in c['rules']),
             'EXISTING_CADDY_TABLE_OR_RULE')
        # Reject Docker allocations across ALL networks without allocating anything there.
        networks = decode(request(UnixHTTP('localhost'), 'GET', '/networks'))
        for network in networks:
            for config in network.get('IPAM', {}).get('Config', []) or []:
                subnet = config.get('Subnet')
                if subnet and ':' not in subnet:
                    net = ipaddress.IPv4Network(subnet)
                    need(not any(net.overlaps(ipaddress.IPv4Network(self.p['peers'][x]['subnet'])) for x in ROLES),
                         'DOCKER_SUBNET_OVERLAP')
        need(encode(self.config()) == encode(self.p['oldConfig']), 'CADDY_BASELINE_DRIFT')
        need(digest(trusted_read('/var/lib/c3-test-fresh-input/root/etc/hosts')) == self.p['hostsSha256'],
             'INDEPENDENT_RUNTIME_HOSTS_REQUIRED')
        rp = in_namespace(self.fds['caddy'], lambda: Path('/proc/sys/net/ipv4/conf/all/rp_filter').read_text().strip())
        need(rp in ('0', '2'), 'CADDY_STRICT_GLOBAL_RPF_UNSUPPORTED')
        return snapshots

    def config(self, value=None):
        if value is not None:
            return self.step('caddy-load', lambda: self.config_operation(value))
        return self.config_operation(None)

    def config_operation(self, value):
        def operation():
            require_listener(self.pids['caddy'], '127.0.0.1', 2019)
            if value is None:
                result = decode(request(http.client.HTTPConnection('127.0.0.1', 2019, timeout=3), 'GET', '/config/'))
            else:
                result = self.load_config(value)
            require_listener(self.pids['caddy'], '127.0.0.1', 2019)
            return result
        return in_namespace(self.fds['caddy'], operation)

    def load_config(self, value):
        self.boundary()
        raw = encode(value)
        if raw == encode(self.p['newConfig']):
            expected = self.p['oldConfig']
        else:
            need(raw == encode(self.p['oldConfig']), 'ACCEPTED_CADDY_TARGET_REQUIRED')
            expected = self.p['newConfig']
        baseline = decode(request(http.client.HTTPConnection('127.0.0.1', 2019, timeout=3), 'GET', '/config/'))
        need(encode(baseline) == encode(expected), 'CADDY_BASELINE_DRIFT')
        require_listener(self.pids['caddy'], '127.0.0.1', 2019)
        self.boundary()
        request(http.client.HTTPConnection('127.0.0.1', 2019, timeout=3), 'POST', '/load', raw)
        self.boundary()
        observed = decode(request(http.client.HTTPConnection('127.0.0.1', 2019, timeout=3), 'GET', '/config/'))
        need(encode(observed) == encode(value), 'CADDY_WRITE_UNCONFIRMED')
        return True

    def create_namespace(self):
        self.step('netns-mountpoint-create', self.create_mountpoint)
        self.step('netns-private-mount', self.mount_namespace)
        self.write_ip('fresh', 'link', 'set', 'lo', 'up')
        self.write_ip('fresh', 'address', 'add', PUBLIC+'/32', 'dev', 'lo')

    def create_mountpoint(self):
        self.boundary()
        need(not os.path.lexists(NETNS), 'EXISTING_NETNS_REFUSED')
        parent = trusted_fd('/run/netns', directory=True)
        try:
            self.boundary()
            fd = os.open(Path(NETNS).name, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
        finally:
            os.close(parent)
        self.path_identity = identity(NETNS)
        os.close(fd)
        self.path_state = 'underlay'

    def mount_namespace(self):
        need(identity(NETNS) == self.path_identity, 'NETNS_MOUNTPOINT_REPLACED')
        # Unshare affects only this bounded child; mount is the persistent dispatch.
        def create():
            self.boundary()
            syscall('unshare', CLONE_NEWNET)
            self.boundary()
            need(identity(NETNS) == self.path_identity, 'NETNS_MOUNTPOINT_REPLACED')
            syscall('mount', b'/proc/self/ns/net', NETNS.encode(), None, 4096, None)
            return identity('/proc/self/ns/net')
        observed = in_namespace(self.host_fd, create)
        nsfd = os.open(NETNS, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.fds['fresh'] = nsfd
        need(identity(NETNS) == observed and observed != self.p['hostNetns'], 'PRIVATE_NETNS_CREATION_FAILED')
        import fcntl
        need(fcntl.ioctl(nsfd, 0xb703) == CLONE_NEWNET, 'NETWORK_NSFS_REQUIRED')
        self.netns_fd = nsfd
        self.path_state = 'mounted'

    def retain_pair(self, role):
        own, peer = NAMES[role]
        rows = {x['ifname']: x for x in self.snapshot('host')['links'] if x['ifname'] in (own, peer)}
        need(set(rows) == {own, peer} and all(x.get('link_type') == 'ether' and
             x.get('linkinfo', {}).get('info_kind') == 'veth' for x in rows.values()) and
             rows[own].get('link_index') == rows[peer]['ifindex'] and
             rows[peer].get('link_index') == rows[own]['ifindex'], 'NEW_VETH_PAIR_UNCONFIRMED')
        for name in (own, peer):
            self.owned['host', name] = {k: rows[name].get(k) for k in ('ifindex', 'ifalias', 'link_index')}

    def connect(self, role):
        own, peer = NAMES[role]
        for where in ('host', 'fresh', *ROLES):
            need(not any(x['ifname'] in (own, peer) for x in self.snapshot(where)['links']),
                 'EXISTING_INTERFACE_REFUSED')
        commands = link_commands(role, self.p['peers'][role]['subnet'], self.p['generation'])
        self.write_ip('host', *commands[0], after=lambda: self.retain_pair(role))
        for command, name in zip(commands[1:], (own, peer)):
            def tagged(name=name, alias=command[-1]):
                self.owned['host', name]['ifalias'] = alias
            self.write_ip('host', *command, after=tagged)
        # Exact indices come from the exclusively created pair, never a fresh name lookup.
        for name, where in ((own, 'fresh'), (peer, role)):
            index = self.owned['host', name]['ifindex']
            def moved(name=name, where=where):
                self.owned[where, name] = self.owned.pop(('host', name))
            self.step('rtnetlink-move:'+name+':'+where,
                      lambda index=index, where=where: self.invoke('host', lambda: move_link(index, self.fds[where], self.boundary)),
                      moved)
        fresh_ip, peer_ip = addresses(self.p, role)
        for where, name, address in (('fresh', own, fresh_ip), (role, peer, peer_ip)):
            self.write_ip(where, 'link', 'set', name, 'addrgenmode', 'none')
            def rpf(name=name):
                path = Path('/proc/sys/net/ipv4/conf')/name/'rp_filter'
                path.write_text('0\n')
                need(path.read_text().strip() == '0', 'PRIVATE_LINK_RPF_WRITE_FAILED')
                return True
            self.step('sysctl-rpf:'+where+':'+name, lambda where=where: self.invoke(where, rpf))
            self.write_ip(where, 'address', 'add', address+'/30', 'dev', name)
            self.write_ip(where, 'link', 'set', name, 'up')
        if role in PORTS:
            self.write_ip('fresh', 'route', 'add', self.p['peers'][role]['address']+'/32', 'via', peer_ip,
                          'dev', own, 'src', fresh_ip)
        else:
            self.write_ip(role, 'route', 'add', PUBLIC+'/32', 'via', fresh_ip, 'dev', peer,
                          'src', peer_ip, 'table', TABLE)
            self.write_ip(role, 'rule', 'add', 'priority', PRIORITY, 'to', PUBLIC+'/32',
                          'ipproto', 'tcp', 'dport', '3000', 'table', TABLE)

    def firewall(self):
        def apply():
            subprocess.run([NFT, '-f', '-'], input=nft_policy(self.p), env={'LC_ALL': 'C'},
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=True)
            return True
        self.step('nft-private-policy', lambda: self.invoke('fresh', apply))

    def nft_observation(self):
        def read():
            c = subprocess.run([NFT, '-j', 'list', 'ruleset'], env={'LC_ALL': 'C'},
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=3, check=True)
            need(len(c.stdout) <= LIMIT, 'NFT_REPLY_OVERFLOW')
            return decode(c.stdout)
        return in_namespace(self.fds['fresh'], read)

    def seal(self):
        self.check()
        self.sealed = {x: self.snapshot(x) for x in ('host', 'fresh', *ROLES)}
        self.firewall_seal = self.nft_observation()
        self.check()

    def serving_pin(self):
        path = '/etc/c3-test-fresh-network-serving.json'
        raw = trusted_read(path)
        value = decode(raw)
        keys(value, 'version context generation serving')
        need(type(value['version']) is int and value['version'] == 1 and value['context'] == CONTEXT and
             value['generation'] == self.p['generation'], 'INDEPENDENT_SERVING_PIN_REQUIRED')
        keys(value['serving'], 'pid start')
        pid, start = value['serving']['pid'], value['serving']['start']
        integer(pid)
        need(type(start) is str and re.fullmatch('[1-9][0-9]*', start) and proc_start(pid) == start and
             identity('/proc/'+str(pid)+'/ns/net') == identity(NETNS), 'SERVING_IDENTITY_DRIFT')
        status = Path('/proc', str(pid), 'status').read_text().splitlines()
        need('Uid:\t65531\t65531\t65531\t65531' in status and
             Path('/proc', str(pid), 'cgroup').read_text().strip() ==
             '0::/system.slice/c3-test-fresh-classic.service', 'FIXED_APPLICATION_PRINCIPAL_REQUIRED')
        self.hold_target(path, raw, [(pid, start)])
        self.check_hold()
        return pid, start

    def direct_probe(self):
        pid, start = self.serving_pin()
        return in_namespace(self.fds['fresh'], lambda: bound_probe(pid, start))

    def caddy_probe(self):
        def probe():
            body = request(http.client.HTTPConnection(PUBLIC, 3000, timeout=2), 'GET', '/classic-ready')
            need(body == READY, 'CADDY_TO_FRESH_PATH_FAILED')
            return digest(body)
        return in_namespace(self.fds['caddy'], probe)

    def return_probe(self):
        path = '/etc/c3-test-fresh-network-return.json'
        raw = trusted_read(path)
        value = decode(raw)
        keys(value, 'version context generation container inspectSha256 address serving')
        need(type(value['version']) is int and value['version'] == 1 and value['context'] == CONTEXT and
             value['generation'] == self.p['generation'], 'INDEPENDENT_RETURN_AUTHORITY_REQUIRED')
        pin(value['container']); pin(value['inspectSha256'])
        keys(value['serving'], 'pid start')
        integer(value['serving']['pid'])
        need(type(value['serving']['start']) is str and value['serving']['start'].isdigit(), 'RETURN_PID_PIN_REQUIRED')
        projection = self.return_container(value)
        serving = value['serving']['pid']
        self.hold_target(path, raw, [(projection['pid'], projection['start']),
                                    (serving, value['serving']['start'])])
        return self.check_hold()

    def return_container(self, value):
        c = decode(request(UnixHTTP('localhost'), 'GET', '/containers/'+value['container']+'/json'))
        pid = c['State']['Pid']
        integer(pid)
        projection = {'id': c['Id'], 'pid': pid, 'start': proc_start(pid),
                      'netns': identity('/proc/'+str(pid)+'/ns/net'), 'image': c['Image'],
                      'restartCount': c['RestartCount'], 'networks': c['NetworkSettings']['Networks']}
        serving = value['serving']['pid']
        need(c['State']['Running'] is True and c['State']['Paused'] is False and
             c['State']['Restarting'] is False and c['Id'] == value['container'] and digest(encode(projection)) == value['inspectSha256'] and
             value['address'] in {x.get('IPAddress') for x in c['NetworkSettings']['Networks'].values()} and
             identity('/proc/'+str(serving)+'/ns/net') == projection['netns'] and
             Path('/proc', str(serving), 'cgroup').read_bytes() == Path('/proc', str(pid), 'cgroup').read_bytes(),
             'RETURN_CONTAINER_IDENTITY_DRIFT')
        return projection

    def hold_target(self, path, raw, processes):
        existing = getattr(self, 'target_hold', None)
        if existing is not None:
            need(existing['path'] == path and existing['raw'] == raw and
                 [(x['pid'], x['start']) for x in existing['processes']] == processes,
                 'ACCEPTED_TARGET_REPLACED')
            return
        hold = {'path': path, 'raw': bytes(raw), 'processes': []}
        self.target_hold = hold  # Partial acquisition remains retained on error.
        for pid, start in processes:
            need(proc_start(pid) == start, 'HELD_TARGET_PID_REPLACED')
            item = {'pid': pid, 'start': start, 'pidfd': os.pidfd_open(pid)}
            hold['processes'].append(item)
            item['nsfd'] = os.open('/proc/'+str(pid)+'/ns/net', os.O_RDONLY | os.O_CLOEXEC)
        self.check_held_processes(hold)

    def check_held_processes(self, hold):
        for x in hold['processes']:
            s = os.fstat(x['nsfd'])
            need(not select.select([x['pidfd']], [], [], 0)[0] and proc_start(x['pid']) == x['start'] and
                 identity('/proc/'+str(x['pid'])+'/ns/net') == [s.st_dev, s.st_ino],
                 'HELD_TARGET_PROCESS_OR_NAMESPACE_DRIFT')

    def check_hold(self):
        hold = getattr(self, 'target_hold', None)
        if hold is None:
            return
        need(trusted_read(hold['path']) == hold['raw'], 'ACCEPTED_TARGET_PIN_DRIFT')
        self.check_held_processes(hold)
        value = decode(hold['raw'])
        pid, start = value['serving']['pid'], value['serving']['start']
        if 'container' in value:
            self.return_container(value)
            def probe():
                need(docker_backend_addresses() == [value['address']], 'RETURN_UPSTREAM_DNS_DRIFT')
                return bound_probe(pid, start, value['address'], 3000)
            result = in_namespace(self.fds['caddy'], probe)
            self.return_container(value)
            need(in_namespace(self.fds['caddy'], docker_backend_addresses) == [value['address']],
                 'RETURN_UPSTREAM_DNS_DRIFT')
        else:
            need(identity('/proc/'+str(pid)+'/ns/net') == identity(NETNS), 'SERVING_IDENTITY_DRIFT')
            result = in_namespace(self.fds['fresh'], lambda: bound_probe(pid, start))
        self.check_held_processes(hold)
        need(trusted_read(hold['path']) == hold['raw'], 'ACCEPTED_TARGET_PIN_DRIFT')
        return result

    def close_holds(self):
        hold = getattr(self, 'target_hold', None)
        if hold is not None:
            for x in hold['processes']:
                for key in ('pidfd', 'nsfd'):
                    if key in x:
                        os.close(x[key])
            self.target_hold = None

    def public_probe(self):
        # Standard verified TLS, fixed hostname/port/path, no proxy/environment use.
        body = request(http.client.HTTPSConnection(CONTEXT, 443, timeout=3), 'GET', '/classic-ready')
        need(body == READY, 'PUBLIC_HTTPS_FAILED')
        return digest(body)

    def observation(self):
        self.check()
        return {'namespace': identity(NETNS), 'snapshots': {x: self.snapshot(x) for x in ('host', 'fresh', *ROLES)},
                'configSha256': digest(encode(self.config()))}

    def remove(self, baseline):
        self.check()
        # Do not destroy a namespace occupied by a supervisor/controller/application.
        self.require_empty_namespace()
        need(encode(self.config()) == encode(self.p['oldConfig']), 'CADDY_NOT_RETURNED')
        for role in ROLES:
            # Verify exact aliases and one veth peer pair before deleting anything.
            own, peer = NAMES[role]
            a = [x for x in self.snapshot('fresh')['links'] if x['ifname'] == own]
            b = [x for x in self.snapshot(role)['links'] if x['ifname'] == peer]
            need(len(a) == len(b) == 1 and
                 a[0].get('ifalias') == 'c3:'+self.p['generation']+':'+role+':fresh' and
                 b[0].get('ifalias') == 'c3:'+self.p['generation']+':'+role+':peer' and
                 a[0].get('link_index') == b[0]['ifindex'] and b[0].get('link_index') == a[0]['ifindex'],
                 'OWNED_VETH_IDENTITY_LOST')
        # Keep the seal live, evolving only the exact expected owned deletion.
        rules = [x for x in self.sealed['caddy']['rules'] if str(x.get('priority')) == PRIORITY]
        routes = [x for x in self.sealed['caddy']['routes'] if str(x.get('table')) == TABLE]
        need(len(rules) == len(routes) == 1, 'OWNED_CADDY_SELECTORS_LOST')
        self.delete_expected('caddy', 'rules', rules[0],
                             ('rule', 'del', 'priority', PRIORITY, 'to', PUBLIC+'/32',
                              'ipproto', 'tcp', 'dport', '3000', 'table', TABLE))
        fresh_ip, peer_ip = addresses(self.p, 'caddy')
        self.delete_expected('caddy', 'routes', routes[0],
                             ('route', 'del', PUBLIC+'/32', 'via', fresh_ip, 'dev', NAMES['caddy'][1],
                              'src', peer_ip, 'table', TABLE))
        for role in ROLES:
            expected = decode(encode(self.sealed))
            for where, name in (('fresh', NAMES[role][0]), (role, NAMES[role][1])):
                for kind in ('links', 'addresses', 'routes'):
                    expected[where][kind] = [x for x in expected[where][kind]
                                             if x.get('ifname') != name and x.get('dev') != name]
            def deleted(role=role, expected=expected):
                for where, name in (('fresh', NAMES[role][0]), (role, NAMES[role][1])):
                    self.owned.pop((where, name))
                self.sealed = expected
            self.write_ip('fresh', 'link', 'del', NAMES[role][0], after=deleted)
        for role in ('host', *ROLES):
            need(encode(self.snapshot(role)) == encode(baseline[role]), 'ENDPOINT_BASELINE_NOT_RESTORED')
        def unmount():
            self.boundary()
            self.require_empty_namespace()
            self.boundary()
            syscall('umount2', NETNS.encode(), 0)  # Never lazy/forced detach.
            self.path_state = 'underlay'
            need(identity(NETNS) == self.path_identity, 'NETNS_MOUNTPOINT_REPLACED')
        self.step('netns-unmount', unmount)
        def unlink():
            self.boundary()
            need(identity(NETNS) == self.path_identity, 'NETNS_MOUNTPOINT_REPLACED')
            os.unlink(NETNS)
            self.path_state = 'absent'
            need(not os.path.lexists(NETNS), 'NETNS_REMOVAL_UNCONFIRMED')
        self.step('netns-mountpoint-unlink', unlink)
        # Retain the unmounted namespace FD until the entire held entry closes.

    def delete_expected(self, where, kind, row, command):
        expected = decode(encode(self.sealed))
        expected[where][kind] = [x for x in expected[where][kind] if encode(x) != encode(row)]
        self.write_ip(where, *command, after=lambda: setattr(self, 'sealed', expected))

    def require_empty_namespace(self):
        target = tuple(identity(NETNS))
        for process in Path('/proc').iterdir():
            if not process.name.isdigit():
                continue
            try:
                for task in (process/'task').iterdir():
                    need(tuple(identity(task/'ns/net')) != target, 'FRESH_NAMESPACE_STILL_OCCUPIED')
            except FileNotFoundError:
                continue

    def close(self):
        self.close_holds()
        for fd in set(self.fds.values()) | set(self.pidfds.values()):
            os.close(fd)


class Journal:
    """New private generation only; every intent fsynced before an external write.

    No restart/recovery adoption. Any exception leaves the generation for separate
    exact-target recovery. Terminal generations remain durable no-replay tombstones.
    """
    def __init__(self, path, p):
        self.path = Path(path)
        os.mkdir(self.path, 0o700)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        s = os.fstat(self.fd)
        self.identity = (s.st_dev, s.st_ino)
        self.counter = 0
        self.append({'kind': 'generation', 'planSha256': digest(encode(p)), 'generation': p['generation']})
        parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)

    def append(self, record):
        s = os.lstat(self.path)
        need((s.st_dev, s.st_ino) == self.identity and stat.S_ISDIR(s.st_mode),
             'JOURNAL_REPLACED')
        name = '%06d.json' % self.counter
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            raw = encode(record)
            view = memoryview(raw)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.fd)
        self.counter += 1

    def close(self):
        os.close(self.fd)


class Controller:
    def __init__(self, p, kernel, journal, clock=time.monotonic, guard=lambda: None):
        self.p, self.k, self.j = p, kernel, journal
        self.guard = guard
        self.clock = clock
        self.phase = 'new'
        self.seq = 0
        self.end = clock()+min(600, max(0, p['deadline']-int(time.time())))
        self.baseline = None
        self.failed = False
        kernel.dispatch = self.effect
        kernel.boundary = self.dispatch_live

    def authority(self):
        need(not self.failed, 'UNKNOWN_RETAINED_NO_MUTATION')
        self.guard()
        need(self.clock() < self.end and time.time() < self.p['deadline'], 'NETWORK_LEASE_EXPIRED')

    def dispatch_live(self):
        # Child is already in the retained target netns; host self-netns is not applicable.
        self.authority()
        self.k.check_targets()
        self.authority()  # Observation work cannot extend a lease or revive a holder.

    def live(self):
        try:
            self.authority()
            self.k.check()
            self.authority()
        except BaseException:
            self.phase = 'unknown-retained'
            self.failed = True
            raise

    def effect(self, label, fn):
        self.live()
        # Poison before journal IO as well as dispatch; uncertain intent is not replayable.
        previous = self.phase
        self.phase = 'unknown-retained'
        try:
            self.j.append({'kind': 'intent', 'effect': label, 'seq': self.seq})
            self.live()  # Intent fsync may itself consume the remaining lease.
            value = fn()
            self.live()
            self.j.append({'kind': 'confirmed', 'effect': label, 'seq': self.seq})
        except BaseException:
            self.failed = True
            raise
        self.phase = previous
        return value

    def prepare(self):
        need(self.phase == 'new', 'NO_REPLAY')
        self.live()
        self.baseline = self.k.preflight()
        self.j.append({'kind': 'baseline', 'value': self.baseline})
        self.effect('create-private-netns', self.k.create_namespace)
        # Default-drop precedes any veth becoming UP.
        self.effect('private-firewall', self.k.firewall)
        for role in ROLES:
            self.effect('connect-'+role, lambda role=role: self.k.connect(role))
        self.effect('seal-network', self.k.seal)
        self.phase = 'prepared'
        return self.observe()

    def observe(self):
        self.live()
        observation = self.k.observation()
        self.live()  # Final readback cannot outrun the held target/lease.
        return {'version': 1, 'context': CONTEXT, 'generation': self.p['generation'],
                'phase': self.phase, 'sequence': self.seq, 'observation': observation,
                'physicalAccepted': False, 'operationalGO': False}

    def checked_probe(self, fn):
        try:
            return fn()
        except BaseException:
            self.phase = 'unknown-retained'
            self.failed = True
            raise

    def command(self, request_):
        keys(request_, 'generation sequence operation')
        need(request_['generation'] == self.p['generation'] and
             type(request_['sequence']) is int and request_['sequence'] == self.seq+1 and
             request_['operation'] in ('observe', 'cutover', 'return', 'abandon'), 'CONTROL_REPLAY_OR_COMMAND_REFUSED')
        self.live()
        self.seq += 1
        self.j.append({'kind': 'command', 'sequence': self.seq, 'operation': request_['operation']})
        op = request_['operation']
        next_phase = None
        if op == 'observe':
            return self.observe()
        need(self.phase != 'unknown-retained', 'UNKNOWN_RETAINED_NO_MUTATION')
        if op == 'cutover':
            need(self.phase == 'prepared' and encode(self.k.config()) == encode(self.p['oldConfig']), 'CUTOVER_BASELINE_REQUIRED')
            # Both observations are real HTTP, not trusted readiness integers.
            self.checked_probe(self.k.direct_probe)
            self.k.caddy_probe()
            self.effect('caddy-exact-new-config', lambda: self.k.config(self.p['newConfig']))
            self.phase = 'unknown-retained'
            need(encode(self.k.config()) == encode(self.p['newConfig']), 'CADDY_WRITE_UNCONFIRMED')
            self.k.public_probe()
            self.checked_probe(self.k.direct_probe)
            self.live()
            next_phase = 'cutover'
        elif op == 'return':
            need(self.phase == 'cutover' and encode(self.k.config()) == encode(self.p['newConfig']), 'RETURN_EXACT_TARGET_REQUIRED')
            # This operation is ONLY usable under independently accepted old-writer
            # authority in the root lease; it does not thaw/restart old services.
            self.checked_probe(self.k.return_probe)
            self.effect('caddy-exact-old-config', lambda: self.k.config(self.p['oldConfig']))
            self.phase = 'unknown-retained'
            need(encode(self.k.config()) == encode(self.p['oldConfig']), 'RETURN_WRITE_UNCONFIRMED')
            self.k.public_probe()
            self.checked_probe(self.k.return_probe)
            self.live()
            next_phase = 'returned'
        elif op == 'abandon':
            need(self.phase in ('prepared', 'returned'), 'SERVING_ABANDON_REFUSED')
            self.effect('remove-owned-resources', lambda: self.k.remove(self.baseline))
            self.phase = 'abandoned'
            return {'phase': self.phase, 'operationalGO': False}
        result = self.observe()
        if op in ('cutover', 'return'):
            self.j.append({'kind': 'public-https-confirmed' if op == 'cutover' else 'public-return-confirmed',
                           'sequence': self.seq})
            self.live()
            self.phase = next_phase
            result['phase'] = self.phase
            self.checked_probe(self.k.close_holds)
        return result
