# DIRECT TEST install and owned removal. This private endpoint accepts only the fixed
# actions/paths below. No remote runner, package installs, or global flushes.
import base64
import contextlib
import ctypes
import errno
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid
from typing import Any, cast

MAIN = '/usr/local/etc/xray/config.json'
BRIDGE = '/usr/local/etc/xray-bridge/config.json'
XRAY = '/usr/local/bin/xray'
SYSTEM = '/etc/systemd/system'
NET_UNIT = 'celerity-rebuild-l2tp-network.service'
NET = SYSTEM + '/' + NET_UNIT
DROP_DIR = SYSTEM + '/xl2tpd.service.d'
DROP = DROP_DIR + '/50-celerity-rebuild-l2tp.conf'
NFT_DIR = '/etc/celerity-rebuild-l2tp'
NFT_FILE = NFT_DIR + '/ingress.nft'
VAULT = '/var/lib/celerity-rebuild-l2tp-direct'
XL, IKE, X, B = 'xl2tpd.service', 'strongswan-starter.service', 'xray.service', 'xray-bridge.service'
# Exact native unit emitted by the stock prerequisite installer.
NATIVE_XL_SHA = '20e9c67838fa8072a5378839fc729a1123d1580879fbf20f9121d558fd0fe0df'
XL_BOOT = SYSTEM + '/multi-user.target.wants/' + XL
XL_DEFAULT = '/etc/default/xl2tpd'
# Extracted from signed Debian trixie/main xl2tpd_1.3.18-1+b1_amd64.deb
# (archive SHA256 dd6fdf32b90f9f7d516f5251e1abdb65851156c80163a41aab60cf94dcff16da).
STOCK_XL_DEFAULT_SHA = '37b5938f462ec60b4f8c179b34f70b548c09da4691c938e88ce111ce41268833'
STOCK_XL_DEFAULT_MD5 = b'fadc31f26078d8c3fb033d7d4516500b'
REQUIRED_PACKAGES = ('strongswan', 'strongswan-starter', 'strongswan-charon', 'xl2tpd', 'ppp', 'nftables')
STOCK_IKE_INCLUDE = b'include /etc/ipsec.d/*.conf'
SWAN_CONF = '/etc/strongswan.conf'
SWAN_DIR = '/etc/strongswan.d'
SWAN_PROFILE = SWAN_DIR + '/celerity-rebuild-l2tp.conf'
SWAN_SETTINGS = b'charon {\n    routing_table = 0\n    install_routes = no\n}\n'
SWAN_START_UNITS = (XL, IKE, NET_UNIT)
# Base and optional conffile sets from authenticated Debian trixie-security
# amd64 strongSwan 6.0.1-6+deb13u7. Each pin is the SHA256 of that set's
# canonical {path relative to /etc: [mode, gid, SHA256 of bytes]} projection.
STOCK_SWAN_SHA = 'ddc103e3bab4b312ab390428dd64ec6606ea6793d715d536d2fa2c0025e5d77e'
STOCK_SWAN_ADDONS = (
    # charon-systemd
    ('charon-systemd.conf', 'ae3da3badf12f70aba2c90e6ada3e68106ae37e281722292a44af467306a9c16'),
    # strongswan-swanctl
    ('swanctl.conf charon/vici.conf', '281f18aaf17874e2eab779b1a12516a4d67fc6e2909897dddec30a94b824a132'),
    # libcharon-extra-plugins
    ('tnc.conf charon/addrblock.conf charon/certexpire.conf charon/dhcp.conf '
     'charon/eap-aka.conf charon/eap-gtc.conf charon/eap-identity.conf charon/eap-md5.conf '
     'charon/eap-radius.conf charon/eap-tls.conf charon/eap-tnc.conf charon/eap-ttls.conf '
     'charon/error-notify.conf charon/farp.conf charon/forecast.conf charon/ha.conf '
     'charon/kernel-libipsec.conf charon/led.conf charon/lookip.conf charon/tnc-tnccs.conf '
     'charon/unity.conf charon/xauth-eap.conf charon/xauth-pam.conf',
     '9217d22d0b888e08f27e4df29a871e8dd459822d312b57bde761508161a307cf'),
)
UNITS = (XL, IKE, X, B, NET_UNIT)
TABLE = 'celerity_rebuild_l2tp'
PRIORITY = 10077
NAMES = {
    'main': MAIN, 'lns': '/etc/xl2tpd/xl2tpd.conf', 'options': '/etc/ppp/options.xl2tpd',
    'chap': '/etc/ppp/chap-secrets', 'secrets': '/etc/ipsec.secrets', 'ike': '/etc/ipsec.d/celerity-rebuild-l2tp.conf',
    'starter': '/etc/ipsec.conf', 'nft': NFT_FILE, 'net': NET, 'drop': DROP,
}
# Install files in this order; all are joined before daemon-reload or starts.
ORDER = ('nft', 'net', 'drop', 'ike', 'starter', 'secrets', 'chap', 'options', 'lns', 'main')
MAX_FILE = 16 * 1024 * 1024
MAX_REQUEST = 25 * 1024 * 1024
DEADLINE = time.monotonic() + 115
STAGE = 'PREREQUISITE'
REMOVE_ENTERED = False
CHAP_ENTERED = False
NETWORK_UPGRADE_ENTERED = False
NO_INSTALL_WRITES = False


class Refusal(Exception):
    pass


def need(condition, code):
    if not condition:
        raise Refusal(code)


def command(*args, data=None, wait=6, unit_show=False, quiet=False):
    limit = min(wait, DEADLINE - time.monotonic())
    if limit <= 0:
        raise subprocess.TimeoutExpired([], 0)
    result = subprocess.run(args, input=data, stdin=subprocess.DEVNULL if data is None else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE if quiet else subprocess.DEVNULL, timeout=limit,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, cwd='/')
    need(result.returncode >= 0, 'IN_FLIGHT')
    need(len(result.stdout) <= MAX_FILE, STAGE)
    need(not quiet or not result.stderr, STAGE)
    # Some systemd versions exit 1 for a structured not-found unit.
    need(result.returncode == 0 or (unit_show and result.returncode == 1
         and result.stdout.splitlines().count(b'LoadState=not-found') == 1), STAGE)
    return result.stdout


def sc(*args, wait=6):
    return command('/usr/bin/systemctl', '--no-pager', *args, wait=wait)


def ip(*args):
    return json.loads(command('/usr/sbin/ip', '-j', '-N', '-4', *args))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def b64(data):
    return base64.b64encode(data).decode('ascii')


@contextlib.contextmanager
def directory(path, private=False):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for component in path.strip('/').split('/') if path != '/' else []:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            st = os.fstat(fd)
            need(st.st_uid == 0 and not st.st_mode & 0o022, 'PREREQUISITE')
        if private:
            st = os.fstat(fd)
            need(stat.S_IMODE(st.st_mode) == 0o700 and st.st_gid == 0, 'PREREQUISITE')
        yield fd
    finally:
        os.close(fd)


def read(path, maximum=MAX_FILE):
    parent, name = os.path.split(path)
    try:
        with directory(parent) as fd:
            with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd), 'rb') as handle:
                st = os.fstat(handle.fileno())
                owner_ok = st.st_uid == 0 or (path in (MAIN, BRIDGE) and st.st_uid == pwd.getpwnam('nobody').pw_uid)
                need(stat.S_ISREG(st.st_mode) and owner_ok and st.st_nlink == 1
                     and not st.st_mode & 0o7022 and not os.listxattr(handle.fileno()), 'PREREQUISITE')
                data = handle.read(maximum + 1)
                need(len(data) <= maximum and len(data) == st.st_size, 'PREREQUISITE')
                return entry(data, stat.S_IMODE(st.st_mode), st.st_gid, st.st_uid)
    except FileNotFoundError:
        return None


def raw(record):
    return base64.b64decode(record['data'], validate=True)


def entry(data, mode=0o600, gid=0, uid=0):
    record = {'data': b64(data), 'mode': mode, 'gid': gid}
    if uid:
        record['uid'] = uid
    return record


def mkdir(path, mode, exist_ok=False):
    parent, name = os.path.split(path)
    with directory(parent) as fd:
        try:
            os.mkdir(name, mode, dir_fd=fd)
            os.fsync(fd)
        except FileExistsError:
            need(exist_ok, 'ROLLBACK_DRIFT')
    with directory(path, private=mode == 0o700):
        pass


def rmdir(path):
    parent, name = os.path.split(path)
    with directory(parent) as fd:
        os.rmdir(name, dir_fd=fd)
        os.fsync(fd)


def write(path, before, after):
    need(read(path, 2 * MAX_FILE) == before, 'ROLLBACK_DRIFT')
    parent, name = os.path.split(path)
    with directory(parent) as fd:
        if after is None:
            os.unlink(name, dir_fd=fd)
        else:
            scratch = '.direct-' + uuid.uuid4().hex
            handle = os.open(scratch, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                with os.fdopen(handle, 'wb') as output:
                    output.write(raw(after))
                    output.flush()
                    uid = after.get('uid', 0)
                    need(uid == 0 or (path in (MAIN, BRIDGE) and uid == pwd.getpwnam('nobody').pw_uid), 'ROLLBACK_DRIFT')
                    os.fchown(output.fileno(), uid, after['gid'])
                    os.fchmod(output.fileno(), after['mode'])
                    os.fsync(output.fileno())
                need(read(path, 2 * MAX_FILE) == before, 'ROLLBACK_DRIFT')
                if before is None:
                    os.link(scratch, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                else:
                    os.replace(scratch, name, src_dir_fd=fd, dst_dir_fd=fd)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(scratch, dir_fd=fd)
        os.fsync(fd)
    need(read(path, 2 * MAX_FILE) == after, 'RUNTIME_UNPROVED')


def unit(name):
    keys = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'InvocationID',
            'NeedDaemonReload', 'FragmentPath', 'DropInPaths', 'ExecStart', 'User', 'Group', 'Job',
            'Environment', 'EnvironmentFiles', 'RootDirectory', 'RootImage', 'PrivateNetwork',
            'KillMode', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'WorkingDirectory',
            'Restart', 'Type', 'Requires', 'After', 'ControlGroup', 'RequiredBy', 'BoundBy', 'ConsistsOf',
            'PropagatesStopTo', 'Conflicts', 'ConflictedBy', 'Wants', 'BindsTo', 'PartOf', 'Upholds',
            'SourcePath', 'ExecCondition', 'ExecReload', 'PassEnvironment', 'UnsetEnvironment')
    # `systemctl show` returns nonzero for some not-found units. LoadState is
    # inspected explicitly; do not treat arbitrary command failures as absence.
    text = command('/usr/bin/systemctl', '--no-pager', 'show', '--all', '--property=' + ','.join(keys), name,
                   unit_show=True).decode('utf-8')
    pairs = [line.split('=', 1) for line in text.splitlines() if '=' in line]
    if name == NET_UNIT:
        starts = [value for key, value in pairs if key == 'ExecStart']
        if len(starts) > 1:
            # systemctl show emits a row per command for our three-command
            # oneshot. Preserve order and keep every other property unique.
            need(len(starts) == 3 and ['Type', 'oneshot'] in pairs
                 and ['LoadState', 'loaded'] in pairs
                 and all(re.fullmatch(r'\{ path=/[^ ;{}]+ ; argv\[\]=[^{}]+ \}', value) for value in starts),
                 'PREREQUISITE')
            pairs = [(key, value) for key, value in pairs if key != 'ExecStart']
            pairs.append(('ExecStart', ' '.join(starts)))
    info = dict(pairs)
    need(len(pairs) == len(info), 'PREREQUISITE')
    need(info.get('LoadState') in ('loaded', 'masked', 'not-found') and
         info.get('ActiveState') in ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'), 'PREREQUISITE')
    return info


def no_jobs(units):
    # Systemd can continue executing jobs after its client has exited. Check
    # actual manager jobs before interpreting runtime or permitting restoration.
    jobs = sc('list-jobs', '--no-legend', '--plain').decode().splitlines()
    need(not any(set(line.split()) & set(units) for line in jobs), 'IN_FLIGHT')


def preflight(machine):
    machine_id = open('/etc/machine-id', 'rb').read(34).strip().decode('ascii')
    need(re.fullmatch(r'[a-f0-9]{32}', machine_id) and machine_id == machine, 'IDENTITY')
    ppp = False
    try:
        dev = os.lstat('/dev/ppp')
        registered = open('/proc/devices', 'rb').read(65536).partition(b'Block devices:')[0]
        ppp = (stat.S_ISCHR(dev.st_mode) and os.major(dev.st_rdev) == 108 and os.minor(dev.st_rdev) == 0
               and re.search(rb'^\s*108\s+ppp\s*$', registered, re.M) is not None)
    except FileNotFoundError:
        pass
    units = [unit(name)['LoadState'] for name in (XL, IKE)]
    if ppp and units == ['loaded'] * 2:
        for package in REQUIRED_PACKAGES:
            status = command('/usr/bin/dpkg-query', '-W', '-f=${db:Status-Abbrev}', package)
            need(status.startswith(b'ii '), 'PREREQUISITE')
    return dict(machineId=machine_id, ppp=ppp, masked='masked' in units, unitsLoaded=units == ['loaded'] * 2)


def sock_rows():
    rows = []
    for line in command('/usr/bin/ss', '-H', '-lntup').decode().splitlines():
        cols = line.split(maxsplit=6)
        need(len(cols) >= 6 and cols[0] in ('tcp', 'udp') and ':' in cols[4], 'RUNTIME_UNPROVED')
        address, port = cols[4].rsplit(':', 1)
        need(port.isdecimal(), 'RUNTIME_UNPROVED')
        rows.append((cols[0], address, int(port), sorted(set(re.findall(r'\bpid=(\d+),', cols[6] if len(cols) == 7 else '')))))
    return rows


def owned_sockets(rows, pid):
    return sorted([p, a, n] for p, a, n, owners in rows if pid in owners and pid != '0')


def working(info):
    return (info.get('LoadState') == 'loaded' and info.get('ActiveState') == 'active'
            and info.get('NeedDaemonReload') == 'no' and info.get('MainPID', '0').isdigit()
            and int(info.get('MainPID', '0')) > 0 and bool(info.get('InvocationID', '').strip('0')))


def no_hooks(info):
    return all(not info.get(k) for k in ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost',
                                         'RootDirectory', 'RootImage')) and info.get('PrivateNetwork') == 'no'


def xray_argv(info, path=MAIN):
    argv = [XRAY, 'run', '-config', path]
    prefix = '{ path=' + XRAY + ' ; argv[]=' + ' '.join(argv) + ' ;'
    need(working(info) and info.get('ExecStart', '').startswith(prefix) and no_hooks(info)
         and not info.get('Environment') and not info.get('EnvironmentFiles') and not info.get('DropInPaths')
         and info.get('WorkingDirectory') in ('', '/') and info.get('KillMode') == 'control-group', 'PREREQUISITE')
    pid = info['MainPID']
    with open('/proc/' + pid + '/cmdline', 'rb') as handle:
        need(handle.read(4096) == b'\0'.join(arg.encode() for arg in argv) + b'\0', 'RUNTIME_UNPROVED')
    need(os.path.realpath('/proc/' + pid + '/exe') == XRAY, 'RUNTIME_UNPROVED')
    return pid


def transit_inbounds(data: dict[str, Any], transit: Any) -> dict[str, int]:
    # The applied graph under the panel's Apply lock supplies these descriptors.
    # HandlerService lists the email index, not generated anonymous accounts.
    need(type(transit) is list and len(transit) <= 32, 'PROFILE_USERS')
    owned: dict[str, int] = {}
    for edge in transit:
        need(type(edge) is dict and set(edge) == {'linkId', 'mode', 'port', 'uuid'}
             and type(edge['linkId']) is str and re.fullmatch(r'[a-f0-9]{24}', edge['linkId'])
             and edge['mode'] in ('forward', 'reverse') and type(edge['port']) is int and 1 <= edge['port'] <= 65535
             and type(edge['uuid']) is str and re.fullmatch(r'\S{1,128}', edge['uuid']), 'PROFILE_USERS')
        suffix = edge['linkId'][-8:]
        reverse = edge['mode'] == 'reverse'
        tag = ('rebuild-rp-conn-' if reverse else 'fwd-hop-') + suffix
        client = {'id': edge['uuid']}
        if reverse:
            client['reverse'] = {'tag': 'rebuild-rp-egress-' + suffix}
        matching = [i for i in data['inbounds'] if i.get('tag') == tag]
        need(tag not in owned and len(matching) == 1, 'PROFILE_USERS')
        row = matching[0]
        need(row.get('protocol') == 'vless' and row.get('listen') == '0.0.0.0'
             and type(row.get('port')) is int and row['port'] == edge['port']
             and row.get('settings', {}).get('clients') == [client], 'PROFILE_USERS')
        owned[tag] = int(row['port'])
    return owned


def xray_users(config, info, rows, transit=None):
    pid = xray_argv(info)
    data = unique_profile(config) if transit else json.loads(raw(config))
    ib = data['inbounds']
    api = [row for row in ib if row.get('tag') == 'API_INBOUND']
    targets = [row for row in ib if row.get('protocol') == 'vless']
    need(all(row.get('protocol') in ('vless', 'dokodemo-door', 'socks') for row in ib)
         and 1 <= len(targets) <= 32 and len(api) == 1, 'PROFILE_USERS')
    port = api[0].get('port')
    need(api[0].get('listen') == '127.0.0.1' and api[0].get('protocol') == 'dokodemo-door'
         and type(port) is int and 1 <= port <= 65535
         and data.get('api', {}).get('tag') == 'API' and 'HandlerService' in data['api'].get('services', [])
         and any(p == 'tcp' and a == '127.0.0.1' and n == port and owners == [pid] for p, a, n, owners in rows),
         'PROFILE_USERS')
    owned = transit_inbounds(data, transit) if transit is not None else {}
    for row in targets:
        tag = row.get('tag', '')
        clients = row.get('settings', {}).get('clients')
        need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', tag) and isinstance(clients, list), 'PROFILE_USERS')
        if tag in owned:
            listeners = [(address, owners) for p, address, n, owners in rows if p == 'tcp' and n == owned[tag]]
            # ss prints the IPv4 wildcard as 0.0.0.0 or * on a dual-stack socket.
            need(any(address in ('0.0.0.0', '*') for address, _ in listeners)
                 and all(owners == [pid] for _, owners in listeners), 'RUNTIME_UNPROVED')
            continue
        # Subscriber inventory still requires the full HandlerService list,
        # not a count. Refuse dynamic or unrecognised account shapes.
        result = json.loads(command(XRAY, 'api', 'inbounduser', '--server=127.0.0.1:' + str(port), '-tag=' + tag,
                                    wait=4, quiet=True))
        # Protobuf JSON can omit an empty repeated field. A nonempty expected
        # inventory still has to match the complete runtime inventory below.
        need(type(result) is dict and set(result) <= {'users'} and type(result.get('users', [])) is list, 'PROFILE_USERS')
        actual = []
        for u in result.get('users', []):
            account = u.get('account', {})
            need(not (set(u) - {'email', 'level', 'account'}) and
                 not (set(account) - {'id', 'flow', '_TypedMessage_', 'reverse'}) and
                 account.get('_TypedMessage_') == 'xray.proxy.vless.Account', 'PROFILE_USERS')
            actual.append(encode([u.get('email', ''), u.get('level', 0), account['id'], account.get('flow', ''), account.get('reverse')]))
        expected = []
        for u in clients:
            need(not (set(u) - {'email', 'level', 'id', 'flow', 'reverse'}), 'PROFILE_USERS')
            expected.append(encode([u.get('email', ''), u.get('level', 0), u['id'], u.get('flow', ''), u.get('reverse')]))
        need(sorted(actual) == sorted(expected), 'PROFILE_USERS')
    return owned_sockets(rows, pid)


def routing(arg):
    need(isinstance(arg, dict) and set(arg) == {'clientCidr', 'tproxyPort', 'fwmark', 'routeTable'}, 'CANDIDATE_INVALID')
    net = ipaddress.IPv4Network(arg['clientCidr'])
    need(str(net) == arg['clientCidr'] and 16 <= net.prefixlen <= 30 and
         any(net.subnet_of(ipaddress.IPv4Network(n)) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')),
         'CANDIDATE_INVALID')
    for k, lo, hi in [('tproxyPort', 1024, 65535), ('fwmark', 1, 0x7fffffff), ('routeTable', 1, 0x7fffffff)]:
        need(type(arg[k]) is int and lo <= arg[k] <= hi, 'CANDIDATE_INVALID')
    need(arg['tproxyPort'] not in (1701, 4500) and arg['routeTable'] not in (253, 254, 255), 'CANDIDATE_INVALID')
    return arg


def nft_tables():
    rows = json.loads(command('/usr/sbin/nft', '-j', 'list', 'tables'))['nftables']
    return [row['table'] for row in rows if 'table' in row]


def nft_projection(token):
    tables = [row for row in nft_tables() if row.get('family') == 'inet' and row.get('name') == TABLE]
    if not tables:
        return None
    rows = json.loads(command('/usr/sbin/nft', '-j', '-s', 'list', 'table', 'inet', TABLE))['nftables']
    own = [row['table'] for row in rows if 'table' in row]
    need(len(own) == 1 and own[0].get('comment') == token and own[0].get('name') == TABLE, 'ROLLBACK_DRIFT')
    return digest(encode(rows))


def number(value):
    return int(value, 0) if isinstance(value, str) and value.isdecimal() is False else int(value)


def network_projection(d, token, removing=False):
    rules = ip('rule', 'show')
    routes = ip('route', 'show', 'table', 'all')
    # The narrow first-install profile supports only the stock all-source rules
    # plus this exact addition. No flushes, masking existing marks, or adoption.
    own_rules = [r for r in rules if r.get('priority') == PRIORITY]
    others = [r for r in rules if r.get('priority') != PRIORITY]
    names = {0: ('local', '255', 255), 32766: ('main', '254', 254), 32767: ('default', '253', 253)}
    table = d['routeTable']
    if removing:
        need(all(str(r.get('table')) != str(table) for r in others), 'NETWORK_CONFLICT')
    else:
        need(len(others) == 3 and all(type(r.get('priority')) is int for r in others)
             and {r['priority'] for r in others} == set(names) and all(
            r.get('src') == 'all' and r.get('table') in names[r['priority']]
            and not (set(r) - {'priority', 'src', 'table', 'protocol'}) for r in others), 'NETWORK_CONFLICT')
    own_routes = [r for r in routes if str(r.get('table')) == str(table)]
    # iproute2's ip/iprule.c prints IPv4 source addresses and prefix lengths
    # separately in JSON. Match the canonical candidate exactly in either
    # encoding; do not accept a hybrid or infer a missing prefix length.
    cidr = d['clientCidr']
    address, length = cidr.split('/')
    need(len(own_rules) <= 1 and all(
         type(r['priority']) is int and str(r.get('table')) == str(table)
         and ((r.get('src') == cidr and 'srclen' not in r)
              or (r.get('src') == address and type(r.get('srclen')) is int and r['srclen'] == int(length)))
         and type(r.get('fwmark')) in (int, str) and number(r['fwmark']) == d['fwmark']
         and not (set(r) - {'priority', 'src', 'srclen', 'table', 'fwmark', 'protocol'}) for r in own_rules),
         'NETWORK_CONFLICT')
    need(len(own_routes) <= 1 and all(r.get('type') in ('local', 2, '2') and r.get('dst') in ('default', '0.0.0.0/0') and r.get('dev') == 'lo'
         and r.get('scope') in ('host', 254, '254') and not (set(r) - {'type', 'dst', 'dev', 'table', 'scope', 'flags', 'protocol'})
         for r in own_routes), 'NETWORK_CONFLICT')
    return dict(rule=bool(own_rules), route=bool(own_routes), nft=nft_projection(token))


def ppp_empty():
    return not any(line.split(':', 1)[0].strip().startswith('ppp')
                   for line in open('/proc/net/dev').read(65536).splitlines()[2:])


def vpn_empty(allow_socket_policies=False):
    # `nokeys` is essential even though the result is discarded on a nonempty
    # host. Text mode returns empty stdout for an empty dump, not JSON `[]`.
    options = ('nosock',) if allow_socket_policies else ()
    return (ppp_empty() and not command('/usr/sbin/ip', 'xfrm', 'policy', 'list', *options).strip()
            and not command('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys').strip())


def is_stock_lns(record):
    data = raw(record)
    if not uncomment(data):
        return True
    info = command('/usr/bin/dpkg-query', '-W', '-f=${Conffiles}', 'xl2tpd')
    match = re.search(rb'^ /etc/xl2tpd/xl2tpd\.conf ([a-f0-9]{32})\s*$', info, re.M)
    return match is not None and hashlib.md5(data, usedforsecurity=False).hexdigest().encode() == match[1]


def uncomment(data):
    return [line.strip() for line in data.split(b'\n') if line.strip() and not line.lstrip().startswith((b'#', b';'))]


def native_vpn(info, name):
    # Refuse generated SysV wrappers and unreviewed local native units.
    paths = ['/usr/lib/systemd/system/' + name, '/lib/systemd/system/' + name]
    fragment = info.get('FragmentPath')
    if name == XL and fragment == SYSTEM + '/' + XL:
        config = read(fragment, 4096)
        if config is not None and config['mode'] == 0o644 and config['gid'] == 0 and digest(raw(config)) == NATIVE_XL_SHA:
            paths.append(fragment)
    expected = [('/usr/sbin/xl2tpd', '-D'), ('/usr/bin/xl2tpd', '-D')] if name == XL else [('/usr/sbin/ipsec', 'start', '--nofork')]
    return (info.get('LoadState') == 'loaded' and fragment in paths
            and any(info.get('ExecStart', '').startswith('{ path=' + argv[0] + ' ; argv[]=' + ' '.join(argv) + ' ;')
                    for argv in expected)
            and info.get('NeedDaemonReload') == 'no' and info.get('PrivateNetwork') == 'no'
            and info.get('KillMode') == 'control-group' and info.get('User') in ('', 'root')
            and not any(info.get(k) for k in ('Environment', 'EnvironmentFiles', 'RootDirectory', 'RootImage', 'ExecStartPre', 'ExecStartPost')))


def xl_defaults_admitted(record, info):
    # An absent file cannot supply defaults. Keep the existing minimal layout.
    if record is None:
        return True
    metadata = command('/usr/bin/dpkg-query', '-W', r'-f=${Version}\n${Architecture}\n${Conffiles}', 'xl2tpd', quiet=True)
    version, arch, *rows = metadata.split(b'\n')
    need(version and arch, 'PREREQUISITE')
    conffiles = [fields[1:] for row in rows if (fields := row.split()) and fields[0] == XL_DEFAULT.encode()]
    data = raw(record)
    if (version, arch) != (b'1.3.18-1+b1', b'amd64'):
        # An inert local file is not the same as a package conffile edited to be inert.
        return not conffiles and not uncomment(data)
    # The dpkg MD5 is only a conffile record check. The authenticated package's
    # full SHA256 pins every byte (including both assignments and comments).
    # observe() has already checked native_vpn, including the helper unit's
    # on-disk digest and metadata. Only that exact unit can ignore these SysV defaults.
    return (conffiles == [[STOCK_XL_DEFAULT_MD5]] and record['mode'] == 0o644 and record['gid'] == 0
            and digest(data) == STOCK_XL_DEFAULT_SHA and info['FragmentPath'] == SYSTEM + '/' + XL
            and no_hooks(info) and info.get('Group', '') in ('', 'root')
            and not any(info.get(k) for k in ('SourcePath', 'ExecCondition', 'ExecReload', 'PassEnvironment', 'UnsetEnvironment'))
            and re.fullmatch(r'\{ path=/usr/sbin/xl2tpd ; argv\[\]=/usr/sbin/xl2tpd -D ;[^{}]*\}', info.get('ExecStart', '')) is not None)


def directory_absent(path):
    parent, name = os.path.split(path)
    with directory(parent) as fd:
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
            return False
        except FileNotFoundError:
            return True


def boot_link_at(fd, name):
    def identity(st):
        need(stat.S_ISLNK(st.st_mode) and st.st_uid == 0, 'ROLLBACK_DRIFT')
        return [st.st_dev, st.st_ino, st.st_ctime_ns]

    try:
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    pin = identity(st)
    target = os.readlink(name, dir_fd=fd)
    need(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == pin, 'ROLLBACK_DRIFT')
    return [target, *pin]


def boot_link():
    parent, name = os.path.split(XL_BOOT)
    with directory(parent) as fd:
        return boot_link_at(fd, name)


def enroll_boot(target, expected=None):
    parent, name = os.path.split(XL_BOOT)
    with directory(parent) as fd:
        if expected is None:
            os.symlink(target, name, dir_fd=fd)  # no replacement or broad systemctl disable
        else:
            # Verify and unlink relative to the same trusted directory FD.
            # As with the file writes, other administrative writers must be excluded.
            need(expected[0] == target and boot_link_at(fd, name) == expected, 'ROLLBACK_DRIFT')
            os.unlink(name, dir_fd=fd)
        os.fsync(fd)


def ike_include_matches(starter, expected):
    if STOCK_IKE_INCLUDE in uncomment(raw(starter)):
        # A wildcard must never enroll or reload an unmanaged connection.
        with directory('/etc/ipsec.d') as fd:
            return sorted(name for name in os.listdir(fd) if not name.startswith('.') and name.endswith('.conf')) == expected
    return True


def swan_inputs(present, bad):
    # The reviewed bytes close both stock globs. Do not validate just individual
    # setting names: alternate includes, section references and other settings
    # could still bypass the managed routing configuration.
    profile = os.path.basename(SWAN_PROFILE)
    rows = {}
    try:
        with directory(SWAN_DIR) as fd:
            top = set(os.listdir(fd))
        need('charon' in top and (profile in top) == present, bad)
        top -= {'charon', profile}
        plugins = SWAN_DIR + '/charon'
        with directory(plugins) as fd:
            names = os.listdir(fd)
        need(len(top) + len(names) <= 50 and all(n.endswith('.conf') for n in (*top, *names)), bad)
        paths = [SWAN_CONF, *(SWAN_DIR + '/' + n for n in top), *(plugins + '/' + n for n in names)]
        for path in paths:
            record = read(path, 262144)
            if record is None or record.get('uid', 0) != 0:
                raise Refusal(bad)
            rows[path.removeprefix('/etc/')] = [record['mode'], record['gid'], digest(raw(record))]
    except (OSError, Refusal):
        raise Refusal(bad) from None

    base = rows.copy()
    for leaves, expected in STOCK_SWAN_ADDONS:
        keys = [SWAN_DIR.removeprefix('/etc/') + '/' + name for name in leaves.split()]
        addon = {key: base.pop(key) for key in keys if key in base}
        need(not addon or (len(addon) == len(keys) and digest(encode(addon)) == expected), bad)
    need(digest(encode(base)) == STOCK_SWAN_SHA, bad)
    # Pin the actual complete tree for phase comparisons, not the base projection.
    return digest(encode(rows))


def no_swan_rule():
    # The existing IPv4 projector remains unchanged (including on Remove).
    # Its removal mode allows unrelated rules; neither family may have 220/220
    # before this operation starts or stops the managed IKE invocation.
    rules4 = ip('rule', 'show')
    rules6 = json.loads(command('/usr/sbin/ip', '-j', '-N', '-6', 'rule', 'show'))
    need(type(rules4) is list and type(rules6) is list and all(
        isinstance(row, dict) and not (row.get('priority') == 220 and str(row.get('table')) == '220')
        for row in (*rules4, *rules6)), 'NETWORK_CONFLICT')


def swan_default_environment(bad):
    # Environment/PassEnvironment on the unit alone do not cover the manager's
    # global service environment. Never expose the other variable values.
    env = command('/usr/bin/systemctl', '--no-pager', 'show-environment', quiet=True)
    need(not any(line.startswith(b'STRONGSWAN_CONF=') for line in env.splitlines()), bad)


def idle_ike(info, rows):
    sockets = [(p, a, n, owners) for p, a, n, owners in rows if n in (500, 4500)]
    if not working(info) or {n for _, _, n, _ in sockets} != {500, 4500} or not all(
        p == 'udp' and owners and all(in_cgroup(pid, info) for pid in owners) for p, _, _, owners in sockets
    ):
        raise Refusal('PREREQUISITE')
    status = command('/usr/sbin/ipsec', 'statusall')
    need(re.search(rb'^Connections:[ \t]*\nSecurity Associations \(0 up, 0 connecting\):\s+none\s*\Z', status, re.M), 'PREREQUISITE')
    return sorted([p, a, n] for p, a, n, _ in sockets)


def boot():
    return open('/proc/sys/kernel/random/boot_id').read(64).strip()


def observe(machine, d, transit=None) -> dict[str, Any]:
    global STAGE
    STAGE = 'PREREQUISITE'
    ready = preflight(machine)
    need(ready['ppp'] and ready['unitsLoaded'] and not ready['masked'], 'PREREQUISITE')
    no_jobs(UNITS)
    units = {name: unit(name) for name in UNITS}
    for name in (XL, IKE):
        info = units[name]
        stopped = info['ActiveState'] == 'inactive' and info['SubState'] == 'dead' and info['MainPID'] == '0'
        stock_idle_ike = name == IKE and working(info) and info['SubState'] == 'running'
        need(native_vpn(info, name) and (stopped or stock_idle_ike) and not info.get('DropInPaths')
             and info['UnitFileState'] in ('enabled', 'disabled'), 'PREREQUISITE')
    # Enroll only the exact helper unit via its single WantedBy symlink.
    install_boot = units[XL]['UnitFileState'] == 'disabled'
    need(not install_boot or (units[XL]['FragmentPath'] == SYSTEM + '/' + XL and boot_link() is None), 'PREREQUISITE')
    need(units[NET_UNIT]['LoadState'] == 'not-found'
         and units[B]['ActiveState'] in ('active', 'inactive'), 'PREREQUISITE')
    for path in (NFT_DIR, DROP_DIR):
        need(directory_absent(path), 'PREREQUISITE')
    need(not any(os.path.lexists(p) for p in ('/etc/nftables.d/celerity-l2tp.nft', '/etc/ipsec.d/celerity-l2tp.conf')),
         'PREREQUISITE')
    files = {key: read(path) for key, path in NAMES.items()}
    need(all(files[k] is None for k in ('ike', 'options', 'nft', 'net', 'drop'))
         and all(files[k] is not None for k in ('main', 'lns', 'starter', 'chap', 'secrets')), 'PREREQUISITE')
    starter = uncomment(raw(files['starter']))
    need(starter in ([], [b'config setup'], [STOCK_IKE_INCLUDE], [b'config setup', STOCK_IKE_INCLUDE])
         and not uncomment(raw(files['secrets']))
         and not uncomment(raw(files['chap'])) and is_stock_lns(files['lns']), 'PREREQUISITE')
    need(ike_include_matches(files['starter'], []), 'PREREQUISITE')
    bridge = read(BRIDGE)
    need(bridge is not None or units[B]['ActiveState'] == 'inactive', 'PREREQUISITE')
    global_paths = ('/etc/ppp/options', SWAN_CONF, XL_DEFAULT)
    for path in global_paths:
        # Fingerprint stock/default inputs that this installer never edits.
        if os.path.lexists(path):
            need(read(path, 262144) is not None, 'PREREQUISITE')
    globals_before = {path: read(path, 262144) for path in global_paths}
    need(xl_defaults_admitted(globals_before[XL_DEFAULT], units[XL]), 'PREREQUISITE')
    rows = sock_rows()
    ike_sockets = idle_ike(units[IKE], rows) if units[IKE]['ActiveState'] == 'active' else []
    net = ipaddress.IPv4Network(d['clientCidr'])
    for addr in ip('addr', 'show'):
        for item in addr.get('addr_info', []):
            host = ipaddress.IPv4Interface(item['local'] + '/' + str(item['prefixlen']))
            need(not net.overlaps(host.network), 'NETWORK_CONFLICT')
    for route in ip('route', 'show', 'table', 'all'):
        dst = route.get('dst', 'default')
        need(dst == 'default' or not net.overlaps(ipaddress.IPv4Network(dst)), 'NETWORK_CONFLICT')
    reserved = (1701, d['tproxyPort']) if ike_sockets else (500, 4500, 1701, d['tproxyPort'])
    need(not any(n in reserved for _, _, n, _ in rows)
         and vpn_empty(allow_socket_policies=bool(ike_sockets)) and network_projection(d, '') == {'nft': None, 'rule': False, 'route': False}, 'NETWORK_CONFLICT')
    need(not any(row.get('name') == 'celerity_l2tp' for row in nft_tables()), 'NETWORK_CONFLICT')
    no_swan_rule()
    # Startup must be ours: do not replace or restart a previously running IKE
    # instance. Retain the old network refusal above for stock 220 conflicts.
    need(units[IKE]['ActiveState'] == 'inactive' and not units[IKE].get('PassEnvironment')
         and STOCK_IKE_INCLUDE in starter, 'PREREQUISITE')
    need(all(removal_native(units[n], n, {'units': units}, installed=False)
             and not units[n].get('ExecCondition') for n in (XL, IKE)), 'PREREQUISITE')
    removal_dependencies({n: units[n] for n in (XL, IKE)}, installed=False)
    swan_default_environment('PREREQUISITE')
    files['swan'] = read(SWAN_PROFILE, 8192)
    need(files['swan'] is None, 'PREREQUISITE')
    swan = swan_inputs(False, 'PREREQUISITE')
    STAGE = 'PROFILE_USERS'
    sockets = xray_users(files['main'], units[X], rows, transit)
    need(sockets, 'RUNTIME_UNPROVED')
    # Project stable unit fields only; systemctl ExecStart includes runtime timestamps.
    unit_pins = {name: {key: units[name].get(key) for key in
                 ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'InvocationID', 'FragmentPath', 'DropInPaths')}
                 for name in UNITS}
    return dict(boot=boot(), files=files, units=unit_pins, bridge=bridge, sockets=sockets, globalFiles=globals_before,
                installBoot=install_boot, ikeSockets=ike_sockets, swanInputs=swan,
                **({'transit': transit} if transit is not None else {}))


def candidate(request, before):
    files = request['files']
    sidecar = 'bridge' in files
    need(set(files) - {'bridge'} == {'main', 'nft', 'ike', 'lns', 'options', 'secrets', 'chap'}, 'CANDIDATE_INVALID')
    bytes_ = {k: base64.b64decode(value, validate=True) for k, value in files.items()}
    need(all(0 < len(value) <= (MAX_FILE if k in ('main', 'bridge') else 1024 * 1024) for k, value in bytes_.items()), 'CANDIDATE_INVALID')
    d, token = request['network'], request['backupId']
    main = unique_profile({'data': files['main']}) if 'transit' in before else json.loads(bytes_['main'])
    if 'transit' in before:
        protected = transit_inbounds(main, before['transit'])
        original_main = unique_profile(before['files']['main'])
        need(encode([i for i in main['inbounds'] if i.get('tag') in protected])
             == encode([i for i in original_main['inbounds'] if i.get('tag') in protected]), 'CANDIDATE_INVALID')
    ppp = [i for i in main['inbounds'] if i.get('tag', '').startswith('relay-l2tp-')]
    owner = json.loads(bytes_['bridge']) if sidecar else main
    handoff = [i for i in owner['inbounds'] if i.get('tag') == 'rebuild-relay-ingress']
    need(len(ppp) == 1 and ppp[0].get('port') == d['tproxyPort'] and len(handoff) == 1
         and handoff[0].get('listen') == '127.0.0.1' and type(handoff[0].get('port')) is int, 'CANDIDATE_INVALID')
    rows = sock_rows()
    if sidecar:
        need(before['bridge'] is not None and not any(i.get('tag') == handoff[0]['tag'] for i in main['inbounds']), 'CANDIDATE_INVALID')
        side = unit(B)
        original_side = json.loads(raw(before['bridge']))
        # An existing managed sidecar only, with no separate dynamic-user API.
        need(not original_side.get('api') and not owner.get('api') and side.get('User') == 'nobody'
             and side.get('UnitFileState') == 'enabled', 'PREREQUISITE')
        pid = xray_argv(side, BRIDGE)
        listeners = [r for r in rows if r[2] == handoff[0]['port']]
        need({p for p, *_ in listeners} == {'tcp', 'udp'} and all(a == '127.0.0.1' and owners == [pid]
             for _, a, _, owners in listeners), 'NETWORK_CONFLICT')
    else:
        need(not any(n == handoff[0]['port'] for _, _, n, _ in rows), 'NETWORK_CONFLICT')
    drop = f'[Unit]\nRequires={NET_UNIT} {IKE}\nAfter={NET_UNIT} {IKE}\n'.encode()
    original = before['files']
    after = {key: entry(data, 0o644 if key in ('lns', 'ike', 'nft') else 0o600) for key, data in bytes_.items()}
    after['main'] = {**original['main'], 'data': b64(bytes_['main'])}
    if sidecar:
        after['bridge'] = {**before['bridge'], 'data': b64(bytes_['bridge'])}
    after['starter'] = original['starter'] if STOCK_IKE_INCLUDE in uncomment(raw(original['starter'])) else entry(
        raw(original['starter']) + b'\ninclude ' + NAMES['ike'].encode() + b'\n', original['starter']['mode'], original['starter']['gid'])
    for k in ('chap', 'secrets'):
        after[k] = entry(raw(original[k]) + b'\n' + bytes_[k])
    after['net'], after['drop'] = entry(network_unit(d, sidecar), 0o644), entry(drop, 0o644)
    if 'swan' in original:
        after['swan'] = entry(SWAN_SETTINGS, 0o644)
    need(nft_marker(bytes_['nft'], token), 'CANDIDATE_INVALID')
    return after


NETWORK_START_CHECK = '/usr/bin/systemctl is-active --quiet ' + X


def network_unit(d, sidecar, *, legacy=False):
    prerequisite = X + (' ' + B if sidecar else '')
    dependency = 'Requires' if legacy else 'Wants'
    # Xray is needed to bring the network up, but a routine restart must not
    # stop the resident policy or the LNS. PPP can't fall back to forwarding:
    # that is denied by the resident nft table even with no Xray listener.
    startup = '' if legacy else f'ExecStartPre={NETWORK_START_CHECK}\n'
    return f'''[Unit]
Description=Celerity rebuild L2TP TPROXY policy
Before={XL}
{dependency}={X}
After={prerequisite} nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=20s
{startup}ExecStart=/usr/sbin/nft -f {NFT_FILE}
ExecStart=/usr/sbin/ip -4 route add local 0.0.0.0/0 dev lo table {d['routeTable']}
ExecStart=/usr/sbin/ip -4 rule add priority {PRIORITY} from {d['clientCidr']} fwmark {d['fwmark']} table {d['routeTable']}
'''.encode()


def nft_marker(data, token):
    return data.startswith(f'create table inet {TABLE} {{\n    comment "{token}"\n'.encode())


def validate_profiles(after):
    for key, name, path in (('main', X, MAIN), ('bridge', B, BRIDGE)):
        if key not in after:
            continue
        info = unit(name)
        uid = pwd.getpwnam(info.get('User') or 'root')
        gid = grp.getgrnam(info['Group']).gr_gid if info.get('Group') else uid.pw_gid
        st = os.stat('/proc/' + info['MainPID'])
        need(st.st_uid == uid.pw_uid and st.st_gid == gid, 'PREREQUISITE')
        as_user = ('/usr/bin/setpriv', '--reuid=' + str(uid.pw_uid), '--regid=' + str(gid), '--init-groups')
        command(*as_user, XRAY, 'run', '-test', '-format', 'json', '-config', path, wait=8)
        command(*as_user, XRAY, 'run', '-test', '-format', 'json', '-config', 'stdin:', data=raw(after[key]), wait=8)


def validate_candidate(after):
    validate_profiles(after)
    command('/usr/sbin/nft', '-c', '-f', '-', data=raw(after['nft']))


def manifest_path(token):
    return VAULT + '/' + token + '/manifest.json'


def read_manifest(token):
    with directory(VAULT, private=True), directory(VAULT + '/' + token, private=True):
        path = manifest_path(token)
        record = read(path, 2 * MAX_FILE)
        need(record is not None and record['mode'] == 0o600 and record['gid'] == 0, 'ROLLBACK_DRIFT')
        value = json.loads(raw(record))
    return path, record, value


def bound_manifest(request):
    path, record, value = read_manifest(request['backupId'])
    need(value['machineId'] == request['machineId'] and value['backupId'] == request['backupId'] and
         value['network'] == request['network'] and digest(encode(value['before'])) == request['baseline']
         and value['before']['boot'] == boot(), 'ROLLBACK_DRIFT')
    return path, record, value


def operation_files(records):
    return {**NAMES, **({'swan': SWAN_PROFILE} if 'swan' in records else {}),
            **({'bridge': BRIDGE} if 'bridge' in records else {})}


def operation_order(records):
    return (*(('swan',) if 'swan' in records else ()), *ORDER, *(('bridge',) if 'bridge' in records else ()))


def original_files(before, records):
    return {**before['files'], **({'bridge': before['bridge']} if 'bridge' in records else {})}


def neighbors(before, sidecar=False):
    b = unit(B)
    # Verify/rollback (and owned removal below) pin the admitted bytes and
    # metadata, rather than rerunning the pristine-unit defaults admission.
    need(all(read(path, 262144) == value for path, value in before['globalFiles'].items()), 'ROLLBACK_DRIFT')
    if sidecar:
        need(all(b.get(k) == before['units'][B][k] for k in ('LoadState', 'UnitFileState', 'FragmentPath', 'DropInPaths'))
             and b.get('User') == 'nobody', 'ROLLBACK_DRIFT')
    else:
        need(read(BRIDGE) == before['bridge'] and all(b.get(k) == v for k, v in before['units'][B].items()), 'ROLLBACK_DRIFT')


def file_generations(records=None, *, include_chap=True):
    result = {}
    for k, path in operation_files(records or {}).items():
        if k == 'chap' and not include_chap:
            continue
        st = os.lstat(path)
        need(stat.S_ISREG(st.st_mode), 'ROLLBACK_DRIFT')
        result[k] = [st.st_dev, st.st_ino, st.st_ctime_ns]
    return result


def in_cgroup(pid, unit_info):
    group = unit_info.get('ControlGroup')
    if not group or not re.fullmatch(r'[1-9][0-9]*', pid):
        return False
    with open('/proc/' + pid + '/cgroup') as handle:
        return '0::' + group in handle.read(65536).splitlines()


def installed_runtime(d, token, before, after):
    global STAGE
    STAGE = 'RUNTIME_UNPROVED'
    no_jobs(UNITS)
    sidecar = 'bridge' in after
    neighbors(before, sidecar)
    x, lns, ike, net_unit = (unit(name) for name in (X, XL, IKE, NET_UNIT))
    need(network_unit_loaded(net_unit, legacy_network(after['net'], d, sidecar)), 'RUNTIME_UNPROVED')
    need(native_vpn(lns, XL) and native_vpn(ike, IKE) and working(lns) and working(ike)
         and lns['UnitFileState'] == 'enabled'
         and ike['UnitFileState'] == before['units'][IKE]['UnitFileState']
         and lns['DropInPaths'] == DROP and NET_UNIT in lns['Requires'].split() and NET_UNIT in lns['After'].split()
         and net_unit.get('ActiveState') == 'active' and net_unit.get('SubState') == 'exited' and net_unit.get('FragmentPath') == NET,
         'RUNTIME_UNPROVED')
    rows = sock_rows()
    pid = xray_argv(x)
    sockets = xray_users(after['main'], x, rows, before.get('transit'))
    need(set(tuple(s) for s in before['sockets']) <= set(tuple(s) for s in sockets)
         and x['InvocationID'] != before['units'][X]['InvocationID'], 'RUNTIME_UNPROVED')
    bridge_info = unit(B) if sidecar else None
    handoff_pid = xray_argv(bridge_info, BRIDGE) if bridge_info is not None else pid
    need(bridge_info is None or bridge_info['InvocationID'] != before['units'][B]['InvocationID'], 'RUNTIME_UNPROVED')
    config = json.loads(raw(after['bridge' if sidecar else 'main']))
    handoff = next(i['port'] for i in config['inbounds'] if i['tag'] == 'rebuild-relay-ingress')
    need(all(any(p == proto and n == port and owners == [owner] and (address is None or a == address)
                 for p, a, n, owners in rows)
             for proto, port, address, owner in [('tcp', d['tproxyPort'], None, pid), ('udp', d['tproxyPort'], None, pid),
                 ('tcp', handoff, '127.0.0.1', handoff_pid), ('udp', handoff, '127.0.0.1', handoff_pid)]),
         'RUNTIME_UNPROVED')
    l2tp_sockets = [owners for p, a, n, owners in rows if p == 'udp' and n == 1701]
    need(l2tp_sockets and all(owners == [lns['MainPID']] for owners in l2tp_sockets), 'RUNTIME_UNPROVED')
    for port in (500, 4500):
        ike_sockets = [owners for p, a, n, owners in rows if p == 'udp' and n == port]
        need(ike_sockets and all(owners and all(in_cgroup(pid, ike) for pid in owners) for owners in ike_sockets),
             'RUNTIME_UNPROVED')
    status = command('/usr/sbin/ipsec', 'statusall')
    need(re.search(rb'^\s*celerity-l2tp\s*:\s+[^\n]+', status, re.M), 'RUNTIME_UNPROVED')
    policy = network_projection(d, token)
    need(policy['rule'] and policy['route'] and policy['nft'] is not None, 'RUNTIME_UNPROVED')
    need(all(read(path) == after[k] for k, path in operation_files(after).items()), 'RUNTIME_UNPROVED')
    need(ike_include_matches(after['starter'], [os.path.basename(NAMES['ike'])]), 'RUNTIME_UNPROVED')
    if 'swan' in after:
        need(not ike.get('PassEnvironment') and swan_inputs(True, STAGE) == before['swanInputs'], STAGE)
        no_swan_rule()
    return {'nft': policy['nft'], 'invocations': [u['InvocationID'] for u in (x, lns, ike, net_unit)]
            + ([bridge_info['InvocationID']] if bridge_info is not None else []),
            'files': file_generations(after), 'bootEnrollment': boot_link() if before.get('installBoot') else None}


def write_swan_profile(path, old_manifest, backup, after):
    before = backup['before']
    need(before['files']['swan'] is None and not before['ikeSockets']
         and after['swan'] == entry(SWAN_SETTINGS, 0o644)
         and swan_inputs(False, 'ROLLBACK_DRIFT') == before['swanInputs'], 'ROLLBACK_DRIFT')
    no_swan_rule()
    write(SWAN_PROFILE, None, after['swan'])
    backup['swanGeneration'] = remove_generation(SWAN_PROFILE)
    check_swan_profile(backup, read(SWAN_PROFILE))
    updated = entry(encode(backup))
    write(path, old_manifest, updated)
    return updated


def swan_unstarted(info, before, name):
    old = before['units'][name].get('InvocationID') or '0' * 32
    return (info.get('ActiveState'), info.get('SubState'), info.get('MainPID'), info.get('InvocationID') or '0' * 32) == (
        'inactive', 'dead', '0', old)


def swan_started_units(before):
    units = {n: unit(n) for n in SWAN_START_UNITS}
    removal_dependencies(units, installed=True)
    births = [units[n].get('InvocationID') for n in SWAN_START_UNITS]
    need(len(set(births)) == len(SWAN_START_UNITS) and all(isinstance(i, str) and re.fullmatch(r'[0-9a-f]{32}', i) and i != '0' * 32
             and i != before['units'][n].get('InvocationID') and units[n]['ActiveState'] == 'active'
             for n, i in zip(SWAN_START_UNITS, births)), 'RUNTIME_UNPROVED')
    return births


def install(request, before, after):
    global STAGE
    STAGE = 'COMMAND_FAILED'
    token, d = request['backupId'], request['network']
    backup: dict[str, Any] = dict(machineId=request['machineId'], backupId=token, before=before, network=d,
                  after={k: {**r, 'data': digest(raw(r))} for k, r in after.items()}, phase='applying')
    payload = encode(backup)
    need(len(payload) <= 2 * MAX_FILE, 'CANDIDATE_INVALID')
    mkdir(VAULT, 0o700, exist_ok=True)
    mkdir(VAULT + '/' + token, 0o700)
    path = manifest_path(token)
    old_manifest = entry(payload)
    write(path, None, old_manifest)
    if 'swan' in after:
        old_manifest = write_swan_profile(path, old_manifest, backup, after)
    mkdir(NFT_DIR, 0o755)
    mkdir(DROP_DIR, 0o755)
    paths, originals = operation_files(after), original_files(before, after)
    for key in (*ORDER, 'bridge') if 'bridge' in after else ORDER:
        if originals[key] != after[key]:
            write(paths[key], originals[key], after[key])
    if before.get('installBoot'):
        target = before['units'][XL]['FragmentPath']
        enroll_boot(target)
        receipt = boot_link()
        need(receipt and receipt[0] == target, 'ROLLBACK_DRIFT')
        backup['bootEnrollment'] = receipt
        current = entry(encode(backup))
        write(path, old_manifest, current)
        old_manifest = current
    sc('daemon-reload', wait=12)
    if 'bridge' in after:
        sc('restart', B, wait=22)
    sc('restart', X, wait=22)
    if before.get('ikeSockets'):
        sc('restart', IKE, wait=22)
    no_jobs(UNITS)
    if 'swan' in after:
        check_swan_profile(backup, read(SWAN_PROFILE))
        units = {n: unit(n) for n in SWAN_START_UNITS}
        ike = units[IKE]
        removal_dependencies(units, installed=True)
        need(all(swan_unstarted(units[n], before, n) for n in SWAN_START_UNITS)
             and not any(port in (500, 4500, 1701) for _, _, port, _ in sock_rows()), 'ROLLBACK_DRIFT')
        need(removal_native(ike, IKE, before, installed=False) and not ike.get('PassEnvironment')
             and not ike.get('ExecCondition') and all(ike.get(k) == v for k, v in before['units'][IKE].items()),
             'ROLLBACK_DRIFT')
        swan_default_environment('ROLLBACK_DRIFT')
    sc('start', XL, wait=26)
    if 'swan' in after:
        # A successful manager start and fresh, named invocations are distinct
        # from the full Install receipt. Persist them before later verification.
        # An uncertain start without this record has no stop authority.
        backup['swanStart'] = swan_started_units(before)
        started = entry(encode(backup))
        write(path, old_manifest, started)
        old_manifest = started
    # Type=simple may be active before its API/UDP listeners are present.
    ready_by = min(DEADLINE, time.monotonic() + 6)
    while True:
        try:
            runtime = installed_runtime(d, token, before, after)
            break
        except Refusal as error:
            if str(error) not in ('RUNTIME_UNPROVED', 'PROFILE_USERS') or time.monotonic() >= ready_by:
                raise
            time.sleep(0.2)
    need(runtime.get('bootEnrollment') == backup.get('bootEnrollment'), 'ROLLBACK_DRIFT')
    if 'swan' in after:
        need(runtime['files']['swan'] == backup['swanGeneration']
             and runtime['invocations'][1:4] == backup['swanStart'], 'ROLLBACK_DRIFT')
    backup.update(phase='installed', runtime=runtime)
    write(path, old_manifest, entry(encode(backup)))


def after_match(record, expected):
    return record is not None and {**record, 'data': digest(raw(record))} == expected


CHAP_ACTIONS = ('check-chap', 'sync-chap')
APPLY_NETWORK_ACTIONS = ('check-apply-network', 'prepare-apply-network', 'verify-apply-network', 'restart-apply-network')
CHAP_BEGIN = b'# BEGIN CELERITY MANAGED L2TP USERS'
CHAP_END = b'# END CELERITY MANAGED L2TP USERS'
CHAP_LOGIN = rb'[A-Za-z0-9._@-]{1,64}'
CHAP_QUOTED_BYTE = rb'(?:[ !#-\[\]-~]|\\["\\])'
CHAP_ROW = re.compile(rb'"(' + CHAP_LOGIN + rb')" l2tpd "(' + CHAP_QUOTED_BYTE + rb'{1,255}|[A-Za-z0-9_-]{256})" ([0-9.]{7,15})')
CHAP_FOREIGN_TOKEN = re.compile(rb'(?:"' + CHAP_QUOTED_BYTE + rb'''*"|'[ -&(-\[\]-~]*'|[!$-&(-\[\]-~]+)''')


def chap_pool(lns, cidr):
    bounds = re.findall(rb'^ip range = ([0-9.]{7,15})-([0-9.]{7,15})$', lns, re.M)
    need(len(bounds) == 1, 'ROLLBACK_DRIFT')
    first, last = (ipaddress.IPv4Address(v.decode('ascii')) for v in bounds[0])
    network = ipaddress.IPv4Network(cidr)
    need(network.network_address < first <= last < network.broadcast_address, 'ROLLBACK_DRIFT')
    return first, last


def chap_user_rows(users: Any, pool):
    bad = 'CANDIDATE_INVALID'
    need(type(users) is list and len(users) <= 2048, bad)
    rows, logins, addresses = {}, set(), set()
    for row in cast(list[dict[str, Any]], users):
        need(type(row) is dict and set(row) == {'login', 'password', 'ipAddress', 'enabled'}
             and type(row['enabled']) is bool and all(type(row[k]) is str for k in ('login', 'password', 'ipAddress')), bad)
        login, password, address = (row[k].encode('ascii') for k in ('login', 'password', 'ipAddress'))
        need(re.fullmatch(CHAP_LOGIN, login) and (re.fullmatch(rb'[ -~]{1,255}', password)
             or re.fullmatch(rb'[A-Za-z0-9_-]{256}', password))
             and not password.startswith(b'@') and login not in logins and address not in addresses
             and pool[0] <= ipaddress.IPv4Address(row['ipAddress']) <= pool[1], bad)
        logins.add(login)
        addresses.add(address)
        if row['enabled']:
            quoted = password.replace(b'\\', b'\\\\').replace(b'"', b'\\"')
            rows[login] = b'"' + login + b'" l2tpd "' + quoted + b'" ' + address + b'\n'
    return rows, logins


def chap_parts(record):
    bad = 'ROLLBACK_DRIFT'
    need(record is not None and (record['mode'], record['gid'], record.get('uid', 0)) == (0o600, 0, 0), bad)
    data = raw(record)
    markers, offset = [], 0
    for line in data.split(b'\n'):
        if line.strip(b' \t\r\v\f') in (CHAP_BEGIN, CHAP_END):
            markers.append((line, offset))
        offset += len(line) + 1
    need([line for line, _ in markers] == [CHAP_BEGIN, CHAP_END], bad)
    start, end = markers[0][1], markers[1][1] + len(CHAP_END) + 1
    need(data[end-1:end] == b'\n', bad)
    block = data[start:end]
    lines = block.split(b'\n')[1:-2]
    need(len(lines) <= 2048, bad)
    rows, addresses = {}, set()
    for line in lines:
        match = CHAP_ROW.fullmatch(line)
        if match is None:
            raise Refusal(bad)
        login, password, address = match.groups()
        # Legacy Install allowed a 256-byte base64url secret; its original
        # block remains removable even without a DB projection on the wire.
        need(not password.startswith(b'@') and login not in rows and address not in addresses, bad)
        rows[login] = line + b'\n'
        addresses.add(address)
    return data[:start], block, data[end:], rows


def check_chap_neighbors(data, logins):
    for source in data.split(b'\n'):
        line = source.removesuffix(b'\r').lstrip(b' \t')
        if not line or line.startswith(b'#'):
            continue
        # Do not interpret a continuation, escaped name or ambiguous active
        # line as unrelated. Inline and full-line comments remain opaque.
        names, count = [], 0
        need(len(line) <= 8192, 'ROLLBACK_DRIFT')
        while line and not line.startswith(b'#'):
            match = CHAP_FOREIGN_TOKEN.match(line)
            if not match:
                raise Refusal('ROLLBACK_DRIFT')
            if count < 2:
                word = match.group()
                need(b'\\' not in word and len(word) <= 255, 'ROLLBACK_DRIFT')
                names.append(word[1:-1] if word.startswith((b'"', b"'")) else word)
            count += 1
            tail = line[match.end():]
            need(not tail or tail[:1] in (b' ', b'\t', b'#'), 'ROLLBACK_DRIFT')
            line = tail.lstrip(b' \t')
        need(count >= 3, 'ROLLBACK_DRIFT')
        login, server = names
        need(login not in logins and not (logins and login == b'*' and server in (b'*', b'l2tpd')), 'ROLLBACK_DRIFT')


def owned_chap(record, backup, expected=None):
    prefix, block, suffix, rows = chap_parts(record)
    if expected is None:
        # Released Install appended LF + managed block to the saved preimage.
        # Authenticate against that install receipt, never the current prefix.
        original = backup['before']['files']['chap']
        need(original is not None and after_match(entry(raw(original) + b'\n' + block), backup['after']['chap']), 'ROLLBACK_DRIFT')
        logins = rows.keys()
    else:
        expected_rows, logins = expected
        need(rows == expected_rows, 'ROLLBACK_DRIFT')
    check_chap_neighbors(prefix, logins)
    check_chap_neighbors(suffix, logins)
    return prefix, suffix, rows


def chap_expected(request, lns):
    if 'currentUsers' in request:
        need(lns is not None, 'ROLLBACK_DRIFT')
        return chap_user_rows(request['currentUsers'], chap_pool(raw(lns), request['network']['clientCidr']))
    return None


def chap_rows_digest(rows):
    return digest(b''.join(rows[key] for key in sorted(rows)))


def remove_chap(record, backup, expected):
    prefix, suffix, rows = owned_chap(record, backup, expected)
    need(record is not None, 'ROLLBACK_DRIFT')
    # Install added one LF. The exact saved prefix proves which byte it owns;
    # never trim an edited prefix. Keep that LF if dropping it would join the
    # original unterminated line to an independently appended suffix.
    original = backup['before']['files']['chap']
    original_bytes = raw(original) if original is not None else None
    if original_bytes is not None and prefix == original_bytes + b'\n':
        if not suffix:
            return original, chap_rows_digest(rows)
        if not original_bytes or original_bytes.endswith(b'\n') or suffix.startswith(b'\n'):
            prefix = original_bytes
    return {**record, 'data': b64(prefix + suffix)}, chap_rows_digest(rows)


def check_swan_profile(backup, record, bad='ROLLBACK_DRIFT'):
    before = backup['before']
    if 'swan' not in before['files']:
        # No enrollment or rebinding of an older manifest.
        need('swan' not in backup['after'] and 'swanGeneration' not in backup, bad)
        return
    generation = backup.get('swanGeneration')
    need('swan' in backup['after'] and before['files']['swan'] is None
         and before['units'][IKE]['ActiveState'] == 'inactive' and not before.get('ikeSockets')
         and swan_inputs(record is not None, bad) == before['swanInputs'], bad)
    if record is None:
        need(backup['phase'] == 'applying' and generation is None, bad)
    else:
        need(generation is not None and record == entry(SWAN_SETTINGS, 0o644)
             and after_match(record, backup['after']['swan']) and remove_generation(SWAN_PROFILE) == generation, bad)
    no_swan_rule()


def load_after(backup, require_all=False):
    current = {key: read(path) for key, path in operation_files(backup['after']).items()}
    check_swan_profile(backup, current.get('swan'))
    original = original_files(backup['before'], current)
    for key, value in current.items():
        need(after_match(value, backup['after'][key]) or (not require_all and value == original[key]),
             'ROLLBACK_DRIFT')
    return current


def rollback(request, path, old_manifest, backup):
    global STAGE
    STAGE = 'COMMAND_FAILED'
    before, d, token = backup['before'], request['network'], request['backupId']
    need(backup['phase'] in ('applying', 'installed'), 'ROLLBACK_DRIFT')
    was_installed = backup['phase'] == 'installed'
    no_jobs(UNITS)
    sidecar = 'bridge' in backup['after']
    neighbors(before, sidecar)
    current = load_after(backup, require_all=backup['phase'] == 'installed')
    need(ike_include_matches(current['starter'], [os.path.basename(NAMES['ike'])] if current['ike'] is not None else []),
         'ROLLBACK_DRIFT')
    boot_enrollment = boot_link() if before.get('installBoot') else None
    need(boot_enrollment == backup.get('bootEnrollment'), 'ROLLBACK_DRIFT')
    need(vpn_empty(allow_socket_policies=True), 'ROLLBACK_DRIFT')
    policy = network_projection(d, token)
    watched = (X, XL, IKE, NET_UNIT, B) if sidecar else (X, XL, IKE, NET_UNIT)
    swan_units = None
    started = None
    partial_start = False
    if 'swan' in current:
        swan_units = {n: unit(n) for n in SWAN_START_UNITS}
        started = backup.get('swanStart')
        if started is None:
            need(not was_installed and all(swan_unstarted(swan_units[n], before, n) for n in SWAN_START_UNITS)
                 and not any(port in (500, 4500, 1701) for _, _, port, _ in sock_rows()), 'ROLLBACK_DRIFT')
        else:
            need(current['swan'] is not None and started == [swan_units[n].get('InvocationID') for n in SWAN_START_UNITS]
                 and (not was_installed or started == backup['runtime']['invocations'][1:4]), 'ROLLBACK_DRIFT')
            removal_dependencies(swan_units, installed=True)
            ike = swan_units[IKE]
            need(removal_native(ike, IKE, before, installed=True) and not ike.get('PassEnvironment'), 'ROLLBACK_DRIFT')
            partial_start = not was_installed
            if partial_start:
                need(removal_native(swan_units[XL], XL, before, installed=True), 'ROLLBACK_DRIFT')
                applying_vpn_ownership(sock_rows(), swan_units)
            else:
                removal_vpn_runtime(sock_rows(), swan_units)
    if was_installed:
        expected = backup['runtime']
        need(policy == {'nft': expected['nft'], 'rule': True, 'route': True}
             and file_generations(current) == expected['files']
             and [unit(n).get('InvocationID') for n in watched] == expected['invocations'], 'ROLLBACK_DRIFT')

    # Do not stop an administrator replacement or unmask a unit. Failed
    # first start can leave a failed (but never active at baseline) stock unit.
    for n in watched:
        info = unit(n)
        need(info['ActiveState'] in ('inactive', 'active', 'failed') and info['LoadState'] != 'masked', 'ROLLBACK_DRIFT')
        if n in (XL, IKE):
            need(native_vpn(info, n) or (info['NeedDaemonReload'] == 'yes' and info['ActiveState'] == 'inactive' and
                 info.get('FragmentPath') == before['units'][n]['FragmentPath']), 'ROLLBACK_DRIFT')
            allowed = ('enabled', 'disabled') if n == XL and boot_enrollment else (before['units'][n]['UnitFileState'],)
            need(info['UnitFileState'] in allowed and
                 info.get('DropInPaths') in (('', DROP) if n == XL else ('',)), 'ROLLBACK_DRIFT')
        if n == NET_UNIT:
            need(info['LoadState'] == 'not-found' or info.get('FragmentPath') == NET, 'ROLLBACK_DRIFT')
        if n == X:
            need(info['FragmentPath'] == before['units'][n]['FragmentPath'] and not info.get('DropInPaths'), 'ROLLBACK_DRIFT')
            if working(info):
                original_invocation = info['InvocationID'] == before['units'][n]['InvocationID']
                xray_users(before['files']['main'] if original_invocation else current['main'], info, sock_rows(), before.get('transit'))
        if n == B and working(info):
            xray_argv(info, BRIDGE)
    if swan_units is not None and partial_start:
        no_jobs(UNITS)
        need(all(unit(n) == info for n, info in swan_units.items()), 'ROLLBACK_DRIFT')
    backup['phase'] = 'rolling-back'
    rolling = entry(encode(backup))
    write(path, old_manifest, rolling)
    for n in SWAN_START_UNITS:
        info = unit(n)
        if swan_units is not None:
            if started is None:
                need(swan_unstarted(info, before, n), 'ROLLBACK_DRIFT')
            else:
                initial = swan_units[n]
                need(info.get('InvocationID') == initial.get('InvocationID'), 'ROLLBACK_DRIFT')
                if partial_start:
                    # Do not rebaseline ownership after recording rollback intent.
                    need(all(info.get(k) == initial.get(k) for k in ('MainPID', 'ControlGroup')), 'ROLLBACK_DRIFT')
                removal_dependencies({n: info}, installed=True)
        if swan_units is not None and partial_start and n == XL:
            ike = unit(IKE)
            need(ike == swan_units[IKE] and removal_native(info, XL, before, installed=True), 'ROLLBACK_DRIFT')
            check_swan_profile(backup, read(SWAN_PROFILE))
            applying_vpn_ownership(sock_rows(), {IKE: ike, XL: info})
            no_jobs(UNITS)
            need(unit(IKE) == ike and unit(n) == info, 'ROLLBACK_DRIFT')
        if n == IKE and 'swan' in current:
            if current['swan'] is None:
                need(read(SWAN_PROFILE) is None and swan_inputs(False, 'ROLLBACK_DRIFT') == before['swanInputs'],
                     'ROLLBACK_DRIFT')
                no_swan_rule()
            else:
                check_swan_profile(backup, read(SWAN_PROFILE))
            if started is not None:
                need(removal_native(info, IKE, before, installed=True) and not info.get('PassEnvironment'), 'ROLLBACK_DRIFT')
                xl = unit(XL)
                if partial_start:
                    need(rollback_quiescent(xl), 'ROLLBACK_DRIFT')
                removal_vpn_runtime(sock_rows(), {IKE: info, XL: xl})
                if partial_start:
                    no_jobs(UNITS)
                    need(unit(XL) == xl and unit(n) == info, 'ROLLBACK_DRIFT')
        if partial_start and n == NET_UNIT:
            # Stopping this dependency must not stop a new dependent generation.
            dependents = {name: unit(name) for name in (XL, IKE)}
            need(all(rollback_quiescent(u) for u in dependents.values()), 'ROLLBACK_DRIFT')
            removal_vpn_runtime(sock_rows(), dependents)
            no_jobs(UNITS)
            need(all(unit(name) == u for name, u in dependents.items()) and unit(n) == info, 'ROLLBACK_DRIFT')
        if info['LoadState'] == 'loaded' and info['ActiveState'] != 'inactive':
            sc('stop', n, wait=14)
            no_jobs(UNITS)
            if unit(n)['ActiveState'] == 'failed':
                sc('reset-failed', n)
    need(vpn_empty() and not any(p == 'udp' and port in (500, 4500, 1701) for p, a, port, owners in sock_rows()),
         'RUNTIME_UNPROVED')
    if policy['rule']:
        command('/usr/sbin/ip', '-4', 'rule', 'del', 'priority', str(PRIORITY), 'from', d['clientCidr'],
                'fwmark', str(d['fwmark']), 'table', str(d['routeTable']))
    if policy['route']:
        command('/usr/sbin/ip', '-4', 'route', 'del', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', str(d['routeTable']))
    if policy['nft'] is not None:
        need(nft_projection(token) == policy['nft'], 'ROLLBACK_DRIFT')
        command('/usr/sbin/nft', 'delete', 'table', 'inet', TABLE)
    paths, originals = operation_files(current), original_files(before, current)
    for k in reversed(operation_order(current)):
        if current[k] != originals[k]:
            if k == 'swan':
                check_swan_profile(backup, read(SWAN_PROFILE))
            write(paths[k], current[k], originals[k])
    if boot_enrollment:
        enroll_boot(before['units'][XL]['FragmentPath'], boot_enrollment)
    for p in (DROP_DIR, NFT_DIR):
        if not directory_absent(p):
            rmdir(p)
    sc('daemon-reload', wait=12)
    if sidecar and (current['bridge'] != originals['bridge'] or not working(unit(B))):
        sc('restart', B, wait=22)
    x = unit(X)
    if current['main'] != before['files']['main'] or not working(x):
        sc('restart', X, wait=22)
    if before.get('ikeSockets'):
        sc('start', IKE, wait=22)
    no_jobs(UNITS)
    neighbors(before, sidecar)
    if 'swan' in current:
        need(swan_inputs(False, STAGE) == before['swanInputs'], STAGE)
    if sidecar:
        bpid = xray_argv(unit(B), BRIDGE)
        handoff = next(i['port'] for i in json.loads(raw(originals['bridge']))['inbounds'] if i['tag'] == 'rebuild-relay-ingress')
        listeners = owned_sockets(sock_rows(), bpid)
        need(all([proto, '127.0.0.1', handoff] in listeners for proto in ('tcp', 'udp')), 'RUNTIME_UNPROVED')
    need({key: read(p) for key, p in paths.items()} == originals and
         (not before.get('installBoot') or boot_link() is None) and
         network_projection(d, token) == {'nft': None, 'rule': False, 'route': False}
         and vpn_empty(allow_socket_policies=bool(before.get('ikeSockets'))), 'RUNTIME_UNPROVED')
    for n in (XL, IKE, NET_UNIT):
        info = unit(n)
        fields = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'DropInPaths', 'FragmentPath')
        need(all(info.get(k) == before['units'][n][k] for k in fields), 'RUNTIME_UNPROVED')
        need((n == IKE and before.get('ikeSockets')) or info.get('MainPID') == before['units'][n]['MainPID'], 'RUNTIME_UNPROVED')
    rows = sock_rows()
    restored_ike = before.get('ikeSockets')
    if restored_ike:
        need(idle_ike(unit(IKE), rows) == restored_ike, 'RUNTIME_UNPROVED')
    reserved = (1701, d['tproxyPort']) if restored_ike else (500, 4500, 1701, d['tproxyPort'])
    need(xray_users(before['files']['main'], unit(X), rows, before.get('transit')) == before['sockets'] and
         not any(port in reserved for p, a, port, owners in rows), 'RUNTIME_UNPROVED')
    backup['phase'] = 'rolled-back'
    write(path, rolling, entry(encode(backup)))


def unique_profile(record):
    def unique(pairs):
        result = dict(pairs)
        # Go's struct parser folds Unicode aliases too (e.g. long s → s).
        need(len({k.casefold() for k, _ in pairs}) == len(pairs), 'CANDIDATE_INVALID')
        return result

    def invalid(_):
        raise Refusal('CANDIDATE_INVALID')

    value = json.loads(raw(record).decode('utf-8'), object_pairs_hook=unique, parse_constant=invalid)
    need(all(type(rows) is list and all(type(row) is dict for row in rows)
             for rows in (value['inbounds'], value['outbounds'], value['routing']['rules'])), 'CANDIDATE_INVALID')
    return value


FOLLOW_RELAY_SOCKS = 'rebuild-relay-ingress'
FOLLOW_RELAY_HOP = 'rebuild-l2tp-handoff'
FOLLOW_RELAY_BLOCK = 'rebuild-l2tp-block'


def follow_relay_reserved(value, shared=False):
    return isinstance(value, str) and (value.startswith('relay-l2tp-')
        or value in (FOLLOW_RELAY_HOP, FOLLOW_RELAY_BLOCK) or (not shared and value == FOLLOW_RELAY_SOCKS))


def follow_relay_refs(value, shared=False):
    if type(value) is dict:
        return any(follow_relay_reserved(k, shared) or follow_relay_refs(v, shared) for k, v in value.items())
    if type(value) is list:
        return any(follow_relay_refs(v, shared) for v in value)
    return follow_relay_reserved(value, shared)


def follow_relay_port_conflict(inbounds, ports):
    for inbound in inbounds:
        for part in str(inbound.get('port', '')).split(','):
            m = re.fullmatch(r'\s*(\d+)(?:-(\d+))?\s*', part)
            if m is None:
                raise Refusal('CANDIDATE_INVALID')
            if any(int(m[1]) <= p <= int(m[2] or m[1]) for p in ports):
                return True
    return False


def follow_relay_tproxy(tag, port):
    return dict(tag=tag, listen='0.0.0.0', port=port, protocol='dokodemo-door',
                settings=dict(network='tcp,udp', followRedirect=True), streamSettings={'sockopt': {'tproxy': 'tproxy'}})


def follow_relay_hop(port):
    return dict(tag=FOLLOW_RELAY_HOP, protocol='socks', settings={'servers': [dict(address='127.0.0.1', port=port)]})


def follow_relay_guard(rule, scope):
    if rule.get('inboundTag') != [scope] or rule.get('outboundTag') != FOLLOW_RELAY_BLOCK:
        return None
    bad = 'CANDIDATE_INVALID'
    keys = set(rule) - {'type', 'inboundTag', 'outboundTag'}
    need(keys in ({'domain'}, {'ip'}) and rule.get('type') == 'field', bad)
    selector = next(iter(keys))
    values = rule[selector]
    need(type(values) is list and values and all(type(v) is str and v for v in values)
         and values == sorted(set(values)), bad)
    values = cast(list[str], values)
    if selector == 'domain':
        need(all(re.fullmatch(r'full:[a-z0-9.-]+', v) for v in values), bad)
    else:
        need('geoip:private' in values, bad)
        for value in values:
            if value != 'geoip:private':
                ipaddress.ip_network(value, strict=False) if '/' in value else ipaddress.ip_address(value)
    return selector, values


def subtract_follow_relay(main, current, side, node_id, tproxy):
    # Inverse of attachLocalFollowRelay, against CURRENT, not the install
    # preimage. Recognize the two fixed listeners, two outbounds and precisely
    # scoped guards. Only canonical shared policy / subscriber denies may lose
    # an inboundTag entry. Never convert a singleton into an unscoped rule.
    ppp, socks, hop, block = ('relay-l2tp-' + node_id, FOLLOW_RELAY_SOCKS, FOLLOW_RELAY_HOP, FOLLOW_RELAY_BLOCK)
    port = 18000 + int(digest(f'cascade-path-ingress:{node_id}:follow-relay-v1'.encode())[:8], 16) % 2000
    bad = 'CANDIDATE_INVALID'
    need(port != tproxy, bad)
    rules = current['routing']['rules']
    reserved = follow_relay_reserved
    ppp_in = follow_relay_tproxy(ppp, tproxy)
    own_in = [i for i in current['inbounds'] if reserved(i.get('tag'))]
    need([i.get('tag') for i in own_in] == [ppp, socks] and encode(own_in[0]) == encode(ppp_in), bad)
    route_only = own_in[1].get('sniffing', {}).get('routeOnly')
    need(type(route_only) is bool, bad)
    socks_in = dict(tag=socks, port=port, listen='127.0.0.1', protocol='socks',
                    settings=dict(auth='noauth', udp=True, ip='127.0.0.1'),
                    sniffing=dict(enabled=True, destOverride=['http', 'tls', 'quic'], routeOnly=route_only))
    need(encode(own_in[1]) == encode(socks_in), bad)
    current['inbounds'] = [i for i in current['inbounds'] if not reserved(i.get('tag'))]
    need(not follow_relay_port_conflict(current['inbounds'] + (side['inbounds'] if side else []), (port, tproxy))
         and not follow_relay_refs(side), bad)

    outbounds = current['outbounds']
    need(outbounds[0].get('protocol') == 'blackhole' and not reserved(outbounds[0].get('tag')), bad)
    need(encode([o for o in outbounds if reserved(o.get('tag'))]) ==
         encode([dict(tag=block, protocol='blackhole'), follow_relay_hop(port)]), bad)
    current['outbounds'] = [o for o in outbounds if not reserved(o.get('tag'))]

    def strings(values):
        return type(values) is list and bool(values) and all(type(v) is str and v for v in values)

    guards = {ppp: [], socks: []}
    policy = {}
    kept = []
    handoff = 0
    plain = {'type', 'inboundTag', 'outboundTag'}
    tags = [i.get('tag') for i in current['inbounds']]
    need(strings(tags) and len(set(tags)) == len(tags), bad)
    subscribers = {t for t in tags if t != 'API_INBOUND' and not t.startswith(('fwd-hop-', 'rebuild-rp-conn-'))}
    transit = {t for t in tags if t.startswith('fwd-hop-')}
    targets = {}
    for o in current['outbounds']:
        need(type(o.get('tag')) is str and o['tag'] not in targets, bad)
        targets[o['tag']] = o.get('protocol')
        tag = o.get('settings', {}).get('reverse', {}).get('tag')
        if tag is not None:
            need(type(tag) is str and tag not in tags and tag not in transit, bad)
            transit.add(tag)
    for i in current['inbounds']:
        for client in i.get('settings', {}).get('clients', []):
            tag = client.get('reverse', {}).get('tag')
            if tag is not None:
                need(type(tag) is str and tag not in targets and i.get('protocol') == 'vless', bad)
                targets[tag] = 'native'
    for rule in rules:
        scope, target = rule.get('inboundTag', []), rule.get('outboundTag')
        need(scope == [] or strings(scope), bad)
        label = rule.get('ruleTag', '')
        need(type(label) is str, bad)
        if scope == [ppp] and target == hop:
            need(set(rule) == plain and rule['type'] == 'field', bad)
            handoff += 1
        elif scope in ([ppp], [socks]) and target == block:
            guards[scope[0]].append(follow_relay_guard(rule, scope[0]))
        elif label.startswith('rebuild-policy-'):
            selector = re.fullmatch(r'rebuild-policy-geo-\d+-(ip|domain)', label)
            keys = plain | {'ruleTag'}
            if selector:
                keys.add(selector[1])
                need(strings(rule.get(selector[1])), bad)
            need((selector or label == 'rebuild-policy-default') and label not in policy and set(rule) == keys
                 and rule['type'] == 'field' and len(scope) > 1 and scope[-1] == socks and len(set(scope)) == len(scope)
                 and set(scope[:-1]) <= subscribers | transit and targets.get(target) in ('blackhole', 'vless', 'vmess', 'native'), bad)
            policy[label] = scope[:-1]
            kept.append({**rule, 'inboundTag': scope[:-1]})
        elif socks in scope:
            # The only unlabelled shared rules are subscriber ACLs targeting
            # the original blackhole. Do not strip from API or tunnel rules.
            need(len(scope) > 1 and scope[-1] == socks and set(scope[:-1]) <= subscribers
                 and set(rule) <= plain | {'ip', 'domain', 'ruleTag'} and rule.get('type') == 'field'
                 and all(strings(rule[k]) for k in ('ip', 'domain') if k in rule)
                 and len(set(scope)) == len(scope) and targets.get(target) == 'blackhole', bad)
            kept.append({**rule, 'inboundTag': scope[:-1]})
        else:
            kept.append(rule)
    need(handoff == 1 and guards[ppp] == guards[socks] and [key for key, _ in guards[ppp]] in (['ip'], ['domain', 'ip'])
         and 'rebuild-policy-default' in policy and all(v == policy['rebuild-policy-default'] for v in policy.values()), bad)
    current['routing']['rules'] = kept
    # Also catch reserved tag references outside the routing rules, e.g.
    # dialerProxy, native reverse tags, or other inbounds with a PPP tag.
    need(not follow_relay_refs(current) and not any(k in current for k in ('observatory', 'burstObservatory'))
         and not current['routing'].get('balancers'), bad)
    candidate = (json.dumps(current, allow_nan=False, separators=(',', ':')) + '\n').encode()
    need(len(candidate) <= MAX_FILE, bad)
    return {'main': {**main, 'data': b64(candidate)}}, port, X


def invert_installed_split(main, side, node_id, tproxy, backup):
    # This is deliberately not a structural inverse for a changed split pair.
    # The caller has already proved both installed file and service generations.
    # Check that the exact original bytes undo only the split composer's delta,
    # including its changes to the pre-existing SOCKS listener and DNS strategy.
    bad = 'CANDIDATE_INVALID'
    orig_main, orig_side = (unique_profile(backup['before']['files']['main']), unique_profile(backup['before']['bridge']))
    ppp, socks, hop, block = ('relay-l2tp-' + node_id, FOLLOW_RELAY_SOCKS, FOLLOW_RELAY_HOP, FOLLOW_RELAY_BLOCK)
    need(not follow_relay_refs(orig_main) and not follow_relay_refs(orig_side, shared=True)
         and not orig_side.get('api') and not side.get('api'), bad)
    listeners = [i for i in orig_side['inbounds'] if i.get('tag') == socks]
    need(len(listeners) == 1, bad)
    listener = listeners[0]
    port = listener.get('port')
    need(type(port) is int and 1 <= port <= 65535 and port not in (tproxy, 500, 4500, 1701)
         and listener.get('listen') == '127.0.0.1' and listener.get('protocol') == 'socks'
         and all(listener['settings'].get(k) == v for k, v in (('auth', 'noauth'), ('ip', '127.0.0.1')))
         and listener['settings'].get('udp') is True, bad)
    need(not follow_relay_port_conflict(orig_main['inbounds'] + [i for i in orig_side['inbounds'] if i is not listener],
                                       (port, tproxy)), bad)
    need(encode(main['inbounds']) == encode(orig_main['inbounds'] + [follow_relay_tproxy(ppp, tproxy)]), bad)
    main['inbounds'].pop()
    sniffing = dict(enabled=True, destOverride=['http', 'tls', 'quic'], routeOnly=True)
    need(encode(side['inbounds']) == encode([{**i, 'sniffing': sniffing} if i is listener else i
                                            for i in orig_side['inbounds']]), bad)
    side['inbounds'] = orig_side['inbounds']
    need(side['routing'].pop('domainStrategy', None) == 'IPOnDemand', bad)
    if 'domainStrategy' in orig_side['routing']:
        side['routing']['domainStrategy'] = orig_side['routing']['domainStrategy']
    handoff_rule = dict(type='field', inboundTag=[ppp], outboundTag=hop)
    guards = []
    for cfg, scope, additions in ((main, ppp, [follow_relay_hop(port)]), (side, socks, [])):
        owned = [dict(tag=block, protocol='blackhole'), *additions]
        need(encode(cfg['outbounds'][-len(owned):]) == encode(owned), bad)
        del cfg['outbounds'][-len(owned):]
        rules = cfg['routing']['rules']
        if cfg is main:
            need(rules.count(handoff_rule) == 1, bad)
            rules.remove(handoff_rule)
        scoped, kept = [], []
        for rule in rules:
            guard = follow_relay_guard(rule, scope)
            if guard is None:
                kept.append(rule)
            else:
                scoped.append(guard)
        guards.append(scoped)
        cfg['routing']['rules'] = kept
    need(guards[0] == guards[1] and [k for k, _ in guards[0]] in (['ip'], ['domain', 'ip'])
         and encode(main) == encode(orig_main) and encode(side) == encode(orig_side), bad)
    return port


def remove_generation(path):
    try:
        st = os.lstat(path)
        return [st.st_dev, st.st_ino, st.st_ctime_ns]
    except FileNotFoundError:
        return None


REMOVE_STOCK_DEPS = {'-.mount', 'system.slice', 'sysinit.target', 'basic.target', 'network.target',
                     'network-online.target', 'nss-lookup.target'}


def removal_dependencies(units, installed):
    # No start/stop propagation to an unrelated unit, including current BRIDGE.
    forward = {X: set(), IKE: set(), NET_UNIT: {X}, XL: {NET_UNIT, IKE}}
    reverse = {X: {NET_UNIT}, IKE: {XL}, NET_UNIT: {XL}, XL: set()}
    for name in units.keys() & forward.keys():
        info = units[name]
        if not installed and name == NET_UNIT and info['LoadState'] == 'not-found':
            continue
        permitted = reverse[name] if installed else set()
        deps = REMOVE_STOCK_DEPS | (forward[name] if installed else set())
        need(all(set(info[k].split()) <= permitted for k in ('RequiredBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo'))
             and all(set(info[k].split()) <= {'shutdown.target'} for k in ('Conflicts', 'ConflictedBy'))
             and all(set(info[k].split()) <= deps for k in ('Requires', 'Wants', 'BindsTo', 'Upholds')), 'ROLLBACK_DRIFT')


def removal_native(info, name, before, installed):
    original = before['units'][name]
    boot_added = name == XL and before.get('installBoot') and installed
    return (native_vpn(info, name) and info['FragmentPath'] == original['FragmentPath']
            and info['UnitFileState'] == ('enabled' if boot_added else original['UnitFileState'])
            and info['DropInPaths'] == (DROP if name == XL and installed else original['DropInPaths'])
            and info.get('Group') in ('', 'root') and not info.get('ExecStopPost')
            and (not info.get('ExecStop') or (name == IKE and re.fullmatch(
                 r'\{ path=/usr/sbin/ipsec ; argv\[\]=/usr/sbin/ipsec stop ; [^{}]*\}', info['ExecStop']))))


def removal_profiles(main, side, node_id, tproxy, backup, units, main_generation, side_generation):
    current = unique_profile(main)
    bridge = unique_profile(side) if side is not None else None
    # Current MAIN owns the handoff after canonical Apply, even with a split
    # install receipt. Do not use that receipt to restore BRIDGE in this case.
    if any(i.get('tag') == FOLLOW_RELAY_SOCKS for i in current['inbounds']):
        return subtract_follow_relay(main, current, bridge, node_id, tproxy)

    after, runtime = backup['after'], backup['runtime']
    if side is None:
        raise Refusal('ROLLBACK_DRIFT')
    need('bridge' in after and len(runtime['invocations']) == 5
         and after_match(main, after['main']) and after_match(side, after['bridge'])
         and main_generation == runtime['files']['main'] and side_generation == runtime['files']['bridge']
         and units[X]['InvocationID'] == runtime['invocations'][0]
         and units[B]['InvocationID'] == runtime['invocations'][4]
         and units[B]['User'] == 'nobody' and units[B]['UnitFileState'] == 'enabled', 'ROLLBACK_DRIFT')
    port = invert_installed_split(current, bridge, node_id, tproxy, backup)
    original = backup['before']
    return {'main': {**main, 'data': original['files']['main']['data']},
            'bridge': {**side, 'data': original['bridge']['data']}}, port, B


def legacy_network(record, d, sidecar):
    need(record in (entry(network_unit(d, sidecar), 0o644),
                    entry(network_unit(d, sidecar, legacy=True), 0o644)), 'ROLLBACK_DRIFT')
    return raw(record) == network_unit(d, sidecar, legacy=True)


def network_unit_loaded(net, legacy):
    pre = net.get('ExecStartPre', '')
    return (net['LoadState'] == 'loaded' and net['FragmentPath'] == NET and not net['DropInPaths']
            and net['UnitFileState'] == 'static' and net['NeedDaemonReload'] == 'no'
            and no_hooks({**net, 'ExecStartPre': ''})
            and not any(net.get(k) for k in ('Environment', 'EnvironmentFiles', 'ExecCondition', 'ExecReload'))
            and net.get('User') in ('', 'root') and net.get('Group') in ('', 'root') and net.get('Type') == 'oneshot'
            and net['MainPID'] == '0' and X in net['After'].split()
            and (X in net['Requires'].split()) == legacy and (X in net['Wants'].split()) != legacy
            and not any(net.get(k) for k in ('BindsTo', 'PartOf', 'Upholds'))
            and (not pre if legacy else re.fullmatch(
                r'\{ path=/usr/bin/systemctl ; argv\[\]=' + re.escape(NETWORK_START_CHECK)
                + r' ; ignore_errors=no ;[^{}]*\}', pre)))


def removal_units(units, before, runtime, restart_bridge, legacy):
    bad = 'ROLLBACK_DRIFT'
    x, xl, ike, net = (units[name] for name in (X, XL, IKE, NET_UNIT))
    need(x['FragmentPath'] == before['units'][X]['FragmentPath'] and working(x), bad)
    need(network_unit_loaded(net, legacy), bad)
    for name, info, invocation, sub in zip((XL, IKE, NET_UNIT), (xl, ike, net), runtime['invocations'][1:],
                                          ('running', 'running', 'exited')):
        if name != NET_UNIT:
            need(removal_native(info, name, before, installed=True), bad)
        if info['ActiveState'] == 'active':
            need(info['InvocationID'] == invocation and info['SubState'] == sub
                 and (name == NET_UNIT or working(info)), bad)
        else:
            # Apply restarts MAIN. systemd can stop its dependents or fail to
            # restart the oneshot (which attempts to add existing policy).
            # Accept only a quiescent service here; the kernel policy still
            # has to match the original installed receipt below.
            need(x['InvocationID'] != runtime['invocations'][0] and info['MainPID'] == '0'
                 and (info['ActiveState'], info['SubState']) in (('inactive', 'dead'), ('failed', 'failed')), bad)
    need(set(xl['Requires'].split()) >= {NET_UNIT, IKE} and set(xl['After'].split()) >= {NET_UNIT, IKE}, bad)
    removal_dependencies(units, installed=True)
    if restart_bridge:
        info = units[B]
        need(all(not info[k] for k in ('RequiredBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo'))
             and all(set(info[k].split()) <= {'shutdown.target'} for k in ('Conflicts', 'ConflictedBy'))
             and all(set(info[k].split()) <= REMOVE_STOCK_DEPS for k in ('Requires', 'Wants', 'BindsTo', 'Upholds')), bad)


def removal_boot(before, backup, runtime):
    receipt = backup.get('bootEnrollment')
    if before['units'][XL]['UnitFileState'] == 'disabled':
        target = before['units'][XL]['FragmentPath']
        need(before.get('installBoot') is True and target == SYSTEM + '/' + XL
             and type(receipt) is list and len(receipt) == 4 and receipt[0] == target
             and runtime.get('bootEnrollment') == receipt and boot_link() == receipt, 'ROLLBACK_DRIFT')
        return receipt
    need(before['units'][XL]['UnitFileState'] == 'enabled' and not before.get('installBoot')
         and receipt is None and runtime.get('bootEnrollment') is None, 'ROLLBACK_DRIFT')
    return None


def rollback_quiescent(info):
    return (info['ActiveState'], info['SubState'], info['MainPID']) == ('inactive', 'dead', '0')


def removal_vpn_runtime(rows, units):
    vpn_stop_checks(rows, units, require_xl_listener=True)


def applying_vpn_ownership(rows, units):
    # The caller already matched the persisted start receipt. An active XL
    # invocation still needs a proven PID; it need not have bound UDP/1701.
    xl = units[XL]
    need(xl['ActiveState'] != 'active' or working(xl), 'RUNTIME_UNPROVED')
    vpn_stop_checks(rows, units, require_xl_listener=False)


def vpn_listener_ownership(rows, units, *, require_xl_listener):
    xl, ike = units[XL], units[IKE]
    lns_active, ike_active = (info['ActiveState'] == 'active' for info in (xl, ike))
    lns_rows = [(p, owners) for p, _, n, owners in rows if n == 1701]
    ike_rows = [(p, n, owners) for p, _, n, owners in rows if n in (500, 4500)]
    lns_ready = bool(lns_rows) == lns_active or (not require_xl_listener and not lns_rows)
    need(lns_ready and all(p == 'udp' and owners == [xl['MainPID']] for p, owners in lns_rows)
         and {n for _, n, _ in ike_rows} == ({500, 4500} if ike_active else set())
         and all(p == 'udp' and owners and all(in_cgroup(pid, ike) for pid in owners) for p, _, owners in ike_rows),
         'RUNTIME_UNPROVED')


def vpn_stop_checks(rows, units, *, require_xl_listener):
    vpn_listener_ownership(rows, units, require_xl_listener=require_xl_listener)
    ike_active = units[IKE]['ActiveState'] == 'active'
    need(vpn_empty(allow_socket_policies=ike_active), 'ROLLBACK_DRIFT')
    if ike_active:
        # Don't stop a foreign connection or an in-flight negotiation.
        status = command('/usr/sbin/ipsec', 'statusall')
        match = re.search(rb'^Connections:[ \t]*\n(.*?)^Security Associations \(0 up, 0 connecting\):\s*(?:none\s*)?\Z',
                          status, re.M | re.S)
        need(match is not None and set(re.findall(rb'^\s*([^\s:]+):', match[1], re.M)) == {b'celerity-l2tp'},
             'ROLLBACK_DRIFT')


def removal_sockets(rows, units, d, handoff, handoff_unit):
    x, xl, ike = (units[name] for name in (X, XL, IKE))
    tproxy = d['tproxyPort']
    expected = {('tcp', tproxy), ('udp', tproxy), ('tcp', handoff), ('udp', handoff)}
    for p, address, n, owners in rows:
        if n in (tproxy, handoff):
            need((p, n) in expected and owners == [units[handoff_unit]['MainPID'] if n == handoff else x['MainPID']]
                 and (n != handoff or address == '127.0.0.1'), 'RUNTIME_UNPROVED')
            expected.discard((p, n))
    need(not expected, 'RUNTIME_UNPROVED')
    return {tproxy, 500, 4500, 1701} | ({handoff} if handoff_unit == X else set())


def removal_xray_sockets(rows, pid):
    need(all(owners == [pid] for _, _, _, owners in rows if pid in owners), 'RUNTIME_UNPROVED')
    return owned_sockets(rows, pid)


def removal_udp_endpoints(profile):
    # Read the admitted post-Remove profile, not a port range or the current
    # socket inventory. TPROXY and the handoff are checked separately.
    bad = 'CANDIDATE_INVALID'

    def fields(obj):
        # unique_profile has already rejected case-folded duplicate keys.
        need(type(obj) is dict, bad)
        return {k.casefold(): v for k, v in obj.items()}

    def string_list(value):
        if type(value) is str:
            return value.split(',')
        need(type(value) is list and all(type(v) is str for v in value), bad)
        return value

    config = unique_profile(profile)
    need(not fields(config).get('transport'), bad)
    endpoints = set()
    for row in config['inbounds']:
        inbound = fields(row)
        stream = fields(inbound.get('streamsettings', {}))
        transport = stream.get('network', 'tcp')
        need(stream.get('method') is None and type(transport) is str, bad)
        transport = transport.lower()
        if transport in ('xhttp', 'splithttp'):
            # Xray's splithttp listener uses UDP for TLS ALPN ["h3"].
            # Do not project an unreviewed transport as TCP-only.
            security = stream.get('security', 'none')
            need(type(security) is str and security.lower() in ('', 'none', 'reality', 'tls'), bad)
            if security.lower() == 'tls':
                alpn = string_list(fields(stream.get('tlssettings', {})).get('alpn', []))
                need('h3' not in alpn, bad)
        else:
            need(transport in ('tcp', 'raw', 'ws', 'websocket', 'grpc', 'httpupgrade'), bad)

        protocol = inbound.get('protocol')
        if protocol == 'vless':
            continue  # proxied UDP over a stream does not imply a UDP bind
        settings = fields(inbound.get('settings', {}))
        if protocol == 'socks':
            # UDP ASSOCIATE is a fixed bind in older cores but per-session
            # in newer cores. Only the separately guarded handoff is supported.
            need(settings.get('udp', False) is False, bad)
            continue
        need(protocol == 'dokodemo-door', bad)
        # DokodemoConfig.Network overrides AllowedNetwork; nil defaults to TCP.
        networks = settings.get('network')
        if networks is None:
            networks = settings.get('allowednetwork')
        networks = ['tcp'] if networks is None else [v.lower() for v in string_list(networks)]
        need(networks and set(networks) <= {'tcp', 'udp'}, bad)
        if 'udp' in networks:
            port, listen = inbound.get('port'), inbound.get('listen', '0.0.0.0')
            need(type(port) is int and 1 <= port <= 65535 and type(listen) is str and '%' not in listen, bad)
            try:
                address = ipaddress.ip_address(listen)
            except ValueError:
                raise Refusal(bad) from None
            endpoint = (str(address) if address.version == 4 else f'[{address}]', port)
            need(endpoint not in endpoints, bad)
            endpoints.add(endpoint)
    return endpoints


def removal_main_sockets(rows, pid, reserved, udp_endpoints):
    # ss -lu reports unconnected outbound sockets too. Their tuples can
    # change between preview, restart and readback; keep only proved binds.
    tcp = [row for row in removal_xray_sockets(rows, pid) if row[0] == 'tcp' and row[2] not in reserved]
    need(all(port not in reserved for _, port in udp_endpoints), 'RUNTIME_UNPROVED')
    seen, udp = set(), []
    for proto, address, port, owners in rows:
        if proto != 'udp':
            continue
        matches = [(address, port)] if address != '*' else [('0.0.0.0', port), ('[::]', port)]
        matches = udp_endpoints.intersection(matches)
        if matches:
            need(len(matches) == 1 and not seen.intersection(matches) and owners == [pid], 'RUNTIME_UNPROVED')
            seen.update(matches)
            udp.append([proto, address, port])
    need(seen == udp_endpoints, 'RUNTIME_UNPROVED')
    return sorted(tcp + udp)


def owned_installation(request):
    bad = 'ROLLBACK_DRIFT'
    token = request['backupId']
    path, manifest, backup = read_manifest(token)
    need(backup['phase'] == 'installed' and backup['machineId'] == request['machineId']
         and backup['backupId'] == token and encode(backup['network']) == encode(request['network'])
         and backup['before']['boot'] == boot(), bad)
    intent = os.path.join(os.path.dirname(path), 'remove-attempt.json')
    need(directory_absent(intent), bad)
    return path, manifest, backup, intent


def apply_network_snapshot(d, token, backup, record, generation, *, listeners_required=True):
    bad = 'ROLLBACK_DRIFT'
    before, runtime = backup['before'], backup['runtime']
    legacy = legacy_network(record, d, 'bridge' in backup['after'])
    need(read(NET, 65536) == record and remove_generation(NET) == generation, bad)
    for key in ('drop', 'nft'):
        p = NAMES[key]
        need(after_match(read(p), backup['after'][key]) and remove_generation(p) == runtime['files'][key], bad)
    removal_boot(before, backup, runtime)
    no_jobs(UNITS)
    units = {n: unit(n) for n in UNITS}
    removal_units(units, before, runtime, False, legacy)
    xpid = xray_argv(units[X])
    # A sidecar may be stopped by putPair even if its replacement will be
    # empty. Neither it nor MAIN may propagate stop outside the old exact edge.
    for name in (X, B):
        info = units[name]
        if name == B and info['LoadState'] == 'not-found':
            continue
        need(info['LoadState'] == 'loaded' and info['NeedDaemonReload'] == 'no' and no_hooks(info)
             and not any(info.get(k) for k in ('ExecCondition', 'ExecReload', 'DropInPaths'))
             and set(info['RequiredBy'].split()) == ({NET_UNIT} if name == X and legacy else set())
             and not any(info[k] for k in ('BoundBy', 'ConsistsOf', 'PropagatesStopTo'))
             and all(set(info[k].split()) <= {'shutdown.target'} for k in ('Conflicts', 'ConflictedBy')), bad)
    need(set(units[NET_UNIT]['RequiredBy'].split()) == {XL}
         and not any(units[n][k] for n in (NET_UNIT, XL, IKE) for k in ('BindsTo', 'PartOf', 'PropagatesStopTo')), bad)
    # Unlike Remove, a negotiated IPsec SA and a live PPP session are allowed.
    # Check their supervisor generations and listener ownership, not emptiness.
    vpn = (XL, IKE, NET_UNIT)
    need(all(units[n]['ActiveState'] == 'active' for n in vpn), bad)
    rows = sock_rows()
    lns = [owners for proto, _, port, owners in rows if proto == 'udp' and port == 1701]
    need(lns and all(owners == [units[XL]['MainPID']] for owners in lns), bad)
    listeners = [(proto, addr, owners) for proto, addr, port, owners in rows if port == d['tproxyPort']]
    need(all(addr in ('0.0.0.0', '*', '[::]') and owners == [xpid] for _, addr, owners in listeners), bad)
    ready = {proto for proto, _, _ in listeners} == {'tcp', 'udp'}
    need(ready or not listeners_required, 'RUNTIME_UNPROVED')
    policy = network_projection(d, token, removing=True)
    need(policy == {'nft': runtime['nft'], 'rule': True, 'route': True} and policy['nft'] is not None, bad)
    no_jobs(UNITS)
    return legacy, [[units[n][key] for key in ('InvocationID', 'MainPID', 'ControlGroup')] for n in vpn], units[X]['InvocationID'], ready


def apply_network(request, action):
    global NETWORK_UPGRADE_ENTERED
    token, d = request['backupId'], request['network']
    path, manifest, backup, _ = owned_installation(request)
    record, generation = read(NET, 65536), remove_generation(NET)
    need(after_match(record, backup['after']['net']) and generation == backup['runtime']['files']['net'], 'ROLLBACK_DRIFT')
    legacy, stable, main_invocation, _ = apply_network_snapshot(d, token, backup, record, generation)
    if legacy and action == 'prepare-apply-network':
        replacement = entry(network_unit(d, 'bridge' in backup['after']), 0o644)
        pin = digest(raw(replacement))
        # Do not adopt a partial file/manager/receipt transition on replay.
        # The intent retains the exact old receipt and the intended new bytes.
        pending = entry(encode({**backup, 'phase': 'network-upgrading', 'networkUpgrade': pin}))
        need(apply_network_snapshot(d, token, backup, record, generation)[:3]
             == (True, stable, main_invocation), 'ROLLBACK_DRIFT')
        NETWORK_UPGRADE_ENTERED = True
        write(path, manifest, pending)
        need(remove_generation(NET) == generation, 'ROLLBACK_DRIFT')
        write(NET, record, replacement)
        generation = remove_generation(NET)
        sc('daemon-reload', wait=12)
        need(apply_network_snapshot(d, token, backup, replacement, generation)[:3]
             == (False, stable, main_invocation), 'ROLLBACK_DRIFT')
        backup['after']['net'] = {**replacement, 'data': pin}
        backup['runtime']['files']['net'] = generation
        manifest = entry(encode(backup))
        write(path, pending, manifest)
        need(read(path, 2 * MAX_FILE) == manifest, 'ROLLBACK_DRIFT')
        legacy = False
    need(action != 'prepare-apply-network' or not legacy, 'RUNTIME_UNPROVED')
    proof = digest(encode([digest(raw(manifest)), generation, stable]))
    if action in ('verify-apply-network', 'restart-apply-network'):
        need(not legacy and proof == request['proof'], 'RUNTIME_UNPROVED')
    if action == 'restart-apply-network':
        # Final effective-graph observation and the actual restart share the
        # DIRECT flock; no manager reload or separate SSH channel intervenes.
        NETWORK_UPGRADE_ENTERED = True
        sc('restart', X, wait=45)
        until = min(DEADLINE, time.monotonic() + 6)
        while True:
            new_legacy, new_stable, active_invocation, ready = apply_network_snapshot(
                d, token, backup, record, generation, listeners_required=False)
            need(not new_legacy and new_stable == stable and active_invocation != main_invocation, 'RUNTIME_UNPROVED')
            need(time.monotonic() < until, 'RUNTIME_UNPROVED')
            if ready:
                break
            time.sleep(0.2)
    return {'ok': True, 'backupId': token, 'proof': proof}


def sync_chap(request, *, write_changes):
    global CHAP_ENTERED
    bad = 'ROLLBACK_DRIFT'
    path, manifest, backup, intent = owned_installation(request)
    before, runtime = backup['before'], backup['runtime']
    no_jobs(UNITS)
    removal_boot(before, backup, runtime)
    records = {}
    for key, file in operation_files(backup['after']).items():
        if key in ('main', 'bridge', 'chap'):
            continue
        generation = remove_generation(file)
        records[key] = read(file)
        need(after_match(records[key], backup['after'][key]) and generation == runtime['files'][key]
             and remove_generation(file) == generation, bad)
    check_swan_profile(backup, records.get('swan'), bad)
    pool = chap_pool(raw(records['lns']), request['network']['clientCidr'])
    current_rows, current_logins = chap_user_rows(request['currentUsers'], pool)
    desired_rows, desired_logins = chap_user_rows(request['desiredUsers'], pool)
    revoked = request.get('revokedLogin')
    if 'revokedLogin' in request:
        need(type(revoked) is str and re.fullmatch(CHAP_LOGIN, revoked.encode('ascii'))
             and revoked != 'relay-bootstrap', 'CANDIDATE_INVALID')
        current = {u['login']: u for u in request['currentUsers']}
        desired = {u['login']: u for u in request['desiredUsers']}
        need(revoked in current and (revoked not in desired or desired[revoked] == {**current[revoked], 'enabled': False})
             and {k: u for k, u in desired.items() if k != revoked} ==
                 {k: u for k, u in current.items() if k != revoked}, 'CANDIDATE_INVALID')
    xl = unit(XL)
    need(all(read(p, 262144) == record for p, record in before['globalFiles'].items())
         and removal_native(xl, XL, before, installed=True)
         and ((working(xl) and xl['InvocationID'] == runtime['invocations'][1])
              or rollback_quiescent(xl) or (xl['ActiveState'], xl['SubState'], xl['MainPID']) == ('failed', 'failed', '0')), bad)
    target = NAMES['chap']
    record = read(target)
    prefix, suffix, rows = owned_chap(record, backup, (current_rows, current_logins | desired_logins))
    need(record is not None, bad)
    after = record
    if rows != desired_rows:
        data = prefix + CHAP_BEGIN + b'\n' + b''.join(desired_rows[k] for k in sorted(desired_rows)) + CHAP_END + b'\n' + suffix
        need(len(data) <= MAX_FILE, bad)
        after = {**record, 'data': b64(data)}
    need(read(path, 2 * MAX_FILE) == manifest and directory_absent(intent) and read(target) == record, bad)
    changed = after != record
    if write_changes and changed:
        # The control-plane intent owns DB settlement. Do not accept the desired
        # projection in place of current, or attempt a physical retry/rollback.
        CHAP_ENTERED = True
        write(target, record, after)
    reply = {'ok': True, 'backupId': request['backupId'], 'changed': changed}
    if write_changes and revoked is not None:
        # Even a previously disabled row can have surviving authenticated calls.
        CHAP_ENTERED = True
        reply.update(revoke_ppp(request, {**request, 'currentUsers': request['desiredUsers']}, after, path, manifest, xl))
    return reply


def observe_removal(request, *, quiescent=False):
    bad = 'ROLLBACK_DRIFT'
    token, d = request['backupId'], request['network']
    path, manifest, backup, intent = owned_installation(request)
    before, runtime = backup['before'], backup['runtime']
    no_jobs(UNITS)
    boot_enrollment = removal_boot(before, backup, runtime)
    original_ike = before.get('ikeSockets', [])
    need(bool(original_ike) == (before['units'][IKE]['ActiveState'] == 'active'), bad)
    paths = operation_files({'swan': None} if 'swan' in backup['after'] else {})
    current = {k: read(p) for k, p in paths.items()}
    check_swan_profile(backup, current.get('swan'), bad)
    main = current['main']
    if main is None:
        raise Refusal(bad)
    generations = file_generations(current, include_chap=False)
    # Apply can replace Xray profiles; CHAP owns only its managed rows. Other
    # owned files must still be the exact installed generation and bytes.
    need(all(after_match(current[k], backup['after'][k]) and generations[k] == runtime['files'][k]
             for k in paths if k not in ('main', 'chap')), bad)
    expected_chap = chap_expected(request, current['lns'])
    chap_after, chap_digest = remove_chap(current['chap'], backup, expected_chap)
    removal_owned_dirs()
    need(ike_include_matches(current['starter'], [os.path.basename(NAMES['ike'])]), bad)
    side, side_generation = read(BRIDGE), remove_generation(BRIDGE)
    need(all(read(p, 262144) == r for p, r in before['globalFiles'].items()), bad)
    units = {n: unit(n) for n in UNITS}
    b = units[B]
    need(b['ActiveState'] in ('active', 'inactive') and b['NeedDaemonReload'] == 'no'
         and (working(b) and side is not None if b['ActiveState'] == 'active' else b['MainPID'] == '0'), bad)
    profiles, handoff, handoff_unit = removal_profiles(current['main'], side, request['nodeId'], d['tproxyPort'],
                                                       backup, units, generations['main'], side_generation)
    if b['ActiveState'] == 'active':
        xray_argv(b, BRIDGE)
    removal_units(units, before, runtime, 'bridge' in profiles,
                  legacy_network(current['net'], d, 'bridge' in backup['after']))
    if quiescent:
        # An inactive unit alone does not prove the supported Apply layout.
        session_need(rollback_quiescent(units[XL])
                     and units[X]['InvocationID'] != runtime['invocations'][0])
    policy = network_projection(d, token, removing=True)
    need(policy == {'nft': runtime['nft'], 'rule': True, 'route': True} and policy['nft'] is not None, bad)
    rows = sock_rows()
    if quiescent:
        # PPP absence does not require IKE/XFRM to be idle. Keep listener
        # ownership and the PPP guard; Remove still requires full VPN idleness.
        vpn_listener_ownership(rows, units, require_xl_listener=True)
        need(ppp_empty(), bad)
    else:
        removal_idle(request, rows, units)
    reserved = removal_sockets(rows, units, d, handoff, handoff_unit)
    transit = request.get('transit', before.get('transit'))
    xray_users(current['main'], units[X], rows, transit)
    udp_endpoints = removal_udp_endpoints(profiles['main'])
    sockets = removal_main_sockets(rows, units[X]['MainPID'], reserved, udp_endpoints)
    bridge_sockets = removal_xray_sockets(rows, b['MainPID'])
    binary = remove_generation(XRAY)
    need(binary is not None, bad)
    manifest_generation = remove_generation(path)
    baseline = digest(encode([request['nodeId'], digest(raw(manifest)), manifest_generation, generations, boot_enrollment,
                              current['main'], {k: digest(raw(v)) for k, v in profiles.items()}, binary,
                              side, side_generation, units, policy, sockets, bridge_sockets, sorted(reserved),
                              handoff, handoff_unit, transit, chap_digest]))
    return dict(baseline=baseline, intent=intent, path=path, manifest=manifest, before=before, current=current,
                profiles=profiles, units=units, side=side, side_generation=side_generation, sockets=sockets,
                udp_endpoints=udp_endpoints,
                bridge_sockets=bridge_sockets, retained_handoff=handoff if handoff_unit == B else None,
                reserved=reserved, policy=policy, generations=generations, binary=binary,
                boot_enrollment=boot_enrollment, ike_sockets=original_ike, manifest_generation=manifest_generation,
                transit=transit, chap_after=chap_after, chap_digest=chap_digest, chap_expected=expected_chap, chap_backup=backup,
                **({'swanBackup': backup} if 'swan' in current else {}))


def removal_owned_dirs():
    for folder, owned in ((NFT_DIR, NFT_FILE), (DROP_DIR, DROP)):
        with directory(folder) as fd:
            need(os.listdir(fd) == [os.path.basename(owned)], 'ROLLBACK_DRIFT')


def removal_neighbors(state):
    # BRIDGE is checked separately against the selected layout and invocation.
    need(all(read(p, 262144) == r for p, r in state['before']['globalFiles'].items())
         and read(state['path'], 2 * MAX_FILE) == state['manifest']
         and remove_generation(state['path']) == state['manifest_generation']
         and boot() == state['before']['boot'] and remove_generation(XRAY) == state['binary'], 'RUNTIME_UNPROVED')


def removal_units_after(state, restore_ike=False):
    before = state['before']
    units = {n: unit(n) for n in (X, XL, IKE, NET_UNIT)}
    keys = ('LoadState', 'UnitFileState', 'DropInPaths', 'FragmentPath')
    for n in (XL, IKE, NET_UNIT):
        after, original = units[n], before['units'][n]
        need(all(after.get(k) == original[k] for k in keys)
             and after['NeedDaemonReload'] == 'no', 'RUNTIME_UNPROVED')
        if n != NET_UNIT:
            need(removal_native(after, n, before, installed=False), 'RUNTIME_UNPROVED')
        if n == IKE and restore_ike:
            need(working(after) and after['SubState'] == original['SubState']
                 and after['InvocationID'] not in (original['InvocationID'], state['units'][IKE]['InvocationID']),
                 'RUNTIME_UNPROVED')
        else:
            need((after['ActiveState'], after['SubState'], after['MainPID']) == ('inactive', 'dead', '0'),
                 'RUNTIME_UNPROVED')
    x = units[X]
    need(all(x.get(k) == state['units'][X].get(k) for k in ('FragmentPath', 'UnitFileState', 'User', 'Group', 'DropInPaths'))
         and working(x), 'RUNTIME_UNPROVED')
    removal_dependencies(units, installed=False)
    return units


def removal_files_after(state):
    before = state['before']
    paths = operation_files(state['current'])
    expected = {**before['files'], 'main': state['profiles']['main'], 'chap': state['chap_after']}
    need(all(read(p) == expected[k] for k, p in paths.items())
         and all(directory_absent(p) for p in (DROP_DIR, NFT_DIR))
         and (state['boot_enrollment'] is None or boot_link() is None)
         and ike_include_matches(before['files']['starter'], []), 'RUNTIME_UNPROVED')
    if 'swan' in paths:
        need(swan_inputs(False, 'RUNTIME_UNPROVED') == before['swanInputs'], 'RUNTIME_UNPROVED')


def removal_bridge_unit(state, restarted=False):
    b, old = unit(B), state['units'][B]
    keys = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'DropInPaths', 'FragmentPath', 'NeedDaemonReload', 'User', 'Group')
    need(all(b.get(k) == old.get(k) for k in keys), 'RUNTIME_UNPROVED')
    if restarted:
        need(b['InvocationID'] != old['InvocationID'], 'RUNTIME_UNPROVED')
    else:
        need(all(b[k] == old[k] for k in ('InvocationID', 'MainPID')), 'RUNTIME_UNPROVED')
    if b['ActiveState'] == 'active':
        xray_argv(b, BRIDGE)
    return b


def removal_bridge_sockets(state, rows, b):
    need(removal_xray_sockets(rows, b['MainPID']) == state['bridge_sockets'], 'RUNTIME_UNPROVED')
    port = state['retained_handoff']
    if port is not None:
        need(sorted((p, a, owners) for p, a, n, owners in rows if n == port)
             == [(p, '127.0.0.1', [b['MainPID']]) for p in ('tcp', 'udp')], 'RUNTIME_UNPROVED')


def removal_xray_ready(state, split):
    until = min(DEADLINE, time.monotonic() + 6)
    while True:
        no_jobs(UNITS)
        rows, x = sock_rows(), unit(X)
        need(not any(n in state['reserved'] for _, _, n, _ in rows), 'RUNTIME_UNPROVED')
        try:
            need(x['InvocationID'] != state['units'][X]['InvocationID'], 'RUNTIME_UNPROVED')
            xray_users(state['profiles']['main'], x, rows, state.get('transit'))
            need(removal_main_sockets(rows, x['MainPID'], state['reserved'], state['udp_endpoints'])
                 == state['sockets'], 'RUNTIME_UNPROVED')
            b = removal_bridge_unit(state, restarted=split)
            removal_bridge_sockets(state, rows, b)
            return x, b
        except Refusal as error:
            if str(error) not in ('PROFILE_USERS', 'RUNTIME_UNPROVED') or time.monotonic() >= until:
                raise
            time.sleep(0.2)


def removal_ike_ready(state):
    until = min(DEADLINE, time.monotonic() + 6)
    while True:
        no_jobs(UNITS)
        ike = unit(IKE)
        try:
            need(idle_ike(ike, sock_rows()) == state['ike_sockets'], 'RUNTIME_UNPROVED')
            return ike['InvocationID']
        except Refusal as error:
            if str(error) not in ('PREREQUISITE', 'RUNTIME_UNPROVED') or time.monotonic() >= until:
                raise
            time.sleep(0.2)


def remove_installation(request, state):
    global REMOVE_ENTERED, STAGE
    token, d = request['backupId'], request['network']
    before, current, profiles, units = (state[k] for k in ('before', 'current', 'profiles', 'units'))
    policy, reserved, sockets = (state[k] for k in ('policy', 'reserved', 'sockets'))
    boot_enrollment, restore_ike = state['boot_enrollment'], bool(state['ike_sockets'])
    split = 'bridge' in profiles
    STAGE = 'RUNTIME_UNPROVED'
    no_jobs(UNITS)
    need(boot_enrollment is None or boot_link() == boot_enrollment, 'ROLLBACK_DRIFT')
    if 'swan' in current:
        check_swan_profile(state['swanBackup'], read(SWAN_PROFILE))

    def live_chap():
        record = read(NAMES['chap'])
        restored, chap_digest = remove_chap(record, state['chap_backup'], state['chap_expected'])
        need(chap_digest == state['chap_digest'], 'ROLLBACK_DRIFT')
        return record, restored

    live_chap()
    if 'expectedCensus' in request:
        # Still under the exclusive DIRECT flock. A panel recount and prepare
        # snapshot cannot authorize a write against a busy or unknown census.
        census = relay_session_census(request, state['baseline'] if rollback_quiescent(units[XL]) else None)
        if census['activeIpsec'] is not None:
            need(census['activeIpsec'] == 0, 'REMOVE_IPSEC_BUSY')
        session_need(census['activeSessions'] == census['activeIpsec'] == 0
                     and census['census'] == request['expectedCensus'])
    else:
        # Older trusted callers don't supply a PPP census token. They still
        # need a positive IPsec zero, not an unreadable/unrecognized status.
        count, _ = ipsec_session_sample(request)
        need(count == 0, 'REMOVE_IPSEC_BUSY')
    # Keep the original residual guards, including unscoped/foreign state.
    removal_idle(request, sock_rows(), units)
    # Retain the install manifest unchanged. Durable no-replace intent
    # prevents blind replay even if the first stop's result is unknown.
    REMOVE_ENTERED = True
    write(state['intent'], None, entry(encode({'baseline': state['baseline']})))
    for name in (XL, IKE, NET_UNIT):
        fresh = {n: unit(n) for n in (X, XL, IKE, NET_UNIT)}
        removal_dependencies(fresh, installed=True)
        info = fresh[name]
        need(info == units[name], 'ROLLBACK_DRIFT')
        if name in (XL, IKE):
            need(removal_native(info, name, before, installed=True), 'ROLLBACK_DRIFT')
        if info['ActiveState'] == 'active':
            if name in (XL, IKE):
                removal_vpn_runtime(sock_rows(), fresh)
            if name == IKE and 'swan' in current:
                check_swan_profile(state['swanBackup'], read(SWAN_PROFILE))
            sc('stop', name, wait=14)
            no_jobs(UNITS)
        elif info['ActiveState'] == 'failed':
            sc('reset-failed', name)
            no_jobs(UNITS)
        after = unit(name)
        # xl2tpd exits 1 on SIGTERM even when systemctl stop itself succeeds.
        if (name == XL and info['ActiveState'] == 'active'
                and (after['ActiveState'], after['SubState'], after['MainPID']) == ('failed', 'failed', '0')):
            sc('reset-failed', name)
            no_jobs(UNITS)
            after = unit(name)
        need((after['ActiveState'], after['SubState'], after['MainPID']) == ('inactive', 'dead', '0'), STAGE)
    need(vpn_empty() and not any(n in (500, 4500, 1701) for _, _, n, _ in sock_rows())
         and network_projection(d, token, removing=True) == policy, STAGE)
    removal_neighbors(state)
    removal_owned_dirs()
    need(file_generations(current, include_chap=False) == state['generations'] and (boot_enrollment is None or boot_link() == boot_enrollment),
         'ROLLBACK_DRIFT')
    live_chap()
    # Keep the ingress firewall in place until the owned listeners are gone.
    x = unit(X)
    need(all(x[k] == units[X][k] for k in ('InvocationID', 'MainPID')), STAGE)
    removal_bridge_unit(state)
    need(read(BRIDGE) == state['side'] and remove_generation(BRIDGE) == state['side_generation'], STAGE)
    side_generation = state['side_generation']
    if split:
        write(BRIDGE, state['side'], profiles['bridge'])
        side_generation = remove_generation(BRIDGE)
    paths = operation_files(current)
    for k in reversed(operation_order(current)):
        if k == 'chap':
            # Re-read the foreign bytes at the actual write boundary; only the
            # owned rows are bound by the preview and the census.
            record, state['chap_after'] = live_chap()
            write(paths[k], record, state['chap_after'])
            continue
        need(remove_generation(paths[k]) == state['generations'][k], STAGE)
        restored = profiles[k] if k == 'main' else before['files'][k]
        if current[k] != restored:
            if k == 'swan':
                check_swan_profile(state['swanBackup'], read(SWAN_PROFILE))
            write(paths[k], current[k], restored)
    if boot_enrollment is not None:
        enroll_boot(before['units'][XL]['FragmentPath'], boot_enrollment)
    main_generation = remove_generation(MAIN)

    def profiles_unchanged():
        need(read(MAIN) == profiles['main'] and remove_generation(MAIN) == main_generation
             and read(BRIDGE) == profiles.get('bridge', state['side'])
             and remove_generation(BRIDGE) == side_generation, STAGE)

    for folder in (DROP_DIR, NFT_DIR):
        rmdir(folder)
    sc('daemon-reload', wait=12)
    no_jobs(UNITS)
    removal_neighbors(state)
    removal_files_after(state)
    pre_restart = removal_units_after(state)[X]
    need(all(pre_restart[k] == units[X][k] for k in ('InvocationID', 'MainPID')), STAGE)
    xray_argv(pre_restart)
    profiles_unchanged()
    removal_bridge_unit(state)
    need(remove_generation(XRAY) == state['binary'], STAGE)
    sc('restart', X, wait=22)
    if split:
        no_jobs(UNITS)
        removal_bridge_unit(state)
        profiles_unchanged()
        need(remove_generation(XRAY) == state['binary'], STAGE)
        sc('restart', B, wait=22)
    x, b = removal_xray_ready(state, split)
    profiles_unchanged()
    need(remove_generation(XRAY) == state['binary'] and network_projection(d, token, removing=True) == policy, STAGE)
    command('/usr/sbin/ip', '-4', 'rule', 'del', 'priority', str(PRIORITY), 'from', d['clientCidr'], 'fwmark',
            str(d['fwmark']), 'table', str(d['routeTable']))
    need(network_projection(d, token, removing=True) == {**policy, 'rule': False}, STAGE)
    command('/usr/sbin/ip', '-4', 'route', 'del', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', str(d['routeTable']))
    need(network_projection(d, token, removing=True) == {**policy, 'rule': False, 'route': False}, STAGE)
    command('/usr/sbin/nft', 'delete', 'table', 'inet', TABLE)
    empty_policy = {'nft': None, 'rule': False, 'route': False}
    restored_invocation = None
    if restore_ike:
        # Only restart a previously running starter, after its original
        # inputs/dependencies are back and every install-only port is empty.
        no_jobs(UNITS)
        removal_neighbors(state)
        removal_files_after(state)
        removal_units_after(state)
        need(vpn_empty() and not any(n in reserved for _, _, n, _ in sock_rows())
             and network_projection(d, token, removing=True) == empty_policy, STAGE)
        sc('start', IKE, wait=22)
        restored_invocation = removal_ike_ready(state)
    no_jobs(UNITS)
    after = removal_units_after(state, restore_ike=restore_ike)
    rows, final_x = sock_rows(), after[X]
    if restore_ike:
        need(after[IKE]['InvocationID'] == restored_invocation
             and idle_ike(after[IKE], rows) == state['ike_sockets'], STAGE)
    absent = reserved - ({500, 4500} if restore_ike else set())
    final_b = removal_bridge_unit(state, restarted=split)
    removal_bridge_sockets(state, rows, final_b)
    profiles_unchanged()
    need(all(final_x[k] == x[k] and final_b[k] == b[k] for k in ('InvocationID', 'MainPID')), STAGE)
    xray_users(profiles['main'], final_x, rows, state.get('transit'))
    need(removal_main_sockets(rows, final_x['MainPID'], reserved, state['udp_endpoints']) == sockets
         and not any(n in absent for _, _, n, _ in rows)
         and network_projection(d, token, removing=True) == {'nft': None, 'rule': False, 'route': False}
         and vpn_empty(allow_socket_policies=restore_ike) and read(state['path'], 2 * MAX_FILE) == state['manifest'] and before['boot'] == boot()
         and remove_generation(XRAY) == state['binary'], STAGE)
    removal_files_after(state)
    removal_neighbors(state)


SESSION_UNKNOWN = 'SESSION_COUNT_UNPROVED'
SESSION_GROUP = '/system.slice/xl2tpd.service'
SESSION_XL = '/usr/sbin/xl2tpd'
SESSION_PPP = '/usr/sbin/pppd'
# Debian trixie amd64 xl2tpd 1.3.18-1+b1 and ppp 2.5.2-1+1 (dpkg-deb -x).
SESSION_STOCK = {
    SESSION_XL: '48bd1fd6a7b9d4cdd3a5f20386654b2fa03ee19a9abdc9a1012ddf605290654b',
    SESSION_PPP: 'eb93a25616854a7bdeeff5e6317601eac9f33c69d68bc5a1d127a9eb4530c3bf',
    '/usr/lib/pppd/2.5.2/pppol2tp.so': 'e5bbd060e4bfd87661f14f9a766a0b2fcf17c7f4eb352127e8da9210b52fc3b8',
}
SESSION_GLOBAL = {
    '/etc/ppp/options': '5ec5ff67de7a81f6fedb5a32ef06b839f543a410a42055da169c8d2ef3d04246',
    '/etc/ppp/ip-pre-up': '4c94ffad8f1eed66bdccd9456f50a1f0aae54978cf6c1e84f439bcb46a32db57',
    '/etc/ppp/ip-up': '3a7c1bf309a3fa4ea4b324fccc5ca2c5d907ada04c6b3b7c35ef9893f0e0eab1',
    '/etc/ppp/ip-down': '57c4112f686ce228078d964555dec9ebf6f07f5dbf77daae01a7ba8e717cfb3f',
    '/etc/ppp/ip-up.d/0000usepeerdns': 'c6642e9baa8a2a489eb0ba1bdac1289aafa5e8e58aa5e46c078eece4eaa8cc4d',
    '/etc/ppp/ip-down.d/0000usepeerdns': 'a2f8eff7abd676b154d11b89522a5556263fdbc0cd43d3474a6122cf983ae492',
}


def session_need(ok):
    need(ok, SESSION_UNKNOWN)


def session_fs(libc, fd, magic):
    # x86_64 Linux: struct statfs begins with a native long f_type.
    buf = (ctypes.c_long * 32)()
    session_need(libc.fstatfs(fd, ctypes.byref(buf)) == 0 and buf[0] == magic)


def session_read(fd, name, maximum):
    with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd), 'rb') as f:
        data = f.read(maximum + 1)
    session_need(len(data) <= maximum)
    return data


def session_generation(st):
    return st.st_dev, st.st_ino, st.st_ctime_ns


def session_binary(path):
    # pppd is legitimately setuid in the stock archive; don't weaken read().
    folder, name = os.path.split(path)
    with directory(folder) as fd:
        with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd), 'rb') as f:
            st = os.fstat(f.fileno())
            session_need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o022
                         and 0 < st.st_size <= 2**21)
            data = f.read(2**21 + 1)
            generation = session_generation(st)
            session_need(len(data) == st.st_size and digest(data) == SESSION_STOCK[path]
                         and generation == session_generation(os.fstat(f.fileno()))
                         == session_generation(os.stat(name, dir_fd=fd, follow_symlinks=False)))
    return generation


def session_profile(lns, options, network):
    addr = rb'([0-9.]{7,15})'
    match = re.fullmatch(rb'\[global\]\nport = 1701\n\n\[lns default\]\nip range = ' + addr + rb'-' + addr
                         + rb'\nlocal ip = ' + addr + rb'\nrequire authentication = yes\n'
                         rb'pppoptfile = /etc/ppp/options\.xl2tpd\nlength bit = yes\n', lns)
    if match is None:
        raise Refusal(SESSION_UNKNOWN)
    start, end, local = (ipaddress.IPv4Address(item.decode('ascii')) for item in match.groups())
    cidr = ipaddress.IPv4Network(network['clientCidr'])
    session_need(cidr.network_address < start <= end < cidr.broadcast_address
                 and cidr.network_address < local < cidr.broadcast_address and not start <= local <= end)
    match = re.fullmatch(rb'auth\nrefuse-pap\nrefuse-chap\nrefuse-mschap\nrequire-mschap-v2\nrefuse-eap\nname l2tpd\n'
                         rb'mtu ([0-9]{3,4})\nmru ([0-9]{3,4})\nnoipv6\nnodefaultroute\n'
                         rb'(ms-dns [0-9.]{7,15}\n){1,4}', options)
    session_need(match is not None and all(576 <= int(n) <= 1500 for n in match.groups()[:2]))
    for line in options.split(b'\n'):
        if line.startswith(b'ms-dns '):
            ipaddress.IPv4Address(line[7:].decode('ascii'))
    return local, start, end


def session_owner(request):
    token, machine, network = (request[k] for k in ('backupId', 'machineId', 'network'))
    identity = read('/etc/machine-id', 34)
    session_need(identity is not None and raw(identity) in (machine.encode('ascii'), (machine + '\n').encode('ascii')))
    path, manifest, backup = read_manifest(token)
    before, runtime = backup['before'], backup['runtime']
    session_need(backup['phase'] == 'installed' and backup['backupId'] == token and backup['machineId'] == machine
                 and encode(backup['network']) == encode(network) and before['boot'] == boot()
                 and directory_absent(os.path.dirname(path) + '/remove-attempt.json'))
    no_jobs((XL, NET_UNIT, IKE))
    info = unit(XL)
    session_need(info['FragmentPath'] == SYSTEM + '/' + XL and removal_native(info, XL, before, installed=True)
                 and working(info) and info['SubState'] == 'running' and info['Type'] == 'simple'
                 and info['InvocationID'] == runtime['invocations'][1]
                 and re.fullmatch(r'[a-f0-9]{32}', info['InvocationID']) and info['ControlGroup'] == SESSION_GROUP
                 and re.fullmatch(r'[1-9][0-9]*', info['MainPID'])
                 and re.fullmatch(r'\{ path=/usr/sbin/xl2tpd ; argv\[\]=/usr/sbin/xl2tpd -D ;[^{}]*\}', info['ExecStart'])
                 and not any(info.get(k) for k in ('SourcePath', 'ExecCondition', 'ExecReload', 'PassEnvironment', 'UnsetEnvironment'))
                 and set(info['Requires'].split()) >= {NET_UNIT, IKE} and set(info['After'].split()) >= {NET_UNIT, IKE})
    rows = [owners for proto, _, port, owners in sock_rows() if proto == 'udp' and port == 1701]
    session_need(rows and all(owners == [info['MainPID']] for owners in rows))
    records, generations = {}, {}
    for k in ('lns', 'options', 'drop', 'net', 'nft'):
        file = NAMES[k]
        generation = remove_generation(file)
        record = read(file, 65536)
        if record is None:
            raise Refusal(SESSION_UNKNOWN)
        records[k] = record
        session_need(encode({**record, 'data': digest(raw(record))}) == encode(backup['after'][k])
                     and encode(generation) == encode(runtime['files'][k]) and generation == remove_generation(file))
        generations[k] = generation
    session_need(nft_marker(raw(records['nft']), token))
    for folder, leaves in (('/etc/ppp/ip-pre-up.d', []), ('/etc/ppp/ip-up.d', ['0000usepeerdns']),
                           ('/etc/ppp/ip-down.d', ['0000usepeerdns'])):
        with directory(folder) as fd:
            session_need(os.listdir(fd) == leaves)
    session_need(pwd.getpwuid(0).pw_dir == '/root')
    for p in ('/root/.ppprc', '/etc/ppp/auth-up', '/etc/ppp/auth-down', '/etc/ppp/net-init', '/etc/ppp/net-pre-up',
              '/etc/ppp/net-down', '/etc/ppp/ip-pre-up.local', '/etc/ppp/ip-up.local', '/etc/ppp/ip-down.local'):
        session_need(directory_absent(p))
    for p, sha in SESSION_GLOBAL.items():
        current = read(p, 65536)
        session_need(current is not None and digest(raw(current)) == sha
                     and (p != '/etc/ppp/options' or current == before['globalFiles'][p]))
    profile = session_profile(raw(records['lns']), raw(records['options']), network)
    _, _, chap_rows = owned_chap(read(NAMES['chap']), backup, chap_expected(request, records['lns']))
    generations['chapRows'] = chap_rows_digest(chap_rows)
    return (before['boot'], info['InvocationID'], int(info['MainPID']), remove_generation(path), digest(raw(manifest)),
            generations, {p: session_binary(p) for p in SESSION_STOCK}, profile)


def session_cgroup(fd):
    data = session_read(fd, 'cgroup.procs', 32768)
    counts = session_read(fd, 'cgroup.stat', 65536).split(b'\n')
    session_need(re.fullmatch(rb'(?:[1-9][0-9]{0,9}\n)+', data) and b'nr_descendants 0' in counts
                 and b'nr_dying_descendants 0' in counts)
    pids = [int(p) for p in data.split()]
    session_need(len(pids) <= 2049 and len(pids) == len(set(pids)))
    return sorted(pids)


@contextlib.contextmanager
def session_process(proc, pid, main, binaries, watch):
    with contextlib.ExitStack() as stack:
        task = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=proc)
        stack.callback(os.close, task)
        data = session_read(task, 'stat', 4096)
        fields = data.rsplit(b') ', 1)[1].split()
        session_need(data.startswith(str(pid).encode() + b' (') and fields[0] in (b'R', b'S')
                     and (pid == main or int(fields[1]) == main) and int(fields[19]) > 0
                     and session_read(task, 'cgroup', 4096) == ('0::' + SESSION_GROUP + '\n').encode())
        for name in ('ns/net', 'ns/mnt', 'ns/pid', 'ns/user', 'ns/cgroup', 'root'):
            ours, theirs = os.stat('self/' + name, dir_fd=proc), os.stat(name, dir_fd=task)
            session_need((ours.st_dev, ours.st_ino) == (theirs.st_dev, theirs.st_ino))
        exe = SESSION_XL if pid == main else SESSION_PPP
        session_need(os.fstat(task).st_uid == 0 and os.readlink('exe', dir_fd=task) == exe
                     and session_generation(os.stat('exe', dir_fd=task)) == binaries[exe])
        argv = session_read(task, 'cmdline', 4096)
        watch()
        yield task, int(fields[19]), argv


def session_ppp_argv(argv, pool):
    # xl2tpd 1.3.18 control.c:ICCN -> start_pppd(), kernel LNS path.
    match = re.fullmatch(rb'/usr/sbin/pppd\0plugin\0pppol2tp\.so\0pppol2tp\0([1-9][0-9]{0,8})\0'
                         rb'pppol2tp_lns_mode\0pppol2tp_tunnel_id\0([1-9][0-9]{0,4})\0'
                         rb'pppol2tp_session_id\0([1-9][0-9]{0,4})\0passive\0nodetach\0'
                         rb'([0-9.]{7,15}):([0-9.]{7,15})\0auth\0file\0/etc/ppp/options\.xl2tpd\0', argv)
    if match is None:
        raise Refusal(SESSION_UNKNOWN)
    fd, tid, sid = map(int, match.groups()[:3])
    local, peer = (ipaddress.IPv4Address(row.decode()) for row in match.groups()[3:])
    session_need(tid <= 65535 and sid <= 65535 and local == pool[0] and pool[1] <= peer <= pool[2])
    return fd, tid, sid, str(local), str(peer)


@contextlib.contextmanager
def session_dup(libc, pidfd, fd):
    # Getters only; never open /dev/ppp, attach a channel, or open the control FIFO.
    dup = libc.pidfd_getfd(pidfd, fd, 0)
    session_need(dup >= 0)
    try:
        yield dup
    finally:
        os.close(dup)


def session_kernel(libc, task, pidfd, l2fd, main, tid, sid):
    with session_dup(libc, pidfd, l2fd) as fd:
        st = os.fstat(fd)
        session_need(stat.S_ISSOCK(st.st_mode) and os.readlink('fd/' + str(l2fd), dir_fd=task) == f'socket:[{st.st_ino}]')
        data = ctypes.create_string_buffer(128)
        length = ctypes.c_uint(len(data))
        abi = '=HIii16sHHHH'  # linux/if_pppox.h: packed v2 IPv4 sockaddr_pppol2tp
        session_need(libc.getsockname(fd, ctypes.byref(data), ctypes.byref(length)) == 0
                     and length.value == struct.calcsize(abi))
        family, proto, owner, tunnel_fd, address, t, s, remote_t, remote_s = struct.unpack_from(abi, data)
        session_need((family, proto, owner, t, s) == (24, 1, main, tid, sid) and address[:2] == b'\x02\x00'
                     and tunnel_fd >= 0 and remote_t > 0 and remote_s > 0)
    with contextlib.ExitStack() as stack:
        fds = os.open('fd', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=task)
        stack.callback(os.close, fds)
        entries = os.listdir(fds)
        session_need(len(entries) <= 128 and all(re.fullmatch(r'[0-9]{1,10}', x) for x in entries))
        ppp_fds = [int(x) for x in entries if os.readlink(x, dir_fd=fds) == '/dev/ppp']
        session_need(len(ppp_fds) == 2)
        units = []
        for number in ppp_fds:
            with session_dup(libc, pidfd, number) as fd:
                dev = os.fstat(fd)
                session_need(stat.S_ISCHR(dev.st_mode) and (os.major(dev.st_rdev), os.minor(dev.st_rdev)) == (108, 0))
                try:
                    index, = struct.unpack('=i', fcntl.ioctl(fd, 0x80047456, b'\0' * 4))  # PPPIOCGUNIT
                except OSError as error:
                    if error.errno != errno.ENOTTY:  # channel ENOIOCTLCMD is mapped by vfs_ioctl
                        raise
                    continue
                mode = fcntl.ioctl(fd, 0xc008744c, struct.pack('=ii', 0x21, -1))  # PPPIOCGNPMODE IPv4
                flags, = struct.unpack('=I', fcntl.ioctl(fd, 0x8004745a, b'\0' * 4))  # PPPIOCGFLAGS
                session_need(index >= 0 and mode == struct.pack('=ii', 0x21, 0)  # NPMODE_PASS
                             and not flags & 0x200)  # SC_LOOP_TRAFFIC
                units.append(index)
        session_need(len(units) == 1)
    return units[0], (t, s, remote_t, remote_s), st.st_ino


SESSION_L2TP_HEADER = (b'PPPoL2TP driver info, V2.0\nTUNNEL name, user-data-ok session-count\n'
                       b' debug tx-pkts/bytes/errs rx-pkts/bytes/errs\n'
                       b'  SESSION name, addr/port src-tid/sid dest-tid/sid state user-data-ok\n'
                       b'   mtu/mru/rcvseq/sendseq/lns debug reorderto\n'
                       b'   nr/ns tx-pkts/bytes/errs rx-pkts/bytes/errs\n')
SESSION_TUNNEL_ROW = re.compile(rb"\nTUNNEL 'tunl ([0-9]{1,5})', [YN] -?[0-9]+\n [0-9a-f]{8} (?:-?[0-9]+/){2}-?[0-9]+ "
                                rb'(?:-?[0-9]+/){2}-?[0-9]+\n')
SESSION_L2TP_ROW = re.compile(rb"  SESSION '[^'\n]*' [0-9A-F]{8}/([0-9]+) ([0-9A-F]{4})/([0-9A-F]{4}) -> "
                              rb'([0-9A-F]{4})/([0-9A-F]{4}) ([0-9]+) ([YN])\n'
                              rb'   0/0/[R-]/[S-]/(LNS|LAC) [0-9a-f]{8} [0-9]+\n'
                              rb'   [0-9]+/[0-9]+ (?:-?[0-9]+/){2}-?[0-9]+ (?:-?[0-9]+/){2}-?[0-9]+\n'
                              rb'(?:   interface ([^\n]*)\n)?')


def session_l2tp_interfaces(data, keys):
    # Linux 6.12 l2tp_ppp.c resolves the channel's current netdev. Parse to
    # EOF, including foreign rows, so an unsupported format is not absence.
    session_need(data.startswith(SESSION_L2TP_HEADER))
    rows = {}
    offset = len(SESSION_L2TP_HEADER)
    tunnel_id = 0
    while offset < len(data):
        tunnel = SESSION_TUNNEL_ROW.match(data, offset)
        if tunnel is not None:
            next_id = int(tunnel[1])
            session_need(tunnel_id < next_id <= 65535)
            tunnel_id = next_id
            offset = tunnel.end()
            continue
        match = SESSION_L2TP_ROW.match(data, offset)
        if match is None:
            raise Refusal(SESSION_UNKNOWN)
        offset = match.end()
        port, *ids, state, associated, role, iface = match.groups()
        key = tuple(int(x, 16) for x in ids)
        session_need(key[0] == tunnel_id and tunnel_id > 0)
        if key not in keys and port != b'1701':
            continue
        # l2tp_v2_session_get_next() skips the synthetic session 0 used by
        # the tunnel's control socket. A TUNNEL row alone isn't a call.
        if iface is None:
            raise Refusal(SESSION_UNKNOWN)
        session_need(key in keys and key not in rows and all(key) and port == b'1701' and state == b'3'
                     and associated == b'Y' and role == b'LNS' and re.fullmatch(rb'ppp[0-9]+', iface))
        rows[key] = iface.decode('ascii')
    session_need(set(rows) == keys)
    return rows


def session_links(rows, name, local, peer):
    session_need(type(rows) is list)
    selected = [row for row in rows if row['ifname'] == name]
    session_need(len(selected) == 1)
    link = selected[0]
    session_need(link.get('link_type') == 'ppp' and {'UP', 'POINTOPOINT', 'LOWER_UP'} <= set(link['flags'])
                 and type(link['ifindex']) is int and link['ifindex'] > 0
                 and len([row for row in rows if row['ifindex'] == link['ifindex']]) == 1)
    (addr,) = link['addr_info']
    session_need(addr.get('family') == 'inet' and addr.get('local') == local and (peer is None or addr.get('address') == peer)
                 and addr.get('prefixlen') == 32 and addr.get('scope') == 'global')
    if peer is None:
        return link['ifindex'], str(ipaddress.IPv4Address(addr['address']))
    return link['ifindex']


def session_pid_stamp(name, pid):
    path = '/run/' + name + '.pid'
    st = remove_generation(path)
    stamp = read(path, 32)
    session_need(st is not None and stamp is not None and raw(stamp) == (str(pid) + '\n').encode()
                 and st == remove_generation(path))
    return st


def session_sample(libc, proc, group, owner, held, watch, *, revoke=False):
    _, _, main, _, _, _, binaries, pool = owner
    pids = session_cgroup(group)
    session_need(main in pids)
    sample = {}
    main_start = 0
    for pid in pids:
        pfd = held(pid)
        with session_process(proc, pid, main, binaries, watch) as (task, start, argv):
            if pid == main:
                session_need(argv == b'/usr/sbin/xl2tpd\0-D\0')
                main_start = start
            else:
                l2fd, tid, sid, local, peer = session_ppp_argv(argv, pool)
                number, key, inode = session_kernel(libc, task, pfd, l2fd, main, tid, sid)
                name = 'ppp' + str(number)
                generation = session_pid_stamp(name, pid)
                session_need(key not in sample)
                sample[key] = pid, start, inode, name, local, peer, generation
    # No LNS/debug command; read even for zero to distinguish missing inventory.
    native = session_l2tp_interfaces(session_read(proc, 'self/net/pppol2tp', 2**20), set(sample))
    result = []
    if sample:
        # session_links needs named link types and scopes; the RPDB ip()
        # deliberately uses -N. Keep this dump separate and refuse warnings.
        links = json.loads(command('/usr/sbin/ip', '-j', '-4', '-details', 'addr', 'show', quiet=True))
        seen_names, seen_peers, seen_inodes = set(), set(), set()
        for key, (pid, start, inode, name, local, peer, generation) in sample.items():
            session_need(native[key] == name and name not in seen_names and (revoke or peer not in seen_peers) and inode not in seen_inodes)
            seen_names.add(name)
            seen_peers.add(peer)
            seen_inodes.add(inode)
            if revoke:
                # xl2tpd offers its next free pool slot. CHAP may replace it
                # at IPCP; multiple calls from one login may share the latter.
                ifindex, peer = session_links(links, name, local, None)
                session_need(pool[1] <= ipaddress.IPv4Address(peer) <= pool[2])
            else:
                ifindex = session_links(links, name, local, peer)
            result.append((key, local, peer, pid, start, inode, ifindex, generation))
    session_need(pids == session_cgroup(group))
    watch()
    return main_start, result


REVOKE_DB_NAME = 'pppd2.tdb'
# Built-in TDB in Debian trixie amd64 ppp 2.5.2-1+1 (SESSION_STOCK),
# pppd/tdb.h and tdb.c: little-endian default header, 131 hash buckets.
REVOKE_DB_BUCKETS = 131
REVOKE_DB_HEADER = struct.pack('<32sII', b'TDB file\n', 0x2601196d, REVOKE_DB_BUCKETS) + bytes(128)
REVOKE_DB_DATA = len(REVOKE_DB_HEADER) + 4 * (1 + REVOKE_DB_BUCKETS)
# pppd 2.5.2 update_db_entry stores a NUL terminator, not a trailing semicolon.
REVOKE_ENV = re.compile(rb'ORIG_UID=0;PPPLOGNAME=(?:' + CHAP_LOGIN + rb'|\(unknown\));'
                        rb'PPPD_PID=([1-9][0-9]{0,9});IFNAME=(ppp(?P<unit>0|[1-9][0-9]{0,9}));'
                        rb'UNIT=(?P=unit);PEERNAME=(' + CHAP_LOGIN + rb');'
                        rb'IPLOCAL=([0-9.]{7,15});IPREMOTE=([0-9.]{7,15})\x00')


def revoke_db_fetch(fd, size, key):
    def at(offset, count):
        data = os.pread(fd, count, offset)
        session_need(len(data) == count)
        return data

    hsize = len(REVOKE_DB_HEADER)
    value = 0x238f13af * len(key) + sum(byte << (i * 5 % 24) for i, byte in enumerate(key))
    full_hash = (1103515243 * value + 12345) & 0xffffffff
    bucket = full_hash % REVOKE_DB_BUCKETS
    offset, = struct.unpack('<I', at(hsize + 4 * (1 + bucket), 4))
    seen, found = set(), None
    while offset:
        session_need(REVOKE_DB_DATA <= offset <= size - 24 and offset % 4 == 0 and offset not in seen
                     and len(seen) < 4096 and time.monotonic() < DEADLINE)
        seen.add(offset)
        following, length, klen, vlen, hashed, magic = struct.unpack('<6I', at(offset, 24))
        end = offset + 24 + length
        session_need(klen + vlen + 4 <= length and end <= size and length % 4 == 0
                     and hashed % REVOKE_DB_BUCKETS == bucket and magic in (0x26011999, 0xfee1dead)
                     and struct.unpack('<I', at(end - 4, 4))[0] == 24 + length)
        if magic == 0x26011999 and full_hash == hashed and klen == len(key) and at(offset + 24, klen) == key:
            session_need(found is None and 0 < vlen <= 4096)
            found = at(offset + 24 + klen, vlen)
        offset = following
    if found is None:
        raise Refusal(SESSION_UNKNOWN)
    return found


def revoke_db_writer(proc, pid, identity):
    # Match the inode already opened by the attested child. No process env,
    # memory, fd contents or journal are read, and no writer FD is duplicated.
    fd = os.open(f'{pid}/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=proc)
    try:
        fds = os.listdir(fd)
        session_need(len(fds) <= 128 and all(re.fullmatch(r'[0-9]{1,10}', leaf) for leaf in fds))
        matches = 0
        for leaf in fds:
            if os.readlink(leaf, dir_fd=fd).rsplit('/', 1)[-1] == REVOKE_DB_NAME:
                st = os.stat(leaf, dir_fd=fd)
                matches += (st.st_dev, st.st_ino) == identity
        session_need(matches == 1)
    finally:
        os.close(fd)


def revoke_db_identity(st):
    session_need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
                 and not st.st_mode & 0o7022)
    return st.st_dev, st.st_ino


def revoke_peer_logins(rows, users):
    if not rows:
        return {}
    observed = {}
    with directory('/run') as run, directory('/proc') as proc:
        fd = os.open(REVOKE_DB_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=run)
        try:
            # Stock tdb_open(O_RDONLY) disables locking. Instead take a
            # nonblocking POSIX read lock covering init/alloc/hash-chain locks.
            identity = revoke_db_identity(os.fstat(fd))
            fcntl.lockf(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            size = os.fstat(fd).st_size
            header = REVOKE_DB_HEADER
            session_need(REVOKE_DB_DATA <= size <= MAX_FILE and os.pread(fd, len(header), 0) == header)
            for _, local, peer, pid, _, _, _, stamp in rows:
                revoke_db_writer(proc, pid, identity)
                pid_bytes = str(pid).encode('ascii')
                key = b'pppd' + pid_bytes
                # main.c writes this process' script_env under pppd<PID> at
                # startup and on updates. auth_peer_success() sets PEERNAME;
                # ipcp_up() sets IPLOCAL/IPREMOTE before kernel activation.
                # Require exact field order: values are not escaped, so a
                # permissive split(';') could truncate a foreign peer name.
                env = REVOKE_ENV.fullmatch(revoke_db_fetch(fd, size, key))
                if env is None:
                    raise Refusal(SESSION_UNKNOWN)
                db_pid, name, number, login, db_local, db_peer = env.groups()
                login = login.decode('ascii')
                session_need(pid not in observed and db_pid == pid_bytes
                             and (db_local, db_peer) == (local.encode('ascii'), peer.encode('ascii'))
                             and users.get(login) == peer and session_pid_stamp(name.decode('ascii'), pid) == stamp)
                # IPREMOTE is not a unique alias (two calls can share it).
                for alias in (b'PPPD_PID=' + pid_bytes, b'IFNAME=' + name, b'UNIT=' + number):
                    session_need(revoke_db_fetch(fd, size, alias) == key)
                observed[pid] = login
            session_need(revoke_db_identity(os.stat(REVOKE_DB_NAME, dir_fd=run, follow_symlinks=False)) == identity)
        finally:
            os.close(fd)  # releases the read lock before any signal/wait
    return observed


@contextlib.contextmanager
def revoke_ppp_view(owner):
    libc = ctypes.CDLL(None, use_errno=True)
    path = '/sys/fs/cgroup' + SESSION_GROUP
    with directory('/proc') as proc, directory(path) as group, contextlib.ExitStack() as stack:
        session_fs(libc, proc, 0x9fa0)
        session_fs(libc, group, 0x63677270)
        route = stack.enter_context(socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_NONBLOCK, 0))
        route.bind((0, 1 | 16))
        poll = select.poll()
        poll.register(route, select.POLLIN)
        pids = {}

        def held(pid):
            if pid not in pids:
                fd = os.pidfd_open(pid)
                stack.callback(os.close, fd)
                poll.register(fd, select.POLLIN)
                pids[pid] = fd
            return pids[pid]

        def watch():
            session_need(not poll.poll(0) and time.monotonic() < DEADLINE)

        def sample():
            value = session_sample(libc, proc, group, owner, held, watch, revoke=True)
            session_need(session_generation(os.fstat(group)) == session_generation(os.lstat(path)))
            return value

        yield sample, held, watch


def revoke_ppp(request, blocked, chap, path, manifest, xl):
    global DEADLINE
    count, completed = 0, False
    outer_deadline = DEADLINE
    DEADLINE = min(outer_deadline, time.monotonic() + 25)
    try:
        session_need(os.uname().machine == 'x86_64' and hasattr(signal, 'pidfd_send_signal'))
        chap_generation = remove_generation(NAMES['chap'])
        manifest_generation = remove_generation(path)

        def unchanged():
            session_need(chap_generation is not None and manifest_generation is not None and read(NAMES['chap']) == chap
                         and remove_generation(NAMES['chap']) == chap_generation and read(path, 2 * MAX_FILE) == manifest
                         and remove_generation(path) == manifest_generation and time.monotonic() < DEADLINE)

        unchanged()
        if rollback_quiescent(xl):
            quiet = quiescent_session_sample(blocked)
            session_need(quiet == quiescent_session_sample(blocked) and unit(XL) == xl)
            unchanged()
            return {'sessionsTerminated': 0, 'complete': True}
        owner = session_owner(blocked)
        session_need((owner[1], str(owner[2])) == (xl['InvocationID'], xl['MainPID']))
        users = {u['login']: u['ipAddress'] for u in request['currentUsers']}
        closed_call = None
        main_start = None
        while True:
            with revoke_ppp_view(owner) as (sample, held, watch):
                before = sample()
                if main_start is None:
                    main_start = before[0]
                session_need(main_start == before[0])
                session_need(owner == session_owner(blocked) and before == sample())
                unchanged()
                watch()
                if closed_call is not None:
                    key, index = closed_call
                    session_need(all(row[0] != key and row[6] != index for row in before[1]))
                    count += 1
                    closed_call = None
                logins = revoke_peer_logins(before[1], users)
                session_need(before == sample() and logins == revoke_peer_logins(before[1], users))
                unchanged()
                selected = next((row for row in before[1] if logins[row[3]] == request['revokedLogin']), None)
                watch()
                if selected is None:
                    completed = True
                    break
                key, _, _, pid, _, _, index, _ = selected
                pfd = held(pid)
                watch()
                try:
                    signal.pidfd_send_signal(pfd, signal.SIGTERM)
                except ProcessLookupError:
                    # Natural exit before delivery, not an operation closure.
                    continue
                exited = select.poll()
                exited.register(pfd, select.POLLIN)
                session_need(any(fd == pfd and flags & select.POLLIN for fd, flags in
                                 exited.poll(max(0, int((DEADLINE - time.monotonic()) * 1000)))))
                # A count requires an accepted signal to the pinned instance,
                # its exit, and absence of both call and interface on readback.
                # It does not distinguish a concurrent natural disconnect as
                # the cause of that same targeted call's confirmed closure.
                closed_call = key, index
    except (Refusal, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        # A checked partial reply is not authority to publish or replay. Never
        # return state contents, PID, address or guessed count over the wire.
        completed = False
    finally:
        DEADLINE = outer_deadline
    return {'sessionsTerminated': count, 'complete': completed}


def session_census(request):
    # Caller holds the shared (preview) or exclusive (Remove) DIRECT flock.
    global DEADLINE
    session_need(os.uname().machine == 'x86_64')
    outer_deadline = DEADLINE
    DEADLINE = min(outer_deadline, time.monotonic() + 7)
    try:
        return collect_session_census(request)
    finally:
        DEADLINE = outer_deadline


def quiescent_session_sample(request):
    ready = preflight(request['machineId'])
    session_need(ready['machineId'] == request['machineId'] and ready['ppp'])
    state = observe_removal(request, quiescent=True)
    xl = state['units'][XL]
    session_need(xl['ControlGroup'] in ('', SESSION_GROUP))
    # KillMode and systemd's PID zero are not an inventory. Prove the actual
    # kernel group absent, or recursively empty. ps can omit cgroup metadata.
    group = '/sys/fs/cgroup' + SESSION_GROUP
    parent, name = os.path.split(group)
    session_need(command('/usr/bin/stat', '-f', '--format=%T', parent, quiet=True) == b'cgroup2fs\n')
    group_type = command('/usr/bin/find', '-P', parent, '-mindepth', '1', '-maxdepth', '1',
                         '-name', name, '-printf', '%y\n', quiet=True)
    session_need(group_type in (b'', b'd\n'))
    if group_type:
        events = command('/usr/bin/head', '-c', '1024', group + '/cgroup.events', quiet=True)
        session_need(events == b'populated 0\nfrozen 0\n')
    # Also refuse stray stock processes outside the native service cgroup.
    tasks = command('/usr/bin/ps', '-ww', '-e', '-o', 'pid=', '-o', 'comm=', quiet=True)
    has_observer = False
    for line in tasks.splitlines():
        fields = line.strip().split(None, 1)
        session_need(len(fields) == 2 and fields[0].isdigit() and fields[1] not in (b'xl2tpd', b'pppd', b'-', b'?'))
        has_observer |= fields[1] == b'ps'
    session_need(has_observer and all(remove_generation(p) is None for p in (
        '/run/xl2tpd.pid', '/run/xl2tpd/l2tp-control'))
        and not any(re.fullmatch(r'ppp.*\.pid', name) for name in os.listdir('/run')))
    # Unlike the Remove listener check, examine connected UDP sockets too.
    session_need(not command('/usr/bin/ss', '-H', '-aun', 'sport = :1701', quiet=True).strip())
    links = json.loads(command('/usr/sbin/ip', '-j', '-details', 'link', 'show', quiet=True))
    link_types = set()
    session_need(type(links) is list)
    for row in links:
        session_need(isinstance(row, dict) and type(row.get('link_type')) is str)
        link_types.add(row['link_type'])
    session_need('loopback' in link_types and 'ppp' not in link_types)  # includes renamed PPP netdevs
    # Require the actual empty kernel table, not ENOENT or a filtered empty
    # set of sessions: even a leftover tunnel without a call blocks Remove.
    native = command('/usr/bin/head', '-c', '1048577', '/proc/self/net/pppol2tp', quiet=True)
    session_need(native == SESSION_L2TP_HEADER)
    session_need(all(unit(name) == info for name, info in state['units'].items()))
    no_jobs(UNITS)
    return state['baseline'], group_type


def quiescent_session_token(baseline):
    return digest(encode(['ppp-quiescent-v1', baseline]))


def ipsec_status_inventory(status):
    # strongSwan starter/stroke statusall prints each CHILD under its parent
    # IKE SA. Count managed IKEv1 connections, never ESP directions, overlapping
    # CHILD rekeys, address pairs or kernel policy templates.
    session_need(len(status) <= 2**20 and status.endswith(b'\n'))
    match = re.search(rb'^Connections:[ \t]*\n(.*?)^Security Associations '
                      rb'\(([0-9]{1,5}) up, 0 connecting\):[ \t]*\n([^\r]*)\Z', status, re.M | re.S)
    if match is None:
        raise Refusal(SESSION_UNKNOWN)
    config, up, body = match.groups()
    session_need(config.strip() and all(line.lstrip().startswith(b'celerity-l2tp:')
                                       for line in config.split(b'\n') if line.strip()))
    if int(up) == 0:
        session_need(body.strip() == b'none')
        return []
    inventory, children, parent, last_child = {}, set(), None, None
    for line in body.split(b'\n')[:-1]:
        # stroke uses %12s, a minimum width; celerity-l2tp needs no padding.
        row = re.fullmatch(rb'[ \t]*celerity-l2tp(?:\[([1-9][0-9]{0,9})\]|\{([1-9][0-9]{0,9})\}):[ \t]+([^\x00-\x1f]+)', line)
        if row is None:
            raise Refusal(SESSION_UNKNOWN)
        ike, child, detail = row.groups()
        if ike and detail.startswith(b'ESTABLISHED '):
            parent = int(ike)
            session_need(parent not in inventory)
            inventory[parent] = None
            last_child = None
        elif ike:
            session_need(parent == int(ike) and last_child is None)
            spi = re.fullmatch(rb'IKEv1 SPIs: ([a-f0-9]{16})_i\*? ([a-f0-9]{16})_r\*?(?:, .+)?', detail)
            if spi:
                session_need(inventory[parent] is None)
                inventory[parent] = tuple(value.decode('ascii') for value in spi.groups())
            else:
                session_need(detail.startswith(b'IKE proposal: '))
        else:
            child = int(child)
            session_need(parent is not None)
            sa = re.fullmatch(rb'(?:INSTALLED, TRANSPORT, reqid [0-9]+, ESP(?: in UDP)? SPIs: [a-f0-9]{8}_i [a-f0-9]{8}_o'
                              rb'|(?:REKEYING|REKEYED), TRANSPORT, reqid [0-9]+, expires in [0-9]+ (?:second|minute|hour|day)s?'
                              rb'|DELETING, TRANSPORT, reqid [0-9]+)', detail)
            if sa:
                session_need(child not in children)
                children.add(child)
                last_child = child
            else:
                session_need(last_child == child and (b' === ' in detail or b' bytes_i' in detail))
    identities = set(inventory.values())
    session_need(len(inventory) == len(identities) == int(up) and None not in identities)
    return sorted(inventory.items())


def ipsec_session_sample(request):
    identity = read('/etc/machine-id', 34)
    session_need(identity is not None and raw(identity).strip() == request['machineId'].encode('ascii'))
    path, manifest, backup, _ = owned_installation(request)
    before, runtime = backup['before'], backup['runtime']
    # Match installed configuration and starter include, not just a connection
    # name. No IPsec secrets are needed in the census.
    generations = []
    for key in ('ike', 'starter'):
        generation = remove_generation(NAMES[key])
        record = read(NAMES[key], 65536)
        session_need(generation == runtime['files'][key] and after_match(record, backup['after'][key])
                     and generation == remove_generation(NAMES[key]))
        if key == 'starter':
            session_need(ike_include_matches(record, [os.path.basename(NAMES['ike'])]))
        generations.append(generation)
    check_swan_profile(backup, read(SWAN_PROFILE) if 'swan' in backup['after'] else None)
    no_jobs((IKE,))
    ike = unit(IKE)
    session_need(removal_native(ike, IKE, before, installed=True))
    sockets = sorted((proto, address, port, sorted(owners)) for proto, address, port, owners in sock_rows()
                     if port in (500, 4500))
    if rollback_quiescent(ike):
        session_need(not sockets)
        inventory = []
    else:
        session_need(working(ike) and ike['SubState'] == 'running' and ike['InvocationID'] == runtime['invocations'][2]
                     and {port for _, _, port, _ in sockets} == {500, 4500}
                     and all(proto == 'udp' and owners and all(in_cgroup(pid, ike) for pid in owners)
                             for proto, _, _, owners in sockets))
        inventory = ipsec_status_inventory(command('/usr/sbin/ipsec', 'statusall', quiet=True))
    if not inventory:
        # A stale child in the kernel or a failed dump is not a known zero.
        session_need(not command('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys', quiet=True).strip())
    session_need(ike == unit(IKE))
    no_jobs((IKE,))
    return len(inventory), digest(encode([before['boot'], remove_generation(path), digest(raw(manifest)),
                                         generations, ike['InvocationID'], ike['MainPID'], sockets, inventory]))


def removal_idle(request, rows, units):
    try:
        removal_vpn_runtime(rows, units)
    except Refusal as error:
        # Classify a proven managed SA without accepting anything that the
        # original Remove guard refused. Foreign/unknown remain refusals.
        if str(error) != 'IN_FLIGHT':
            ipsec = census_observation(ipsec_session_sample, request)
            if ipsec and ipsec[0] > 0:
                raise Refusal('REMOVE_IPSEC_BUSY') from None
        raise


def census_observation(probe, request):
    try:
        return probe(request)
    except Refusal as error:
        if str(error) == 'IN_FLIGHT':
            raise
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        pass  # Unreadable or unsupported, never a count of zero.
    return None


def relay_session_census(request, quiescent_baseline=None):
    global DEADLINE
    outer_deadline = DEADLINE
    DEADLINE = min(outer_deadline, time.monotonic() + 7)
    try:
        ipsec = census_observation(ipsec_session_sample, request)
        ppp = census_observation(session_census, {k: v for k, v in request.items()
                                                 if k not in ('action', 'baseline', 'expectedCensus')})
        if ipsec is not None and ipsec != census_observation(ipsec_session_sample, request):
            ipsec = None
        if ppp and quiescent_baseline is not None:
            session_need(ppp['census'] == quiescent_session_token(quiescent_baseline))
        session_need(ppp is not None or ipsec is not None)
        if time.monotonic() >= DEADLINE:
            raise subprocess.TimeoutExpired([], 0)
        return {'activeSessions': ppp['activeSessions'] if ppp else None,
                'activeIpsec': ipsec[0] if ipsec else None,
                'census': digest(encode(['vpn-census-v1', ppp['census'], ipsec[1]])) if ppp and ipsec else None}
    finally:
        DEADLINE = outer_deadline


def collect_session_census(request):
    if rollback_quiescent(unit(XL)):
        snapshot = quiescent_session_sample(request)
        session_need(quiescent_session_sample(request) == snapshot)
        if time.monotonic() >= DEADLINE:
            raise subprocess.TimeoutExpired([], 0)
        return {'activeSessions': 0, 'census': quiescent_session_token(snapshot[0])}
    libc = ctypes.CDLL(None, use_errno=True)
    owner = session_owner(request)
    group_path = '/sys/fs/cgroup' + SESSION_GROUP
    with directory('/proc') as proc, directory(group_path) as group, contextlib.ExitStack() as stack:
        session_fs(libc, proc, 0x9fa0)  # PROC_SUPER_MAGIC
        session_fs(libc, group, 0x63677270)  # CGROUP2_SUPER_MAGIC
        route = stack.enter_context(socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_NONBLOCK, 0))
        route.bind((0, 1 | 16))  # RTMGRP_LINK | RTMGRP_IPV4_IFADDR; overflow also refuses.
        poll = select.poll()
        poll.register(route, select.POLLIN)
        pids = {}

        def held(pid):
            if pid not in pids:
                fd = os.pidfd_open(pid)
                stack.callback(os.close, fd)
                poll.register(fd, select.POLLIN)
                pids[pid] = fd
            return pids[pid]

        def watch():
            session_need(not poll.poll(0) and time.monotonic() < DEADLINE)

        sample = session_sample(libc, proc, group, owner, held, watch)
        session_need(owner == session_owner(request))
        session_need(sample == session_sample(libc, proc, group, owner, held, watch)
                     and session_generation(os.fstat(group)) == session_generation(os.lstat(group_path)))
        watch()
    session_need(time.monotonic() < DEADLINE)
    # Include the authenticated managed rows, not the surrounding file/inode.
    return {'activeSessions': len(sample[1]), 'census': digest(encode([
        'ppp-census-v2', request['nodeId'], request['backupId'], owner[:4], owner[5], sample[0],
        [row[3:] for row in sample[1]]]))}


def read_session_count(request):
    keys = {'action', 'machineId', 'nodeId', 'backupId', 'network'}
    session_need(keys <= set(request) <= keys | {'transit', 'currentUsers'}
                 and ('transit' not in request or type(request['transit']) is list)
                 and re.fullmatch(r'[a-f0-9]{32}', request['machineId']) and re.fullmatch(r'[a-f0-9]{24}', request['nodeId'])
                 and re.fullmatch(r'[a-f0-9]{32}', request['backupId']))
    routing(request['network'])
    with directory(SYSTEM) as lock:
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        return relay_session_census(request)


def dispatch(request: dict[str, Any]):
    global STAGE, NO_INSTALL_WRITES
    need(os.geteuid() == 0 and type(request) is dict, 'PREREQUISITE')
    action, machine = request['action'], request['machineId']
    if action == 'session-count':
        return read_session_count(request)
    need(re.fullmatch(r'[a-f0-9]{32}', machine) and action in
         ('preflight', 'prepare', 'check', 'install', 'verify', 'rollback', 'prepare-remove', 'remove')
         + CHAP_ACTIONS + APPLY_NETWORK_ACTIONS, 'PREREQUISITE')
    NO_INSTALL_WRITES = action == 'install'
    ready = preflight(machine)
    if action == 'preflight':
        return ready
    d = routing(request['network'])
    # Lock a stable system directory without creating a lock file in prepare.
    # This only serializes DIRECT invocations; the caller must exclude other
    # administrative writers. No locks from the old runners are consulted.
    with directory(SYSTEM) as fd:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action in APPLY_NETWORK_ACTIONS:
            keys = {'action', 'machineId', 'backupId', 'network'}
            if action in ('verify-apply-network', 'restart-apply-network'):
                keys.add('proof')
                need(re.fullmatch(r'[a-f0-9]{64}', request['proof']), 'CANDIDATE_INVALID')
            need(set(request) == keys and re.fullmatch(r'[a-f0-9]{32}', request['backupId']), 'CANDIDATE_INVALID')
            need(ready['ppp'] and ready['unitsLoaded'] and not ready['masked'], 'PREREQUISITE')
            return apply_network(request, action)
        if action in CHAP_ACTIONS:
            token = request['backupId']
            keys = {'action', 'machineId', 'backupId', 'network', 'nodeId', 'currentUsers', 'desiredUsers'}
            need(keys <= set(request) <= keys | {'revokedLogin'}
                 and re.fullmatch(r'[a-f0-9]{32}', token) and re.fullmatch(r'[a-f0-9]{24}', request['nodeId']), 'CANDIDATE_INVALID')
            need(ready['ppp'] and ready['unitsLoaded'] and not ready['masked'], 'PREREQUISITE')
            return sync_chap(request, write_changes=action == 'sync-chap')
        if action in ('prepare-remove', 'remove'):
            token = request['backupId']
            keys = {'action', 'machineId', 'backupId', 'network', 'nodeId'}
            keys |= {'baseline'} if action == 'remove' else set()
            optional = {'transit', 'currentUsers'} | ({'expectedCensus'} if action == 'remove' else set())
            need(re.fullmatch(r'[a-f0-9]{32}', token) and re.fullmatch(r'[a-f0-9]{24}', request['nodeId'])
                 and keys <= set(request) <= keys | optional
                 and ('expectedCensus' not in request or re.fullmatch(r'[a-f0-9]{64}', request['expectedCensus']))
                 and ('transit' not in request or type(request['transit']) is list), 'CANDIDATE_INVALID')
            state = observe_removal(request)
            if action == 'prepare-remove':
                STAGE = 'CANDIDATE_INVALID'
                validate_profiles(state['profiles'])
                return {'ok': True, 'backupId': token, 'machineId': machine, 'baseline': state['baseline']}
            need(state['baseline'] == request['baseline'], 'BASELINE_CHANGED')
            remove_installation(request, state)
            return {'ok': True, 'backupId': token, 'removed': True}
        transit = request.get('transit')
        need('transit' not in request or type(transit) is list, 'CANDIDATE_INVALID')
        if action == 'prepare':
            before = observe(machine, d, transit)
            main = raw(before['files']['main'])
            bridge = raw(before['bridge']) if before['bridge'] is not None else None
            return {**ready, 'baseline': digest(encode(before)), 'main': main.decode(), 'mainSha256': digest(main),
                    'bridge': bridge.decode() if bridge is not None else None, 'bridgeSha256': digest(bridge) if bridge is not None else None}
        token = request['backupId']
        need(re.fullmatch(r'[a-f0-9]{32}', token) and re.fullmatch(r'[a-f0-9]{64}', request['baseline']), 'CANDIDATE_INVALID')
        if action in ('check', 'install'):
            before = observe(machine, d, transit)
            need(digest(encode(before)) == request['baseline'], 'BASELINE_CHANGED')
            after = candidate(request, before)
            validate_candidate(after)
            if action == 'install':
                need(observe(machine, d, transit) == before, 'BASELINE_CHANGED')
                NO_INSTALL_WRITES = False
                install(request, before, after)
        else:
            path, record, backup = bound_manifest(request)
            if action == 'verify':
                need(backup['phase'] == 'installed', 'RUNTIME_UNPROVED')
                files = load_after(backup, require_all=True)
                need(installed_runtime(d, token, backup['before'], files) == backup['runtime'], 'RUNTIME_UNPROVED')
            else:
                rollback(request, path, record, backup)
        return {'ok': True, 'backupId': token}


def main():
    os.umask(0o077)
    action = None
    try:
        wire = sys.stdin.buffer.read(MAX_REQUEST + 1)
        need(0 < len(wire) <= MAX_REQUEST, 'CANDIDATE_INVALID')
        request = json.loads(wire)
        action = request.get('action') if type(request) is dict else None
        result = dispatch(request)
    except (subprocess.TimeoutExpired, BlockingIOError):
        return 75
    except Refusal as error:
        if REMOVE_ENTERED or CHAP_ENTERED or NETWORK_UPGRADE_ENTERED or str(error) == 'IN_FLIGHT':
            return 75
        print(('DIRECT_NO_WRITE_' if NO_INSTALL_WRITES else 'DIRECT_') + (
              'REMOVE_IPSEC_BUSY' if action in ('prepare-remove', 'remove') and str(error) == 'REMOVE_IPSEC_BUSY' else
              'REMOVE_REFUSED' if action == 'remove' else
              'CHAP_REFUSED' if action in CHAP_ACTIONS else
              SESSION_UNKNOWN if action == 'session-count' else str(error)), file=sys.stderr)
        return 70
    except Exception:
        # Trap parser failures without ever echoing file contents/child stderr.
        if REMOVE_ENTERED or CHAP_ENTERED or NETWORK_UPGRADE_ENTERED:
            return 75
        print(('DIRECT_NO_WRITE_' if NO_INSTALL_WRITES else 'DIRECT_') + ('REMOVE_REFUSED' if action == 'remove' else
              'CHAP_REFUSED' if action in CHAP_ACTIONS else
              SESSION_UNKNOWN if action == 'session-count' else STAGE), file=sys.stderr)
        return 70
    print(json.dumps(result, ensure_ascii=True, separators=(',', ':')), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
