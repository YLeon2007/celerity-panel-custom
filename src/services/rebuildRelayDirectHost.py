# DIRECT TEST install and owned removal. This private endpoint accepts only the fixed
# actions/paths below. No remote runner, package installs, or global flushes.
import base64
import contextlib
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import re
import stat
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
    global_paths = ('/etc/ppp/options', '/etc/strongswan.conf', XL_DEFAULT)
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
    STAGE = 'PROFILE_USERS'
    sockets = xray_users(files['main'], units[X], rows, transit)
    need(sockets, 'RUNTIME_UNPROVED')
    # Project stable unit fields only; systemctl ExecStart includes runtime timestamps.
    unit_pins = {name: {key: units[name].get(key) for key in
                 ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'InvocationID', 'FragmentPath', 'DropInPaths')}
                 for name in UNITS}
    return dict(boot=boot(), files=files, units=unit_pins, bridge=bridge, sockets=sockets, globalFiles=globals_before,
                installBoot=install_boot, ikeSockets=ike_sockets, **({'transit': transit} if transit is not None else {}))


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
    prerequisite = X + (' ' + B if sidecar else '')
    net_unit = f'''[Unit]
Description=Celerity rebuild L2TP TPROXY policy
Before={XL}
Requires={X}
After={prerequisite} nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=20s
ExecStart=/usr/sbin/nft -f {NFT_FILE}
ExecStart=/usr/sbin/ip -4 route add local 0.0.0.0/0 dev lo table {d['routeTable']}
ExecStart=/usr/sbin/ip -4 rule add priority {PRIORITY} from {d['clientCidr']} fwmark {d['fwmark']} table {d['routeTable']}
'''.encode()
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
    after['net'], after['drop'] = entry(net_unit, 0o644), entry(drop, 0o644)
    need(nft_marker(bytes_['nft'], token), 'CANDIDATE_INVALID')
    return after


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
    return {**NAMES, **({'bridge': BRIDGE} if 'bridge' in records else {})}


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


def file_generations(records=None):
    result = {}
    for k, path in operation_files(records or {}).items():
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
    return {'nft': policy['nft'], 'invocations': [u['InvocationID'] for u in (x, lns, ike, net_unit)]
            + ([bridge_info['InvocationID']] if bridge_info is not None else []),
            'files': file_generations(after), 'bootEnrollment': boot_link() if before.get('installBoot') else None}


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
    sc('start', XL, wait=26)
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
    backup.update(phase='installed', runtime=runtime)
    write(path, old_manifest, entry(encode(backup)))


def after_match(record, expected):
    return record is not None and {**record, 'data': digest(raw(record))} == expected


def load_after(backup, require_all=False):
    current = {key: read(path) for key, path in operation_files(backup['after']).items()}
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
    if backup['phase'] == 'installed':
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
    backup['phase'] = 'rolling-back'
    rolling = entry(encode(backup))
    write(path, old_manifest, rolling)
    for n in (XL, IKE, NET_UNIT):
        info = unit(n)
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
    for k in reversed((*ORDER, 'bridge') if sidecar else ORDER):
        if current[k] != originals[k]:
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


def removal_units(units, before, runtime, restart_bridge):
    bad = 'ROLLBACK_DRIFT'
    x, xl, ike, net = (units[name] for name in (X, XL, IKE, NET_UNIT))
    need(x['FragmentPath'] == before['units'][X]['FragmentPath'] and working(x), bad)
    need(net['LoadState'] == 'loaded' and net['FragmentPath'] == NET and not net['DropInPaths']
         and net['UnitFileState'] == 'static' and net['NeedDaemonReload'] == 'no' and no_hooks(net)
         and not any(net.get(k) for k in ('Environment', 'EnvironmentFiles'))
         and net.get('User') in ('', 'root') and net.get('Type') == 'oneshot'
         and X in net['Requires'].split() and net['MainPID'] == '0', bad)
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


def removal_vpn_runtime(rows, units):
    xl, ike = units[XL], units[IKE]
    lns_active, ike_active = (info['ActiveState'] == 'active' for info in (xl, ike))
    lns_rows = [(p, owners) for p, _, n, owners in rows if n == 1701]
    ike_rows = [(p, n, owners) for p, _, n, owners in rows if n in (500, 4500)]
    need(bool(lns_rows) == lns_active and all(p == 'udp' and owners == [xl['MainPID']] for p, owners in lns_rows)
         and {n for _, n, _ in ike_rows} == ({500, 4500} if ike_active else set())
         and all(p == 'udp' and owners and all(in_cgroup(pid, ike) for pid in owners) for p, _, owners in ike_rows),
         'RUNTIME_UNPROVED')
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


def observe_removal(request):
    bad = 'ROLLBACK_DRIFT'
    token, d = request['backupId'], request['network']
    path, manifest, backup = read_manifest(token)
    before, runtime = backup['before'], backup['runtime']
    need(backup['phase'] == 'installed' and backup['machineId'] == request['machineId']
         and backup['backupId'] == token and backup['network'] == d and before['boot'] == boot(), bad)
    intent = os.path.join(os.path.dirname(path), 'remove-attempt.json')
    need(directory_absent(intent), bad)
    no_jobs(UNITS)
    boot_enrollment = removal_boot(before, backup, runtime)
    original_ike = before.get('ikeSockets', [])
    need(bool(original_ike) == (before['units'][IKE]['ActiveState'] == 'active'), bad)
    current = {k: read(p) for k, p in NAMES.items()}
    main = current['main']
    if main is None:
        raise Refusal(bad)
    generations = file_generations()
    # Apply can replace Xray profiles. Every other owned file must still be
    # the exact installed generation, even if a replacement has the same bytes.
    need(all(after_match(current[k], backup['after'][k]) and generations[k] == runtime['files'][k]
             for k in NAMES if k != 'main'), bad)
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
    removal_units(units, before, runtime, 'bridge' in profiles)
    policy = network_projection(d, token, removing=True)
    need(policy == {'nft': runtime['nft'], 'rule': True, 'route': True} and policy['nft'] is not None, bad)
    rows = sock_rows()
    removal_vpn_runtime(rows, units)
    reserved = removal_sockets(rows, units, d, handoff, handoff_unit)
    transit = request.get('transit', before.get('transit'))
    xray_users(current['main'], units[X], rows, transit)
    sockets = [row for row in removal_xray_sockets(rows, units[X]['MainPID']) if row[2] not in reserved]
    bridge_sockets = removal_xray_sockets(rows, b['MainPID'])
    binary = remove_generation(XRAY)
    need(binary is not None, bad)
    manifest_generation = remove_generation(path)
    baseline = digest(encode([request['nodeId'], digest(raw(manifest)), manifest_generation, generations, boot_enrollment,
                              current['main'], {k: digest(raw(v)) for k, v in profiles.items()}, binary,
                              side, side_generation, units, policy, sockets, bridge_sockets, sorted(reserved),
                              handoff, handoff_unit, transit]))
    return dict(baseline=baseline, intent=intent, path=path, manifest=manifest, before=before, current=current,
                profiles=profiles, units=units, side=side, side_generation=side_generation, sockets=sockets,
                bridge_sockets=bridge_sockets, retained_handoff=handoff if handoff_unit == B else None,
                reserved=reserved, policy=policy, generations=generations, binary=binary,
                boot_enrollment=boot_enrollment, ike_sockets=original_ike, manifest_generation=manifest_generation,
                transit=transit)


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
    need(all(read(p) == (state['profiles']['main'] if k == 'main' else before['files'][k]) for k, p in NAMES.items())
         and all(directory_absent(p) for p in (DROP_DIR, NFT_DIR))
         and (state['boot_enrollment'] is None or boot_link() is None)
         and ike_include_matches(before['files']['starter'], []), 'RUNTIME_UNPROVED')


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
            need(x['InvocationID'] != state['units'][X]['InvocationID']
                 and xray_users(state['profiles']['main'], x, rows, state.get('transit')) == state['sockets']
                 and removal_xray_sockets(rows, x['MainPID']) == state['sockets'], 'RUNTIME_UNPROVED')
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
            sc('stop', name, wait=14)
            no_jobs(UNITS)
        elif info['ActiveState'] == 'failed':
            sc('reset-failed', name)
            no_jobs(UNITS)
        info = unit(name)
        need((info['ActiveState'], info['SubState'], info['MainPID']) == ('inactive', 'dead', '0'), STAGE)
    need(vpn_empty() and not any(n in (500, 4500, 1701) for _, _, n, _ in sock_rows())
         and network_projection(d, token, removing=True) == policy, STAGE)
    removal_neighbors(state)
    removal_owned_dirs()
    need(file_generations() == state['generations'] and (boot_enrollment is None or boot_link() == boot_enrollment),
         'ROLLBACK_DRIFT')
    # Keep the ingress firewall in place until the owned listeners are gone.
    x = unit(X)
    need(all(x[k] == units[X][k] for k in ('InvocationID', 'MainPID')), STAGE)
    removal_bridge_unit(state)
    need(read(BRIDGE) == state['side'] and remove_generation(BRIDGE) == state['side_generation'], STAGE)
    side_generation = state['side_generation']
    if split:
        write(BRIDGE, state['side'], profiles['bridge'])
        side_generation = remove_generation(BRIDGE)
    for k in reversed(ORDER):
        need(remove_generation(NAMES[k]) == state['generations'][k], STAGE)
        restored = profiles[k] if k == 'main' else before['files'][k]
        if current[k] != restored:
            write(NAMES[k], current[k], restored)
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
    need(all(final_x[k] == x[k] and final_b[k] == b[k] for k in ('InvocationID', 'MainPID'))
         and xray_users(profiles['main'], final_x, rows, state.get('transit')) == sockets
         and removal_xray_sockets(rows, final_x['MainPID']) == sockets
         and not any(n in absent for _, _, n, _ in rows)
         and network_projection(d, token, removing=True) == {'nft': None, 'rule': False, 'route': False}
         and vpn_empty(allow_socket_policies=restore_ike) and read(state['path'], 2 * MAX_FILE) == state['manifest'] and before['boot'] == boot()
         and remove_generation(XRAY) == state['binary'], STAGE)
    removal_files_after(state)
    removal_neighbors(state)


def dispatch(request: dict[str, Any]):
    global STAGE, NO_INSTALL_WRITES
    need(os.geteuid() == 0 and type(request) is dict, 'PREREQUISITE')
    action, machine = request['action'], request['machineId']
    need(re.fullmatch(r'[a-f0-9]{32}', machine) and action in
         ('preflight', 'prepare', 'check', 'install', 'verify', 'rollback', 'prepare-remove', 'remove'), 'PREREQUISITE')
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
        if action in ('prepare-remove', 'remove'):
            token = request['backupId']
            keys = {'action', 'machineId', 'backupId', 'network', 'nodeId'}
            keys |= {'baseline'} if action == 'remove' else set()
            need(re.fullmatch(r'[a-f0-9]{32}', token) and re.fullmatch(r'[a-f0-9]{24}', request['nodeId'])
                 and keys <= set(request) <= keys | {'transit'}
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
        if REMOVE_ENTERED or str(error) == 'IN_FLIGHT':
            return 75
        print(('DIRECT_NO_WRITE_' if NO_INSTALL_WRITES else 'DIRECT_') + ('REMOVE_REFUSED' if action == 'remove' else str(error)), file=sys.stderr)
        return 70
    except Exception:
        # Trap parser failures without ever echoing file contents/child stderr.
        if REMOVE_ENTERED:
            return 75
        print(('DIRECT_NO_WRITE_' if NO_INSTALL_WRITES else 'DIRECT_') + ('REMOVE_REFUSED' if action == 'remove' else STAGE), file=sys.stderr)
        return 70
    print(json.dumps(result, ensure_ascii=True, separators=(',', ':')), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
