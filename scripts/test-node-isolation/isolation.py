#!/usr/bin/python3 -I
"""TEST-only node maintenance. Root operator is TCB; no app authority export.

No CLI fake-root, shell passthrough, automatic retry or historical journal adoption.
V2 early return restores only the same live apply's known pre-capture effects.
Use only after independent review/install; see README.md.
"""
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shlex
import socket
import stat
import struct
import subprocess
import sys
import time

RUNNER = '/usr/local/bin/celerity-topology-node-runner-v2'
HELPER = '/usr/local/libexec/c3-test-node-isolation'
CONFIG = '/etc/c3-test-node-isolation.json'
INVENTORY = '/etc/celerity/topology-test-inventory.json'
STATE = '/var/lib/c3-test-node-isolation'
# Export only with the actual sticky Engine.dispatch admission gate below.
# Installed helper SHA256 must still be independently accepted by the restorer.
RESTORE_ADMISSION_VERSION = 1
RUNNER_FENCES = '/var/lib/celerity/topology/fences'
MAINT_UNIT = 'c3-test-maintenance-sshd.service'
MAINT_CONFIG = '/etc/ssh/c3-test-maintenance.conf'
MASK_ROOT = '/etc/systemd/system'
OPERATOR = 'c3-test-operator'
RUNNER_USER = 'c3-test-runner'
TEST_NODES = {
    '6ab18adc63913ebd4a917471': ('132.243.230.19', 'xray-main'),
    '6ab93ad2646b4b7d2f43c907': ('94.103.2.186', 'xray-main'),
    '6ab18d9c63913ebd4a917670': ('50.114.160.63', 'xray-bridge'),
    '6ab4b53bc4c0304573e06c72': ('104.143.201.72', 'xray-bridge'),
}
SAFE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
UNIT = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9_.@:-]|\\x[0-9a-fA-F]{2})*\.(service|socket|timer|scope)\Z')
NAMES = ['command', 'operation-id', 'node-id', 'candidate-hash', 'backup-id',
         'target-profile', 'execution-context', 'attempt-id', 'generation',
         'predecessor-generation', 'command-id']
CLEAN_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}


class Refusal(Exception):
    pass


class EarlyReturnUnknown(Refusal):
    """Return was attempted; journal retention does not prove writer exclusion."""


class KnownIsolationRefusal(Refusal):
    """A local inventory predicate refused; NOT an unknown read/guard/effect."""


def need(condition, code):
    if not condition:
        raise Refusal(code)


def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, 'DUPLICATE_JSON_KEY')
        out[key] = value
    return out


def decode_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise Refusal('INVALID_JSON') from None


def parse_runner(original, plan):
    need(isinstance(original, str) and len(original) <= 16384, 'INVALID_COMMAND')
    try:
        words = shlex.split(original, posix=True)
    except ValueError:
        raise Refusal('INVALID_COMMAND') from None
    need(words and words[0] == RUNNER, 'NOT_FIXED_RUNNER')
    args = words[1:]
    need(len(args) in (22, 24) and args[::2] == ['--' + n for n in NAMES] +
         (['--checks'] if len(args) == 24 else []), 'INVALID_ARGV')
    request = dict(zip(NAMES + ['checks'], args[1::2]))
    need(request['command'] in ('prepare', 'commit', 'verify', 'rollback', 'close', 'status', 'restore-users', 'verify-ppp-users'), 'INVALID_COMMAND')
    for name in ('operation-id', 'node-id', 'backup-id', 'attempt-id', 'generation', 'predecessor-generation', 'command-id'):
        need(bool(SAFE.fullmatch(request[name])) and request[name] not in ('.', '..'), 'INVALID_ID')
    need(request['generation'] != 'none', 'INVALID_GENERATION')
    need(bool(re.fullmatch(r'sha256:[a-f0-9]{64}', request['candidate-hash'])), 'INVALID_HASH')
    need(request['execution-context'] == 'test.infograd.online' and
         request['node-id'] == plan['nodeId'] and request['target-profile'] == plan['targetProfile'], 'FOREIGN_BINDING')
    need(('checks' in request) == (request['command'] in ('verify', 'restore-users', 'verify-ppp-users')), 'INVALID_CHECKS')
    if 'checks' in request:
        value = request['checks']
        need(bool(re.fullmatch(r'[A-Za-z0-9_-]{1,8192}', value)), 'INVALID_CHECKS')
        try:
            raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
        except ValueError:
            raise Refusal('INVALID_CHECKS') from None
        need(base64.urlsafe_b64encode(raw).decode().rstrip('=') == value, 'INVALID_CHECKS')
        checks = decode_json(raw)
        if request['command'] in ('restore-users', 'verify-ppp-users'):
            need(isinstance(checks, dict), 'INVALID_CHECKS')
            def token(value):
                return isinstance(value, str) and bool(SAFE.fullmatch(value)) and value not in ('.', '..')
            need(token(checks.get('bootId')), 'INVALID_CHECKS')
            if request['command'] == 'restore-users':
                need(plan['targetProfile'] == 'xray-main' and set(checks) == {'bootId', 'snapshotSha256', 'userCount'}
                     and isinstance(checks.get('snapshotSha256'), str) and bool(re.fullmatch(r'[a-f0-9]{64}', checks['snapshotSha256']))
                     and type(checks.get('userCount')) is int and 1 <= checks['userCount'] <= 4096, 'INVALID_CHECKS')
            else:
                need(set(checks) == {'bootId', 'operationId', 'expectedCredentialRevision', 'expectedEnabledUserCount'}
                     and token(checks.get('operationId')) and type(checks.get('expectedCredentialRevision')) is int
                     and 1 <= checks['expectedCredentialRevision'] <= 2**53-1
                     and type(checks.get('expectedEnabledUserCount')) is int
                     and 0 <= checks['expectedEnabledUserCount'] <= 2**53-1, 'INVALID_CHECKS')
            return args
        need(isinstance(checks, list) and len(checks) <= 64, 'INVALID_CHECKS')
        service = 'xray.service' if plan['targetProfile'] == 'xray-main' else 'xray-bridge.service'
        for check in checks:
            need(isinstance(check, dict), 'INVALID_CHECKS')
            valid_service = check == {'type': 'service', 'serviceUnit': service, 'expectedState': 'active'}
            valid_port = (set(check) == {'type', 'port', 'protocol', 'expectedState'} and
                          check.get('type') == 'port' and check.get('protocol') == 'tcp' and
                          type(check.get('port')) is int and 1 <= check['port'] <= 65535 and
                          check.get('expectedState') in ('listening', 'absent'))
            need(valid_service or valid_port, 'INVALID_CHECKS')
    return args


PLAN_KEYS = {'version', 'context', 'nodeId', 'endpointIp', 'targetProfile', 'machineId',
             'bootId', 'sshHostKeySha256', 'maintenanceId', 'runnerSha256',
             'maintenanceConfigSha256', 'maintenanceUnitSha256', 'runtimePins',
             'isolateUnits', 'keepCgroups', 'unitFilePins'}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def assert_readiness_receipt(receipt, request, fields, plan):
    """Exact auxiliary result, in addition to dispatch's common identity checks."""
    code = 'RUNNER_RECEIPT_UNKNOWN_RETAINED'
    need(set(receipt) == {'command', *fields.values(), 'protocolVersion', 'completion',
                         'phase', 'ownershipRetained', 'bootId', 'checksSha256', 'result'}, code)
    raw = base64.urlsafe_b64decode(request['checks'] + '=' * (-len(request['checks']) % 4))
    checks = decode_json(raw)
    need(checks['bootId'] == plan['bootId'] and receipt['phase'] == 'verified'
         and receipt['checksSha256'] == digest(raw), code)
    result = receipt['result']
    need(isinstance(result, dict) and result.get('ok') is True, code)
    if request['command'] == 'restore-users':
        need(set(result) == {'ok', 'code', 'userCount', 'inboundCount'}
             and result['code'] == 'XRAY_USERS_RESTORED' and type(result['userCount']) is int
             and result['userCount'] == checks['userCount'] and type(result['inboundCount']) is int
             and 1 <= result['inboundCount'] <= 64, code)
    else:
        expected = {'ok': True, 'code': 'USERS_VERIFIED',
                    'credentialRevision': checks['expectedCredentialRevision'],
                    'enabledUserCount': checks['expectedEnabledUserCount'],
                    'managedUserCount': checks['expectedEnabledUserCount']}
        need(result == expected and all(type(result[k]) is type(v) for k, v in expected.items()), code)


def validate_plan(p):
    need(isinstance(p, dict) and set(p) == plan_keys(p), 'INVALID_PLAN_FIELDS')
    if p.get('version') == 2:
        inventory = accepted_inventory(p)
        need(p['nodeId'] != inventory['sharedNodeId'], 'DEDICATED_TEST_NODE_ONLY')
        inventory_node(p, inventory=inventory)
    else:
        need(isinstance(p['nodeId'], str) and p['nodeId'] in TEST_NODES, 'DEDICATED_TEST_NODE_ONLY')
        need((p['endpointIp'], p['targetProfile']) == TEST_NODES[p['nodeId']], 'ENDPOINT_PROFILE_MISMATCH')
    return validate_common_plan(p)


def plan_keys(p):
    return PLAN_KEYS | ({'inventorySha256'} if p.get('version') == 2 else set())


def validate_inventory(value):
    """Independent root policy, never derived from mutable node/HTTP/env data."""
    import ipaddress
    need(isinstance(value, dict) and set(value) == {'version','profile','executionContext','nodes','sharedNodeId'}
         and type(value['version']) is int and value['version'] == 1 and value['profile'] == 'accepted-test-v1'
         and value['executionContext'] == {'target':'test','hostIdentity':'test.infograd.online'}
         and isinstance(value['nodes'], list) and 1 <= len(value['nodes']) <= 5, 'INVALID_ACCEPTED_INVENTORY')
    ids, machines, keys, endpoints = set(), set(), set(), set()
    for pin in value['nodes']:
        need(isinstance(pin, dict) and set(pin) == {'nodeId','targetProfile','endpoint','physical','profiles'}
             and isinstance(pin['nodeId'], str) and re.fullmatch('[a-f0-9]{24}', pin['nodeId'])
             and pin['nodeId'] not in ids and pin['targetProfile'] in ('xray-main','xray-bridge'), 'INVALID_INVENTORY_NODE')
        ids.add(pin['nodeId'])
        endpoint = pin['endpoint']
        need(isinstance(endpoint, dict) and set(endpoint) == {'ip','port','username'} and isinstance(endpoint['ip'], str)
             and type(endpoint['port']) is int and endpoint['port'] == 2222 and endpoint['username'] == RUNNER_USER, 'INVALID_INVENTORY_ENDPOINT')
        try:
            ip = ipaddress.IPv4Address(endpoint['ip'])
        except ipaddress.AddressValueError:
            raise Refusal('INVALID_INVENTORY_ENDPOINT') from None
        need(any(ip in ipaddress.IPv4Network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
             and str(ip) == endpoint['ip'] and str(ip) not in endpoints, 'INVALID_INVENTORY_ENDPOINT')
        endpoints.add(str(ip))
        physical = pin['physical']
        need(isinstance(physical, dict) and set(physical) == {'machineId','bootId','sshHostKeySha256'}, 'INVALID_INVENTORY_PHYSICAL')
        for field, pattern in (('machineId','[a-f0-9]{32}'),('bootId','[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'),('sshHostKeySha256','[a-f0-9]{64}')):
            need(isinstance(physical[field], str) and re.fullmatch(pattern, physical[field]), 'INVALID_INVENTORY_PHYSICAL')
        need(physical['machineId'] not in machines and physical['sshHostKeySha256'] not in keys, 'ALIASED_NODE_RETAINED')
        machines.add(physical['machineId']); keys.add(physical['sshHostKeySha256'])
        need(pin['profiles'] in ([pin['targetProfile']], ['xray-main','xray-bridge']), 'INVALID_INVENTORY_PROFILES')
    shared = next((pin for pin in value['nodes'] if pin['nodeId'] == value['sharedNodeId']), None)
    need(shared is not None and shared['targetProfile'] == 'xray-bridge' and shared['profiles'] == ['xray-main','xray-bridge'], 'SHARED_INVENTORY_REQUIRED')
    return value


def accepted_inventory(p, read=None):
    need(type(p.get('version')) is int and p['version'] == 2 and isinstance(p.get('inventorySha256'), str)
         and re.fullmatch('[a-f0-9]{64}', p['inventorySha256']), 'ACCEPTED_INVENTORY_REQUIRED')
    inventory = validate_inventory(decode_json((read or secure_file)(INVENTORY)))
    raw = json.dumps(inventory, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    need(digest(raw) == p['inventorySha256'], 'ACCEPTED_INVENTORY_DRIFT')
    return inventory


def inventory_node(p, read=None, *, inventory=None):
    inventory = accepted_inventory(p, read) if inventory is None else inventory
    pin = next((pin for pin in inventory['nodes'] if pin['nodeId'] == p.get('nodeId')), None)
    need(pin is not None and p.get('context') == 'test.infograd.online' and pin['endpoint']['ip'] == p.get('endpointIp')
         and pin['targetProfile'] == p.get('targetProfile') and all(p.get(k) == v for k,v in pin['physical'].items()), 'ACCEPTED_NODE_IDENTITY_DRIFT')
    return pin


NETWORK_RUNTIME_PINS = {
    '/usr/local/libexec/c3-test-node-isolation',
    '/usr/local/libexec/c3-test-shared-host.py',
    '/usr/local/libexec/c3-test-fresh-network.py',
    '/usr/local/libexec/c3-test-fresh-network-control.py',
    '/usr/local/libexec/c3-test-fresh-network-exec.py',
}


def validate_common_plan(p, *, network_bound=False):
    # Shared mode uses this shape/policy check, never the dedicated node allowlist.
    need(isinstance(p, dict) and set(p) == plan_keys(p), 'INVALID_PLAN_FIELDS')
    need(type(p['version']) is int and p['version'] in (1, 2) and p['context'] == 'test.infograd.online', 'TEST_ONLY')
    if p['version'] == 2:
        inventory_node(p)
    for name, pattern in [('machineId', r'[a-f0-9]{32}'), ('bootId', r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'),
                          ('maintenanceId', r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')]:
        need(isinstance(p[name], str) and re.fullmatch(pattern, p[name]) is not None, 'INVALID_IDENTITY')
    for name in ('sshHostKeySha256', 'runnerSha256', 'maintenanceConfigSha256', 'maintenanceUnitSha256'):
        need(isinstance(p[name], str) and re.fullmatch(r'[a-f0-9]{64}', p[name]) is not None, 'INVALID_DIGEST')
    need(not network_bound or p['version'] == 2, 'NETWORK_SHARED_V2_REQUIRED')
    need(isinstance(p['runtimePins'], dict) and set(p['runtimePins']) ==
         {'/bin/bash', '/usr/bin/python3'} | (NETWORK_RUNTIME_PINS if network_bound else set()), 'RUNTIME_PINS_REQUIRED')
    for pins in (p['runtimePins'], p['unitFilePins']):
        need(isinstance(pins, dict), 'INVALID_PINS')
        for path, sha in pins.items():
            need(isinstance(path, str) and path.startswith('/') and '..' not in path.split('/') and
                 isinstance(sha, str) and re.fullmatch(r'[a-f0-9]{64}', sha) is not None, 'INVALID_PINS')
    units = p['isolateUnits']
    need(isinstance(units, list) and len(units) <= 256 and len(set(units)) == len(units) and
         all(isinstance(u, str) and UNIT.fullmatch(u) for u in units), 'INVALID_UNITS')
    # Never allow a writer review to disable the maintenance transport or data plane.
    need(not any(u.startswith(('xray', 'ppp', 'xl2tp', 'strongswan', 'ipsec', 'network', 'systemd-network')) or
                 u == MAINT_UNIT for u in units), 'DATA_PLANE_OR_RECOVERY_UNIT')
    need({'cc-agent.service', 'certbot.service', 'certbot.timer', 'atd.service'} <= set(units) and
         bool({'ssh.service', 'sshd.service'} & set(units)) and 'ssh.socket' in units and
         bool({'cron.service', 'crond.service'} & set(units)), 'REQUIRED_WRITER_MASKS_MISSING')
    groups = p['keepCgroups']
    need(isinstance(groups, list) and len(groups) <= 256 and len(set(groups)) == len(groups) and groups and
         all(isinstance(g, str) and g.startswith('/') and g != '/' and not g.endswith('/') and
             all(x not in ('', '.', '..') for x in g.split('/')[1:]) for g in groups), 'INVALID_KEEP_CGROUPS')
    need('/system.slice/' + MAINT_UNIT in groups, 'RECOVERY_CGROUP_REQUIRED')
    need(all(g == '/init.scope' or (g.startswith('/system.slice/') and
             UNIT.fullmatch(g.rsplit('/', 1)[-1]) and g.endswith('.service')) for g in groups),
         'BROAD_KEEP_CGROUP_FORBIDDEN')
    need(not any(g.rsplit('/', 1)[-1] in units for g in groups), 'WRITER_KEEP_CONFLICT')
    return p


def proc_identity(pid):
    # /proc stat comm can contain spaces and parentheses. starttime is field 22.
    raw = pathlib.Path('/proc', str(pid), 'stat').read_text()
    rest = raw[raw.rfind(')') + 2:].split()
    return {'pid': int(pid), 'start': rest[19], 'ppid': int(rest[1]), 'state': rest[0]}


def secure_file(path, allow_symlink=False):
    path = pathlib.Path(path)
    for part in reversed([path, *path.parents]):
        info = part.lstat()
        need(info.st_uid == 0 and not info.st_mode & 0o022, 'UNTRUSTED_PATH')
        if stat.S_ISLNK(info.st_mode):
            need(allow_symlink, 'SYMLINK_PATH')
    need(path.resolve().is_file(), 'NOT_REGULAR_FILE')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOATIME |
                 (0 if allow_symlink else os.O_NOFOLLOW))
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             'UNTRUSTED_PATH')
        data = bytearray()
        while block := os.read(fd, 65536):
            data.extend(block)
            need(len(data) <= 16*1024*1024, 'SECURE_FILE_LIMIT')
        return bytes(data)
    finally: os.close(fd)


def atomic_json(directory, name, obj):
    directory = pathlib.Path(directory)
    raw = (json.dumps(obj, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(directory / (name + '.next'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    os.replace(directory / (name + '.next'), directory / name)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def parse_sshd_effective(raw):
    values = {}
    for line in raw.splitlines():
        if ' ' in line:
            key, value = line.split(' ', 1)
            values.setdefault(key, []).append(value)
    return {key: (' '.join(items) if key == 'allowusers' else items[0] if len(items) == 1 else items)
            for key, items in values.items()}


class Host:
    """Real Linux adapter. No environment-selected root or command executable."""
    def run(self, argv):
        remaining = getattr(self, 'return_deadline', float('inf')) - time.monotonic()
        need(remaining > 0, 'EARLY_RETURN_DEADLINE_RETAINED')
        result = subprocess.run(argv, env=CLEAN_ENV, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(40, remaining))
        need(result.returncode == 0, 'HOST_COMMAND_FAILED')
        return result.stdout.decode()

    def unit(self, name):
        keys = ['Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'ControlGroup',
                'MainPID', 'Job', 'FragmentPath', 'DropInPaths', 'KillMode', 'Triggers', 'TriggeredBy',
                'RuntimeDirectory', 'RuntimeDirectoryMode', 'RuntimeDirectoryPreserve', 'User', 'Group']
        raw = self.run(['/usr/bin/systemctl', 'show', '--no-pager', '--property=' + ','.join(keys), '--', name])
        return dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)

    def processes(self):
        result = []
        for entry in pathlib.Path('/proc').iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                ident = proc_identity(entry.name)
                groups = (entry / 'cgroup').read_text().splitlines()
                need(len(groups) == 1 and groups[0].startswith('0::/'), 'CGROUP_V2_REQUIRED')
                # Kernel tasks have no exe. Zombies cannot write but remain diagnostic.
                try:
                    exe = os.readlink(entry / 'exe')
                except FileNotFoundError:
                    if ident['state'] == 'Z':
                        continue
                    status = (entry / 'status').read_text()
                    need('Kthread:\t1\n' in status, 'UNCLASSIFIED_PROCESS')
                    continue
                ident.update(cgroup=groups[0][3:], exe=exe)
                need(proc_identity(entry.name)['start'] == ident['start'], 'PROCESS_IDENTITY_CHANGED')
                result.append(ident)
            except (FileNotFoundError, ProcessLookupError):
                continue
        return result

    def physical(self):
        raw = secure_file('/etc/ssh/ssh_host_ed25519_key.pub').split()
        need(len(raw) >= 2 and raw[0] == b'ssh-ed25519', 'ED25519_HOST_KEY_REQUIRED')
        blob = base64.b64decode(raw[1], validate=True)
        need(base64.b64encode(blob) == raw[1], 'NONCANONICAL_HOST_KEY')
        return {'machineId': pathlib.Path('/etc/machine-id').read_text().strip(),
                'bootId': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'sshHostKeySha256': digest(blob)}

    def inventory(self):
        units = self.run(['/usr/bin/systemctl', 'list-units', '--all', '--no-legend', '--plain', '--no-pager',
                          '--type=service,socket,timer,scope'])
        files = self.run(['/usr/bin/systemctl', 'list-unit-files', '--no-legend', '--no-pager',
                          '--type=service,socket,timer'])
        loaded = {l.split()[0] for l in units.splitlines() if l.split()}
        unit_files = {parts[0]: parts[1:] for l in files.splitlines()
                      if (parts := l.split()) and UNIT.fullmatch(parts[0])}
        # Uninstantiated template files are not runtime units: systemctl show
        # rejects them. Retain their file-list columns as diagnostic observations,
        # never invent an instance. Loaded names and concrete instances still
        # require show; their fragment/drop-in pins are collected below as before.
        templates = {u: fields for u, fields in unit_files.items()
                     if u.count('@') == 1 and u.endswith(('@.service', '@.socket', '@.timer'))}
        names = loaded | (unit_files.keys() - templates.keys())
        details = {u: self.unit(u) for u in sorted(names) if UNIT.fullmatch(u)}
        pins = {}
        for item in details.values():
            for f in [item.get('FragmentPath', ''), *item.get('DropInPaths', '').split()]:
                if f and pathlib.Path(f).is_file():
                    pins[f] = digest(pathlib.Path(f).read_bytes())
        jobs = self.run(['/usr/bin/systemctl', 'list-jobs', '--no-legend', '--no-pager'])
        sched = {}
        for root in ['/etc/crontab', '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly',
                     '/etc/cron.monthly', '/var/spool/cron', '/var/spool/at', '/etc/letsencrypt/renewal-hooks']:
            path = pathlib.Path(root)
            if path.is_file():
                sched[root] = digest(path.read_bytes())
            elif path.is_dir():
                for f in path.rglob('*'):
                    if f.is_file():
                        sched[str(f)] = digest(f.read_bytes())
        return {'diagnosticOnly': True, 'notAuthority': True, 'physicalObservation': self.physical(),
                'processes': self.processes(), 'units': details, 'unitFileTemplates': templates, 'unitFilePins': pins,
                'schedulerFileDigests': sched, 'jobsPresent': bool(jobs.strip())}

    def check_ssh_runtime(self, p):
        maintenance = self.unit(MAINT_UNIT)
        expected = {'RuntimeDirectory': 'sshd', 'RuntimeDirectoryMode': '0755',
                    'RuntimeDirectoryPreserve': 'yes', 'User': 'root', 'Group': 'root'}
        need(all(maintenance.get(k) == v for k, v in expected.items()), 'MAINT_RUNTIME_OWNERSHIP_REQUIRED')
        for name in p['isolateUnits']:
            if name.startswith('ssh') and name.endswith('.service'):
                item = self.unit(name)
                if item.get('ActiveState') not in ('inactive', 'failed') and 'sshd' in item.get('RuntimeDirectory', '').split():
                    need(item.get('RuntimeDirectoryPreserve') == 'yes', 'SSH_RUNTIME_PRESERVATION_REQUIRED')

    def check_prerequisites(self, p):
        need(self.physical() == {k: p[k] for k in ('machineId', 'bootId', 'sshHostKeySha256')}, 'PHYSICAL_IDENTITY_DRIFT')
        need(digest(secure_file(RUNNER)) == p['runnerSha256'], 'RUNNER_PIN_MISMATCH')
        for path, sha in p['runtimePins'].items():
            # /bin and python3 may be distribution-owned symlinks; resolved ancestors
            # must independently be trusted. Never accept a writable interpreter.
            target = str(pathlib.Path(path).resolve())
            need(digest(secure_file(target)) == sha, 'RUNTIME_PIN_MISMATCH')
        need(digest(secure_file(MAINT_CONFIG)) == p['maintenanceConfigSha256'], 'MAINT_CONFIG_DRIFT')
        need(digest(secure_file('/etc/systemd/system/' + MAINT_UNIT)) == p['maintenanceUnitSha256'], 'MAINT_UNIT_DRIFT')
        need(self.unit(MAINT_UNIT).get('ActiveState') == 'active', 'RECOVERY_TRANSPORT_DOWN')
        self.check_ssh_runtime(p)
        self.run(['/usr/sbin/sshd', '-t', '-f', MAINT_CONFIG])
        for user in (OPERATOR, RUNNER_USER, 'root'):
            raw = self.run(['/usr/sbin/sshd', '-T', '-f', MAINT_CONFIG, '-C',
                            'user=' + user + ',host=localhost,addr=127.0.0.1,laddr=' + p['endpointIp'] + ',lport=2222'])
            cfg = parse_sshd_effective(raw)
            expected = {'port': '2222', 'allowusers': OPERATOR + ' ' + RUNNER_USER, 'permitrootlogin': 'no',
                        'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
                        'pubkeyauthentication': 'yes', 'usepam': 'no', 'permittty': 'no',
                        'disableforwarding': 'yes', 'permituserenvironment': 'no',
                        'authorizedkeyscommand': 'none', 'authorizedkeysfile': '/etc/ssh/c3-test-keys/%u',
                        'authenticationmethods': 'publickey',
                        'listenaddress': p['endpointIp'] + ':2222',
                        'hostkey': '/etc/ssh/ssh_host_ed25519_key'}
            need(all(cfg.get(k) == v for k, v in expected.items()), 'UNSAFE_MAINT_SSHD')
            need(cfg.get('forcecommand') == ('/usr/bin/sudo -n ' + HELPER + ' dispatch' if user == RUNNER_USER else 'none'),
                 'UNSAFE_FORCE_COMMAND')
        for path, sha in p['unitFilePins'].items():
            # A reviewed /etc unit/alias is replaced by our durable mask. Its exact
            # original bytes live in the write-ahead snapshot; hold checks the mask.
            if path.startswith('/etc/systemd/system/') and path.rsplit('/', 1)[-1] in p['isolateUnits']:
                unit_path = pathlib.Path(path)
                if unit_path.is_symlink() and os.readlink(unit_path) == '/dev/null':
                    continue
            need(digest(secure_file(str(pathlib.Path(path).resolve()))) == sha, 'UNIT_FILE_DRIFT')

    def check_inventory(self, p, held=False):
        # Reject every unreviewed timer/socket/service activation unit, including
        # dormant ACME variants. Pins are the exact audited unit bytes, not DB rows.
        inventory = self.inventory()
        # Brand only our pure predicates, never transport/read failures, guard
        # loss or arbitrary error codes supplied by an adapter.
        def need(condition, code):
            if not condition:
                raise KnownIsolationRefusal(code)
        need(not inventory['jobsPresent'], 'SYSTEMD_JOB_PENDING')
        for name, item in inventory['units'].items():
            present = item.get('LoadState') != 'not-found' or item.get('ActiveState') not in ('inactive', 'failed')
            legacy_entry = name != MAINT_UNIT and (name.startswith(('ssh', 'cc-agent', 'cron', 'certbot', 'acme')) or
                           name in ('atd.service', 'user@0.service', 'unattended-upgrades.service',
                                    'apt-daily.service', 'apt-daily-upgrade.service'))
            if present and (name.endswith('.timer') or legacy_entry):
                need(name in p['isolateUnits'], 'UNREVIEWED_ACTIVATION_UNIT')
            if name.endswith('.timer') and not held:
                need(set(item.get('Triggers', '').split()) <= set(p['isolateUnits']), 'TIMER_CHILD_NOT_ISOLATED')
            for index, path in enumerate([item.get('FragmentPath', ''), *item.get('DropInPaths', '').split()]):
                if path and path != '/dev/null':
                    # systemd can report the lexical mask as FragmentPath, not
                    # /dev/null. It has no regular-file bytes to pin. Recognize
                    # only a direct mask for a masked fragment, never a drop-in
                    # or an arbitrary symlink resolving through other paths.
                    if index == 0 and item.get('LoadState') == 'masked':
                        mask = pathlib.Path(path)
                        if mask.is_symlink() and os.readlink(mask) == '/dev/null':
                            continue
                    need(path in p['unitFilePins'] and inventory['unitFilePins'].get(path) == p['unitFilePins'][path],
                         'UNREVIEWED_UNIT_FILE')
        stopgroups = {self.unit(u).get('ControlGroup') for u in p['isolateUnits']} - {'', None}
        allowed = set(p['keepCgroups']) | (set() if held else stopgroups)
        for proc in inventory['processes']:
            need(any(proc['cgroup'] == g or proc['cgroup'].startswith(g + '/') for g in allowed),
                 'UNCLASSIFIED_PROCESS_CGROUP')
            if held:
                exe = os.path.basename(proc.get('exe', '')).removesuffix(' (deleted)')
                legacy = exe in ('cc-agent', 'certbot', 'acme.sh', 'cron', 'crond', 'atd')
                maintenance_ssh = '/system.slice/' + MAINT_UNIT
                need(not legacy, 'LEGACY_WRITER_EXECUTABLE_REMAINS')
                need(not exe.startswith('sshd') or proc['cgroup'] == maintenance_ssh or
                     proc['cgroup'].startswith(maintenance_ssh + '/'), 'OLD_SSH_EXECUTABLE_REMAINS')
        return inventory

    def boot_ticks(self):
        # /proc stat starttime uses ticks since boot. Strict > refuses same-tick
        # or preopened connections; a later independent login must authenticate.
        return str(int(time.clock_gettime(time.CLOCK_BOOTTIME) * os.sysconf('SC_CLK_TCK')))

    def operator_session(self):
        import pwd
        need(os.environ.get('SUDO_USER') == OPERATOR and
             os.environ.get('SUDO_UID') == str(pwd.getpwnam(OPERATOR).pw_uid), 'INDEPENDENT_OPERATOR_SSH_REQUIRED')
        main = int(self.unit(MAINT_UNIT).get('MainPID', '0'))
        chain = []
        pid = os.getpid()
        while pid > 1 and len(chain) < 64:
            ident = proc_identity(pid)
            if ident['ppid'] == main:
                need(pathlib.Path('/proc', str(pid), 'comm').read_text().strip().startswith('sshd'), 'NOT_MAINTENANCE_SSH')
                return {k: ident[k] for k in ('pid', 'start')}
            chain.append(pid)
            pid = ident['ppid']
        raise Refusal('NOT_MAINTENANCE_SSH')

    def guard_check(self, guard, session=None):
        return check_guard(guard, session)

    def assert_runner_terminal(self, p, dispatched):
        fence = pathlib.Path('/var/lib/celerity/topology/fences') / p['targetProfile']
        if not (fence / 'lock').exists():
            need(not dispatched and not (fence / 'journal.json').exists(), 'RUNNER_TERMINAL_UNPROVEN')
            return
        fd = os.open(fence / 'lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            need(not (fence / 'journal.next').exists(), 'RUNNER_TERMINAL_UNPROVEN')
            journal = decode_json(secure_file(fence / 'journal.json'))
            need(journal['version'] == 2 and journal['bootId'] == p['bootId'] and
                 journal['nodeId'] == p['nodeId'] and journal['executionContext'] == p['context'], 'RUNNER_TERMINAL_UNPROVEN')
            head = journal['head']
            need(head is None or (journal['generations'][head]['phase'] == 'closed' and
                 all(c['state'] == 'completed' for c in journal['generations'][head]['commands'].values())),
                 'RUNNER_TERMINAL_UNPROVEN')
        finally:
            os.close(fd)

    @contextmanager
    def held_current_runner_head(self, p):
        """Current disk head, not status of a requested historical generation.

        No default-positive virgin/missing journal. Hold the actual runner mutex
        through the caller's final checks. Root administration is the TCB.
        """
        fence = pathlib.Path(RUNNER_FENCES) / p['targetProfile']
        secure_file(fence / 'lock')
        fd = os.open(fence / 'lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = os.fstat(fd)
            pin = (info.st_dev, info.st_ino)
            current = (fence / 'lock').stat()
            need(pin == (current.st_dev, current.st_ino),
                 'RUNNER_TERMINAL_UNPROVEN')
            def read():
                need(not os.path.lexists(fence / 'journal.next'), 'RUNNER_TERMINAL_UNPROVEN')
                raw = secure_file(fence / 'journal.json')
                need(len(raw) <= 16777216, 'RUNNER_TERMINAL_UNPROVEN')
                row = decode_json(raw)
                need(isinstance(row, dict) and set(row) == {'version', 'bootId', 'nodeId',
                     'executionContext', 'head', 'generations'} and type(row['version']) is int
                     and row['version'] == 2 and row['bootId'] == p['bootId']
                     and row['nodeId'] == p['nodeId'] and row['executionContext'] == p['context'],
                     'RUNNER_TERMINAL_UNPROVEN')
                generations = row['generations']
                need(isinstance(generations, dict) and 1 <= len(generations) <= 1024
                     and isinstance(row['head'], str) and row['head'] in generations,
                     'RUNNER_TERMINAL_UNPROVEN')
                for generation, entry in generations.items():
                    need(isinstance(entry, dict) and entry.get('phase') == 'closed'
                         and isinstance(entry.get('binding'), dict)
                         and all(entry['binding'].get(k) == v for k, v in {
                             'generation': generation, 'nodeId': p['nodeId'],
                             'targetProfile': p['targetProfile'], 'executionContext': p['context']}.items()),
                         'RUNNER_TERMINAL_UNPROVEN')
                    commands = entry.get('commands')
                    need(isinstance(commands, dict) and commands and
                         all(isinstance(c, dict) and c.get('state') == 'completed' for c in commands.values()),
                         'RUNNER_TERMINAL_UNPROVEN')
                    closes = [(cid, c) for cid, c in commands.items() if c.get('command') == 'close']
                    need(len(closes) == 1, 'RUNNER_TERMINAL_UNPROVEN')
                    cid, close = closes[0]; receipt = close.get('receipt')
                    need(isinstance(receipt, dict) and receipt.get('ok') is True
                         and receipt.get('terminal') is True and receipt.get('ownershipRetained') is True
                         and receipt.get('protocolVersion') == 2 and receipt.get('phase') == 'closed'
                         and receipt.get('command') == receipt.get('completedCommand') == 'close'
                         and receipt.get('commandId') == cid and receipt.get('bootId') == p['bootId']
                         and receipt.get('completion') == 'completed'
                         and all(receipt.get(k) == v for k, v in entry['binding'].items())
                         and ((receipt.get('terminalOutcome') in ('verified', 'rolledback')
                               and receipt.get('systemdJob') == 'completed'
                               and receipt.get('serviceState') in ('active:running', 'inactive:dead'))
                              or (receipt.get('terminalOutcome') == 'cancelled'
                                  and receipt.get('systemdJob') == receipt.get('serviceState') == 'not-applicable')),
                         'RUNNER_TERMINAL_UNPROVEN')
                return raw, row
            raw, row = read()
            yield {'head': row['head'], 'journalSha256': digest(raw)}
            current = (fence / 'lock').stat()
            need(read()[0] == raw and pin == (current.st_dev, current.st_ino),
                 'RUNNER_TERMINAL_UNPROVEN')
        finally:
            os.close(fd)

    def snapshot_mask(self, name):
        path = pathlib.Path(MASK_ROOT) / name
        attrs = {key: base64.b64encode(os.getxattr(path, key, follow_symlinks=False)).decode()
                 for key in os.listxattr(path, follow_symlinks=False)} if path.exists() or path.is_symlink() else {}
        if path.is_symlink():
            info = path.lstat()
            return {'kind': 'symlink', 'target': os.readlink(path), 'uid': info.st_uid, 'gid': info.st_gid, 'xattrs': attrs}
        if path.exists():
            need(path.is_file(), 'UNSAFE_UNIT_PATH')
            info = path.stat()
            return {'kind': 'file', 'data': base64.b64encode(path.read_bytes()).decode(), 'mode': stat.S_IMODE(info.st_mode),
                    'uid': info.st_uid, 'gid': info.st_gid, 'xattrs': attrs}
        return {'kind': 'absent'}

    def write_mask(self, name):
        path = pathlib.Path(MASK_ROOT) / name
        temporary = path.with_name('.c3-isolate-' + name)
        os.symlink('/dev/null', temporary)
        os.replace(temporary, path)
        self.sync_masks()

    def mask_identity(self, name):
        info = (pathlib.Path(MASK_ROOT) / name).lstat()
        need(stat.S_ISLNK(info.st_mode), 'EARLY_RETURN_MASK_DRIFT_RETAINED')
        return info.st_dev, info.st_ino

    def sync_masks(self):
        fd = os.open(MASK_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def restore_mask(self, name, saved):
        path = pathlib.Path(MASK_ROOT) / name
        need(path.is_symlink() and os.readlink(path) == '/dev/null', 'MASK_DRIFT_RETAINED')
        temporary = path.with_name('.c3-restore-' + name)
        if saved['kind'] == 'absent':
            path.unlink()
        elif saved['kind'] == 'symlink':
            os.symlink(saved['target'], temporary)
            os.chown(temporary, saved['uid'], saved['gid'], follow_symlinks=False)
            for key, value in saved['xattrs'].items():
                os.setxattr(temporary, key, base64.b64decode(value, validate=True), follow_symlinks=False)
            os.replace(temporary, path)
        else:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, saved['mode'])
            with os.fdopen(fd, 'wb') as f:
                f.write(base64.b64decode(saved['data'], validate=True))
                os.fchown(f.fileno(), saved['uid'], saved['gid'])
                os.fchmod(f.fileno(), saved['mode'])
                for key, value in saved['xattrs'].items():
                    os.setxattr(f.fileno(), key, base64.b64decode(value, validate=True))
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, path)
        self.sync_masks()

    def reload(self):
        self.run(['/usr/bin/systemctl', 'daemon-reload'])

    def stop(self, name):
        # A missing unit needs its persistent mask, not a fictitious successful stop.
        state = self.unit(name)
        if state.get('ActiveState') not in ('inactive', 'failed'):
            self.run(['/usr/bin/systemctl', 'stop', '--', name])

    def start(self, name):
        self.run(['/usr/bin/systemctl', 'start', '--', name])

    def assert_runner_virgin(self, p):
        for profile in inventory_node(p)['profiles']:
            root = pathlib.Path(RUNNER_FENCES) / profile
            need(not any(os.path.lexists(root / name) for name in ('lock', 'journal.json', 'journal.next')),
                 'EARLY_RETURN_RUNNER_HISTORY_RETAINED')

    def prepare_ssh_drain(self, name, item):
        # Sole exception to control-group/mixed: distro's normal SSH service.
        # Its exact fragment/drop-ins were already checked by check_inventory.
        need(name in ('ssh.service', 'sshd.service') and
             item.get('Id') in ('ssh.service', 'sshd.service') and
             item.get('KillMode') == 'process' and
             item.get('ControlGroup') == '/system.slice/' + item['Id'], 'UNSAFE_KILL_MODE')
        fd = os.open('/sys/fs/cgroup' + item['ControlGroup'],
                     os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            kill = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(kill)  # Require cgroup v2's atomic descendant kill before mutation.
            return {'device': info.st_dev, 'inode': info.st_ino}
        finally:
            os.close(fd)

    def drain_ssh(self, name, saved):
        # Called only after ALL activation units, old services and session scopes
        # have completed synchronous stop. Never kill by PID or a recomputed path.
        item, pin = saved['unit'], saved['sshDrain']
        need(name in ('ssh.service', 'sshd.service') and item.get('KillMode') == 'process' and
             item.get('Id') in ('ssh.service', 'sshd.service') and
             saved['oldCgroup'] == '/system.slice/' + item['Id'], 'UNSAFE_KILL_MODE')
        state = self.unit(name)
        mask = pathlib.Path(MASK_ROOT) / name
        need(mask.is_symlink() and os.readlink(mask) == '/dev/null' and
             state.get('LoadState') == 'masked' and state.get('ActiveState') in ('inactive', 'failed') and
             state.get('Job') in ('', '0') and state.get('MainPID') == '0' and
             state.get('ControlGroup', '') in ('', saved['oldCgroup']), 'SSH_ENTRY_NOT_STOPPED')
        try:
            fd = os.open('/sys/fs/cgroup' + saved['oldCgroup'],
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return  # Removed cgroup is joined; verify_exclusion still checks all old PIDs.
        try:
            info = os.fstat(fd)
            need(pin == {'device': info.st_dev, 'inode': info.st_ino}, 'SSH_CGROUP_IDENTITY_CHANGED')
            kill = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                need(os.write(kill, b'1\n') == 2, 'SSH_CGROUP_KILL_UNCERTAIN')
            finally:
                os.close(kill)
            deadline = time.monotonic() + 5
            while True:
                try:
                    events = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    break
                try:
                    values = dict(line.split() for line in os.read(events, 4096).decode().splitlines())
                finally:
                    os.close(events)
                if values.get('populated') == '0':
                    break
                need(time.monotonic() < deadline, 'SSH_CGROUP_NOT_DRAINED')
                time.sleep(0.05)
        finally:
            os.close(fd)

    def assert_stopped(self, name, oldgroup):
        state = self.unit(name)
        need((name.endswith('.scope') or state.get('LoadState') == 'masked') and
             state.get('ActiveState') in ('inactive', 'failed') and state.get('Job') in ('', '0'),
             'WRITER_UNIT_NOT_DRAINED')
        path = pathlib.Path(MASK_ROOT) / name
        need(path.is_symlink() and os.readlink(path) == '/dev/null', 'WRITER_NOT_PERSISTENTLY_MASKED')
        if oldgroup:
            path = pathlib.Path('/sys/fs/cgroup' + oldgroup) / 'cgroup.events'
            if path.exists():
                values = dict(l.split() for l in path.read_text().splitlines())
                need(values.get('populated') == '0', 'WRITER_CGROUP_POPULATED')
        for proc in self.processes():
            need(not oldgroup or not (proc['cgroup'] == oldgroup or proc['cgroup'].startswith(oldgroup + '/')),
                 'WRITER_DESCENDANT_REMAINS')


def check_guard(guard, session=None):
    ident = proc_identity(guard['pid'])
    need(ident['start'] == guard['start'] and ident['state'] != 'Z', 'RECOVERY_GUARD_LOST')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(2)
        conn.connect(guard['socket'])
        pid, uid, _gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(pid == guard['pid'] and uid == 0, 'GUARD_PEER_MISMATCH')
        nonce = os.urandom(32).hex()
        conn.sendall((nonce + '\n').encode())
        reply = b''
        while not reply.endswith(b'\n') and len(reply) < 4096:
            part = conn.recv(4096)
            need(bool(part), 'GUARD_CLOSED')
            reply += part
        answer = decode_json(reply)
        need(answer['nonce'] == nonce and answer['identity'] == guard, 'GUARD_CHALLENGE_MISMATCH')
        need(session is None or answer['session'] != session, 'FRESH_INDEPENDENT_SESSION_REQUIRED')
        parent = proc_identity(answer['session']['pid'])
        need(parent['start'] == answer['session']['start'] and parent['state'] != 'Z', 'RECOVERY_SSH_SESSION_LOST')
        return answer


def recovery_roundtrip(nonce):
    # A live local sshd PID alone is not a fresh usable operator connection.
    # Demand a bidirectional nonce echo through its actual SSH stdio channel.
    import select
    print(json.dumps({'recoveryChallenge': nonce}), flush=True)
    deadline = time.monotonic() + 2
    response = b''
    while not response.endswith(b'\n'):
        remaining = deadline - time.monotonic()
        need(remaining > 0 and bool(select.select([sys.stdin], [], [], max(0, remaining))[0]), 'RECOVERY_CHANNEL_TIMEOUT')
        part = os.read(sys.stdin.fileno(), 256 - len(response))
        need(bool(part), 'RECOVERY_CHANNEL_LOST')
        response += part
        need(len(response) < 256, 'RECOVERY_CHANNEL_INVALID')
    need(decode_json(response) == {'recoveryResponse': nonce}, 'RECOVERY_CHANNEL_LOST')


def recovery_guard(directory, host):
    session = host.operator_session()
    socket_path = str(pathlib.Path(directory) / 'recovery.sock')
    # Never replace an old guard/socket automatically.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(socket_path)
        os.chmod(socket_path, 0o600)
        server.listen(4)
        identity = {k: proc_identity(os.getpid())[k] for k in ('pid', 'start')}
        identity['socket'] = socket_path
        atomic_json(directory, 'guard.json', identity)
        print(json.dumps({'guardReady': True, 'identity': identity, 'session': session}), flush=True)
        server.settimeout(1)
        while True:
            # SSH death must revoke recovery, not leave a detached artificial guard.
            current = proc_identity(session['pid'])
            need(current['start'] == session['start'] and current['state'] != 'Z', 'RECOVERY_SSH_SESSION_LOST')
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(2)
                _pid, uid, _gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                need(uid == 0, 'ROOT_GUARD_CLIENT_REQUIRED')
                request = conn.recv(1024)
                need(bool(re.fullmatch(rb'[a-f0-9]{64}\n', request)), 'INVALID_GUARD_CHALLENGE')
                recovery_roundtrip(request.decode().strip())
                conn.sendall((json.dumps({'nonce': request.decode().strip(), 'identity': identity,
                                         'session': session}) + '\n').encode())


class Engine:
    def __init__(self, directory, plan, host, *, validator=validate_plan):
        self.directory = pathlib.Path(directory)
        self.plan = validator(plan)
        self.host = host
        self.plan_hash = digest(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode())
        # Deliberately NOT reconstructed from disk. Only this live apply may
        # unwind its completed effects; pending/unknown effects poison return.
        self._early = None

    def read(self):
        need(not (self.directory / 'journal.json.next').exists(), 'JOURNAL_UNCERTAIN_RETAINED')
        path = self.directory / 'journal.json'
        if not path.exists():
            return None
        value = decode_json(path.read_bytes())
        need(isinstance(value, dict) and set(value) == {'version', 'phase', 'plan', 'planHash', 'guard', 'saved',
                                                       'initialProcesses', 'dispatchInFlight', 'dispatchCount', 'accessBoundary'}, 'JOURNAL_CORRUPT_RETAINED')
        need(type(value['version']) is int and value['version'] == 1 and
             value['phase'] in ('isolating', 'awaiting-fresh-login', 'held', 'restoring', 'masks-restored-no-restart',
                                'early-returning', 'early-returned', 'early-return-unknown') and
             type(value['dispatchCount']) is int and value['dispatchCount'] >= 0 and
             isinstance(value['initialProcesses'], list) and isinstance(value['saved'], dict) and
             set(value['saved']) == set(self.plan['isolateUnits']), 'JOURNAL_CORRUPT_RETAINED')
        for name, saved in value['saved'].items():
            need(isinstance(saved, dict) and set(saved) == {'mask', 'unit', 'oldCgroup', 'sshDrain'} and
                 isinstance(saved['unit'], dict) and isinstance(saved['mask'], dict) and
                 isinstance(saved['oldCgroup'], str) and saved['oldCgroup'] == saved['unit'].get('ControlGroup', ''),
                 'JOURNAL_CORRUPT_RETAINED')
            pin = saved['sshDrain']
            need(pin is None or (name in ('ssh.service', 'sshd.service') and
                 isinstance(pin, dict) and set(pin) == {'device', 'inode'} and
                 all(type(v) is int and v >= 0 for v in pin.values())), 'JOURNAL_CORRUPT_RETAINED')
        boundary = value['accessBoundary']
        need((value['phase'] in ('isolating', 'early-returning', 'early-returned', 'early-return-unknown') and boundary is None) or
             (isinstance(boundary, dict) and set(boundary) == {'session', 'ticks'} and
              isinstance(boundary['session'], dict) and
              isinstance(boundary['ticks'], str) and boundary['ticks'].isdecimal()), 'JOURNAL_CORRUPT_RETAINED')
        need(value.get('planHash') == self.plan_hash and value.get('plan') == self.plan, 'PLAN_DRIFT_RETAINED')
        return value

    def save(self, value):
        atomic_json(self.directory, 'journal.json', value)

    def apply(self, guard):
        need(self.read() is None, 'EXISTING_MAINTENANCE_RETAINED')
        if self.plan['version'] == 2:
            self.assert_before_capture()
        self.host.check_prerequisites(self.plan)
        session = self.host.operator_session()
        self.host.guard_check(guard, session)
        inventory = self.host.check_inventory(self.plan)
        saved = {}
        for name in self.plan['isolateUnits']:
            item = self.host.unit(name)
            if self.plan['version'] == 2:
                need(item.get('ActiveState') in ('active', 'inactive', 'failed') and item.get('Job') in ('', '0'),
                     'UNRESTORABLE_INITIAL_UNIT_STATE')
                if item['ActiveState'] == 'active' and not name.endswith('.scope'):
                    substate = 'listening' if name.endswith('.socket') else 'waiting' if name.endswith('.timer') else 'running'
                    need(item.get('SubState') == substate, 'UNRESTORABLE_INITIAL_UNIT_STATE')
            ssh_drain = None
            if (name.endswith('.service') and item.get('KillMode') not in ('control-group', 'mixed') and
                    item.get('ActiveState') not in ('inactive', 'failed')):
                need(name in ('ssh.service', 'sshd.service') and item.get('KillMode') == 'process', 'UNSAFE_KILL_MODE')
                ssh_drain = self.host.prepare_ssh_drain(name, item)
            group = item.get('ControlGroup', '')
            if group:
                need(group.startswith('/') and group != '/' and '..' not in group.split('/') and
                     not any(group == keep or keep.startswith(group + '/') or group.startswith(keep + '/')
                             for keep in self.plan['keepCgroups']), 'WRITER_CGROUP_OVERLAPS_RECOVERY_OR_DATA_PLANE')
            saved[name] = {'mask': self.host.snapshot_mask(name), 'unit': item,
                           'oldCgroup': item.get('ControlGroup', ''), 'sshDrain': ssh_drain}
            if self.plan['version'] == 2 and item['ActiveState'] == 'active':
                need(not (saved[name]['mask'].get('kind') == 'symlink' and saved[name]['mask'].get('target') == '/dev/null'),
                     'UNRESTORABLE_INITIAL_UNIT_STATE')
        state = {'version': 1, 'phase': 'isolating', 'plan': self.plan, 'planHash': self.plan_hash,
                 'guard': guard, 'saved': saved, 'initialProcesses': inventory['processes'],
                 'dispatchInFlight': None, 'dispatchCount': 0, 'accessBoundary': None}
        self.save(state)  # All touched config and states durable before first mutation.
        early = self.plan['version'] == 2
        if early:
            self._early = {'state': state, 'owner': {k: proc_identity(os.getpid())[k] for k in ('pid', 'start')}, 'pending': False,
                           'active': True, 'masks': {}, 'maskPins': {}, 'stopped': []}
        live = self._early or {}

        def effect(work):
            if early:
                live['pending'] = True
            work()
            if early:
                live['pending'] = False

        def checkpoint():
            if early:
                self.host.guard_check(guard, session)
                self.host.check_prerequisites(self.plan)
                self.host.check_inventory(self.plan)

        try:
            for name in saved:
                def mask():
                    self.host.write_mask(name)
                    if early:
                        pin = self.host.snapshot_mask(name)
                        need(pin.get('kind') == 'symlink' and pin.get('target') == '/dev/null', 'MASK_WRITE_UNKNOWN_RETAINED')
                        live['masks'][name] = pin
                        live['maskPins'][name] = self.host.mask_identity(name)
                effect(mask)
                checkpoint()
            effect(self.host.reload)
            # Stop activation first. Keep only acknowledged effects in live memory.
            ordered = sorted(saved, key=lambda u: (not u.endswith(('.socket', '.timer')), u))
            for name in ordered:
                def stop():
                    self.host.stop(name)
                    if early:
                        current = self.host.unit(name)
                        need(current.get('ActiveState') in ('inactive', 'failed') and current.get('Job') in ('', '0'),
                             'STOP_OUTCOME_UNKNOWN_RETAINED')
                        live['stopped'].append(name)
                effect(stop)
                checkpoint()
            for name, item in saved.items():
                if item['sshDrain'] is not None:
                    effect(lambda: self.host.drain_ssh(name, item))
            self.verify_exclusion(state)
            self.host.guard_check(guard, session)
            state['accessBoundary'] = {'session': session, 'ticks': self.host.boot_ticks()}
            state['phase'] = 'awaiting-fresh-login'
            effect(lambda: self.save(state))
            return self.evidence(state)
        except BaseException as error:
            if not early:
                raise
            if type(error) is not KnownIsolationRefusal or live['pending']:
                live['active'] = False
                raise
            # Only a branded local predicate can request a known-partial unwind.
            # Fresh checks must still prove ownership and no downstream work.
            result = self.abort_return(getattr(self, '_outer_lock_fd', None))
            return {**result, 'isolationRefusal': str(error)}

    def assert_before_capture(self):
        need(self.plan['version'] == 2, 'V2_EARLY_RETURN_ONLY')
        # Any capture attempt (including an empty/unfinished store), durable
        # admission close or coordinator intent is beyond this local return.
        names = ('originals', 'restore-admission.json', 'restore-admission.json.next',
                 'coordinated-capture.json', 'coordinated-capture.json.next',
                 'coordinated-restore.json', 'coordinated-restore.json.next',
                 'handoff-commit.json', 'handoff-commit.json.next',
                 'handoff-activation.json', 'handoff-activation.json.next')
        need(not any(os.path.lexists(self.directory / name) for name in names), 'EARLY_RETURN_DOWNSTREAM_UNKNOWN_RETAINED')
        self.host.assert_runner_virgin(self.plan)

    def require_early_lock(self, lock_fd):
        # require_outer_lock alone may acquire an unlocked OFD. Early return
        # must instead prove continuous exclusion, never repair a lost lock.
        probe = os.open(self.directory / 'lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                fcntl.flock(probe, fcntl.LOCK_UN)
                raise Refusal('EARLY_RETURN_OUTER_LOCK_LOST_RETAINED')
        finally:
            os.close(probe)
        self.require_outer_lock(lock_fd)

    def abort_return(self, lock_fd):
        """Same-live apply only; never replay/adopt an isolating disk journal.

        OLD means original masks and service activation state, not resurrected
        drained SSH/session PIDs. No Xray/profile or DB mutation is performed.
        """
        live = self._early
        need(live is not None and live['active'], 'EARLY_RETURN_LIVE_OWNER_REQUIRED')
        assert live is not None
        live['active'] = False  # Consume even a refused check; no repaired-unknown retry.
        need(not live['pending'], 'EARLY_RETURN_LIVE_OWNER_REQUIRED')
        self.require_early_lock(lock_fd)
        self.assert_before_capture()
        state = self.read()
        need(state is not None and live['owner'] == {k: proc_identity(os.getpid())[k] for k in ('pid', 'start')} and state == live['state'] and
             state['phase'] in ('isolating', 'awaiting-fresh-login', 'held') and
             state['dispatchCount'] == 0 and state['dispatchInFlight'] is None,
             'EARLY_RETURN_LIVE_OWNER_REQUIRED')
        session = self.host.operator_session()
        self.host.guard_check(state['guard'], session)
        self.host.check_prerequisites(self.plan)
        for name, saved in state['saved'].items():
            need(self.host.snapshot_mask(name) == live['masks'].get(name, saved['mask']), 'EARLY_RETURN_MASK_DRIFT_RETAINED')
            if name in live['masks']:
                need(self.host.mask_identity(name) == live['maskPins'][name], 'EARLY_RETURN_MASK_DRIFT_RETAINED')
            current = self.host.unit(name)
            expected = ('inactive', 'failed') if name in live['stopped'] else (saved['unit']['ActiveState'],)
            need(current.get('ActiveState') in expected and current.get('Job') in ('', '0'), 'EARLY_RETURN_UNIT_DRIFT_RETAINED')
        assert state is not None
        self.host.return_deadline = time.monotonic() + 120
        try:
            state['phase'] = 'early-returning'
            self.save(state)
            for name in reversed(live['masks']):
                self.host.guard_check(state['guard'], session)
                need(self.host.mask_identity(name) == live['maskPins'][name], 'EARLY_RETURN_MASK_DRIFT_RETAINED')
                self.host.restore_mask(name, state['saved'][name]['mask'])
            self.host.reload()
            # Services first, sockets/timers last; never enable/disable, restart
            # inactive units, or attempt to recreate a drained login scope.
            for name in sorted(live['stopped'], key=lambda u: (u.endswith(('.socket', '.timer')), u)):
                saved = state['saved'][name]['unit']
                self.host.guard_check(state['guard'], session)
                if not name.endswith('.scope') and saved['ActiveState'] == 'active' and self.host.unit(name).get('ActiveState') != 'active':
                    self.host.start(name)
            for name, saved in state['saved'].items():
                need(self.host.snapshot_mask(name) == saved['mask'], 'EARLY_RETURN_MASK_READBACK_FAILED')
                if not name.endswith('.scope'):
                    current = self.host.unit(name)
                    need(all(current.get(key) == saved['unit'].get(key) for key in ('ActiveState', 'SubState', 'UnitFileState'))
                         and current.get('Job') in ('', '0'), 'EARLY_RETURN_SERVICE_READBACK_FAILED')
            self.host.guard_check(state['guard'], session)
            state['phase'] = 'early-returned'
            self.save(state)
            result = self.finish_early_return(lock_fd)
            return {**self.evidence(state), **result, 'returnState': 'OLD',
                    'drainedSessionScopes': [u for u in live['stopped'] if u.endswith('.scope')]}
        except BaseException as error:
            state['phase'] = 'early-return-unknown'
            try:
                self.save(state)
            finally:
                raise EarlyReturnUnknown('EARLY_RETURN_OUTCOME_UNKNOWN') from error
        finally:
            del self.host.return_deadline

    def finish_early_return(self, lock_fd):
        return {'nodeIsolation': 'returned', 'notApplicationAuthority': True}

    def confirm_access(self):
        state = self.read()
        need(state is not None and state['phase'] == 'awaiting-fresh-login' and
             state['dispatchInFlight'] is None, 'MAINTENANCE_UNKNOWN_RETAINED')
        self.verify_exclusion(state)
        session = self.host.operator_session()
        boundary = state['accessBoundary']
        need(session != boundary['session'] and int(session['start']) > int(boundary['ticks']),
             'POST_DRAIN_FRESH_LOGIN_REQUIRED')
        self.host.guard_check(state['guard'], session)
        if self._early is not None and self._early['active'] and state == self._early['state']:
            self._early['state'] = state
        state['phase'] = 'held'
        self.save(state)
        return self.evidence(state)

    def verify_exclusion(self, state):
        self.host.check_prerequisites(self.plan)
        for name, saved in state['saved'].items():
            self.host.assert_stopped(name, saved['oldCgroup'])
        current = self.host.check_inventory(self.plan, held=True)
        writer_groups = {saved['oldCgroup'] for saved in state['saved'].values()} - {''}
        old_writers = {(p['pid'], p['start']) for p in state['initialProcesses']
                       if any(p['cgroup'] == g or p['cgroup'].startswith(g + '/') for g in writer_groups)}
        need(not any((p['pid'], p['start']) in old_writers for p in current['processes']), 'OLD_PID_SURVIVED_DRAIN')

    def assert_held(self):
        state = self.read()
        need(state is not None and state['phase'] == 'held' and state['dispatchInFlight'] is None,
             'MAINTENANCE_UNKNOWN_RETAINED')
        self.host.guard_check(state['guard'])
        self.verify_exclusion(state)
        return state

    def evidence(self, state):
        # Intentionally not external-execution-maintenance-v1: backend containment,
        # reassignment/alias reservations, and enrollment are outside this node slice.
        return {'scope': 'dedicated-test-node-maintenance-v1', 'phase': state['phase'],
                'maintenanceId': self.plan['maintenanceId'], 'nodeId': self.plan['nodeId'],
                'physicalObservation': {k: self.plan[k] for k in ('machineId', 'bootId', 'sshHostKeySha256')},
                'planHash': self.plan_hash, 'notApplicationAuthority': True}

    def require_outer_lock(self, lock_fd):
        need(os.geteuid() == 0, 'ROOT_REQUIRED')
        info, path = os.fstat(lock_fd), (self.directory / 'lock').lstat()
        need(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(path.st_mode) and
             (info.st_dev, info.st_ino) == (path.st_dev, path.st_ino), 'OUTER_LOCK_REQUIRED')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def close_dispatch(self, lock_fd):
        """Permanent root-operator admission close. No restore/reopen capability."""
        self.require_outer_lock(lock_fd)
        state = self.assert_held()
        self.host.guard_check(state['guard'], self.host.operator_session())
        marker = {'version': 1, 'planHash': self.plan_hash,
                  'maintenanceId': self.plan['maintenanceId'], 'nodeId': self.plan['nodeId'],
                  'bootId': self.plan['bootId'], 'state': 'closed'}
        need(not os.path.lexists(self.directory / 'restore-admission.json.next'),
             'DISPATCH_ADMISSION_UNKNOWN_RETAINED')
        path = self.directory / 'restore-admission.json'
        def check_closed_marker():
            value = decode_json(secure_file(path))
            need(isinstance(value, dict) and type(value.get('version')) is int and value == marker,
                 'DISPATCH_ADMISSION_UNKNOWN_RETAINED')
        if os.path.lexists(path):
            check_closed_marker()
        else:
            # Close ingress durably BEFORE completion inspection or releasing either
            # lock. Unknown completion still leaves dispatch permanently closed.
            atomic_json(self.directory, 'restore-admission.json', marker)
        # Rename may have succeeded before parent fsync failed. A retry must
        # prove the same file AND parent durable, not merely read visible bytes.
        raw = secure_file(path)
        need(len(raw) <= 4096, 'DISPATCH_ADMISSION_UNKNOWN_RETAINED')
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            named = path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                 and (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino)
                 and os.read(fd, 4097) == raw, 'DISPATCH_ADMISSION_UNKNOWN_RETAINED')
            os.fsync(fd)
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                parent = os.fstat(directory)
                named_parent = self.directory.lstat()
                need((parent.st_dev, parent.st_ino) == (named_parent.st_dev, named_parent.st_ino),
                     'DISPATCH_ADMISSION_UNKNOWN_RETAINED')
                os.fsync(directory)
                named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
                need((info.st_dev, info.st_ino) == (named.st_dev, named.st_ino)
                     and secure_file(path) == raw
                     and not os.path.lexists(self.directory / 'restore-admission.json.next'),
                     'DISPATCH_ADMISSION_UNKNOWN_RETAINED')
                check_closed_marker()
            finally:
                os.close(directory)
        finally:
            os.close(fd)
        with self.host.held_current_runner_head(self.plan) as head:
            self.assert_held()
            check_closed_marker()
            output = {**self.evidence(state), 'dispatchAdmission': 'closed',
                      'nodeEffects': 'drained', 'runnerHead': head, 'ownershipRetained': True}
        return output

    def assert_dispatch_open(self):
        # lexists also rejects dangling symlinks and incomplete write-ahead files.
        need(not any(os.path.lexists(self.directory / name) for name in
                     ('restore-admission.json', 'restore-admission.json.next')),
             'DISPATCH_ADMISSION_CLOSED_RETAINED')

    def dispatch(self, original, payload, lock_fd):
        self.assert_dispatch_open()
        args = parse_runner(original, self.plan)
        need(len(payload) <= 4194304 and (args[1] in ('prepare', 'restore-users') or not payload), 'INVALID_STDIN')
        state = self.assert_held()
        state['dispatchInFlight'] = {'argvSha256': digest(json.dumps(args).encode()), 'startedBootId': self.plan['bootId']}
        state['dispatchCount'] += 1
        self.save(state)
        # No timeout is interpreted as cancellation. Kill leaves the durable in-flight
        # marker; lock is inherited, and the pinned V2 runner owns its own sticky fence.
        # FD 3 is reserved by runner.sh for its embedded Python heredoc. Preserve
        # the outer mutex on a higher descriptor rather than silently replacing it.
        inherited = fcntl.fcntl(lock_fd, fcntl.F_DUPFD_CLOEXEC, 10)
        try:
            result = subprocess.run(['/bin/bash', RUNNER, *args], input=payload, env=CLEAN_ENV,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(inherited,))
        finally:
            os.close(inherited)
        need(result.returncode == 0 and not result.stderr, 'RUNNER_OUTCOME_UNKNOWN_RETAINED')
        receipt = decode_json(result.stdout)
        request = dict(zip(NAMES + ['checks'], args[1::2]))
        fields = dict(zip(NAMES[1:], ['operationId', 'nodeId', 'candidateHash', 'backupId', 'targetProfile',
                                      'executionContext', 'attemptId', 'generation', 'predecessorGeneration', 'commandId']))
        auxiliary = request['command'] in ('restore-users', 'verify-ppp-users')
        need(isinstance(receipt, dict) and (auxiliary or receipt.get('ok') is True) and receipt.get('protocolVersion') == 2 and
             receipt.get('bootId') == self.plan['bootId'] and receipt.get('command') == request['command'] and
             receipt.get('completion') == 'completed' and receipt.get('ownershipRetained') is True and
             all(receipt.get(field) == request[name] for name, field in fields.items()),
             'RUNNER_RECEIPT_UNKNOWN_RETAINED')
        if auxiliary:
            assert_readiness_receipt(receipt, request, fields, self.plan)
        self.host.guard_check(state['guard'])
        self.verify_exclusion(state)
        state['dispatchInFlight'] = None
        self.save(state)
        return result.stdout

    def restore(self):
        self.assert_dispatch_open()  # Closure never authorizes this legacy mask-return path.
        # Only a fully known hold and empty/closed pinned runner may return masks.
        # This is a trusted-operator handback step, NOT topology/DB ownership release.
        state = self.assert_held()
        self.host.operator_session()
        self.host.assert_runner_terminal(self.plan, state['dispatchCount'] > 0)
        state['phase'] = 'restoring'
        self.save(state)
        for name, saved in reversed(list(state['saved'].items())):
            self.host.restore_mask(name, saved['mask'])
        self.host.reload()
        for name, saved in state['saved'].items():
            need(self.host.snapshot_mask(name) == saved['mask'], 'RESTORE_READBACK_FAILED')
        state['phase'] = 'masks-restored-no-restart'
        self.save(state)
        return self.evidence(state)


SHARED_MODULE = '/usr/local/libexec/c3-test-shared-host.py'


def select_mode(plan):
    if isinstance(plan, dict) and plan.get('mode') == 'shared-test':
        import types
        raw = secure_file(SHARED_MODULE)
        module = types.ModuleType('c3_shared_host')
        module.__file__ = SHARED_MODULE
        exec(compile(raw, SHARED_MODULE, 'exec'), module.__dict__)
        return module.validate_plan(plan, sys.modules[__name__]), module
    return validate_plan(plan), None


def main():
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    need(len(sys.argv) == 2 and sys.argv[1] in ('inventory', 'guard', 'host-hold', 'apply', 'confirm-access', 'status', 'dispatch', 'close-dispatch', 'close-candidate', 'restore-masks', 'abort-return'), 'INVALID_CLI')
    command = sys.argv[1]
    host = Host()
    if command == 'inventory':
        print(json.dumps(host.inventory(), sort_keys=True))
        return
    plan, shared = select_mode(decode_json(secure_file(CONFIG)))
    directory = pathlib.Path(STATE)
    # Installation creates this directory; no CLI creates/replaces authority roots.
    info = directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'UNSAFE_STATE_ROOT')
    secure_file(HELPER)
    if command == 'guard':
        host.check_prerequisites(plan)
        recovery_guard(directory, host)
        return
    if command == 'host-hold':
        need(shared is not None, 'SHARED_MODE_REQUIRED')
        host.check_prerequisites(plan)
        shared.serve_hold(plan, directory, sys.modules[__name__])
        return
    lock = os.open(directory / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    primary = engine = output = None
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        engine = (shared.make_engine(directory, plan, sys.modules[__name__]) if shared else
                  Engine(directory, plan, host))
        engine._outer_lock_fd = lock
        if command == 'apply':
            guard = decode_json(secure_file(directory / 'guard.json'))
            output = engine.apply(guard)
        elif command == 'confirm-access':
            output = engine.confirm_access()
        elif command == 'status':
            output = engine.evidence(engine.assert_held())
        elif command == 'close-dispatch':
            output = engine.close_dispatch(lock)
        elif command == 'close-candidate':
            need(shared is not None, 'SHARED_MODE_REQUIRED')
            output = engine.close_candidate(lock)
        elif command == 'restore-masks':
            output = engine.restore()
        elif command == 'abort-return':
            # A new CLI process may request only a virgin shared Fence return.
            # Partial node effects belong exclusively to the original apply.
            need(shared is not None, 'EARLY_RETURN_LIVE_OWNER_REQUIRED')
            output = engine.abort_return(lock)
        else:
            payload = sys.stdin.buffer.read(4194305)
            result = engine.dispatch(os.environ.get('SSH_ORIGINAL_COMMAND', ''), payload, lock)
    except BaseException as error:
        primary = error
        raise
    finally:
        # Retire both the owned FD and Engine's borrowed reference before the
        # one close attempt: acknowledgement loss must never close a reused FD.
        closing, lock = lock, None
        if engine is not None:
            engine._outer_lock_fd = None
        try:
            os.close(closing)
        except BaseException as cleanup:
            if primary is None:
                if output is not None and output.get('returnState') == 'OLD':
                    unknown = EarlyReturnUnknown('EARLY_RETURN_OUTCOME_UNKNOWN')
                    unknown.cleanup_errors = [cleanup]
                    raise unknown from cleanup
                raise
            primary.cleanup_errors = [*getattr(primary, 'cleanup_errors', ()), cleanup]
            primary.add_note('Outer lock cleanup failed: ' + repr(cleanup))
    # No completion is delivered before the owned lock's checked disposal.
    # OLD has already enabled writers/released the host Fence; delivery failure
    # cannot assert retained exclusion or make that one-shot return retryable.
    try:
        if command == 'dispatch':
            sys.stdout.buffer.write(result)
            sys.stdout.buffer.flush()
            return
        print(json.dumps(output, sort_keys=True), flush=True)
    except BaseException as error:
        if output is not None and output.get('returnState') == 'OLD':
            raise EarlyReturnUnknown('EARLY_RETURN_OUTCOME_UNKNOWN') from error
        raise
    if output.get('status') == 'partial-unknown-retained':
        raise SystemExit(75)


if __name__ == '__main__':
    try:
        main()
    except (Refusal, OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, Refusal) else 'NODE_MAINTENANCE_UNKNOWN_RETAINED'
        print(json.dumps({'ok': False, 'code': code, **(
            {'returnState': 'UNKNOWN', 'exclusion': 'unknown', 'retryAllowed': False} if isinstance(error, EarlyReturnUnknown)
            else {'ownershipRetained': True})}), file=sys.stderr)
        raise SystemExit(75)
