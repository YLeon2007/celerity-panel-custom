#!/usr/bin/python3 -I
"""Finite read-only TEST attestor. No install, apply, thaw, restore or dispatch.

Requires an already held node isolation + live recovery SSH controller. Shared
mode additionally requires the reviewed shared_host host-hold implementation.
CLI has no fake root, configurable executable or environment authority.
"""
import base64
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import sys
sys.dont_write_bytecode = True

HELPER = '/usr/local/libexec/c3-test-node-isolation'
RUNNER = '/usr/local/bin/celerity-topology-node-runner'
REQUEST_TIMEOUT_SECONDS = 12


def timed_out(*_):
    raise RuntimeError('PHYSICAL_ATTESTOR_TIMEOUT_RETAINED')


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def secure_read(path, directory=False):
    """Descriptor walk: no symlinks or writable/root-foreign ancestors."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'UNSAFE_PATH')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(path.parts) - 2 or directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            need(info.st_uid == 0 and not info.st_mode & 0o022, 'UNTRUSTED_PATH')
        before = os.fstat(fd)
        need(stat.S_ISDIR(before.st_mode) if directory else stat.S_ISREG(before.st_mode), 'UNSAFE_TYPE')
        need(before.st_size <= 8 * 1024 * 1024, 'READ_LIMIT')
        data = b''
        if not directory:
            while True:
                part = os.read(fd, 65536)
                if not part:
                    break
                data += part
                need(len(data) <= 8 * 1024 * 1024, 'READ_LIMIT')
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'READ_CHANGED')
        return data, after
    finally:
        os.close(fd)


def installation(profile, host, read=secure_read, paths=None):
    need(profile in ('xray-main', 'xray-bridge'), 'FOREIGN_PROFILE')
    paths = paths or {'runner': RUNNER,
                      'config': '/usr/local/etc/' + ('xray' if profile == 'xray-main' else 'xray-bridge'),
                      'unit': '/etc/systemd/system/xray-bridge.service'}
    raw, info = read(paths['runner'])
    need(info.st_uid == 0 and info.st_gid == 0 and stat.S_ISREG(info.st_mode) and
         stat.S_IMODE(info.st_mode) == 0o750, 'UNSAFE_RUNNER')
    runner_mode = format(stat.S_IMODE(info.st_mode), '04o')
    _, directory = read(paths['config'], directory=True)
    need(directory.st_uid == 0 and directory.st_gid == 0 and stat.S_ISDIR(directory.st_mode) and
         stat.S_IMODE(directory.st_mode) == 0o755, 'UNSAFE_CONFIG_DIRECTORY')
    sha, drops = None, None
    if profile == 'xray-bridge':
        unit, info = read(paths['unit'])
        need(info.st_uid == 0 and info.st_gid == 0 and not info.st_mode & 0o022, 'UNSAFE_BRIDGE_UNIT')
        loaded = host.unit('xray-bridge.service')
        need(loaded.get('FragmentPath') == paths['unit'] and loaded.get('DropInPaths') == '' and
             loaded.get('LoadState') == 'loaded' and loaded.get('UnitFileState') != 'masked', 'BRIDGE_UNIT_DRIFT')
        sha, drops = 'sha256:' + hashlib.sha256(unit).hexdigest(), 'absent'
    return {'runner': {'path': RUNNER, 'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest(),
                       'mode': runner_mode,
                       'owner': 'root', 'regularFile': True, 'symlink': False, 'writableByRunner': False},
            'profile': {'targetProfile': profile, 'configDirectoryReady': True,
                        'bridgeUnitSha256': sha, 'bridgeUnitDropIns': drops}}


def config_snapshot(profile, host, read=secure_read, paths=None):
    """Fixed-profile read-only original bytes, private SSH channel only, never logs.

    No accepted digest/state is supplied by the request. The app independently
    pins this observation before retaining it. Reject unsupported layouts rather
    than following unit symlinks, drop-ins or choosing an alternate config path.
    """
    need(profile in ('xray-main', 'xray-bridge'), 'FOREIGN_PROFILE')
    service = 'xray.service' if profile == 'xray-main' else 'xray-bridge.service'
    paths = paths or {'config': '/usr/local/etc/' + ('xray' if profile == 'xray-main' else 'xray-bridge') + '/config.json',
                      'unit': '/etc/systemd/system/' + service}
    before = host.unit(service)
    need(before.get('Id') == service and before.get('LoadState') == 'loaded' and
         before.get('FragmentPath') == paths['unit'] and before.get('DropInPaths') == '' and
         before.get('Job') == '' and before.get('ActiveState') in ('active', 'inactive') and
         before.get('UnitFileState') in ('enabled', 'disabled'), 'CONFIG_SERVICE_UNPROVEN')
    blobs = {}
    for name in ('config', 'unit'):
        raw, info = read(paths[name])
        need(info.st_uid == 0 and info.st_gid == 0 and stat.S_ISREG(info.st_mode) and
             not info.st_mode & 0o022 and len(raw) <= 512 * 1024, 'UNSAFE_CONFIG_SNAPSHOT')
        blobs[name] = raw
    after = host.unit(service)
    need(before == after, 'CONFIG_SERVICE_CHANGED')
    # Reread exact bytes after the manager observation too. Held exclusion is
    # still provided by observe()'s before/after live engine checks.
    for name in ('config', 'unit'):
        need(read(paths[name])[0] == blobs[name], 'CONFIG_BYTES_CHANGED')
    return {'configBase64': base64.b64encode(blobs['config']).decode('ascii'),
            'unitBase64': base64.b64encode(blobs['unit']).decode('ascii'),
            'readback': {'source': 'node-readback',
                         'configSha256': hashlib.sha256(blobs['config']).hexdigest(),
                         'unitSha256': hashlib.sha256(blobs['unit']).hexdigest(),
                         'serviceActive': after['ActiveState'], 'serviceEnabled': after['UnitFileState']}}


def runner_state(plan, m, predecessor):
    root = Path('/var/lib/celerity/topology')
    fence = root / 'fences' / plan['targetProfile']
    need(not os.path.lexists(fence / 'journal.next'), 'RUNNER_UNKNOWN_RETAINED')
    journal_path = fence / 'journal.json'
    if not os.path.lexists(journal_path):
        need(not os.path.lexists(fence / 'lock') and predecessor is None, 'RUNNER_UNKNOWN_RETAINED')
        # Same finite pre-v2 exclusion as runner.sh; never create a journal/lock.
        for name in ('operations', 'backups'):
            legacy = root / name
            if os.path.lexists(legacy):
                secure_read(legacy, directory=True)
                for entry in legacy.iterdir():
                    need(not entry.is_symlink() and not os.path.lexists(entry / plan['targetProfile']), 'LEGACY_STATE_UNPROVEN')
        return {'head': None, 'journal': 'absent', 'legacyState': 'absent', 'terminal': None}
    fd = os.open(fence / 'lock', os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        journal = m.decode_json(secure_read(journal_path)[0])
        need(set(journal) == {'version', 'bootId', 'nodeId', 'executionContext', 'head', 'generations'} and
             journal['version'] == 2 and journal['bootId'] == plan['bootId'] and
             journal['nodeId'] == plan['nodeId'] and journal['executionContext'] == plan['context'], 'RUNNER_IDENTITY_DRIFT')
        head = journal['head']
        need(head is None or head in journal['generations'], 'RUNNER_UNKNOWN_RETAINED')
        for generation in journal['generations'].values():
            need(all(c['state'] == 'completed' for c in generation['commands'].values()), 'RUNNER_UNKNOWN_RETAINED')
        receipt = None
        if predecessor is not None:
            binding = predecessor['binding']
            record = journal['generations'][binding['generation']]
            close = record['commands'][binding['commandIds']['close']]
            need(record['phase'] == 'closed' and close['state'] == 'completed' and close['command'] == 'close', 'TERMINAL_UNPROVEN')
            # Exactly the actual runner's status projection, without invoking or
            # changing the runner. JS validates every receipt field against binding.
            receipt = dict(close['receipt'], command='status')
            service = m.Host().unit('xray.service' if plan['targetProfile'] == 'xray-main' else 'xray-bridge.service')
            need(not service.get('Job'), 'SYSTEMD_JOB_PENDING')
        return {'head': head, 'journal': 'present', 'legacyState': 'not-applicable', 'terminal': receipt}
    finally:
        os.close(fd)


def observe(engine, m, shared, predecessor=None):
    state = engine.assert_held()  # live nonce/PID/start/root-peer + current exclusion
    plan = engine.plan
    physical = engine.host.physical()  # NEVER echo plan identity as observation
    need(physical == {k: plan[k] for k in ('machineId', 'bootId', 'sshHostKeySha256')}, 'PHYSICAL_IDENTITY_DRIFT')
    value = {'physical': physical, 'nodeId': plan['nodeId'], 'targetProfile': plan['targetProfile'],
             'maintenanceId': plan['maintenanceId'], 'planHash': engine.plan_hash,
             'guard': state['guard'], 'endpoint': {'ip': plan['endpointIp'], 'port': 2222, 'username': 'c3-test-runner'},
             'installation': installation(plan['targetProfile'], engine.host),
             'configTransfer': config_snapshot(plan['targetProfile'], engine.host),
             'runnerState': runner_state(plan, m, predecessor), 'host': None}
    if shared:
        current = engine.host.host_hold()  # actual host pipe + independent kernel reread
        backend = next(c for c in current['containers'] if c['name'] == 'hysteria-backend')
        value['host'] = {'owner': plan['hostHold']['owner'],
                         'guard': m.decode_json(secure_read(Path(m.STATE) / 'host-guard.json')[0]),
                         'backend': {'instanceId': backend['id'], 'pid': backend['init']['pid'],
                                     'processStartTime': backend['init']['startTicks']}}
    engine.assert_held()
    return value


def serve(engine, m, shared, inp=sys.stdin, out=sys.stdout):
    # Each nonce roundtrip revalidates both real recovery protocols. No old reply
    # can authorize a new request. EOF/errors close only this read-only channel.
    signal.signal(signal.SIGALRM, timed_out)
    while True:
        ready, _, _ = select.select([inp], [], [], 60)
        if not ready:
            continue  # Live SSH keepalives; only a fresh request attests authority.
        signal.setitimer(signal.ITIMER_REAL, REQUEST_TIMEOUT_SECONDS)
        try:
            raw = inp.buffer.readline(65537)
            need(raw and len(raw) <= 65536 and raw.endswith(b'\n'), 'ATTESTOR_CHANNEL_LOST')
            request = m.decode_json(raw)
            need(set(request) == {'nonce', 'predecessor'} and isinstance(request['nonce'], str) and
                 re.fullmatch('[a-f0-9]{64}', request['nonce']), 'INVALID_ATTESTATION_REQUEST')
            fd = os.open(Path(m.STATE) / 'lock', os.O_RDONLY | os.O_NOFOLLOW)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = observe(engine, m, shared, request['predecessor'])
                print(json.dumps({'nonce': request['nonce'], 'observation': result}), file=out, flush=True)
            finally:
                os.close(fd)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)


def select_engine(m, raw):
    if raw.get('mode') == 'shared-test':
        need(hasattr(m, 'select_mode'), 'SHARED_HOST_ATTESTATION_HOOK_REQUIRED')
        plan, shared = m.select_mode(raw)
        return shared.make_engine(m.STATE, plan, m), shared
    plan = m.validate_plan(raw)
    return m.Engine(m.STATE, plan, m.Host()), None


def main():
    need(os.geteuid() == 0 and len(sys.argv) == 1, 'ROOT_FIXED_ATTESTOR_REQUIRED')
    secure_read('/usr/local/libexec/c3-test-physical-attestor')
    secure_read(HELPER)
    loader = importlib.machinery.SourceFileLoader('c3_isolation', HELPER)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    need(spec is not None, 'ISOLATION_MODULE_UNAVAILABLE')
    m = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = m
    loader.exec_module(m)
    raw = m.decode_json(secure_read(m.CONFIG)[0])
    engine, shared = select_engine(m, raw)
    _, info = secure_read(m.STATE, directory=True)
    need(stat.S_IMODE(info.st_mode) == 0o700, 'UNSAFE_STATE_ROOT')
    engine.host.operator_session()  # actual independent maintenance SSH ancestry
    serve(engine, m, shared)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        # Expose only the one explicit missing deployment hook, never arbitrary
        # exception text, input, credentials or OS errors; no cleanup writes.
        code = ('SHARED_HOST_ATTESTATION_HOOK_REQUIRED' if type(error) is RuntimeError and
                str(error) == 'SHARED_HOST_ATTESTATION_HOOK_REQUIRED' else 'PHYSICAL_ATTESTOR_UNKNOWN_RETAINED')
        print(json.dumps({'ok': False, 'code': code}), file=sys.stderr, flush=True)
        raise SystemExit(75)
