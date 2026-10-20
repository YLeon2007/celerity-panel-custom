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


def durable_originals(engine, m, read=secure_read):
    """Read-only validation of the already published capture, never recapture.

    Compare *all* profiles (including the dual-profile relay) with independently
    accepted pins. Current candidate config/runtime may legitimately differ. No
    historical observation, receipt or process cache is used as permission.
    Called only under attest()'s outer lock and live exclusion checks.
    """
    state = engine.assert_held()
    root = '/var/lib/c3-test-node-isolation/originals'
    bundle_path = root + '/originals.json'
    accepted_path = '/etc/c3-test-node-originals.json'
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    for directory in ('/var/lib/c3-test-node-isolation', root):
        _, info = read(directory, directory=True)
        need(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_ORIGINALS_REQUIRED')
    for pending in ('originals.json.next', 'restore.json', 'restore.json.next'):
        try:
            read(root + '/' + pending)
        except FileNotFoundError:
            continue
        need(False, 'PARTIAL_ORIGINALS_RETAINED')
    accepted_raw, _ = read(accepted_path)
    accepted = m.decode_json(accepted_raw)
    raw, info = read(bundle_path)
    need(info.st_uid == 0 and info.st_gid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
         'PRIVATE_ORIGINALS_REQUIRED')
    bundle = m.decode_json(raw)
    identity = {k: engine.plan[k] for k in ('context', 'nodeId', 'endpointIp', 'targetProfile', 'machineId', 'bootId',
                                          'sshHostKeySha256', 'maintenanceId')}
    identity['planHash'] = engine.plan_hash
    profiles = ['xray-main', 'xray-bridge'] if identity['endpointIp'] == '104.143.201.72' else [identity['targetProfile']]
    need(set(accepted) == {'version', *identity, 'isolationSha256', 'xraySha256', 'profiles'} and
         type(accepted['version']) is int and accepted['version'] == 1 and
         all(accepted[k] == v for k, v in identity.items()) and set(accepted['profiles']) == set(profiles), 'ORIGINAL_ACCEPTED_IDENTITY_DRIFT')
    need(sha(read(HELPER)[0]) == accepted['isolationSha256'], 'ORIGINAL_ISOLATION_PIN_DRIFT')
    need(set(bundle) == {'version', *identity, 'guard', 'profiles', 'acceptedSha256'} and
         type(bundle['version']) is int and bundle['version'] == 1 and raw == canonical(bundle) and
         all(bundle[k] == v for k, v in identity.items()) and bundle['guard'] == state['guard'] and
         bundle['acceptedSha256'] == sha(canonical(accepted)) and set(bundle['profiles']) == set(profiles), 'ORIGINAL_BUNDLE_IDENTITY_DRIFT')
    for profile in profiles:
        original, pins = bundle['profiles'][profile], accepted['profiles'][profile]
        need(set(original) == {'files', 'service', 'runtime'} and set(original['files']) == {'config', 'unit'} and
             set(pins) == {'files', 'service', 'runtimeSha256'} and original['service'] == pins['service'] and
             sha(canonical(original['runtime'])) == pins['runtimeSha256'], 'ORIGINAL_PIN_DRIFT')
        for name in ('config', 'unit'):
            item = original['files'][name]
            need(set(item) == {'sha256', 'mode', 'uid', 'gid', 'xattrs', 'data'} and
                 {k: v for k, v in item.items() if k != 'data'} == pins['files'][name], 'ORIGINAL_METADATA_DRIFT')
            data = base64.b64decode(item['data'], validate=True)
            need(len(data) <= 512 * 1024 and base64.b64encode(data).decode() == item['data'] and sha(data) == item['sha256'],
                 'ORIGINAL_BYTES_DRIFT')
    need(read(bundle_path)[0] == raw and read(accepted_path)[0] == accepted_raw and
         engine.assert_held()['guard'] == state['guard'], 'ORIGINALS_CHANGED')
    selected = bundle['profiles'][identity['targetProfile']]
    return {'version': 1, 'bundleSha256': sha(raw), 'readback': {'source': 'node-readback',
            'configSha256': selected['files']['config']['sha256'], 'unitSha256': selected['files']['unit']['sha256'],
            'serviceActive': selected['service']['ActiveState'], 'serviceEnabled': selected['service']['UnitFileState']}}


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


def attest(engine, m, shared, request, *, held=None):
    """One finite fresh observation; a retained capture OFD is never reacquired.

    `held` is the live in-process CaptureHold, not an FD number/receipt from a
    request. Its checks bind this exact engine, descriptor and current pathname
    before and after observe. Separate SSH observer processes still use flock.
    """
    need(set(request) == {'nonce', 'predecessor'} and isinstance(request['nonce'], str) and
         re.fullmatch('[a-f0-9]{64}', request['nonce']), 'INVALID_ATTESTATION_REQUEST')
    if held is not None:
        need(held.writer.engine is engine, 'FOREIGN_CAPTURE_HOLDER')
        held.check()
        try:
            result = observe(engine, m, shared, request['predecessor'])
            held.check()
        except BaseException:
            held.active = False
            raise
    else:
        fd = os.open(Path(m.STATE) / 'lock', os.O_RDONLY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = os.fstat(fd)
            state = engine.assert_held()
            engine.host.guard_check(state['guard'], engine.host.operator_session())
            durable = durable_originals(engine, m)
            result = observe(engine, m, shared, request['predecessor'])
            need(durable_originals(engine, m) == durable, 'ORIGINALS_CHANGED')
            named = (Path(m.STATE) / 'lock').lstat()
            need((before.st_dev, before.st_ino) == (named.st_dev, named.st_ino), 'OUTER_LOCK_REPLACED')
            result['durableOriginals'] = durable
        finally:
            os.close(fd)
    return {'nonce': request['nonce'], 'observation': result}


def serve(engine, m, shared, inp=sys.stdin, out=sys.stdout, *, held=None):
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
            print(json.dumps(attest(engine, m, shared, request, held=held)), file=out, flush=True)
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
