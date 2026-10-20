"""Bounded shared TEST host mode. Loaded only from a fixed trusted install path.

No authority export, Docker payload wildcard, thaw, restore, or host-root override.
The original freezer owns all kernel freeze operations and retains unknown on loss.
"""
import copy
import os
import pathlib
import re
import uuid

NODE = '6ab189dc63913ebd4a917399'
MACHINE = '7fa266f995fe4aa69e96cf7d01359e34'
ENDPOINT = '212.119.42.100'
FREEZER = '/usr/local/libexec/c3-panel-host-freezer.py'
CONTROLS = ['/system.slice/docker.service', '/system.slice/containerd.service']
PAYLOADS = {'hysteria-mongo', 'hysteria-redis', 'hysteria-caddy', 'c3-test-candidate'}
NAMES = PAYLOADS | {'hysteria-backend', 'hysteria-updater'}


def validate_plan(p, m):
    m.need(isinstance(p, dict) and set(p) == m.PLAN_KEYS | {'mode', 'hostHold'}, 'INVALID_SHARED_PLAN')
    m.need(p['mode'] == 'shared-test' and p['nodeId'] == NODE and
           p['endpointIp'] == ENDPOINT and p['targetProfile'] == 'xray-main' and
           p['machineId'] == MACHINE, 'SHARED_TEST_IDENTITY_REQUIRED')
    m.validate_common_plan({k: p[k] for k in m.PLAN_KEYS})
    hold = p['hostHold']
    m.need(isinstance(hold, dict) and set(hold) == {'owner', 'freezerSha256', 'expected'}, 'HOST_HOLD_REQUIRED')
    m.need(isinstance(hold['owner'], str) and str(uuid.UUID(hold['owner'])) == hold['owner'], 'HOST_OWNER_REQUIRED')
    m.need(isinstance(hold['freezerSha256'], str) and re.fullmatch('[a-f0-9]{64}', hold['freezerSha256']), 'FREEZER_PIN_REQUIRED')
    e = hold['expected']
    m.need(isinstance(e, dict) and e.get('schema') == 1 and
           e.get('host') == {'machineId': MACHINE, 'bootId': p['bootId']} and
           e.get('controls') == CONTROLS and 'relaunch' not in e and 'proxyGroup' not in e,
           'ACCEPTED_HOST_INVENTORY_REQUIRED')
    containers = e.get('containers')
    m.need(isinstance(containers, list) and len(containers) in (5, 6) and
           all(isinstance(c, dict) for c in containers), 'EXACT_PAYLOADS_REQUIRED')
    names = [c.get('name') for c in containers]
    m.need(set(names) in (NAMES, NAMES - {'c3-test-candidate'}) and len(set(names)) == len(names),
           'EXACT_PAYLOADS_REQUIRED')
    for c in containers:
        m.need(isinstance(c.get('id'), str) and re.fullmatch('[a-f0-9]{64}', c['id']) and
               c.get('cgroup') == '/system.slice/docker-' + c['id'] + '.scope' and
               isinstance(c.get('init'), dict) and c['init'].get('cgroup') == c['cgroup'], 'EXACT_PAYLOADS_REQUIRED')
    by_name = {c['name']: c['cgroup'] for c in containers}
    m.need(len(set(by_name.values())) == len(containers) and
           e.get('backend') == by_name['hysteria-backend'] and
           e.get('freezeOrder') == [by_name['hysteria-updater'], *CONTROLS, by_name['hysteria-backend']] and
           set(e.get('groups', {})) == set(CONTROLS) | set(by_name.values()) and
           set(e.get('supervisors', {})) == {'docker.service', 'containerd.service'}, 'EXACT_FREEZE_POLICY_REQUIRED')
    # Runtime roots are allowed only internally after fresh host verification.
    m.need(not any(g in p['keepCgroups'] for g in CONTROLS) and
           not any(u in p['isolateUnits'] for u in ('docker.service', 'containerd.service')),
           'HOST_CONTROL_POLICY_CONFLICT')
    m.need({'/system.slice/xray.service', '/system.slice/xl2tpd.service'} <= set(p['keepCgroups']),
           'NATIVE_SURVIVORS_REQUIRED')
    return p


def verify_record(row, p, kernel, m):
    """Journal is a pin source, not proof: always perform a fresh kernel read."""
    original = p['hostHold']['expected']
    m.need(isinstance(row, dict) and set(row) == {'phase', 'owner', 'pending', 'originalExpected',
           'expected', 'frozen', 'dead'} and row['phase'] in ('held', 'empty') and
           row['owner'] == p['hostHold']['owner'] and row['pending'] is None and
           row['originalExpected'] == original and type(row['dead']) is bool and
           row['dead'] == (row['phase'] == 'empty'),
           'HOST_STATE_UNKNOWN_RETAINED')
    expected = copy.deepcopy(original)
    current = row['expected']
    # Derive the ONLY allowed projection change: exact original docker-proxy PIDs
    # moved to the owner's dedicated group. Never bless a shim/exec descendant.
    proxies = [r for r in original['runtime'] if pathlib.Path(r['exe']).name == 'docker-proxy']
    if proxies:
        group = '/system.slice/c3-test-host-proxies-' + row['owner'] + '.scope'
        pin = current.get('groups', {}).get(group, {})
        m.need(type(pin.get('inode')) is int and pin['inode'] > 0, 'HOST_PROXY_PIN_REQUIRED')
        expected['proxyGroup'] = group
        expected['proxyOriginals'] = copy.deepcopy(proxies)
        moved = [{**r, 'cgroup': group} for r in proxies]
        expected['groups'][group] = {'inode': pin['inode'], 'members': sorted(moved, key=lambda r: r['pid'])}
        for proxy in proxies:
            source = expected['groups'][proxy['cgroup']]['members']
            m.need(proxy in source, 'HOST_PROXY_SOURCE_CHANGED')
            source.remove(proxy)
        expected['runtime'] = [{**r, 'cgroup': group} if r in proxies else r for r in original['runtime']]
    relaunch = current.get('relaunch')
    m.need(isinstance(relaunch, dict) and set(relaunch) == {'owner', 'dropins'} and
           relaunch['owner'] == row['owner'] and len(relaunch['dropins']) == 2,
           'HOST_SUPERVISION_REQUIRED')
    for item, unit in zip(relaunch['dropins'], ('docker.service', 'containerd.service')):
        m.need(set(item) == {'path', 'createdDirectory'} and type(item['createdDirectory']) is bool and
               item['path'] == '/run/systemd/system/' + unit + '.d/90-c3-test-host-isolation.conf',
               'HOST_SUPERVISION_REQUIRED')
    expected['relaunch'] = copy.deepcopy(relaunch)
    frozen = original['freezeOrder'][:]
    if 'candidateClosure' in current:
        candidates = [c for c in original['containers'] if c['name'] == 'c3-test-candidate']
        m.need(len(candidates) == 1, 'HOST_POLICY_DRIFT_RETAINED')
        group = candidates[0]['cgroup']
        m.need(current['candidateClosure'] == {'group': group}, 'HOST_POLICY_DRIFT_RETAINED')
        expected['candidateClosure'] = {'group': group}
        members = current.get('groups', {}).get(group, {}).get('members')
        m.need(isinstance(members, list) and 1 <= len(members) <= 4096, 'HOST_POLICY_DRIFT_RETAINED')
        expected['groups'][group]['members'] = copy.deepcopy(members)
        frozen.append(group)
    m.need(row['frozen'] == frozen, 'HOST_STATE_UNKNOWN_RETAINED')
    m.need(current == expected, 'HOST_POLICY_DRIFT_RETAINED')
    try:
        kernel.verify(current, row['frozen'], row['dead'])
        assert_payload_lineage(current, kernel, m)
        kernel.verify(current, row['frozen'], row['dead'])
    except (RuntimeError, OSError, ValueError, KeyError, TypeError):
        raise m.Refusal('HOST_KERNEL_PROOF_LOST') from None
    return current


def assert_payload_lineage(expected, kernel, m):
    """No blanket trust for an unfrozen Docker scope (shim exec is NOT init)."""
    for container in expected['containers']:
        if container['name'] not in PAYLOADS:
            continue
        init = container['init']
        m.need(kernel.pid(init['pid']) == init, 'SURVIVOR_INIT_CHANGED')
        for member in kernel.members(container['cgroup']):
            pid, seen, pins = member['pid'], set(), []
            while pid != init['pid']:
                m.need(pid > 1 and pid not in seen and len(seen) < 4096,
                       'ACCEPTED_WORK_IN_SURVIVOR')
                seen.add(pid)
                path = kernel.proc / str(pid) / 'stat'
                raw = path.read_text()
                fields = raw[raw.rfind(')') + 2:].split()
                pins.append((path, fields[19], fields[1]))
                pid = int(fields[1])
            # Refuse a moving/reused/reparented chain rather than adopting it.
            for path, start, parent in pins:
                raw = path.read_text(); fields = raw[raw.rfind(')') + 2:].split()
                m.need((fields[19], fields[1]) == (start, parent), 'SURVIVOR_LINEAGE_CHANGED')
            m.need(kernel.pid(member['pid']) == member and kernel.pid(init['pid']) == init,
                   'SURVIVOR_LINEAGE_CHANGED')


def load_freezer(p, m):
    import importlib.util
    m.need(m.digest(m.secure_file(FREEZER)) == p['hostHold']['freezerSha256'], 'FREEZER_SOURCE_DRIFT')
    spec = importlib.util.spec_from_file_location('c3_host_freezer', FREEZER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    kernel = module.LinuxKernel()
    kernel.barrier = module.SystemdRelaunchBarrier()
    module.host_precheck(kernel)
    return module, kernel


def plan_hash(p, m):
    return m.digest(m.json.dumps(p, sort_keys=True, separators=(',', ':')).encode())


def read_record(directory, m):
    root = pathlib.Path(directory) / 'host'
    m.need(not (root / 'next.json').exists(), 'HOST_JOURNAL_UNCERTAIN_RETAINED')
    return m.decode_json(m.secure_file(root / 'hold.json'))


def check_identity(identity, p, directory, m):
    m.need(isinstance(identity, dict) and set(identity) == {'pid', 'start', 'socket', 'owner', 'planHash', 'session'} and
           identity['owner'] == p['hostHold']['owner'] and identity['planHash'] == plan_hash(p, m) and
           identity['socket'] == str(pathlib.Path(directory) / 'host.sock'), 'HOST_GUARD_IDENTITY_DRIFT')
    for pin in (identity, identity['session']):
        m.need(type(pin['pid']) is int and pin['pid'] > 1 and isinstance(pin['start'], str), 'HOST_GUARD_IDENTITY_DRIFT')
        current = m.proc_identity(pin['pid'])
        m.need(current['start'] == pin['start'] and current['state'] != 'Z', 'HOST_GUARD_LOST')


def peer_identity(conn):
    import socket
    import struct
    return struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))


def check_hold(p, directory, m, *, command='check'):
    """Real UDS roundtrip + SO_PEERCRED + independent current kernel verification."""
    import socket
    m.need(command in ('check', 'close-candidate'), 'INVALID_HOST_OPERATION')
    identity = m.decode_json(m.secure_file(pathlib.Path(directory) / 'host-guard.json'))
    check_identity(identity, p, directory, m)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(identity['socket'])
        pid, uid, _ = peer_identity(conn)
        m.need(pid == identity['pid'] and uid == 0, 'HOST_GUARD_PEER_MISMATCH')
        nonce = os.urandom(32).hex()
        frame = nonce if command == 'check' else m.json.dumps({
            'nonce': nonce, 'command': command, 'owner': identity['owner'], 'planHash': identity['planHash']})
        conn.sendall((frame + '\n').encode())
        reply = b''
        while not reply.endswith(b'\n') and len(reply) <= 8192:
            chunk = conn.recv(8192)
            m.need(bool(chunk), 'HOST_GUARD_LOST')
            reply += chunk
        m.need(len(reply) <= 8192 and reply.endswith(b'\n'), 'HOST_GUARD_FRAME_LIMIT')
        answer = m.decode_json(reply)
        m.need(set(answer) == {'nonce', 'identity', 'recordSha256'} and answer['nonce'] == nonce and
               answer['identity'] == identity, 'HOST_GUARD_CHALLENGE_MISMATCH')
        raw = m.secure_file(pathlib.Path(directory) / 'host/hold.json')
        m.need(m.digest(raw) == answer['recordSha256'], 'HOST_RECORD_CHANGED')
        row = read_record(directory, m)
        m.need(row == m.decode_json(raw), 'HOST_RECORD_CHANGED')
        _, kernel = load_freezer(p, m)
        current = verify_record(row, p, kernel, m)
        check_identity(identity, p, directory, m)
        m.need(read_record(directory, m) == row, 'HOST_RECORD_CHANGED')
        return current


def make_host(directory, p, m):
    class SharedHost(m.Host):
        def host_hold(self):
            return check_hold(p, directory, m)

        def check_prerequisites(self, plan):
            self.host_hold()
            super().check_prerequisites(plan)
            self.host_hold()

        def guard_check(self, guard, session=None):
            self.host_hold()
            result = super().guard_check(guard, session)
            self.host_hold()
            return result

        def check_inventory(self, plan, held=False):
            current = self.host_hold()
            effective = copy.deepcopy(plan)
            # Exact groups are admitted only inside the freshly checked hold. Do
            # not modify the accepted keep list or permit generic Docker scopes.
            effective['keepCgroups'] += list(current['groups'])
            for row in current['relaunch']['dropins']:
                effective['unitFilePins'][row['path']] = m.digest(
                    b'[Unit]\nConditionPathExists=!/run\n[Service]\nRestart=no\nExecCondition=\nExecCondition=/usr/bin/false\n')
            result = super().check_inventory(effective, held)
            self.host_hold()
            return result
    return SharedHost()


def make_engine(directory, p, m, host=None):
    class SharedEngine(m.Engine):
        def evidence(self, state):
            value = super().evidence(state)
            value['scope'] = 'shared-test-node-maintenance-v1'
            value['hostOwner'] = p['hostHold']['owner']
            return value

        def close_candidate(self, lock_fd):
            self.require_outer_lock(lock_fd)
            state = self.assert_held()
            self.host.guard_check(state['guard'], self.host.operator_session())
            current = check_hold(p, directory, m, command='close-candidate')
            m.need('candidateClosure' in current, 'CANDIDATE_CLOSURE_UNPROVEN')
            local = self.close_dispatch(lock_fd)
            # This host cannot inspect another node's live outer + runner locks.
            # No receipt/boolean/frozen-candidate shortcut for remote effects.
            return {**self.evidence(state), 'status': 'partial-unknown-retained',
                    'candidate': 'closed', 'localNodeEffects': local['nodeEffects'],
                    'unknownNodes': sorted(m.TEST_NODES), 'nodeEffects': 'unknown',
                    'handbackAllowed': False, 'ownershipRetained': True}

        def restore(self):
            self.assert_held()
            raise m.Refusal('SHARED_HANDBACK_UNAVAILABLE')
    return SharedEngine(directory, p, host or make_host(directory, p, m),
                        validator=lambda value: validate_plan(value, m))


def serve_hold(p, directory, m, freezer=None, kernel=None, host=None, infd=0):
    """Foreground owner of the REAL Fence; EOF/signal/lost recovery retains hold.

    Injectable adapters are Python-only local test seams. CLI has no fake root.
    No destructive kill, thaw, adoption of old journals, or mask restore API.
    """
    import select
    import signal
    import socket
    validate_plan(p, m)
    if freezer is None:
        freezer, kernel = load_freezer(p, m)
    host = host or m.Host()
    session = host.operator_session()
    recovery = m.decode_json(m.secure_file(pathlib.Path(directory) / 'guard.json'))
    host.guard_check(recovery, session)
    expected = p['hostHold']['expected']
    m.need(freezer.capture(kernel) == expected and freezer.capture(kernel) == expected,
           'ACCEPTED_HOST_INVENTORY_DRIFT')
    kernel.pins = {g: pin['inode'] for g, pin in expected['groups'].items()}
    journal = freezer.Journal(pathlib.Path(directory) / 'host')
    fence = freezer.Fence(expected, kernel, journal, p['hostHold']['owner'])
    identity = {k: m.proc_identity(os.getpid())[k] for k in ('pid', 'start')}
    identity.update(socket=str(pathlib.Path(directory) / 'host.sock'), owner=p['hostHold']['owner'],
                    planHash=plan_hash(p, m), session=session)

    def interrupted(*args):
        raise InterruptedError('host guard interrupted')

    def check():
        check_identity(identity, p, directory, m)
        host.guard_check(recovery, session)
        fence.check()
        verify_record(read_record(directory, m), p, kernel, m)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        fence.arm()
        check()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(identity['socket'])  # Never replace/adopt a prior socket.
            os.chmod(identity['socket'], 0o600)
            server.listen(4)
            m.atomic_json(directory, 'host-guard.json', identity)
            print(m.json.dumps({'hostHoldReady': True, 'owner': fence.owner,
                               'notApplicationAuthority': True}), flush=True)
            while True:
                check()
                ready, _, _ = select.select([server, infd], [], [], .2)
                if infd in ready:
                    # The supervising SSH channel must stay open; no stdin commands.
                    raise m.Refusal('HOST_CONTROLLER_CHANNEL_LOST')
                if server not in ready:
                    continue
                with server.accept()[0] as conn:
                    conn.settimeout(3)
                    _, uid, _ = peer_identity(conn)
                    m.need(uid == 0, 'ROOT_HOST_GUARD_CLIENT_REQUIRED')
                    request = b''
                    while not request.endswith(b'\n') and len(request) <= 1024:
                        chunk = conn.recv(1025)
                        m.need(bool(chunk), 'HOST_CLIENT_LOST')
                        request += chunk
                    m.need(len(request) <= 1024 and request.endswith(b'\n'), 'HOST_GUARD_FRAME_LIMIT')
                    if re.fullmatch(rb'[a-f0-9]{64}\n', request):
                        nonce = request.decode().strip()
                        command = 'check'
                    else:
                        frame = m.decode_json(request)
                        m.need(isinstance(frame, dict) and set(frame) == {'nonce', 'command', 'owner', 'planHash'}
                               and frame['command'] == 'close-candidate' and frame['owner'] == identity['owner']
                               and frame['planHash'] == identity['planHash'] and isinstance(frame['nonce'], str)
                               and re.fullmatch('[a-f0-9]{64}', frame['nonce']), 'INVALID_HOST_CHALLENGE')
                        nonce, command = frame['nonce'], frame['command']
                    check()
                    if command == 'close-candidate':
                        fence.close_candidate(identity['owner'])
                        check()
                    raw = m.secure_file(pathlib.Path(directory) / 'host/hold.json')
                    conn.sendall((m.json.dumps({'nonce': nonce, 'identity': identity,
                                              'recordSha256': m.digest(raw)}) + '\n').encode())
    except BaseException:
        fence.unknown()  # No finally-thaw; old dispatch remains kernel-fenced.
        raise
    finally:
        os.close(journal.fd)
