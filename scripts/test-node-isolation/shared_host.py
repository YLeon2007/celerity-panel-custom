"""Bounded shared TEST host mode. Loaded only from a fixed trusted install path.

No authority export, Docker payload wildcard or host-root override.
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
    m.need(isinstance(p, dict) and set(p) == m.plan_keys(p) | {'mode', 'hostHold'}, 'INVALID_SHARED_PLAN')
    if p.get('version') == 2:
        inventory = m.accepted_inventory(p)
        m.inventory_node(p, inventory=inventory)
        m.need(p['mode'] == 'shared-test' and p['nodeId'] == inventory['sharedNodeId'], 'SHARED_TEST_IDENTITY_REQUIRED')
    else:
        m.need(p['mode'] == 'shared-test' and p['nodeId'] == NODE and
               p['endpointIp'] == ENDPOINT and p['targetProfile'] == 'xray-bridge' and
               p['machineId'] == MACHINE, 'SHARED_TEST_IDENTITY_REQUIRED')
    hold = p['hostHold']
    network = isinstance(hold, dict) and 'networkPlanSha256' in hold
    common = {k:p[k] for k in m.plan_keys(p)}
    if network: m.validate_common_plan(common,network_bound=True)
    else: m.validate_common_plan(common)
    m.need(isinstance(hold, dict) and set(hold) == {'owner', 'freezerSha256', 'expected'} |
           ({'networkPlanSha256'} if network else set()), 'HOST_HOLD_REQUIRED')
    if network:
        m.need(p.get('version') == 2 and type(hold['networkPlanSha256']) is str and
               re.fullmatch('[a-f0-9]{64}', hold['networkPlanSha256']) and
               '/system.slice/c3-test-fresh-network.service' in p['keepCgroups'], 'NETWORK_SUCCESSOR_BINDING_REQUIRED')
    m.need(isinstance(hold['owner'], str) and str(uuid.UUID(hold['owner'])) == hold['owner'], 'HOST_OWNER_REQUIRED')
    m.need(isinstance(hold['freezerSha256'], str) and re.fullmatch('[a-f0-9]{64}', hold['freezerSha256']), 'FREEZER_PIN_REQUIRED')
    e = hold['expected']
    m.need(isinstance(e, dict) and e.get('schema') == 1 and
           e.get('host') == {'machineId': p['machineId'], 'bootId': p['bootId']} and
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
    m.need({'/system.slice/xray.service', '/system.slice/xray-bridge.service',
            '/system.slice/xl2tpd.service'} <= set(p['keepCgroups']),
           'NATIVE_SURVIVORS_REQUIRED')
    return p


def verify_record(row, p, kernel, m):
    """Journal is a pin source, not proof: always perform a fresh kernel read."""
    original = p['hostHold']['expected']
    m.need(isinstance(row, dict) and set(row) == {'phase', 'owner', 'pending', 'originalExpected',
           'expected', 'frozen', 'dead'} and row['phase'] in ('held', 'empty', 'committed-backend-active') and
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
    if row['phase'] == 'committed-backend-active':
        activation = current.get('classicActivation')
        m.need(isinstance(activation, dict) and set(activation) == {'commitSha256', 'group'} and
               re.fullmatch('[a-f0-9]{64}', activation['commitSha256']) and
               activation['group'] == original['backend'] and 'candidateClosure' in current and not row['dead'],
               'HOST_COMMITTED_BINDING_REQUIRED')
        expected['classicActivation'] = copy.deepcopy(activation)
        frozen.remove(original['backend'])
    m.need(row['frozen'] == frozen, 'HOST_STATE_UNKNOWN_RETAINED')
    m.need(current == expected, 'HOST_POLICY_DRIFT_RETAINED')
    try:
        kernel.verify(current, row['frozen'], row['dead'])
        if row['phase'] == 'committed-backend-active':
            kernel.assert_classic_activation_safe(current)
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
    expected_machine_id = None
    if p.get('version') == 2:
        # This loader is also reached by hold readback: never trust a prior
        # caller validation or forward the plan's machineId as authority.
        validate_plan(p, m)
        expected_machine_id = m.inventory_node(p)['physical']['machineId']
    raw = m.secure_file(FREEZER)
    m.need(m.digest(raw) == p['hostHold']['freezerSha256'], 'FREEZER_SOURCE_DRIFT')
    spec = importlib.util.spec_from_file_location('c3_host_freezer', FREEZER)
    m.need(spec is not None and spec.loader is not None, 'FIXED_FREEZER_LOADER_REQUIRED')
    # Keep the existing loader seam, but execute only the verified buffer: no
    # second source read, timestamp race or bytecode cache acceptance.
    spec.loader.get_code = lambda _name: compile(raw, FREEZER, 'exec')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    kernel = module.LinuxKernel()
    kernel.barrier = module.SystemdRelaunchBarrier()
    if expected_machine_id is None:
        module.host_precheck(kernel)
    else:
        module.host_precheck(kernel, expected_machine_id=expected_machine_id)
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


def check_hold(p, directory, m, *, command='check', commit_sha=None):
    """Real UDS roundtrip + SO_PEERCRED + independent current kernel verification."""
    import socket
    m.need(command in ('check', 'close-candidate', 'activate-classic', 'prepare-classic'), 'INVALID_HOST_OPERATION')
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
        if command == 'activate-classic':
            m.need(isinstance(commit_sha, str) and re.fullmatch('[a-f0-9]{64}', commit_sha), 'COMMIT_BINDING_REQUIRED')
            frame = m.json.dumps({**m.json.loads(frame), 'commitSha256': commit_sha})
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
        def apply(self, guard):
            if p.get('version') == 2:
                # Register BEFORE the first node journal/mutation, on this live
                # Fence. A later process may not adopt its partial journal.
                early_request(p, directory, m, 'begin-isolation', self._outer_lock_fd)
            try:
                return super().apply(guard)
            except m.KnownIsolationRefusal as error:
                # A known pure preflight refusal has no node journal/effects.
                # Return now, while the registered apply peer is still alive.
                if p.get('version') == 2 and self._early is None and self.read() is None:
                    return {**self.abort_return(self._outer_lock_fd), 'isolationRefusal': str(error)}
                raise

        def abort_return(self, lock_fd):
            if self._early is not None:
                return super().abort_return(lock_fd)
            m.need(self.read() is None, 'EARLY_RETURN_LIVE_OWNER_REQUIRED')
            self.require_early_lock(lock_fd)
            try:
                return early_request(p, directory, m, 'abort-return', lock_fd)
            except (m.Refusal, OSError, RuntimeError) as error:
                raise m.EarlyReturnUnknown('HOST_RETURN_OUTCOME_UNKNOWN') from error

        def finish_early_return(self, lock_fd):
            return early_request(p, directory, m, 'abort-return', lock_fd,
                                 node_return_sha=m.digest(m.secure_file(pathlib.Path(directory) / 'journal.json')))

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
                    'unknownNodes': sorted(pin['nodeId'] for pin in m.accepted_inventory(p)['nodes']) if p.get('version') == 2 else sorted(m.TEST_NODES), 'nodeEffects': 'unknown',
                    'handbackAllowed': False, 'ownershipRetained': True}

        def restore(self):
            self.assert_held()
            raise m.Refusal('SHARED_HANDBACK_UNAVAILABLE')
    return SharedEngine(directory, p, host or make_host(directory, p, m),
                        validator=lambda value: validate_plan(value, m))


def early_request(p, directory, m, command, lock_fd, *, node_return_sha=None):
    """Finite same-live-owner extension of the existing root UDS channel.

    Transfer the ALREADY held outer OFD; never unlock/reacquire around return.
    No disk token authorizes adoption, retry, capture, DB writes or handback.
    """
    import array
    import socket
    m.need(p.get('version') == 2 and command in ('begin-isolation', 'abort-return'), 'V2_EARLY_RETURN_ONLY')
    identity = m.decode_json(m.secure_file(pathlib.Path(directory) / 'host-guard.json'))
    check_identity(identity, p, directory, m)
    nonce = os.urandom(32).hex()
    frame = {'nonce': nonce, 'command': command, 'owner': identity['owner'],
             'planHash': identity['planHash'], 'nodeReturnSha256': node_return_sha}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(120)
        conn.connect(identity['socket'])
        pid, uid, _ = peer_identity(conn)
        m.need(pid == identity['pid'] and uid == 0, 'HOST_GUARD_PEER_MISMATCH')
        raw = (m.json.dumps(frame) + '\n').encode()
        sent = conn.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [lock_fd]))])
        m.need(sent == len(raw), 'HOST_RETURN_SEND_UNKNOWN_RETAINED')
        reply = b''
        while not reply.endswith(b'\n') and len(reply) <= 8192:
            part = conn.recv(8192)
            m.need(bool(part), 'HOST_RETURN_OUTCOME_UNKNOWN')
            reply += part
        m.need(len(reply) <= 8192 and reply.endswith(b'\n'), 'HOST_GUARD_FRAME_LIMIT')
        answer = m.decode_json(reply)
        keys = {'nonce', 'identity', 'recordSha256'} | ({'returnState'} if command == 'abort-return' else set())
        m.need(set(answer) == keys and answer['nonce'] == nonce and answer['identity'] == identity,
               'HOST_GUARD_CHALLENGE_MISMATCH')
        raw = m.secure_file(pathlib.Path(directory) / 'host/hold.json')
        m.need(m.digest(raw) == answer['recordSha256'], 'HOST_RECORD_CHANGED')
        row = read_record(directory, m)
        if command == 'abort-return':
            m.need(answer['returnState'] == 'OLD' and row == {
                'phase': 'restored', 'owner': identity['owner'], 'pending': None,
                'originalExpected': p['hostHold']['expected'], 'expected': p['hostHold']['expected'],
                'frozen': [], 'dead': False}, 'HOST_RETURN_OUTCOME_UNKNOWN')
            return {'returnState': 'OLD', 'hostFence': 'released', 'notApplicationAuthority': True}
        m.need(row['phase'] == 'held', 'HOST_STATE_UNKNOWN_RETAINED')
        return {}


def receive_request(conn, m):
    """Close every transferred FD once, including malformed/extra rights."""
    import array
    import contextlib
    import socket
    @contextlib.contextmanager
    def receive():
        rights = []
        try:
            conn.settimeout(3)
            request, ancillary, flags, _ = conn.recvmsg(1025, socket.CMSG_SPACE(16 * array.array('i').itemsize))
            invalid = False
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    values = array.array('i')
                    usable = len(data)-len(data) % values.itemsize
                    values.frombytes(data[:usable]); rights.extend(values)
                    invalid |= usable != len(data)
                else:
                    invalid = True
            m.need(not invalid and not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC), 'INVALID_HOST_RIGHTS')
            while not request.endswith(b'\n') and len(request) <= 1024:
                chunk = conn.recv(1025)
                m.need(bool(chunk), 'HOST_CLIENT_LOST')
                request += chunk
            m.need(len(request) <= 1024 and request.endswith(b'\n'), 'HOST_GUARD_FRAME_LIMIT')
            yield request, rights
        finally:
            for fd in rights:
                os.close(fd)
    return receive()


def network_peer(conn, p, m, frame):
    """Authenticate the preaccepted existing unit, never a caller-selected helper."""
    import subprocess
    peer, uid, gid = peer_identity(conn)
    m.need(uid == gid == 0 and 'networkPlanSha256' in p['hostHold'], 'NETWORK_SUCCESSOR_NOT_SELECTED')
    raw = m.secure_file('/etc/c3-test-fresh-network.json')
    plan = m.decode_json(raw)
    m.need(m.digest(raw) == p['hostHold']['networkPlanSha256'] and plan.get('ordinaryOwner',{}).get('version') == 1 and
           plan['machine'] == p['machineId'] and plan['boot'] == p['bootId'], 'ACCEPTED_NETWORK_PLAN_REQUIRED')
    lease_raw = m.secure_file('/etc/c3-test-fresh-network-lease.json'); lease = m.decode_json(lease_raw)
    m.need(lease['planSha256'] == m.digest(raw) and lease['generation'] == plan['generation'] and
           lease['operations'] == ['observe','cutover','return','abandon','handoff'] and
           type(lease['deadline']) is int and m.time.time() < lease['deadline'] == plan['deadline'], 'LIVE_NETWORK_LEASE_REQUIRED')
    unit = 'c3-test-fresh-network.service'
    output = subprocess.run(['/usr/bin/systemctl','show','--all',unit,
        *['--property='+key for key in ('Id','Names','MainPID','ExecMainPID','InvocationID','ControlGroup',
                                      'FragmentPath','DropInPaths','LoadState','ActiveState','SubState','Job')]],
        check=True,timeout=3,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL).stdout
    m.need(len(output) <= 65536, 'NETWORK_UNIT_REPLY_LIMIT')
    row = dict(line.split('=',1) for line in output.decode().splitlines() if '=' in line)
    m.need(row.get('Id') == unit and row.get('Names','').split() == [unit] and
           row.get('MainPID') == row.get('ExecMainPID') == str(peer) and
           row.get('ControlGroup') == '/system.slice/'+unit and
           row.get('FragmentPath') == '/etc/systemd/system/'+unit and not row.get('DropInPaths') and
           row.get('LoadState') == 'loaded' and row.get('ActiveState') == 'active' and
           row.get('SubState') == 'running' and row.get('Job','') in ('','0'), 'EXACT_NETWORK_UNIT_PEER_REQUIRED')
    for path in ('/usr/local/libexec/c3-test-fresh-network-exec.py',
                 '/usr/local/libexec/c3-test-fresh-network-control.py', '/usr/local/libexec/c3-test-fresh-network.py'):
        m.need(path in p['runtimePins'] and m.digest(m.secure_file(path)) == p['runtimePins'][path], 'NETWORK_SOURCE_ASSOCIATION_REQUIRED')
    unit_path = '/etc/systemd/system/'+unit
    m.need(unit_path in p['unitFilePins'] and m.digest(m.secure_file(unit_path)) == p['unitFilePins'][unit_path],
           'NETWORK_UNIT_SOURCE_REQUIRED')
    current = m.proc_identity(peer)
    m.need(pathlib.Path('/proc', str(peer), 'cgroup').read_text() == '0::/system.slice/'+unit+'\n' and
           frame == {'pid':peer,'start':current['start'],'invocation':row['InvocationID'],
                     'networkPlanSha256':m.digest(raw),'leaseSha256':m.digest(lease_raw)}, 'NETWORK_PEER_ASSOCIATION_DRIFT')
    return frame


def serve_hold(p, directory, m, freezer=None, kernel=None, host=None, infd=0):
    """Foreground owner of the REAL Fence; EOF/signal retains candidate/control holds.

    Injectable adapters are Python-only local test seams. CLI has no fake root.
    No destructive kill, journal adoption or general mask restore API.
    Only the same-peer committed bridge may enable the accepted classic backend.
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
    isolation_peer = None  # Process-local only, never reconstructed from a journal.
    network_selected = 'networkPlanSha256' in p['hostHold']
    armed = False
    successor = None
    network_binding = None
    coordinator_binding = None
    old_returned = False
    old_node_sha = None
    return_end = None
    primary = None

    def interrupted(*args):
        raise InterruptedError('host guard interrupted')

    def check():
        check_identity(identity, p, directory, m)
        host.guard_check(recovery, session)
        fence.check()
        verify_record(read_record(directory, m), p, kernel, m)

    def return_check():
        if return_end is not None:
            m.need(m.time.monotonic() < return_end, 'FINITE_NETWORK_RETURN_EXPIRED')
        check_identity(identity, p, directory, m)
        host.guard_check(recovery, session)
        m.need(not select.select([infd], [], [], 0)[0], 'HOST_CONTROLLER_CHANNEL_LOST')

    def begin_network_return():
        nonlocal return_end
        m.need(return_end is None, 'NETWORK_RETURN_REPLAY_REFUSED')
        network_raw = m.secure_file('/etc/c3-test-fresh-network.json')
        network_plan = m.decode_json(network_raw)
        m.need(m.digest(network_raw) == p['hostHold']['networkPlanSha256'],
               'ACCEPTED_NETWORK_PLAN_REQUIRED')
        return_end = m.time.monotonic()+min(120,max(0,network_plan['deadline']-m.time.time()))
        return_check()

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        if not network_selected:
            fence.arm(); armed = True
            check()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(identity['socket'])  # Never replace/adopt a prior socket.
            os.chmod(identity['socket'], 0o600)
            server.listen(4)
            m.atomic_json(directory, 'host-guard.json', identity)
            if armed:
                print(m.json.dumps({'hostHoldReady': True, 'owner': fence.owner,
                                   'notApplicationAuthority': True}), flush=True)
            while True:
                if armed and not old_returned: check()
                else: return_check()
                ready, _, _ = select.select([server, infd], [], [], .2)
                if infd in ready:
                    # The supervising SSH channel must stay open; no stdin commands.
                    raise m.Refusal('HOST_CONTROLLER_CHANNEL_LOST')
                if server not in ready:
                    continue
                with server.accept()[0] as conn, receive_request(conn, m) as (request, rights):
                    conn.settimeout(3)
                    peer_pid, uid, _ = peer_identity(conn)
                    m.need(uid == 0, 'ROOT_HOST_GUARD_CLIENT_REQUIRED')
                    frame = {}
                    if re.fullmatch(rb'[a-f0-9]{64}\n', request):
                        nonce = request.decode().strip()
                        command = 'check'
                    else:
                        frame = m.decode_json(request)
                        if type(frame) is dict and frame.get('command') in ('network-check','stage-network-successor',
                                'surrender-network-successor','finish-network-successor','restore-network-old'):
                            op = frame['command']
                            fields = {'nonce','command','owner','planHash','network'}
                            fields |= {'coordinator'} if op == 'stage-network-successor' else set()
                            fields |= {'commitSha256'} if op in ('surrender-network-successor','finish-network-successor') else set()
                            m.need(network_selected and not rights and set(frame) == fields and
                                   frame['owner'] == identity['owner'] and frame['planHash'] == identity['planHash'] and
                                   type(frame['nonce']) is str and re.fullmatch('[a-f0-9]{64}',frame['nonce']), 'INVALID_NETWORK_CHALLENGE')
                            association = network_peer(conn, p, m, frame['network'])
                            if network_binding is None: network_binding = association
                            m.need(association == network_binding, 'NETWORK_SUCCESSOR_REPLACED')
                            if op == 'restore-network-old':
                                m.need(armed and successor is None and coordinator_binding is None and
                                       not fence.passive and not fence.escrow and 'candidateClosure' not in fence.expected,
                                       'KNOWN_OLD_PRECAPTURE_ONLY')
                                engine = m.Engine(directory,p,host,validator=lambda value:validate_plan(value,m))
                                engine.assert_before_capture()
                                state = engine.read()
                                if old_returned:
                                    m.need(return_end is not None and (state is None and old_node_sha is None or
                                           state is not None and state['phase'] == 'early-returned' and
                                           m.digest(m.secure_file(pathlib.Path(directory)/'journal.json')) == old_node_sha),
                                           'EARLY_RETURN_LIVE_OWNER_REQUIRED')
                                else:
                                    m.need(isolation_peer is None and state is None, 'EARLY_RETURN_LIVE_OWNER_REQUIRED')
                                    begin_network_return()
                                    fence.restore(identity['owner'],checkpoint=return_check)
                                    old_returned = True
                                return_check()
                                m.need(fence.phase == 'restored' and not fence.frozen and fence.expected == fence.original,
                                       'HOST_RETURN_OUTCOME_UNKNOWN')
                                kernel.verify(fence.expected,[],False)
                                conn.sendall((m.json.dumps({'nonce':frame['nonce'],'identity':identity,'returnState':'OLD',
                                    'recordSha256':m.digest(m.secure_file(pathlib.Path(directory)/'host/hold.json'))})+'\n').encode())
                                return
                            m.need(not old_returned,'KNOWN_OLD_AWAITING_NETWORK_ABANDON')
                            if not armed:
                                m.need(op == 'network-check', 'PREARM_RENDEZVOUS_REQUIRED')
                                fence.arm(); armed = True; check()
                                print(m.json.dumps({'hostHoldReady':True,'owner':fence.owner,
                                                   'notApplicationAuthority':True}), flush=True)
                            check()
                            if op == 'stage-network-successor':
                                m.need(successor is None and 'candidateClosure' in fence.expected, 'ONE_CLOSED_CANDIDATE_SUCCESSION_REQUIRED')
                                intent = m.decode_json(m.secure_file(pathlib.Path(directory)/'coordinated-restore.json'))
                                coordinator_binding = frame['coordinator']
                                m.need(set(coordinator_binding) == {'pid','start','nonce'} and
                                       {k:coordinator_binding[k] for k in ('pid','start')} ==
                                       {k:intent['origin'][k] for k in ('pid','start')} and
                                       coordinator_binding['nonce'] == intent['nonce'] and intent['phase'] == 'restored-held' and
                                       m.proc_identity(coordinator_binding['pid'])['start'] == coordinator_binding['start'], 'SAME_COORDINATOR_REQUIRED')
                                successor = fence.stage_live(m.digest(freezer.live_encode({'network':association,'coordinator':coordinator_binding})))
                                successor.send(conn)
                                continue
                            transcript = None
                            if op in ('surrender-network-successor','finish-network-successor'):
                                commit_raw = m.secure_file(pathlib.Path(directory)/'handoff-commit.json')
                                commit = m.decode_json(commit_raw)
                                m.need(successor is not None and m.digest(commit_raw) == frame['commitSha256'] and
                                       commit['nonce'] == coordinator_binding['nonce'] and
                                       commit['networkHandoff']['recipientInvocationId'] == association['invocation'] and
                                       commit['networkHandoff']['networkPlanSha256'] == p['hostHold']['networkPlanSha256'], 'ORIGINAL_NETWORK_COMMIT_REQUIRED')
                                if op == 'surrender-network-successor':
                                    transcript = fence.surrender_live(successor.sha256, frame['commitSha256'])
                                else:
                                    intent = m.decode_json(m.secure_file(pathlib.Path(directory)/'coordinated-restore.json'))
                                    m.need(fence.passive and intent['phase'] == 'handoff-completed' and
                                           intent['nonce'] == coordinator_binding['nonce'], 'ACTUAL_NODE_CLEANUP_REQUIRED')
                            answer = {'nonce':frame['nonce'],'identity':identity,
                                      'recordSha256':m.digest(m.secure_file(pathlib.Path(directory)/'host/hold.json'))}
                            if transcript is not None: answer['transcriptSha256'] = transcript
                            conn.sendall((m.json.dumps(answer)+'\n').encode())
                            if op == 'finish-network-successor': return
                            continue
                        m.need(armed, 'PREARM_RENDEZVOUS_REQUIRED')
                        early = frame.get('command') in ('begin-isolation', 'abort-return')
                        keys = {'nonce', 'command', 'owner', 'planHash'}
                        keys |= {'nodeReturnSha256'} if early else {'commitSha256'} if frame.get('command') == 'activate-classic' else set()
                        m.need(isinstance(frame, dict) and set(frame) == keys
                               and frame['command'] in ('close-candidate', 'activate-classic', 'prepare-classic', 'begin-isolation', 'abort-return')
                               and frame['owner'] == identity['owner'] and frame['planHash'] == identity['planHash']
                               and isinstance(frame['nonce'], str) and re.fullmatch('[a-f0-9]{64}', frame['nonce']), 'INVALID_HOST_CHALLENGE')
                        nonce, command = frame['nonce'], frame['command']
                    m.need(len(rights) == (1 if command in ('begin-isolation', 'abort-return') else 0), 'INVALID_HOST_RIGHTS')
                    check()
                    if command in ('begin-isolation', 'abort-return'):
                        m.need(p.get('version') == 2, 'V2_EARLY_RETURN_ONLY')
                        engine = m.Engine(directory, p, host, validator=lambda value: validate_plan(value, m))
                        engine.require_early_lock(rights[0])
                        engine.assert_before_capture()
                        host.guard_check(recovery, host.operator_session())
                        peer = {k: m.proc_identity(peer_pid)[k] for k in ('pid', 'start')}
                        state = engine.read()
                        if command == 'begin-isolation':
                            m.need(isolation_peer is None and state is None and frame['nodeReturnSha256'] is None,
                                   'EARLY_RETURN_LIVE_OWNER_REQUIRED')
                            isolation_peer = peer
                        else:
                            if isolation_peer is None:
                                m.need(state is None and frame['nodeReturnSha256'] is None, 'EARLY_RETURN_LIVE_OWNER_REQUIRED')
                            else:
                                m.need(peer == isolation_peer and (
                                       (state is None and frame['nodeReturnSha256'] is None) or
                                       (state is not None and state['phase'] == 'early-returned'
                                        and state['dispatchCount'] == 0 and state['dispatchInFlight'] is None
                                        and m.digest(m.secure_file(pathlib.Path(directory) / 'journal.json')) == frame['nodeReturnSha256'])),
                                       'EARLY_RETURN_LIVE_OWNER_REQUIRED')
                            # All checks precede the first enable. Never adopt a
                            # disk Fence, capture state or terminal ownership COMMIT.
                            if network_selected:
                                m.need(successor is None and network_binding is not None, 'KNOWN_OLD_PRECAPTURE_ONLY')
                                begin_network_return()
                            fence.restore(identity['owner'], checkpoint=return_check)
                            old_returned = network_selected
                            old_node_sha = frame['nodeReturnSha256']
                            raw = m.secure_file(pathlib.Path(directory) / 'host/hold.json')
                            conn.sendall((m.json.dumps({'nonce': nonce, 'identity': identity,
                                                      'recordSha256': m.digest(raw), 'returnState': 'OLD'}) + '\n').encode())
                            if not network_selected: return
                            continue
                    if command == 'close-candidate':
                        fence.close_candidate(identity['owner'])
                        check()
                    if command == 'prepare-classic':
                        fence.require(('held',), identity['owner'])
                        kernel.assert_classic_activation_safe(fence.expected)
                        m.need('candidateClosure' in fence.expected and 'relaunch' in fence.expected and not fence.dead,
                               'BOUNDED_CLASSIC_ACTIVATION_UNAVAILABLE')
                    if command == 'activate-classic':
                        # Shared LocalXray aliases the panel host, not a sixth
                        # host. Read its real same-run COMMIT, never a JSON GO.
                        raw_commit = m.secure_file(pathlib.Path(directory) / 'handoff-commit.json')
                        commit = m.decode_json(raw_commit)
                        node = p['nodeId']
                        expected_peer = commit['nodePeers'][node]
                        m.need(m.digest(raw_commit) == frame['commitSha256'] and
                               commit['context'] == p['context'] and
                               commit['activationSet'] == ['existing-classic-backend'] and
                               expected_peer == {k: m.proc_identity(peer_pid)[k] for k in ('pid', 'start')} and
                               commit['nodePins'][node]['identity']['planHash'] == plan_hash(p, m),
                               'SAME_HOLDER_COMMIT_REQUIRED')
                        fence.activate_classic(identity['owner'], frame['commitSha256'])
                        check()
                    raw = m.secure_file(pathlib.Path(directory) / 'host/hold.json')
                    conn.sendall((m.json.dumps({'nonce': nonce, 'identity': identity,
                                              'recordSha256': m.digest(raw)}) + '\n').encode())
    except BaseException as error:
        primary = error
        try: fence.unknown()  # No finally-thaw; candidate/control dispatch stays fenced.
        except BaseException as cleanup: error.cleanup_errors = (*getattr(error,'cleanup_errors',()),cleanup)
        raise
    finally:
        held = getattr(kernel,'_live',[])
        if kernel is not None: kernel._live = []
        errors = []
        for fd in [*(fd for row,fd in held),journal.fd]:
            try: os.close(fd)
            except BaseException as error: errors.append(error)
        if errors:
            failure = primary if primary is not None else errors[0]
            failure.cleanup_errors = (*getattr(failure,'cleanup_errors',()),*errors)
            if primary is None: raise failure
