#!/usr/bin/python3 -I
"""Finite root-only five-node restoration, irreversible commit and bounded activation.

Only main() builds operational authority from fixed root-owned accepted pins.
Programmatic constructor injection is for explicitly simulated local tests.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import select
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
SELF = '/usr/local/libexec/c3-test-coordinated-restore.py'
ORIGINALS = '/usr/local/libexec/c3-test-node-originals.py'
SHARED = '/usr/local/libexec/c3-test-shared-host.py'
FREEZER = '/usr/local/libexec/c3-panel-host-freezer.py'
CONFIG = '/etc/c3-test-coordinated-restore.json'
STATE = '/var/lib/c3-test-node-isolation'
INTENT = STATE + '/coordinated-restore.json'
SOCKET = STATE + '/coordinated-restore.sock'
LOCK = STATE + '/coordinated-restore.lock'
COMMIT = STATE + '/handoff-commit.json'
ACTIVATION = STATE + '/handoff-activation.json'
SHARED_NODE = '6ab189dc63913ebd4a917399'
KEY = '/etc/c3-test-coordinated-restore/operator-key'
KNOWN = STATE + '/coordinated-known-hosts'
COMMAND = 'sudo -n /usr/local/libexec/c3-test-coordinated-restore.py node-hold'
NODES = {
 '6ab18adc63913ebd4a917471': ('132.243.230.19', 'xray-main'),
 '6ab93ad2646b4b7d2f43c907': ('94.103.2.186', 'xray-main'),
 '6ab18d9c63913ebd4a917670': ('50.114.160.63', 'xray-bridge'),
 '6ab4b53bc4c0304573e06c72': ('104.143.201.72', 'xray-bridge'),
 '6ab189dc63913ebd4a917399': ('212.119.42.100', 'xray-main'),
}
DIGEST = re.compile('[a-f0-9]{64}\\Z')
BASE = {'version', 'op', 'nodeId', 'coordinatorNonce', 'nodeNonce', 'seq', 'challenge', 'origin'}
CLEAN_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}


class Refusal(RuntimeError):
    pass


def need(ok, code='COORDINATED_RESTORE_UNKNOWN_RETAINED'):
    if not ok:
        raise Refusal(code)


def dispose_socket(conn, code, primary=None):
    """One local disposal attempt; never replace an in-flight protocol failure."""
    if conn is not None:
        try:
            conn.close()
        except BaseException as error:
            failure = primary if primary is not None else error
            failure.code = code
            failure.cleanup_errors = (*getattr(failure, 'cleanup_errors', ()), error)
            if primary is None:
                raise


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_FRAME_RETAINED')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False))


def proc_start(pid):
    return Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]


def local_origin(config):
    actual = {'machineId': Path('/etc/machine-id').read_text().strip(),
              'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'cgroup': Path('/proc/self/cgroup').read_text().strip(), 'uid': os.geteuid()}
    need(actual == config['origin'] and actual['uid'] == 0, 'ORIGIN_DRIFT_RETAINED')
    return {**actual, 'pid': os.getpid(), 'start': proc_start(os.getpid())}


def validate(config):
    need(isinstance(config, dict) and set(config) == {'version', 'context', 'lifetimeSeconds', 'origin', 'nodes', 'keySha256'})
    need(type(config['version']) is int and config['version'] == 1 and config['context'] == 'test.infograd.online')
    need(type(config['lifetimeSeconds']) is int and 80 <= config['lifetimeSeconds'] <= 120)
    need(set(config['origin']) == {'machineId', 'bootId', 'cgroup', 'uid'} and type(config['origin']['uid']) is int
         and config['origin']['uid'] == 0 and isinstance(config['origin']['cgroup'], str)
         and 'candidate' not in config['origin']['cgroup'] and config['origin']['cgroup'])
    need(re.fullmatch('[a-f0-9]{32}', config['origin']['machineId']) and
         re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', config['origin']['bootId']))
    need(isinstance(config['keySha256'], str) and DIGEST.fullmatch(config['keySha256']))
    need(set(config['nodes']) == set(NODES), 'EXACT_FIVE_NODES_REQUIRED')
    machines, keys = set(), set()
    for node, pin in config['nodes'].items():
        need(set(pin) == {'identity', 'profiles', 'guard', 'files', 'hostKey'})
        ident = pin['identity']
        need(set(ident) == {'context', 'nodeId', 'endpointIp', 'targetProfile', 'machineId', 'bootId',
                            'sshHostKeySha256', 'maintenanceId', 'planHash'})
        need(ident['context'] == config['context'] and ident['nodeId'] == node and
             (ident['endpointIp'], ident['targetProfile']) == NODES[node])
        profiles = ['xray-main', 'xray-bridge'] if ident['endpointIp'] == '104.143.201.72' else [ident['targetProfile']]
        need(pin['profiles'] == profiles and isinstance(pin['guard'], dict) and pin['guard'])
        need(re.fullmatch('[a-f0-9]{32}', ident['machineId']) and
             re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', ident['bootId']) and
             re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', ident['maintenanceId']))
        files = {'self', 'originals', 'isolation', 'accepted', 'restoreAccepted'}
        if node == '6ab189dc63913ebd4a917399':
            files |= {'shared', 'freezer'}
        need(set(pin['files']) == files)
        need(all(isinstance(v, str) and DIGEST.fullmatch(v) for v in [*pin['files'].values(), ident['planHash'], ident['sshHostKeySha256']]))
        raw = base64.b64decode(pin['hostKey'], validate=True)
        need(base64.b64encode(raw).decode() == pin['hostKey'] and len(raw) == 51 and
             raw[:19] == struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) and sha(raw) == ident['sshHostKeySha256'])
        need(ident['machineId'] not in machines and ident['sshHostKeySha256'] not in keys, 'ALIASED_NODE_RETAINED')
        machines.add(ident['machineId']); keys.add(ident['sshHostKeySha256'])
    return config


class Wire:
    """Bounded newline codec: no text buffering, credentials or permissive fields."""
    def __init__(self, reader, writer, deadline):
        self.reader, self.writer, self.deadline = reader, writer, deadline
        self.buffer = b''

    def send(self, value):
        raw = canonical(value) + b'\n'
        need(len(raw) <= 131072)
        # Ordinary replies are below PIPE_BUF; settlement proofs are bounded
        # separately at 128 KiB. A partial send is unknown, never retried. Root UDS
        # sockets have a timeout. Detect partial writes, never retry an effect.
        need(os.write(self.writer, raw) == len(raw), 'FRAME_WRITE_UNKNOWN_RETAINED')

    def receive(self, watch=()):
        while b'\n' not in self.buffer:
            remaining = self.deadline - time.monotonic()
            need(remaining > 0, 'CHANNEL_TIMEOUT_RETAINED')
            ready, _, _ = select.select([self.reader, *watch], [], [], min(remaining, .25))
            need(not any(fd in ready for fd in watch), 'OTHER_CHANNEL_LOST_RETAINED')
            if self.reader not in ready:
                continue
            part = os.read(self.reader, 131073)
            need(part, 'CHANNEL_EOF_RETAINED')
            self.buffer += part
            need(len(self.buffer) <= 131072, 'FRAME_LIMIT_RETAINED')
        raw, self.buffer = self.buffer.split(b'\n', 1)
        need(not self.buffer, 'PIPELINED_FRAME_RETAINED')
        value = decode(raw)
        need(isinstance(value, dict))
        return value

    def quiet(self):
        need(not self.buffer and not select.select([self.reader], [], [], 0)[0], 'CHANNEL_LOST_OR_UNSOLICITED_RETAINED')


class NodeServer:
    """Root fixed CLI server. The live scope owns actual outer + runner OFDs."""
    def __init__(self, writer, originals, config, wire, *, shared=None):
        self.writer, self.n, self.config, self.wire, self.shared = writer, originals, validate(config), wire, shared
        self.node = writer.engine.plan['nodeId']
        self.pin = config['nodes'][self.node]
        self.nonce = secrets.token_hex(32)
        self.busy = False
        self.checkpoint_original = writer.checkpoint
        self.session = writer.engine.host.operator_session()
        self.root_process = {'pid': os.getpid(), 'start': proc_start(os.getpid())}

    def pins(self):
        fs, n = self.writer.fs, self.n
        need(n.identity(self.writer.engine) == self.pin['identity'] and self.writer.profiles == self.pin['profiles'])
        need(self.writer.held()['guard'] == self.pin['guard'], 'GUARD_PIN_DRIFT_RETAINED')
        need(self.writer.engine.host.operator_session() == self.session, 'OPERATOR_SESSION_DRIFT_RETAINED')
        paths = {'self': SELF, 'originals': ORIGINALS, 'isolation': n.HELPER,
                 'accepted': n.ACCEPTED, 'restoreAccepted': n.RESTORE_ACCEPTED}
        if self.node == '6ab189dc63913ebd4a917399':
            paths.update(shared=SHARED, freezer=FREEZER)
        for name, path in paths.items():
            need(sha(fs.read(path)[0]) == self.pin['files'][name], 'ACCEPTED_FILE_PIN_DRIFT_RETAINED')
        need(canonical(fs.read_json(CONFIG)) == canonical(self.config), 'COORDINATOR_PIN_DRIFT_RETAINED')
        if self.node == '6ab189dc63913ebd4a917399':
            need(self.shared is not None, 'SHARED_CANDIDATE_HOLD_REQUIRED')
            assert self.shared is not None
            current = self.shared.check_hold(self.writer.engine.plan, STATE, self.writer.module)
            need('candidateClosure' in current, 'CANDIDATE_NOT_FROZEN_RETAINED')

    def checkpoint(self):
        if self.busy:
            self.wire.quiet()
        need(time.monotonic() < self.wire.deadline, 'NODE_HOLD_TIMEOUT_RETAINED')
        self.pins()
        self.checkpoint_original()

    def serve(self):
        self.pins()
        self.wire.send({'version': 1, 'op': 'hello', 'nodeId': self.node, 'nodeNonce': self.nonce,
                        'pinSha256': sha(canonical(self.pin)), **self.root_process})
        first = self.wire.receive()
        need(set(first) == BASE and first['op'] == 'open' and first['nodeNonce'] == self.nonce and first['nodeId'] == self.node)
        origin = first['origin']
        need(set(origin) == {*self.config['origin'], 'pid', 'start'} and
             {k: origin[k] for k in self.config['origin']} == self.config['origin'] and
             type(origin['pid']) is int and origin['pid'] > 1 and isinstance(origin['start'], str) and origin['start'].isdigit())
        need(isinstance(first['coordinatorNonce'], str) and DIGEST.fullmatch(first['coordinatorNonce']))
        seq, restored, committed = 0, False, None
        self.writer.checkpoint = self.checkpoint
        try:
            with self.writer.restoration_hold() as held:
                frame = first
                while True:
                    need(set(frame) == (BASE | {'commitSha256'} if frame.get('op') in ('activate-classic', 'commit-phase') else BASE) and type(frame['version']) is int and frame['version'] == 1 and
                         frame['nodeId'] == self.node and frame['nodeNonce'] == self.nonce and
                         frame['coordinatorNonce'] == first['coordinatorNonce'] and frame['origin'] == origin and
                         type(frame['seq']) is int and frame['seq'] == seq and
                         isinstance(frame['challenge'], str) and DIGEST.fullmatch(frame['challenge']))
                    op = frame['op']
                    need(op in (('open',) if seq == 0 else ('check', 'restore', 'verify', 'release', 'activate-classic', 'commit-phase', 'activation-preflight')))
                    self.busy = True
                    held.check()
                    if op == 'activation-preflight':
                        need(self.node == SHARED_NODE and restored and not committed)
                        assert self.shared is not None
                        self.shared.check_hold(self.writer.engine.plan, STATE, self.writer.module, command='prepare-classic')
                    if op == 'commit-phase':
                        need(restored and not committed and DIGEST.fullmatch(frame['commitSha256']))
                        held.verify()
                        committed = frame['commitSha256']
                    if op == 'activate-classic':
                        need(committed == frame['commitSha256'] and self.node == SHARED_NODE and restored, 'SHARED_COMMITTED_ACTIVATION_ONLY')
                        held.verify()
                        assert self.shared is not None
                        raw = self.writer.fs.read(COMMIT)[0]
                        commit = decode(raw)
                        need(sha(raw) == frame['commitSha256'] and commit['nodePeers'][self.node] == self.root_process and
                             commit['configSha256'] == sha(canonical(self.config)), 'SAME_HOLDER_COMMIT_REQUIRED')
                        self.shared.check_hold(self.writer.engine.plan, STATE, self.writer.module,
                                               command='activate-classic', commit_sha=frame['commitSha256'])
                    if op == 'restore':
                        need(not committed and not restored, 'NODE_RESTORE_REPLAY_FORBIDDEN')
                        held.restore()
                        restored = True
                    if not committed and (op == 'verify' or (op == 'check' and restored)):
                        held.verify()
                    self.checkpoint()
                    self.busy = False
                    if op == 'release':
                        return  # never emit positive authority after unlocking
                    self.wire.send({**frame, 'op': op + '-held', 'pinSha256': sha(canonical(self.pin)),
                                    'guardSha256': sha(canonical(self.pin['guard'])), 'restored': restored,
                                    'operator': self.session, **self.root_process})
                    seq += 1
                    # Poll real guard and fixed pins while waiting. EOF cannot
                    # turn a historical successful restoration into live authority.
                    while not select.select([self.wire.reader], [], [], .25)[0]:
                        held.check()
                    frame = self.wire.receive()
        finally:
            self.writer.checkpoint = self.checkpoint_original


def ssh_argv(config, node):
    validate(config)
    endpoint = config['nodes'][node]['identity']['endpointIp']
    return ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', '2222', '-i', KEY,
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'HostKeyAlgorithms=ssh-ed25519',
            '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
            '-o', 'KbdInteractiveAuthentication=no', '-o', 'UserKnownHostsFile=' + KNOWN,
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UpdateHostKeys=no',
            '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ControlPersist=no',
            '-o', 'ClearAllForwardings=yes', '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no',
            '-o', 'PermitLocalCommand=no', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
            '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=8',
            '-o', 'ServerAliveInterval=3', '-o', 'ServerAliveCountMax=2',
            'c3-test-operator@' + endpoint, COMMAND]


class Channel:
    def __init__(self, process, node, pin, nonce, origin, deadline):
        self.process, self.node, self.pin, self.nonce, self.origin = process, node, pin, nonce, origin
        need(process.stdin is not None and process.stdout is not None)
        assert process.stdin is not None and process.stdout is not None
        self.wire = Wire(process.stdout.fileno(), process.stdin.fileno(), deadline)
        self.seq, self.hello, self.operator, self.restored = 0, None, None, False

    def start(self, watch):
        hello = self.wire.receive(watch)
        need(set(hello) == {'version', 'op', 'nodeId', 'nodeNonce', 'pinSha256', 'pid', 'start'} and
             type(hello['version']) is int and hello['version'] == 1 and hello['op'] == 'hello' and hello['nodeId'] == self.node and
             hello['pinSha256'] == sha(canonical(self.pin)) and isinstance(hello['nodeNonce'], str) and DIGEST.fullmatch(hello['nodeNonce']) and
             type(hello['pid']) is int and hello['pid'] > 1 and isinstance(hello['start'], str) and hello['start'].isdigit())
        self.hello = hello
        self.request('open', watch)

    def request(self, op, watch, *, commit_sha=None):
        need(self.hello is not None and self.process.poll() is None, 'NODE_PROCESS_LOST_RETAINED')
        assert self.hello is not None
        frame = {'version': 1, 'op': op, 'nodeId': self.node, 'nodeNonce': self.hello['nodeNonce'],
                 'coordinatorNonce': self.nonce, 'seq': self.seq, 'challenge': secrets.token_hex(32), 'origin': self.origin}
        if op in ('activate-classic', 'commit-phase'):
            need((op != 'activate-classic' or self.node == SHARED_NODE) and isinstance(commit_sha, str) and DIGEST.fullmatch(commit_sha))
            frame['commitSha256'] = commit_sha
        self.wire.send(frame)
        if op == 'release':
            return
        reply = self.wire.receive(watch)
        need(set(reply) == set(frame) | {'pinSha256', 'guardSha256', 'restored', 'operator', 'pid', 'start'})
        need(type(reply['version']) is int and type(reply['seq']) is int and type(reply['pid']) is int)
        need({k: reply[k] for k in frame} == {**frame, 'op': op + '-held'} and
             reply['pinSha256'] == sha(canonical(self.pin)) and reply['guardSha256'] == sha(canonical(self.pin['guard'])) and
             (reply['pid'], reply['start']) == (self.hello['pid'], self.hello['start']) and type(reply['restored']) is bool)
        need(isinstance(reply['operator'], dict) and set(reply['operator']) == {'pid', 'start'} and
             type(reply['operator']['pid']) is int and reply['operator']['pid'] > 1 and
             isinstance(reply['operator']['start'], str) and reply['operator']['start'].isdigit())
        need(self.operator is None or self.operator == reply['operator'], 'REMOTE_OPERATOR_DRIFT_RETAINED')
        self.operator = reply['operator']
        if op in ('restore', 'verify') or self.restored:
            need(reply['restored'] is True, 'RESTORATION_UNPROVEN_RETAINED')
        else:
            need(reply['restored'] is False, 'UNEXPECTED_RESTORATION_RETAINED')
        self.restored = reply['restored']
        self.seq += 1
        return reply

    def close(self):
        # Disposal only: never thaw/reopen/replay. A failed close or signal must
        # not skip the other pipe, bounded reap, or final kill/reap attempt.
        errors = []
        for stream in (self.process.stdin, self.process.stdout):
            if stream:
                try:
                    stream.close()
                except BaseException as error:
                    errors.append(error)
        try:
            if self.process.poll() is None:
                self.process.terminate()
        except BaseException as error:
            errors.append(error)
        try:
            self.process.wait(timeout=3)
        except BaseException as error:
            errors.append(error)
            try:
                self.process.kill()
            except BaseException as error:
                errors.append(error)
            try:
                self.process.wait(timeout=3)
            except BaseException as error:
                errors.append(error)
        if errors:
            failure = Refusal('CHANNEL_CLEANUP_FAILED')
            failure.cleanup_errors = tuple(errors)
            raise failure from errors[0]


class Coordinator:
    """Trusted root orchestrator API: live object, never JSON GO or app callback."""
    def __init__(self, config, fs, spawn, *, origin):
        self.config, self.fs, self.spawn, self.origin = validate(config), fs, spawn, origin
        need({k: origin[k] for k in config['origin']} == config['origin'])
        self.nodes = []
        self.deadline = time.monotonic() + config['lifetimeSeconds']
        self.nonce = secrets.token_hex(32)
        self.active = False
        self.intent = None
        self.commit_attempted = False
        self.commit_sha = None
        self.activation_attempted = False
        self.activation_confirmed = False
        self.handoff_completed = False
        self.cleanup_attempted = False
        self.cleanup_errors = ()

    def failure_code(self):
        # Frozen irreversible state; cleanup never infers rollback from EOF.
        return ('COMMITTED_ACTIVATION_UNKNOWN' if self.commit_sha else
                'COMMIT_UNKNOWN_NO_ACTIVATION' if self.commit_attempted else
                'COORDINATED_RESTORE_UNKNOWN_RETAINED')

    def cleanup_channels(self, primary=None):
        self.active = False
        if not self.cleanup_attempted:
            self.cleanup_attempted = True
            errors = []
            for channel in self.nodes:
                try:
                    channel.close()
                except BaseException as error:
                    errors.append(error)
            self.cleanup_errors = tuple(errors)
        if self.cleanup_errors:
            failure = primary if primary is not None else Refusal(self.failure_code())
            failure.code = self.failure_code()
            failure.cleanup_errors = (*getattr(failure, 'cleanup_errors', ()),
                                      *(e for e in self.cleanup_errors if e not in getattr(failure, 'cleanup_errors', ())))
            if primary is None:
                raise failure from self.cleanup_errors[0]

    def watch(self, except_node=None):
        return [c.wire.reader for c in self.nodes if c is not except_node]

    def live(self):
        need(self.active and time.monotonic() < self.deadline, 'RESTORATION_CAPABILITY_REVOKED')
        need(canonical(self.fs.read_json(CONFIG)) == canonical(self.config), 'LOCAL_ACCEPTED_PIN_DRIFT_RETAINED')
        need(self.fs.read_json(INTENT) == self.intent, 'COORDINATOR_INTENT_DRIFT_RETAINED')
        if self.fs.fixture is None:
            need(local_origin(self.config) == self.origin, 'LOCAL_ORIGIN_DRIFT_RETAINED')
            need(sha(self.fs.read(KEY)[0]) == self.config['keySha256'], 'OPERATOR_KEY_PIN_DRIFT_RETAINED')
        for c in self.nodes:
            need(c.process.poll() is None, 'NODE_PROCESS_LOST_RETAINED')
            c.wire.quiet()

    def check(self):
        try:
            self.live()
            need(len(self.nodes) == 5, 'EXACT_FIVE_ACTIVE_HOLDS_REQUIRED')
            for channel in self.nodes:
                channel.request('check', self.watch(channel))
            self.live()
        except BaseException:
            self.active = False
            raise

    def commit_handoff(self, proof):
        """Same root peer, current all-five holds; not a bearer receipt or retry."""
        need(not self.commit_attempted and self.commit_sha is None, 'HANDOFF_REPLAY_FORBIDDEN')
        self.check()
        need(set(proof) == {'context', 'revision', 'deployedRevision', 'quietSha256', 'nodes'} and
             proof['context'] == self.config['context'] and DIGEST.fullmatch(proof['quietSha256']) and
             all(type(proof[k]) is int and proof[k] >= 0 for k in ('revision','deployedRevision')))
        need(len(proof['nodes']) == 5 and {n['nodeId'] for n in proof['nodes']} == set(NODES))
        for item in proof['nodes']:
            need(set(item) == {'nodeId','targetProfile','enrollmentId','enrollmentSha256','priorOwnerGeneration','owner'})
            pin, owner = self.config['nodes'][item['nodeId']], item['owner']
            need(item['targetProfile'] == pin['identity']['targetProfile'] and DIGEST.fullmatch(item['enrollmentSha256']))
            need(owner['owner'] == 'classic' and owner['generation'] != item['priorOwnerGeneration'] and
                 owner['handbackReceipt']['fromGeneration'] == item['priorOwnerGeneration'] and
                 owner['handbackReceipt']['toGeneration'] == owner['generation'] and
                 owner['nodeIdentity'] == {k: pin['identity'][k] for k in ('machineId','sshHostKeySha256')})
        need(self.fs.absent(COMMIT) and self.fs.absent(COMMIT+'.next') and
             self.fs.absent(ACTIVATION) and self.fs.absent(ACTIVATION+'.next'), 'HANDOFF_REPLAY_FORBIDDEN')
        row = {'version': 1, 'context': self.config['context'], 'nonce': self.nonce,
               'configSha256': sha(canonical(self.config)), 'restoreIntent': self.intent,
               'nodePins': self.config['nodes'], 'nodePeers': {c.node: {'pid': c.hello['pid'], 'start': c.hello['start']} for c in self.nodes},
               'settlement': proof, 'activationSet': ['existing-classic-backend']}
        self.check()
        shared = next(c for c in self.nodes if c.node == SHARED_NODE)
        shared.request('activation-preflight', self.watch(shared))
        self.check()
        self.commit_attempted = True  # unknown file/parent fsync must NEVER activate
        self.fs.atomic(COMMIT, canonical(row), new=True)
        need(self.fs.read_json(COMMIT) == row, 'COMMIT_UNKNOWN_NO_ACTIVATION')
        self.commit_sha = sha(canonical(row))
        self.check()  # guard loss here is committed, never an ownership rollback
        return self.commit_sha

    def activate_classic(self):
        need(self.commit_sha and not self.activation_attempted, 'HANDOFF_ACTIVATION_REPLAY_FORBIDDEN')
        self.check()
        need(sha(self.fs.read(COMMIT)[0]) == self.commit_sha, 'COMMITTED_ACTIVATION_UNKNOWN')
        self.activation_attempted = True
        for c in self.nodes:
            c.request('commit-phase', self.watch(c), commit_sha=self.commit_sha)
        self.check()
        row = {'version': 1, 'commitSha256': self.commit_sha, 'attempted': [SHARED_NODE], 'confirmed': []}
        self.fs.atomic(ACTIVATION, canonical(row), new=True)
        self.check()
        channel = next(c for c in self.nodes if c.node == SHARED_NODE)
        channel.request('activate-classic', self.watch(channel), commit_sha=self.commit_sha)
        self.check()
        row['confirmed'] = [SHARED_NODE]
        self.fs.atomic(ACTIVATION, canonical(row))
        need(self.fs.read_json(ACTIVATION) == row)
        self.check()
        self.activation_confirmed = True

    def finish_handoff(self):
        need(self.activation_confirmed and not self.handoff_completed, 'COMMITTED_ACTIVATION_UNKNOWN')
        self.check()
        for index, channel in enumerate(self.nodes):
            remaining = self.nodes[index:]
            for other in remaining:
                other.request('check', [c.wire.reader for c in remaining if c is not other])
            # Explicit committed transition, never reacquire a released OFD.
            channel.request('release', [])
            need(channel.process.wait(timeout=3) == 0, 'COMMITTED_ACTIVATION_UNKNOWN')
        # Required coordinator pipe/process disposal precedes durable completion
        # and the owner's complete-handoff-ack, not restore_scope's finally.
        self.cleanup_channels()
        self.intent['phase'] = 'handoff-completed'
        self.fs.atomic(INTENT, canonical(self.intent))
        need(self.fs.read_json(INTENT) == self.intent, 'COMMITTED_ACTIVATION_UNKNOWN')
        self.handoff_completed = True
        self.active = False

    @contextmanager
    def restore_scope(self):
        need(self.intent is None and not self.nodes, 'COORDINATOR_REPLAY_FORBIDDEN')
        need(self.fs.absent(INTENT) and self.fs.absent(INTENT + '.next'), 'COORDINATOR_PARTIAL_RETAINED')
        # Durable intent precedes even channel launch. An unknown SSH startup is
        # retained rather than reinterpreted as "not dispatched" after restart.
        self.intent = {'version': 1, 'configSha256': sha(canonical(self.config)), 'nonce': self.nonce,
                       'origin': self.origin, 'phase': 'acquiring-retained', 'restoredNodes': [], 'inFlightNode': None}
        self.fs.atomic(INTENT, canonical(self.intent), new=True)
        need(self.fs.read_json(INTENT) == self.intent, 'COORDINATOR_INTENT_READBACK_REQUIRED')
        primary = None
        try:
            for node, pin in self.config['nodes'].items():
                channel = Channel(self.spawn(node), node, pin, self.nonce, self.origin, self.deadline)
                self.nodes.append(channel)
                channel.start(self.watch(channel))
            self.active = True
            self.check()
            self.intent['phase'] = 'restoring-retained'
            self.fs.atomic(INTENT, canonical(self.intent))
            for channel in self.nodes:
                self.check()
                self.intent['inFlightNode'] = channel.node
                self.fs.atomic(INTENT, canonical(self.intent))
                self.live()
                channel.request('restore', self.watch(channel))
                self.intent['restoredNodes'].append(channel.node)
                self.intent['inFlightNode'] = None
                self.fs.atomic(INTENT, canonical(self.intent))
            for channel in self.nodes:
                channel.request('verify', self.watch(channel))
            self.check()
            self.intent['phase'] = 'restored-held'
            self.fs.atomic(INTENT, canonical(self.intent))
            self.check()
            yield self
            if not self.handoff_completed:
                self.check()
                self.intent['phase'] = 'scope-closed-retained'
                self.fs.atomic(INTENT, canonical(self.intent))
        except BaseException as error:
            primary = error
            error.code = self.failure_code()
            raise
        finally:
            self.cleanup_channels(primary)

    def serve_owner(self, listener):
        """Finite root-peer UDS. Diagnostics valid only during this live channel.

        No DB settlement, arbitrary callback, runner dispatch or transferable GO.
        A future privileged owner orchestrator must hold this connection through
        its own settlement and challenge again after every awaited boundary.
        """
        conn = None
        wire = None
        completed = False
        nonce, peer = secrets.token_hex(32), None
        primary = None
        try:
            while True:
                self.check()
                if conn is None:
                    if not select.select([listener], [], [], .25)[0]:
                        continue
                    conn, _ = listener.accept()
                    conn.settimeout(2)
                    pid, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    expected_uid = self.fs.fixture.uid if self.fs.fixture is not None else 0
                    need(uid == expected_uid and pid != os.getpid(), 'ROOT_OWNER_PEER_REQUIRED')
                    peer = {'pid': pid, 'start': proc_start(pid)}
                    wire = Wire(conn.fileno(), conn.fileno(), self.deadline)
                    wire.send({'version': 1, 'op': 'owner-challenge', 'nonce': nonce, 'peer': peer})
                if not select.select([conn], [], [], .25)[0]:
                    continue
                assert wire is not None and peer is not None
                frame = wire.receive(self.watch())
                need(set(frame) == ({'version', 'op', 'nonce', 'peer', 'challenge', 'proof'} if frame.get('op') == 'commit-handoff' else {'version', 'op', 'nonce', 'peer', 'challenge'}) and type(frame['version']) is int and
                     frame['version'] == 1 and frame['nonce'] == nonce and frame['peer'] == peer and
                     proc_start(peer['pid']) == peer['start'] and isinstance(frame['challenge'], str) and DIGEST.fullmatch(frame['challenge']) and
                     frame['op'] in ('check-restoration', 'finish', 'commit-handoff', 'activate-classic', 'complete-handoff'))
                self.check()
                if frame['op'] == 'finish':
                    need(not self.commit_attempted, 'COMMITTED_ACTIVATION_UNKNOWN')
                    completed = True
                    return
                if frame['op'] != 'check-restoration':
                    if frame['op'] == 'commit-handoff':
                        self.commit_handoff(frame['proof'])
                    elif frame['op'] == 'activate-classic':
                        self.activate_classic()
                    else:
                        self.finish_handoff()
                    next_nonce = secrets.token_hex(32)
                    wire.send({k: v for k, v in {**frame, 'op': frame['op']+'-ack',
                               'commitSha256': self.commit_sha, 'nextNonce': next_nonce}.items() if k != 'proof'})
                    nonce = next_nonce
                    if self.handoff_completed:
                        completed = True
                        return
                    continue
                next_nonce = secrets.token_hex(32)
                wire.send({**frame, 'op': 'restoration-held', 'nodeCount': 5,
                           'handbackAllowed': False, 'nextNonce': next_nonce})
                nonce = next_nonce
        except BaseException as error:
            primary = error
            error.code = self.failure_code()
            raise
        finally:
            if not completed:
                self.active = False
            # The reply covers required node cleanup. A later local transport
            # disposal failure still reports committed uncertainty, never retained.
            dispose_socket(conn, self.failure_code(), primary)


class RestorationChannel:
    """Fixed root-peer client for a future trusted owner orchestrator.

    check() returns no receipt/GO. Its authority is lexical and dies on EOF,
    drift or context exit. No arbitrary callable is accepted or executed.
    Fixture filesystem/socket injection is programmatic and never a CLI option.
    """
    def __init__(self, fs=None, *, fixture_socket=None):
        if fs is None:
            config = validate(decode(trusted_read(CONFIG)))
            pin = next(iter(config['nodes'].values()))['files']['originals']
            fs = load_module('c3_channel_originals', ORIGINALS, pin).Files()
        need(fixture_socket is None or fs.fixture is not None, 'FIXTURE_SOCKET_FORBIDDEN')
        self.fs = fs
        self.path = str(fixture_socket) if fixture_socket is not None else SOCKET
        self.conn = None
        self.active = False
        self.nonce = None
        self.peer = None
        self.commit_attempted = False
        self.committed = False

    def state(self):
        need(self.active and self.conn is not None, 'RESTORATION_CHANNEL_REVOKED')
        assert self.conn is not None
        need(self.fs.read_json(CONFIG) == self.config, 'OWNER_ACCEPTED_PIN_DRIFT_RETAINED')
        need(self.fs.read_json(INTENT) == self.intent, 'OWNER_INTENT_DRIFT_RETAINED')
        pid, uid, _ = struct.unpack('3i', self.conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(uid == self.fs.uid and pid == self.intent['origin']['pid'] and
             proc_start(pid) == self.intent['origin']['start'], 'ROOT_COORDINATOR_PEER_REQUIRED')

    def __enter__(self):
        try:
            need(os.geteuid() == self.fs.uid, 'ROOT_OWNER_REQUIRED')
            self.config = validate(self.fs.read_json(CONFIG))
            self.intent = self.fs.read_json(INTENT)
            need(self.intent['phase'] == 'restored-held' and self.intent['inFlightNode'] is None and
                 len(self.intent['restoredNodes']) == 5 and set(self.intent['restoredNodes']) == set(NODES) and
                 self.intent['configSha256'] == sha(canonical(self.config)), 'LIVE_RESTORATION_INTENT_REQUIRED')
            if self.fs.fixture is None:
                # Descriptor-validate parents separately; socket is not a regular file.
                with self.fs.opened(STATE, directory=True) as directory:
                    info = os.stat(Path(SOCKET).name, dir_fd=directory, follow_symlinks=False)
                    need(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
                         stat.S_IMODE(info.st_mode) == 0o600, 'TRUSTED_ROOT_SOCKET_REQUIRED')
            self.conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.conn.settimeout(2)
            self.conn.connect(self.path)
            self.active = True
            self.state()
            self.wire = Wire(self.conn.fileno(), self.conn.fileno(), time.monotonic() + self.config['lifetimeSeconds'])
            hello = self.wire.receive()
            need(set(hello) == {'version', 'op', 'nonce', 'peer'} and type(hello['version']) is int and
                 hello['version'] == 1 and hello['op'] == 'owner-challenge' and
                 isinstance(hello['nonce'], str) and DIGEST.fullmatch(hello['nonce']) and
                 hello['peer'] == {'pid': os.getpid(), 'start': proc_start(os.getpid())}, 'OWNER_CHALLENGE_INVALID')
            self.nonce, self.peer = hello['nonce'], hello['peer']
            self.check()
            return self
        except BaseException as error:
            self.close(error)
            raise

    def frame(self, op):
        return {'version': 1, 'op': op, 'nonce': self.nonce, 'peer': self.peer, 'challenge': secrets.token_hex(32)}

    def check(self):
        try:
            self.state()
            request = self.frame('check-restoration')
            self.wire.send(request)
            reply = self.wire.receive()
            need(set(reply) == {*request, 'nodeCount', 'handbackAllowed', 'nextNonce'} and
                 type(reply['version']) is int and type(reply['nodeCount']) is int and reply['nodeCount'] == 5 and
                 {k: reply[k] for k in request} == {**request, 'op': 'restoration-held'} and
                 reply['handbackAllowed'] is False and isinstance(reply['nextNonce'], str) and
                 DIGEST.fullmatch(reply['nextNonce']) and reply['nextNonce'] != self.nonce, 'OWNER_REPLY_INVALID')
            self.nonce = reply['nextNonce']
            self.state()
            # Deliberately no JSON / bool / transferable permission returned.
        except BaseException as error:
            self.close(error)
            raise

    def handoff(self, op, proof=None):
        try:
            need(op in ('commit-handoff', 'activate-classic', 'complete-handoff'))
            self.state()
            request = self.frame(op)
            if op == 'commit-handoff':
                self.commit_attempted = True
                request['proof'] = proof
            self.wire.send(request)
            reply = self.wire.receive()
            expected = {k: v for k, v in request.items() if k != 'proof'}
            need(set(reply) == set(expected) | {'commitSha256', 'nextNonce'} and
                 {k: reply[k] for k in expected} == {**expected, 'op': op+'-ack'} and
                 isinstance(reply['commitSha256'], str) and DIGEST.fullmatch(reply['commitSha256']) and
                 isinstance(reply['nextNonce'], str) and DIGEST.fullmatch(reply['nextNonce']))
            self.nonce = reply['nextNonce']
            self.committed = True
            if op == 'complete-handoff':
                self.close()
            else:
                self.state()
            return reply['commitSha256']
        except BaseException as error:
            self.close(error)
            raise

    def close(self, primary=None):
        self.active = False
        conn, self.conn = self.conn, None  # no second attempt after an unknown close
        code = ('COMMITTED_ACTIVATION_UNKNOWN' if self.committed else
                'COMMIT_UNKNOWN_NO_ACTIVATION' if self.commit_attempted else
                'OWNER_RESTORATION_CHANNEL_UNKNOWN_RETAINED')
        dispose_socket(conn, code, primary)

    def __exit__(self, kind, value, traceback):
        primary = value
        try:
            if kind is None:
                self.check()
                self.wire.send(self.frame('finish'))
        except BaseException as error:
            primary = error
            raise
        finally:
            self.close(primary)


def trusted_read(path):
    """Bootstrap without importing user-writable Python on a privileged path."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = Path(path).parts[1:]
        for index, part in enumerate(parts):
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                            (os.O_DIRECTORY if index < len(parts)-1 else 0), dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            need(info.st_uid == 0 and info.st_gid == 0 and not info.st_mode & 0o022)
            need(stat.S_ISDIR(info.st_mode) if index < len(parts)-1 else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        need(os.fstat(fd).st_size <= 8*1024*1024)
        raw = os.read(fd, 8*1024*1024 + 1)
        need(len(raw) <= 8*1024*1024)
        return raw
    finally:
        os.close(fd)


def load_module(name, path, expected):
    # Execute the exact trusted source, never an independently unpinned .pyc.
    import types
    raw = trusted_read(path)
    need(sha(raw) == expected, 'EXECUTED_SOURCE_PIN_DRIFT_RETAINED')
    module = types.ModuleType(name)
    module.__file__ = path
    sys.modules[name] = module
    exec(compile(raw, path, 'exec'), module.__dict__)
    return module


def main():
    need(os.geteuid() == 0 and len(sys.argv) == 2 and sys.argv[1] in ('restore', 'node-hold'), 'ROOT_FIXED_CLI_REQUIRED')
    config = validate(decode(trusted_read(CONFIG)))
    raw = trusted_read(ORIGINALS)
    need(all(sha(raw) == p['files']['originals'] for p in config['nodes'].values()), 'ORIGINALS_SOURCE_PIN_REQUIRED')
    own = trusted_read(SELF)
    need(all(sha(own) == p['files']['self'] for p in config['nodes'].values()), 'COORDINATOR_SOURCE_PIN_REQUIRED')
    n = load_module('c3_installed_originals', ORIGINALS, sha(raw))
    fs = n.Files()
    signal.signal(signal.SIGALRM, lambda *_: need(False, 'COORDINATION_TIMEOUT_RETAINED'))
    signal.signal(signal.SIGTERM, lambda *_: need(False, 'COORDINATION_SIGNAL_RETAINED'))
    signal.signal(signal.SIGHUP, lambda *_: need(False, 'COORDINATION_SIGNAL_RETAINED'))
    signal.alarm(config['lifetimeSeconds'])
    if sys.argv[1] == 'node-hold':
        accepted = fs.read_json(n.ACCEPTED)
        pin = config['nodes'][accepted['nodeId']]
        need(sha(trusted_read(n.HELPER)) == pin['files']['isolation'])
        module = load_module('c3_installed_isolation', n.HELPER, pin['files']['isolation'])
        proposed = n.decode(fs.read(module.CONFIG)[0])
        need(proposed.get('nodeId') == accepted['nodeId'], 'NODE_CONFIG_IDENTITY_DRIFT')
        shared = None
        if accepted['nodeId'] == '6ab189dc63913ebd4a917399':
            need(sha(fs.read(FREEZER)[0]) == pin['files']['freezer'])
            shared = load_module('c3_shared_host', SHARED, pin['files']['shared'])
            plan = shared.validate_plan(proposed, module)
        else:
            plan = module.validate_plan(proposed)
        engine = shared.make_engine(module.STATE, plan, module) if shared else module.Engine(module.STATE, plan, module.Host())
        writer = n.NodeOriginals(engine, module)
        NodeServer(writer, n, config, Wire(0, 1, time.monotonic() + config['lifetimeSeconds']), shared=shared).serve()
        return
    origin = local_origin(config)
    fs.private(STATE)
    need(fs.info(KEY)['mode'] == 0o600 and sha(fs.read(KEY)[0]) == config['keySha256'], 'OPERATOR_KEY_PIN_DRIFT_RETAINED')
    # Fixed lock must be independently provisioned, never create/adopt a lock.
    # The outer flock's readback/FD close is required cleanup too. Keep its
    # context exit inside the same frozen phase classifier as inner resources.
    held = None
    primary = None
    try:
        with fs.lock(LOCK):
            try:
                need(fs.absent(KNOWN) and fs.absent(KNOWN + '.next') and fs.absent(SOCKET), 'STALE_COORDINATOR_RETAINED')
                known = ''.join('[' + p['identity']['endpointIp'] + ']:2222 ssh-ed25519 ' + p['hostKey'] + '\n' for p in config['nodes'].values())
                fs.atomic(KNOWN, known.encode(), new=True)
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    listener.bind(SOCKET); os.chmod(SOCKET, 0o600); listener.listen(1)
                    def spawn(node):
                        need(sha(fs.read(KEY)[0]) == config['keySha256'] and fs.read(KNOWN)[0] == known.encode())
                        local_origin(config)
                        return subprocess.Popen(ssh_argv(config, node), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                stderr=subprocess.DEVNULL, env=CLEAN_ENV, bufsize=0)
                    held = Coordinator(config, fs, spawn, origin=origin)
                    with held.restore_scope():
                        held.serve_owner(listener)
                except BaseException as error:
                    primary = error
                    error.code = held.failure_code() if held is not None else 'COORDINATED_RESTORE_UNKNOWN_RETAINED'
                    raise
                finally:
                    code = held.failure_code() if held is not None else 'COORDINATED_RESTORE_UNKNOWN_RETAINED'
                    dispose_socket(listener, code, primary)
                    # Leave socket/known/intents as sticky reconciliation state.
                    # Never unlink unknown paths or reopen admission during cleanup.
            except BaseException as error:
                # Latch the entire region, including setup and listener finally,
                # before outer lock teardown can replace its first failure.
                if primary is None:
                    primary = error
                raise
        # Success is observable only after required outer lock teardown/readback.
        # Flush inside the classifier: a broken result pipe is postcommit unknown.
        print(json.dumps({'code': 'COMMITTED_BOUNDED_ACTIVATION_CONFIRMED' if held is not None and held.handoff_completed else
                          'RESTORATION_SCOPE_CLOSED_RETAINED', 'admission': 'closed'}), flush=True)
    except BaseException as error:
        failure = primary if primary is not None else error
        setattr(failure, 'code', held.failure_code() if held is not None else 'COORDINATED_RESTORE_UNKNOWN_RETAINED')
        if error is not primary:
            setattr(failure, 'cleanup_errors', (*getattr(failure, 'cleanup_errors', ()), error))
        if failure is not error:
            raise failure from error
        raise


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        print(json.dumps({'ok': False, 'code': getattr(error, 'code', 'COORDINATED_RESTORE_UNKNOWN_RETAINED'),
                          'automaticRetryAllowed': False}), file=sys.stderr)
        raise SystemExit(75)
