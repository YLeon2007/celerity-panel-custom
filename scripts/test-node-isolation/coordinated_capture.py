#!/usr/bin/python3 -I
"""Fixed TEST capture, not restoration. No DB, thaw, dispatch or pin acceptance.

A manually started root coordinator holds five independent foreground SSH
channels. The default app's fixed owner-channel client consumes only that live
root-peer UDS capability, bound to the independently accepted owner challenge.
"""
from contextlib import contextmanager, ExitStack
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
SELF = '/usr/local/libexec/c3-test-coordinated-capture.py'
PROTOCOL = '/usr/local/libexec/c3-test-coordinated-restore.py'
ORIGINALS = '/usr/local/libexec/c3-test-node-originals.py'
SHARED = '/usr/local/libexec/c3-test-shared-host.py'
FREEZER = '/usr/local/libexec/c3-panel-host-freezer.py'
CONFIG = '/etc/c3-test-coordinated-capture.json'
STATE = '/var/lib/c3-test-node-isolation'
INTENT = STATE + '/coordinated-capture.json'
SOCKET = STATE + '/coordinated-capture.sock'
LOCK = STATE + '/coordinated-capture.lock'
KEY = '/etc/c3-test-coordinated-capture/operator-key'
KNOWN = STATE + '/capture-known-hosts'
COMMAND = 'sudo -n /usr/local/libexec/c3-test-coordinated-capture.py node-hold'
NODES = {
 '6ab18adc63913ebd4a917471': ('132.243.230.19', 'xray-main'),
 '6ab93ad2646b4b7d2f43c907': ('94.103.2.186', 'xray-main'),
 '6ab18d9c63913ebd4a917670': ('50.114.160.63', 'xray-bridge'),
 '6ab4b53bc4c0304573e06c72': ('104.143.201.72', 'xray-bridge'),
 '6ab189dc63913ebd4a917399': ('212.119.42.100', 'xray-main'),
}
SHARED_NODE = '6ab189dc63913ebd4a917399'
DIGEST = re.compile('[a-f0-9]{64}\\Z')
BASE = {'version', 'op', 'nodeId', 'coordinatorNonce', 'nodeNonce', 'seq', 'challenge', 'origin'}
CLEAN_ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LANG':'C', 'LC_ALL':'C', 'HOME':'/root'}


class Refusal(RuntimeError):
    pass


def need(ok, code='DURABLE_CAPTURE_UNKNOWN_RETAINED'):
    if not ok:
        raise Refusal(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


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


def validate(config):
    need(isinstance(config, dict) and set(config) == {'version','context','lifetimeSeconds','origin','nodes','keySha256','protocolSha256','ownerChallenge'})
    need(type(config['version']) is int and config['version'] == 1 and config['context'] == 'test.infograd.online')
    need(type(config['lifetimeSeconds']) is int and 80 <= config['lifetimeSeconds'] <= 120)
    need(set(config['origin']) == {'machineId','bootId','cgroup','uid'} and type(config['origin']['uid']) is int and config['origin']['uid'] == 0
         and isinstance(config['origin']['cgroup'], str) and config['origin']['cgroup'] and 'candidate' not in config['origin']['cgroup'])
    need(re.fullmatch('[a-f0-9]{32}',config['origin']['machineId']) and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',config['origin']['bootId']))
    need(all(isinstance(config[k], str) and DIGEST.fullmatch(config[k]) for k in ('keySha256','protocolSha256')))
    need(set(config['nodes']) == set(NODES), 'EXACT_FIVE_NODES_REQUIRED')
    challenge = config['ownerChallenge']
    need(set(challenge) == {'version','executionContext','nodes','host'} and type(challenge['version']) is int and challenge['version'] == 1
         and challenge['executionContext'] == {'target':'test','hostIdentity':'test.infograd.online'} and isinstance(challenge['nodes'], list) and len(challenge['nodes']) == 5)
    need({p['nodeId'] for p in challenge['nodes']} == set(NODES))
    machines, keys = set(), set()
    for node, pin in config['nodes'].items():
        need(set(pin) == {'identity','profiles','guard','files','hostKey'})
        ident = pin['identity']
        need(set(ident) == {'context','nodeId','endpointIp','targetProfile','machineId','bootId','sshHostKeySha256','maintenanceId','planHash'})
        need(ident['context'] == config['context'] and ident['nodeId'] == node and (ident['endpointIp'],ident['targetProfile']) == NODES[node])
        profiles = ['xray-main','xray-bridge'] if ident['endpointIp'] == '104.143.201.72' else [ident['targetProfile']]
        need(pin['profiles'] == profiles and isinstance(pin['guard'],dict) and pin['guard'])
        need(re.fullmatch('[a-f0-9]{32}',ident['machineId']) and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',ident['bootId'])
             and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}',ident['maintenanceId']))
        names = {'self','originals','isolation','accepted'} | ({'shared','freezer'} if node == SHARED_NODE else set())
        need(set(pin['files']) == names and all(isinstance(v,str) and DIGEST.fullmatch(v) for v in [*pin['files'].values(), ident['planHash'],ident['sshHostKeySha256']]))
        raw = base64.b64decode(pin['hostKey'],validate=True)
        need(base64.b64encode(raw).decode() == pin['hostKey'] and len(raw) == 51 and raw[:19] == struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32) and sha(raw) == ident['sshHostKeySha256'])
        need(ident['machineId'] not in machines and ident['sshHostKeySha256'] not in keys,'ALIASED_NODE_RETAINED')
        machines.add(ident['machineId']); keys.add(ident['sshHostKeySha256'])
        owner = next(p for p in challenge['nodes'] if p['nodeId'] == node)
        need(set(owner) == {'nodeId','targetProfile','endpoint','nodeIdentity','bootId','maintenanceId','planHash','guard','originalSnapshot'})
        need(owner['targetProfile'] == ident['targetProfile'] and owner['endpoint'] == {'ip':ident['endpointIp'],'port':2222,'username':'c3-test-runner'}
             and owner['nodeIdentity'] == {k:ident[k] for k in ('machineId','sshHostKeySha256')}
             and all(owner[k] == ident[k] for k in ('bootId','maintenanceId','planHash')) and owner['guard'] == pin['guard'])
        snapshot = owner['originalSnapshot']
        need(set(snapshot) == {'proofRef','configSha256','unitSha256','serviceActive','serviceEnabled'}
             and isinstance(snapshot['proofRef'],str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}',snapshot['proofRef'])
             and all(isinstance(snapshot[k],str) and DIGEST.fullmatch(snapshot[k]) for k in ('configSha256','unitSha256'))
             and snapshot['serviceActive'] in ('active','inactive') and snapshot['serviceEnabled'] in ('enabled','disabled'))
    # Complete host proof is independently fixed in the owner challenge; the
    # installed shared engine freshly validates its guard/backend while held.
    host = challenge['host']
    need(set(host) == {'owner','guard','backend'} and host['owner'] == host['guard']['owner'] and host['guard']['planHash'] == config['nodes'][SHARED_NODE]['identity']['planHash'])
    return config


class CaptureHold:
    """Actual original capture with the SAME outer OFD retained through callback.

    Do not create/lock runner fence files: an empty enrollment requires their
    absence. The outer engine lock plus fresh dispatchCount=0/recovery guard is
    the existing dispatch exclusion authority, not a new runner journal.
    """
    def __init__(self, writer, originals):
        self.writer, self.n = writer, originals
        self.active = False
        self.attempted = False
        self.bundle = None
        self.locks = {}

    def __enter__(self):
        self.stack = ExitStack()
        self.real_lock, self.real_checkpoint = self.writer.fs.lock, self.writer.checkpoint
        try:
            fd = self.stack.enter_context(self.real_lock(self.n.OUTER_LOCK))
            self.locks = {self.n.OUTER_LOCK: fd}
            self.writer.locks = (fd,)
            self.writer.lock_paths = dict(self.locks)
            self.guard = self.writer.held()['guard']
            self.writer.guard = self.guard
            self.active = True
            self.writer.checkpoint = self.check
            @contextmanager
            def reuse(path):
                need(path == self.n.OUTER_LOCK and self.active, 'FOREIGN_CAPTURE_LOCK_RETAINED')
                self.check()
                yield fd
                self.check()
            self.writer.fs.lock = reuse
            self.check()
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def check(self):
        try:
            need(self.active and self.locks, 'CAPTURE_HOLD_REVOKED')
            state = self.writer.held(self.guard)
            need(state['dispatchCount'] == 0, 'CAPTURE_AFTER_DISPATCH_FORBIDDEN')
            for path, fd in self.locks.items():
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.writer.fs.opened(path) as current:
                    a,b = os.fstat(fd),os.fstat(current)
                    need((a.st_dev,a.st_ino) == (b.st_dev,b.st_ino), 'LOCK_REPLACED_RETAINED')
            self.real_checkpoint()
            if not self.writer.fs.absent(self.n.STORE):
                for path in (self.n.BUNDLE+'.next',self.n.RESTORE_STATE,self.n.RESTORE_STATE+'.next'):
                    need(self.writer.fs.absent(path), 'PARTIAL_ORIGINALS_RETAINED')
            if self.bundle is not None:
                raw = self.writer.fs.read(self.n.BUNDLE)[0]
                need(raw == self.bundle, 'DURABLE_BUNDLE_DRIFT_RETAINED')
                bundle = self.n.decode(raw)
                if not getattr(self, '_checking_snapshot', False):
                    self._checking_snapshot = True
                    try:
                        for profile in self.writer.profiles:
                            snapshot = self.writer.snapshot(profile)
                            self.writer.check_original(profile,snapshot)
                            need(snapshot == bundle['profiles'][profile], 'CAPTURE_CURRENT_DRIFT_RETAINED')
                    finally:
                        self._checking_snapshot = False
        except BaseException:
            self.active = False
            raise

    def capture(self):
        self.check()
        need(not self.attempted, 'CAPTURE_REPLAY_FORBIDDEN')
        self.attempted = True
        try:
            # This executes the real file write/fsync/no-overwrite publication
            # and readback; no alternate snapshot or approval implementation.
            self.writer.capture()
            self.bundle = self.writer.fs.read(self.n.BUNDLE)[0]
            self.check()
        except BaseException:
            self.active = False
            raise

    def __exit__(self, *_):
        self.active = False
        self.writer.fs.lock, self.writer.checkpoint = self.real_lock, self.real_checkpoint
        try:
            self.stack.close()
        finally:
            self.writer.locks, self.writer.lock_paths = (), {}


class NodeServer:
    def __init__(self, writer, originals, config, wire, protocol, *, shared=None):
        self.writer, self.n, self.config, self.wire, self.c, self.shared = writer, originals, validate(config), wire, protocol, shared
        self.node = writer.engine.plan['nodeId']
        self.pin = config['nodes'][self.node]
        self.nonce = secrets.token_hex(32)
        self.session = writer.engine.host.operator_session()
        self.root = {'pid':os.getpid(),'start':protocol.proc_start(os.getpid())}

    def pins(self):
        need(self.n.identity(self.writer.engine) == self.pin['identity'] and self.writer.profiles == self.pin['profiles'])
        need(self.writer.held()['guard'] == self.pin['guard'] and self.writer.engine.host.operator_session() == self.session, 'GUARD_OPERATOR_PIN_DRIFT_RETAINED')
        paths = {'self':SELF,'originals':ORIGINALS,'isolation':self.n.HELPER,'accepted':self.n.ACCEPTED}
        if self.node == SHARED_NODE:
            paths.update(shared=SHARED,freezer=FREEZER)
        for name,path in paths.items():
            need(sha(self.writer.fs.read(path)[0]) == self.pin['files'][name], 'INSTALLED_PIN_DRIFT_RETAINED')
        need(canonical(self.writer.fs.read_json(CONFIG)) == canonical(self.config), 'ACCEPTED_CONFIG_DRIFT_RETAINED')
        owner = next(p for p in self.config['ownerChallenge']['nodes'] if p['nodeId'] == self.node)
        accepted = self.writer.accepted['profiles'][self.writer.engine.plan['targetProfile']]
        snap = owner['originalSnapshot']
        need(snap['configSha256'] == accepted['files']['config']['sha256'] and snap['unitSha256'] == accepted['files']['unit']['sha256']
             and snap['serviceActive'] == accepted['service']['ActiveState'] and snap['serviceEnabled'] == accepted['service']['UnitFileState'], 'OWNER_ORIGINAL_PIN_DRIFT_RETAINED')
        if self.node == SHARED_NODE:
            need(self.shared is not None, 'SHARED_HOLD_REQUIRED')
            current = self.shared.check_hold(self.writer.engine.plan,STATE,self.writer.module)
            backend = next(p for p in current['containers'] if p['name'] == 'hysteria-backend')
            observed = {'owner':self.writer.engine.plan['hostHold']['owner'],
                        'guard':self.writer.fs.read_json(STATE+'/host-guard.json'),
                        'backend':{'instanceId':backend['id'],'pid':backend['init']['pid'],'processStartTime':backend['init']['startTicks']}}
            need(observed == self.config['ownerChallenge']['host'], 'SHARED_HOST_PIN_DRIFT_RETAINED')

    def serve(self):
        self.pins()
        self.wire.send({'version':1,'op':'hello','nodeId':self.node,'nodeNonce':self.nonce,'pinSha256':sha(canonical(self.pin)),**self.root})
        first = self.wire.receive()
        need(set(first) == BASE and first['op'] == 'open')
        origin = first['origin']
        need(set(origin) == {*self.config['origin'],'pid','start'} and {k:origin[k] for k in self.config['origin']} == self.config['origin']
             and type(origin['pid']) is int and origin['pid'] > 1 and isinstance(origin['start'],str) and origin['start'].isdigit())
        need(isinstance(first['coordinatorNonce'],str) and DIGEST.fullmatch(first['coordinatorNonce']))
        with CaptureHold(self.writer,self.n) as held:
            seq,frame = 0,first
            while True:
                need(set(frame) == BASE and type(frame['version']) is int and frame['version'] == 1 and frame['nodeId'] == self.node
                     and frame['nodeNonce'] == self.nonce and frame['coordinatorNonce'] == first['coordinatorNonce'] and frame['origin'] == origin
                     and type(frame['seq']) is int and frame['seq'] == seq and isinstance(frame['challenge'],str) and DIGEST.fullmatch(frame['challenge']))
                op = frame['op']
                need(op in (('open',) if seq == 0 else ('check','capture','verify')))
                self.pins(); held.check(); self.wire.quiet()
                if op == 'capture':
                    held.capture()
                if op == 'verify':
                    need(held.bundle is not None, 'CAPTURE_NOT_COMPLETED')
                self.pins(); held.check(); self.wire.quiet()
                self.wire.send({**frame,'op':op+'-held','pinSha256':sha(canonical(self.pin)),'guardSha256':sha(canonical(self.pin['guard'])),
                                'captured':held.bundle is not None,'operator':self.session,**self.root})
                seq += 1
                while not select.select([self.wire.reader],[],[],.25)[0]:
                    need(time.monotonic() < self.wire.deadline, 'NODE_CAPTURE_TIMEOUT_RETAINED')
                    self.pins(); held.check()
                frame = self.wire.receive()


class Channel:
    def __init__(self, process, node, pin, nonce, origin, deadline, protocol):
        self.process,self.node,self.pin,self.nonce,self.origin = process,node,pin,nonce,origin
        self.wire = protocol.Wire(process.stdout.fileno(),process.stdin.fileno(),deadline)
        self.seq,self.hello,self.operator,self.captured = 0,None,None,False

    def start(self, watch):
        hello = self.wire.receive(watch)
        need(set(hello) == {'version','op','nodeId','nodeNonce','pinSha256','pid','start'} and type(hello['version']) is int and hello['version'] == 1
             and hello['op'] == 'hello' and hello['nodeId'] == self.node and hello['pinSha256'] == sha(canonical(self.pin))
             and isinstance(hello['nodeNonce'],str) and DIGEST.fullmatch(hello['nodeNonce']) and type(hello['pid']) is int and hello['pid'] > 1
             and isinstance(hello['start'],str) and hello['start'].isdigit())
        self.hello = hello
        self.request('open',watch)

    def request(self, op, watch):
        need(self.hello is not None and self.process.poll() is None, 'NODE_CHANNEL_LOST_RETAINED')
        frame = {'version':1,'op':op,'nodeId':self.node,'nodeNonce':self.hello['nodeNonce'],'coordinatorNonce':self.nonce,
                 'seq':self.seq,'challenge':secrets.token_hex(32),'origin':self.origin}
        self.wire.send(frame)
        reply = self.wire.receive(watch)
        need(set(reply) == BASE | {'pinSha256','guardSha256','captured','operator','pid','start'}
             and type(reply['version']) is int and type(reply['seq']) is int and type(reply['pid']) is int and type(reply['captured']) is bool)
        need({k:reply[k] for k in BASE} == {**frame,'op':op+'-held'} and reply['pinSha256'] == sha(canonical(self.pin))
             and reply['guardSha256'] == sha(canonical(self.pin['guard'])) and (reply['pid'],reply['start']) == (self.hello['pid'],self.hello['start']))
        need(reply['captured'] is (self.captured or op in ('capture','verify')), 'CAPTURE_UNPROVEN_RETAINED')
        session = reply['operator']
        need(isinstance(session,dict) and set(session) == {'pid','start'} and type(session['pid']) is int and session['pid'] > 1
             and isinstance(session['start'],str) and session['start'].isdigit() and (self.operator is None or session == self.operator))
        self.operator,self.captured = session,reply['captured']
        self.seq += 1

    def close(self):
        for stream in (self.process.stdin,self.process.stdout):
            stream.close()
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(timeout=3)


class Coordinator:
    def __init__(self, config, fs, spawn, protocol, *, origin):
        self.config,self.fs,self.spawn,self.c,self.origin = validate(config),fs,spawn,protocol,origin
        need({k:origin[k] for k in config['origin']} == config['origin'])
        self.deadline = time.monotonic()+config['lifetimeSeconds']
        self.nonce = secrets.token_hex(32)
        self.nodes,self.intent,self.active = [],None,False

    def watch(self, other=None):
        return [c.wire.reader for c in self.nodes if c is not other]

    def live(self):
        need(self.active and time.monotonic() < self.deadline, 'CAPTURE_CAPABILITY_REVOKED')
        need(self.fs.read_json(CONFIG) == self.config and self.fs.read_json(INTENT) == self.intent, 'COORDINATOR_DRIFT_RETAINED')
        if self.fs.fixture is None:
            need(self.c.local_origin(self.config) == self.origin and sha(self.fs.read(KEY)[0]) == self.config['keySha256'])
        for channel in self.nodes:
            need(channel.process.poll() is None, 'NODE_CHANNEL_LOST_RETAINED')
            channel.wire.quiet()

    def check(self, *, captured=True):
        try:
            self.live()
            need(len(self.nodes) == 5 and (not captured or all(c.captured for c in self.nodes)), 'FIVE_CAPTURED_HOLDS_REQUIRED')
            for channel in self.nodes:
                channel.request('check',self.watch(channel))
            self.live()
        except BaseException:
            self.active = False
            raise

    @contextmanager
    def capture_scope(self):
        need(self.intent is None and not self.nodes and self.fs.absent(INTENT) and self.fs.absent(INTENT+'.next'), 'CAPTURE_REPLAY_RETAINED')
        self.intent = {'version':1,'configSha256':sha(canonical(self.config)),'nonce':self.nonce,'origin':self.origin,
                       'phase':'acquiring-retained','capturedNodes':[],'inFlightNode':None}
        self.fs.atomic(INTENT,canonical(self.intent),new=True)
        need(self.fs.read_json(INTENT) == self.intent)
        try:
            for node,pin in self.config['nodes'].items():
                channel = Channel(self.spawn(node),node,pin,self.nonce,self.origin,self.deadline,self.c)
                self.nodes.append(channel); channel.start(self.watch(channel))
            self.active = True
            self.check(captured=False)
            # All five actual outer locks + guards are held BEFORE the FIRST
            # durable bundle publication on any node.
            self.intent['phase'] = 'capturing-retained'
            self.fs.atomic(INTENT,canonical(self.intent))
            for channel in self.nodes:
                self.check(captured=False)
                self.intent['inFlightNode'] = channel.node
                self.fs.atomic(INTENT,canonical(self.intent))
                channel.request('capture',self.watch(channel))
                self.intent['capturedNodes'].append(channel.node)
                self.intent['inFlightNode'] = None
                self.fs.atomic(INTENT,canonical(self.intent))
            for channel in self.nodes:
                channel.request('verify',self.watch(channel))
            self.check()
            self.intent['phase'] = 'captured-held'
            self.fs.atomic(INTENT,canonical(self.intent))
            self.check()
            yield self
            self.check()
            self.intent['phase'] = 'scope-closed-retained'
            self.fs.atomic(INTENT,canonical(self.intent))
        finally:
            self.active = False
            for channel in self.nodes:
                channel.close()

    def serve_owner(self, listener):
        conn,completed = None,False
        nonce = secrets.token_hex(32)
        try:
            while True:
                self.check()
                if conn is None:
                    if not select.select([listener],[],[],.25)[0]:
                        continue
                    conn,_ = listener.accept(); conn.settimeout(2)
                    pid,uid,_ = struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    need(uid == self.fs.uid and pid != os.getpid(), 'ROOT_OWNER_PEER_REQUIRED')
                    peer = {'pid':pid,'start':self.c.proc_start(pid)}
                    wire = self.c.Wire(conn.fileno(),conn.fileno(),self.deadline)
                    wire.send({'version':1,'op':'owner-challenge','nonce':nonce,'peer':peer})
                if not select.select([conn],[],[],.25)[0]:
                    continue
                frame = wire.receive(self.watch())
                need(set(frame) == {'version','op','nonce','peer','challenge','ownerChallengeSha256'} and type(frame['version']) is int
                     and frame['version'] == 1 and frame['nonce'] == nonce and frame['peer'] == peer and self.c.proc_start(peer['pid']) == peer['start']
                     and isinstance(frame['challenge'],str) and DIGEST.fullmatch(frame['challenge'])
                     and frame['ownerChallengeSha256'] == sha(canonical(self.config['ownerChallenge'])) and frame['op'] in ('check-capture','finish'))
                self.check()
                if frame['op'] == 'finish':
                    completed = True
                    return
                next_nonce = secrets.token_hex(32)
                wire.send({**frame,'op':'capture-held','nodeCount':5,'handbackAllowed':False,'nextNonce':next_nonce})
                nonce = next_nonce
        finally:
            if not completed:
                self.active = False
            if conn:
                conn.close()


class CaptureChannel:
    """Lexical root UDS capability; check returns no boolean/receipt."""
    def __init__(self, fs, protocol, *, fixture_socket=None):
        need(fixture_socket is None or fs.fixture is not None)
        self.fs,self.c,self.path = fs,protocol,str(fixture_socket) if fixture_socket else SOCKET
        self.active,self.conn = False,None

    def state(self):
        need(self.active and self.conn is not None, 'CAPTURE_CHANNEL_REVOKED')
        need(self.fs.read_json(CONFIG) == self.config and self.fs.read_json(INTENT) == self.intent, 'CAPTURE_STATE_DRIFT_RETAINED')
        pid,uid,_ = struct.unpack('3i',self.conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        need(uid == self.fs.uid and pid == self.intent['origin']['pid'] and self.c.proc_start(pid) == self.intent['origin']['start'], 'ROOT_COORDINATOR_PEER_REQUIRED')

    def __enter__(self):
        try:
            need(os.geteuid() == self.fs.uid, 'ROOT_OWNER_REQUIRED')
            self.config = validate(self.fs.read_json(CONFIG))
            self.intent = self.fs.read_json(INTENT)
            need(self.intent['phase'] == 'captured-held' and self.intent['inFlightNode'] is None and len(self.intent['capturedNodes']) == 5
                 and set(self.intent['capturedNodes']) == set(NODES) and self.intent['configSha256'] == sha(canonical(self.config)), 'LIVE_CAPTURE_REQUIRED')
            if self.fs.fixture is None:
                with self.fs.opened(STATE,directory=True) as fd:
                    info = os.stat(Path(SOCKET).name,dir_fd=fd,follow_symlinks=False)
                    need(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600)
            self.conn = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.conn.settimeout(2); self.conn.connect(self.path)
            self.active = True; self.state()
            self.wire = self.c.Wire(self.conn.fileno(),self.conn.fileno(),time.monotonic()+self.config['lifetimeSeconds'])
            hello = self.wire.receive()
            need(set(hello) == {'version','op','nonce','peer'} and type(hello['version']) is int and hello['version'] == 1
                 and hello['op'] == 'owner-challenge' and isinstance(hello['nonce'],str) and DIGEST.fullmatch(hello['nonce'])
                 and hello['peer'] == {'pid':os.getpid(),'start':self.c.proc_start(os.getpid())})
            self.nonce,self.peer = hello['nonce'],hello['peer']
            self.check()
            return self
        except BaseException:
            self.close()
            raise

    def frame(self, op):
        return {'version':1,'op':op,'nonce':self.nonce,'peer':self.peer,'challenge':secrets.token_hex(32),
                'ownerChallengeSha256':sha(canonical(self.config['ownerChallenge']))}

    def check(self):
        try:
            self.state()
            frame = self.frame('check-capture'); self.wire.send(frame)
            reply = self.wire.receive()
            need(set(reply) == {*frame,'nodeCount','handbackAllowed','nextNonce'} and type(reply['version']) is int and type(reply['nodeCount']) is int
                 and reply['nodeCount'] == 5 and {k:reply[k] for k in frame} == {**frame,'op':'capture-held'} and reply['handbackAllowed'] is False
                 and isinstance(reply['nextNonce'],str) and DIGEST.fullmatch(reply['nextNonce']) and reply['nextNonce'] != self.nonce)
            self.nonce = reply['nextNonce']; self.state()
        except BaseException:
            self.close()
            raise

    def close(self):
        self.active = False
        if self.conn:
            self.conn.close(); self.conn = None

    def __exit__(self, kind, *_):
        try:
            if kind is None:
                self.check(); self.wire.send(self.frame('finish'))
        finally:
            self.close()


def owner_bridge(fs, protocol, wire, *, fixture_socket=None):
    """Finite app pipe protocol over the real root-peer client; never DB code."""
    config = validate(fs.read_json(CONFIG))
    opened,seq = False,0
    with CaptureChannel(fs,protocol,fixture_socket=fixture_socket) as held:
        while True:
            frame = wire.receive()
            need(set(frame) == {'version','op','seq','nonce','ownerChallenge'} and type(frame['version']) is int and frame['version'] == 1
                 and type(frame['seq']) is int and frame['seq'] == seq and isinstance(frame['nonce'],str) and DIGEST.fullmatch(frame['nonce'])
                 and canonical(frame['ownerChallenge']) == canonical(config['ownerChallenge'])
                 and frame['op'] in (('open',) if not opened else ('check','finish')))
            held.check()
            if frame['op'] == 'finish':
                return
            wire.send({'version':1,'op':'capture-held','seq':seq,'nonce':frame['nonce']})
            opened = True; seq += 1


def trusted_read(path):
    fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        parts = Path(path).parts[1:]
        for index,part in enumerate(parts):
            child = os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_DIRECTORY if index < len(parts)-1 else 0),dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            need(info.st_uid == 0 and info.st_gid == 0 and not info.st_mode & 0o022)
            need(stat.S_ISDIR(info.st_mode) if index < len(parts)-1 else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        need(os.fstat(fd).st_size <= 8*1024*1024)
        raw = os.read(fd,8*1024*1024+1); need(len(raw) <= 8*1024*1024)
        return raw
    finally:
        os.close(fd)


def load_module(name, path, pin):
    import types
    raw = trusted_read(path); need(sha(raw) == pin,'SOURCE_PIN_DRIFT_RETAINED')
    module = types.ModuleType(name); module.__file__ = path; sys.modules[name] = module
    exec(compile(raw,path,'exec'),module.__dict__)
    return module


def ssh_argv(config, node):
    validate(config)
    return ['/usr/bin/ssh','-F','/dev/null','-T','-p','2222','-i',KEY,
            '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
            '-o','StrictHostKeyChecking=yes','-o','HostKeyAlgorithms=ssh-ed25519',
            '-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
            '-o','UserKnownHostsFile='+KNOWN,'-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no',
            '-o','ControlMaster=no','-o','ControlPath=none','-o','ControlPersist=no','-o','ClearAllForwardings=yes',
            '-o','ForwardAgent=no','-o','ForwardX11=no','-o','PermitLocalCommand=no','-o','ProxyCommand=none','-o','ProxyJump=none',
            '-o','ConnectionAttempts=1','-o','ConnectTimeout=8','-o','ServerAliveInterval=3','-o','ServerAliveCountMax=2',
            'c3-test-operator@'+NODES[node][0],COMMAND]


def main():
    need(os.geteuid() == 0 and len(sys.argv) == 2 and sys.argv[1] in ('capture','node-hold','owner-channel'),'ROOT_FIXED_CLI_REQUIRED')
    config = validate(decode(trusted_read(CONFIG)))
    need(all(sha(trusted_read(SELF)) == p['files']['self'] for p in config['nodes'].values()))
    c = load_module('c3_capture_protocol',PROTOCOL,config['protocolSha256'])
    pin = next(iter(config['nodes'].values()))['files']['originals']
    n = load_module('c3_capture_originals',ORIGINALS,pin)
    need(all(p['files']['originals'] == pin for p in config['nodes'].values()))
    fs = n.Files()
    for sig in (signal.SIGALRM,signal.SIGTERM,signal.SIGHUP):
        signal.signal(sig,lambda *_: need(False,'CAPTURE_INTERRUPTED_RETAINED'))
    signal.alarm(config['lifetimeSeconds'])
    if sys.argv[1] == 'owner-channel':
        need(c.local_origin(config) == {**config['origin'],'pid':os.getpid(),'start':c.proc_start(os.getpid())})
        owner_bridge(fs,c,c.Wire(0,1,time.monotonic()+config['lifetimeSeconds']))
        return
    if sys.argv[1] == 'node-hold':
        accepted = fs.read_json(n.ACCEPTED)
        pin = config['nodes'][accepted['nodeId']]
        module = load_module('c3_capture_isolation',n.HELPER,pin['files']['isolation'])
        proposed = decode(fs.read(module.CONFIG)[0])
        need(proposed['nodeId'] == accepted['nodeId'])
        shared = None
        if accepted['nodeId'] == SHARED_NODE:
            need(sha(fs.read(FREEZER)[0]) == pin['files']['freezer'])
            shared = load_module('c3_capture_shared',SHARED,pin['files']['shared'])
            plan = shared.validate_plan(proposed,module)
        else:
            plan = module.validate_plan(proposed)
        engine = shared.make_engine(module.STATE,plan,module) if shared else module.Engine(module.STATE,plan,module.Host())
        NodeServer(n.NodeOriginals(engine,module),n,config,c.Wire(0,1,time.monotonic()+config['lifetimeSeconds']),c,shared=shared).serve()
        return
    origin = c.local_origin(config)
    fs.private(STATE)
    need(fs.info(KEY)['mode'] == 0o600 and sha(fs.read(KEY)[0]) == config['keySha256'])
    with fs.lock(LOCK):
        need(fs.absent(KNOWN) and fs.absent(KNOWN+'.next') and fs.absent(SOCKET),'STALE_COORDINATOR_RETAINED')
        known = ''.join('['+p['identity']['endpointIp']+']:2222 ssh-ed25519 '+p['hostKey']+'\n' for p in config['nodes'].values()).encode()
        fs.atomic(KNOWN,known,new=True)
        listener = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            listener.bind(SOCKET); os.chmod(SOCKET,0o600); listener.listen(1)
            def spawn(node):
                need(sha(fs.read(KEY)[0]) == config['keySha256'] and fs.read(KNOWN)[0] == known)
                c.local_origin(config)
                return subprocess.Popen(ssh_argv(config,node),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=CLEAN_ENV,bufsize=0)
            with Coordinator(config,fs,spawn,c,origin=origin).capture_scope() as held:
                held.serve_owner(listener)
        finally:
            listener.close()  # sticky socket/intent/known files; no automatic cleanup


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print(json.dumps({'ok':False,'code':'DURABLE_CAPTURE_UNKNOWN_RETAINED','ownershipRetained':True,'handbackAllowed':False}),file=sys.stderr)
        raise SystemExit(75)
