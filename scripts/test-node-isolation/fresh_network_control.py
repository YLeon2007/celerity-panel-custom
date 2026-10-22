#!/usr/bin/python3 -I
"""Root-only held-owner control protocol for the fixed network constructor.

Installation and lease publication belong to the independent operator. No CLI
paths, environment commands, auto-recovery or GO exist. An unknown outcome leaves
all kernel resources and journal tombstones untouched.
"""
import os
from pathlib import Path
import select
import socket
import stat
import struct
import time


def receive(channel, module):
    header = b''
    while len(header) < 4:
        block = channel.recv(4-len(header))
        module.need(block, 'CONTROL_EOF_RETAINED')
        header += block
    size = struct.unpack('!I', header)[0]
    module.need(0 < size <= 4096, 'CONTROL_FRAME_REFUSED')
    raw = b''
    while len(raw) < size:
        block = channel.recv(size-len(raw))
        module.need(block, 'CONTROL_EOF_RETAINED')
        raw += block
    return module.decode(raw)


def send(channel, value, module):
    raw = module.encode(value)
    module.need(len(raw) <= module.LIMIT, 'CONTROL_REPLY_OVERFLOW')
    channel.sendall(struct.pack('!I', len(raw))+raw)


class Lease:
    def __init__(self, m, p, raw_plan):
        self.m, self.p, self.raw_plan = m, p, raw_plan
        self.raw = m.trusted_read(m.LEASE)
        value = m.decode(self.raw)
        m.keys(value, 'version context generation boot planSha256 holder deadline operations')
        m.need(type(value['version']) is int and value['version'] == 1 and value['context'] == m.CONTEXT and
               value['generation'] == p['generation'] and value['boot'] == p['boot'] and
               value['planSha256'] == m.digest(raw_plan) and type(value['deadline']) is int and
               value['deadline'] == p['deadline'] and 0 < value['deadline']-time.time() <= 600,
               'INDEPENDENT_LIVE_LEASE_REQUIRED')
        m.keys(value['holder'], 'pid start')
        m.integer(value['holder']['pid'])
        m.need(type(value['holder']['start']) is str and value['holder']['start'].isdigit() and
               value['operations'] == ['observe', 'cutover', 'return', 'abandon'], 'CLOSED_OWNER_LEASE_REQUIRED')
        self.holder = value['holder']
        self.pidfd = os.pidfd_open(self.holder['pid'])
        self.revoked = False
        self.check()

    def check(self):
        m = self.m
        try:
            m.need(not self.revoked and not select.select([self.pidfd], [], [], 0)[0] and
                   m.proc_start(self.holder['pid']) == self.holder['start'] and
                   time.time() < self.p['deadline'], 'OWNER_LEASE_LOST')
            status = Path('/proc', str(self.holder['pid']), 'status').read_text().splitlines()
            m.need('Uid:\t0\t0\t0\t0' in status and
                   m.trusted_read(m.INPUT) == self.raw_plan and m.trusted_read(m.LEASE) == self.raw,
                   'OWNER_OR_ACCEPTED_INPUT_DRIFT')
        except BaseException:
            self.revoked = True
            raise

    def peer(self, channel):
        pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        self.m.need(uid == gid == 0 and pid == self.holder['pid'], 'EXACT_ROOT_OWNER_REQUIRED')
        self.check()

    def close(self):
        os.close(self.pidfd)


def unlink_owned_control(m, controller, socket_identity):
    def operation():
        controller.live()
        m.need(m.identity(m.SOCKET) == socket_identity and stat.S_ISSOCK(os.lstat(m.SOCKET).st_mode),
               'CONTROL_SOCKET_OWNERSHIP_LOST')
        os.unlink(m.SOCKET)
        m.need(not os.path.lexists(m.SOCKET), 'CONTROL_SOCKET_UNLINK_UNCONFIRMED')
    return controller.effect('control-socket-unlink', operation)


def run(m):
    m.need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
           'ROOT_ONLY_FIXED_NETWORK_ENTRY')
    m.need(m.identity('/proc/self/ns/mnt') == m.identity('/proc/1/ns/mnt') and
           m.identity('/proc/self/ns/pid') == m.identity('/proc/1/ns/pid'), 'HOST_PID_MOUNT_NAMESPACES_REQUIRED')
    raw = m.trusted_read(m.INPUT)
    p = m.validate_plan(m.decode(raw))
    lease = Lease(m, p, raw)
    kernel = journal = listener = None
    socket_identity = None
    try:
        # Parent paths are independently preinstalled root-controlled directories.
        for path in ('/run/netns', m.STATE, '/run'):
            fd = m.trusted_fd(path, directory=True)
            os.close(fd)
        journal = m.Journal(Path(m.STATE)/p['generation'], p)
        kernel = m.Linux(p)
        controller = m.Controller(p, kernel, journal, guard=lease.check)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # bind never unlinks/adopts an existing path; this process keeps exact inode.
        listener.bind(m.SOCKET)
        os.chmod(m.SOCKET, 0o600)
        socket_identity = m.identity(m.SOCKET)
        listener.listen(1)
        listener.settimeout(max(.01, min(3, p['deadline']-time.time())))
        # No networking effects until exact independently accepted owner connects.
        channel, _ = listener.accept()
        with channel:
            lease.peer(channel)
            channel.settimeout(3)
            result = controller.prepare()
            send(channel, result, m)
            while controller.phase != 'abandoned':
                lease.peer(channel)
                m.need(m.identity(m.SOCKET) == socket_identity, 'CONTROL_SOCKET_REPLACED')
                channel.settimeout(max(.01, min(30, p['deadline']-time.time())))
                command = receive(channel, m)
                result = controller.command(command)
                lease.peer(channel)
                send(channel, result, m)
        # Only normal confirmed abandonment permits exact-owned socket unlink.
        unlink_owned_control(m, controller, socket_identity)
        controller.live()
        journal.append({'kind': 'terminal-abandoned', 'generation': p['generation']})
    finally:
        if listener is not None: listener.close()
        if kernel is not None: kernel.close()
        if journal is not None: journal.close()
        lease.close()
