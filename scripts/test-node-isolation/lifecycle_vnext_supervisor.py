#!/usr/bin/env python3
"""Finite LOCAL TEST F/R invocation. Not a constructor or terminal authority.

Only retained pidfds are signalled. No PID/path adoption, process-group kill,
service discovery, network APIs or D activation. The physical path is CLOSED.
"""
import argparse
import array
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import select
import signal
import socket
import sys
import time

NS = 1_000_000_000


def parse():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--local-fixture', action='store_true')
    p.add_argument('--role', required=True, choices=['F', 'R'])
    for name in ['owner-fd', 'control-fd', 'deadline-ns', 'grace-ms']:
        p.add_argument('--' + name, required=True, type=int)
    p.add_argument('--peer-fd', action='append', type=int, default=[])
    p.add_argument('--fixture-observer-fd', type=int)
    for name in ['invocation', 'token', 'boot-id', 'artifact', 'index-sha256',
                 'bootstrap', 'node', 'settings', 'events']:
        p.add_argument('--' + name, required=True)
    return p.parse_args()


def ready(fd):
    return bool(select.select([fd], [], [], 0)[0])


def validate_pidfd(fd):
    if os.readlink('/proc/self/fd/' + str(fd)) != 'anon_inode:[pidfd]':
        raise ValueError('PIDFD_REQUIRED')
    if ready(fd):
        raise ValueError('PINNED_INVOCATION_ALREADY_DEAD')


def main(a):
    # Explicit refusal, not a claim that unprivileged process proofs enforce TEST.
    if not a.local_fixture or os.geteuid() == 0:
        raise ValueError('PHYSICAL_DEPLOYMENT_REFUSED_MANIFEST_ROOT_ENFORCEMENT_MISSING')
    if a.boot_id != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise ValueError('BOOT_MISMATCH')
    grace = a.grace_ms * 1_000_000
    remaining = a.deadline_ns - time.monotonic_ns()
    if not 20_000_000 <= grace <= 10 * NS or not grace + 50_000_000 < remaining <= 600 * NS:
        raise ValueError('ORIGINAL_DEADLINE_REFUSED')
    if len(a.invocation) != 32 or len(a.token) != 64:
        raise ValueError('INVOCATION_TOKEN_REFUSED')
    for value in [a.invocation, a.token, a.index_sha256]:
        if any(c not in '0123456789abcdef' for c in value):
            raise ValueError('IDENTITY_FORMAT_REFUSED')
    if len(a.index_sha256) != 64:
        raise ValueError('ARTIFACT_HASH_REFUSED')
    inherited = [a.owner_fd, a.control_fd, *a.peer_fd]
    if a.fixture_observer_fd is not None:
        inherited.append(a.fixture_observer_fd)
    if len(set(inherited)) != len(inherited):
        raise ValueError('DUPLICATE_FD_REFUSED')
    for fd in [a.owner_fd, *a.peer_fd]:
        validate_pidfd(fd)
    control = socket.socket(fileno=a.control_fd)
    if control.family != socket.AF_UNIX or control.type != socket.SOCK_SEQPACKET:
        raise ValueError('PRIVATE_SEQPACKET_REQUIRED')
    control.setblocking(False)
    # Optional LOCAL fixture export only; never a physical capability or PID lookup.
    observer = None
    if a.fixture_observer_fd is not None:
        observer = socket.socket(fileno=a.fixture_observer_fd)
        if observer.family != socket.AF_UNIX or observer.type != socket.SOCK_SEQPACKET:
            raise ValueError('PRIVATE_FIXTURE_SEQPACKET_REQUIRED')
        observer.setblocking(False)
    artifact = Path(a.artifact).resolve(strict=True)
    index = artifact / 'index.js'
    if hashlib.sha256(index.read_bytes()).hexdigest() != a.index_sha256:
        raise ValueError('INDEX_HASH_MISMATCH')
    # The constructor must pin the entire immutable release/runtime, not just index.
    # The local harness separately inventories every copied source file.
    log_fd = os.open(a.events, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    def emit(event, **fields):
        data = dict(event=event, invocation=a.invocation, role=a.role,
                    monotonicNs=time.monotonic_ns(), deadlineNs=a.deadline_ns, **fields)
        os.write(log_fd, (json.dumps(data, sort_keys=True) + '\n').encode())
        os.fsync(log_fd)

    capsule_read, capsule_write = os.pipe2(os.O_CLOEXEC)
    ack_read, ack_write = os.pipe2(os.O_CLOEXEC)
    capsule = dict(schema='c3-local-temporary-invocation/1', role=a.role,
                   invocation=a.invocation, bootId=a.boot_id, deadlineNs=str(a.deadline_ns),
                   index=str(index), indexSha256=a.index_sha256)
    os.write(capsule_write, json.dumps(capsule).encode())
    os.close(capsule_write)
    os.set_inheritable(capsule_read, True)
    os.set_inheritable(ack_write, True)
    # SIGKILL supervisor -> kernel kills exact Node child, even if owner is dead.
    # This does NOT constrain Node descendants. Physical cgroup/no-escape is absent.
    parent = os.getpid()
    pid = os.fork()
    if pid == 0:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
                os._exit(125)
            if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
                os._exit(125)
            for fd in [*inherited, log_fd, ack_read]:
                os.close(fd)
            os.chdir(artifact)
            env = dict(C3_SETTINGS=a.settings, NODE_ENV='production',
                       C3_VNEXT_CAPSULE_FD=str(capsule_read), C3_VNEXT_ACK_FD=str(ack_write),
                       UV_THREADPOOL_SIZE='2')
            # Read-only local dependencies; never inherited into settings publication.
            if 'NODE_PATH' in os.environ:
                env['NODE_PATH'] = os.environ['NODE_PATH']
            os.execve(a.node, [a.node, '--v8-pool-size=1', '--max-old-space-size=192', a.bootstrap], env)
        except BaseException:
            os._exit(125)
    os.close(capsule_read)
    os.close(ack_write)
    app_fd = None
    supervisor_fd = None
    status = None
    forced = False
    kill_ns = None
    reason = None
    stop_ns = None
    requested = []
    signal.signal(signal.SIGTERM, lambda *_: requested.append('SUPERVISOR_STOP'))
    signal.signal(signal.SIGINT, lambda *_: requested.append('SUPERVISOR_STOP'))
    try:
        # Direct fork child is unreaped, so PID cannot be reused here.
        app_fd = os.pidfd_open(pid)
        if observer is not None:
            # Self-open while alive, ONCE. Queue original descriptors before any
            # reap; delayed receiver obtains DEAD originals, not reused PIDs.
            supervisor_fd = os.pidfd_open(os.getpid())
            metadata = dict(schema='c3-local-fixture-original-pidfds/1',
                            invocation=a.invocation, role=a.role, bootId=a.boot_id,
                            deadlineNs=a.deadline_ns, indexSha256=a.index_sha256)
            packet = json.dumps(metadata, sort_keys=True).encode()
            sent = observer.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                               array.array('i', [app_fd, supervisor_fd]))])
            if sent != len(packet):
                raise ValueError('FIXTURE_EXPORT_INCOMPLETE')
        emit('CREATED', appPid=pid, supervisorPid=parent, indexSha256=a.index_sha256,
             authority='LOCAL_SIMULATED_TEMPORARY_ONLY', physicalAccepted=False)
        started = False
        os.set_blocking(ack_read, False)
        while reason is None:
            now = time.monotonic_ns()
            if ready(a.owner_fd):
                reason = 'OWNER_DEAD'
            elif any(ready(fd) for fd in a.peer_fd):
                reason = 'PEER_DEAD'
            elif ready(app_fd):
                reason = 'APP_DEAD'
            elif now >= a.deadline_ns - grace:
                reason = 'DEADLINE'
            elif requested:
                reason = requested[0]
            else:
                watched = [a.owner_fd, *a.peer_fd, app_fd, a.control_fd]
                if not started:
                    watched.append(ack_read)
                select.select(watched, [], [], min(.025, max(0, (a.deadline_ns - grace - now) / NS)))
                if not started and ready(ack_read):
                    ack = os.read(ack_read, 128)
                    if ack == b'LOCAL_TEMPORARY_ADMITTED\n':
                        started = True
                        # Observational provenance only; no namespace/cgroup exclusivity claim.
                        proc = Path('/proc') / str(pid)
                        stat = proc.joinpath('stat').read_text()
                        emit('STARTED', appPid=pid, supervisorPid=parent, indexSha256=a.index_sha256,
                             startTicks=stat[stat.rindex(')') + 2:].split()[19],
                             executable=os.readlink(proc / 'exe'),
                             namespaces={n: os.readlink(proc / 'ns' / n) for n in ['pid', 'mnt', 'net']},
                             cgroup=proc.joinpath('cgroup').read_text().strip())
                    else:
                        reason = 'BOOTSTRAP_REFUSED'
                if ready(a.control_fd):
                    try:
                        message, _, flags, _ = control.recvmsg(4096)
                        if not message:
                            reason = 'CONTROL_LOST'
                        else:
                            cmd = json.loads(message)
                            valid = (not flags & socket.MSG_TRUNC and isinstance(cmd, dict)
                                     and set(cmd) == {'invocation', 'token', 'action'}
                                     and isinstance(cmd['token'], str)
                                     and hmac.compare_digest(cmd['token'], a.token)
                                     and cmd['invocation'] == a.invocation and cmd['action'] == 'STOP')
                            if valid:
                                reason = 'EXACT_STOP'
                            else:
                                emit('CONTROL_REFUSED')
                    except (ValueError, TypeError, UnicodeError):
                        emit('CONTROL_REFUSED')
        stop_ns = time.monotonic_ns()
        emit('STOPPING', reason=reason, stopNs=stop_ns)
        if not ready(app_fd):
            signal.pidfd_send_signal(app_fd, signal.SIGTERM)
            # Grace is INSIDE original absolute lifetime, never a new 600s.
            kill_at = min(stop_ns + grace, a.deadline_ns - 20_000_000)
            if not select.select([app_fd], [], [], max(0, (kill_at - time.monotonic_ns()) / NS))[0]:
                kill_ns = time.monotonic_ns()
                signal.pidfd_send_signal(app_fd, signal.SIGKILL)
                forced = True
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        result = 1 if forced or reason in ['APP_DEAD', 'BOOTSTRAP_REFUSED'] or code != 0 else 0
        emit('EXIT', reason=reason, appExit=code, forced=forced, killNs=kill_ns,
             stopNs=stop_ns, finishedNs=time.monotonic_ns(), supervisorExit=result,
             naturalSupervisorExit=True, completeNamespaceEmpty=False)
        return result
    finally:
        # Unexpected journal/control failure must not leave the app alive.
        if status is None:
            if app_fd is None:
                app_fd = os.pidfd_open(pid)
            try:
                signal.pidfd_send_signal(app_fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
        if app_fd is not None:
            os.close(app_fd)
        if supervisor_fd is not None:
            os.close(supervisor_fd)
        if observer is not None:
            observer.close()
        os.close(ack_read)
        os.close(log_fd)
        control.close()


if __name__ == '__main__':
    try:
        sys.exit(main(parse()))
    except Exception as exc:
        print('VNEXT_REFUSED:' + type(exc).__name__ + ':' + str(exc), file=sys.stderr)
        sys.exit(1)
