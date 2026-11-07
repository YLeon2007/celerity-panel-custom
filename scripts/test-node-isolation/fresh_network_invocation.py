#!/usr/bin/python3 -I
"""Finite TEST original holder creator, not an issuer or resource authority.

The fixed public settlement entry is the completion boundary. Never reap the
holder while it can still be the subject of the owner's held-proc status check.
"""
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time

HOLDER_ARGV = ('/usr/bin/python3', '-I', '-B',
               '/usr/local/libexec/c3-test-fresh-network-client-exec.py')
SETTLEMENT_ARGV = ('/usr/bin/node',
    '/opt/celerity-fresh-owner/scripts/test-node-isolation/settle-fresh-held-owner.js')
NETWORK = '/usr/local/libexec/c3-test-fresh-network.py'
NETWORK_SHA256 = 'faa21dcfb3ca5f8d339ce8934893dc0d1b90790ee09d208b2e305b627bc31518'
CLEAN_ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LANG':'C', 'LC_ALL':'C'}
IO_SECONDS = 3


class Invocation:
    """Sole original parent in the trusted finite invocation process.

    No poll/wait/communicate/waitpid on the holder until successful public entry
    completion, or original plan expiry on uncertainty. No child status receipt
    is sent to the owner. Only its existing held proc descriptor supplies status.
    """
    def __init__(self, m):
        self.m = m
        self.holder = self.settlement = None
        self.pidfd = self.settlement_pidfd = None
        self.handoff_attempted = self.settlement_attempted = self.finish_attempted = False
        self.public_completed = self.closed = False
        self.cancelled = False
        self.buffers = {key:bytearray() for key in
                        ('holderStdout','holderStderr','settlementStdout','settlementStderr')}
        self.eof = set()
        # Do not inherit SIG_IGN/SA_NOCLDWAIT, or install a SIGCHLD reaper. The
        # fixed isolated entry is single-threaded and owns no unrelated children.
        m.need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
               'ORIGINAL_CHILD_REAPING_OWNER_REQUIRED')
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        self.p = m.validate_plan(m.decode(m.trusted_read(m.INPUT)))
        m.need('ordinaryOwner' in self.p, 'ORDINARY_FINITE_INVOCATION_REQUIRED')
        remaining = self.p['deadline']-time.time()
        m.need(0 < remaining <= 600, 'FINITE_INSTALLED_DEADLINE_REQUIRED')
        self.end = time.monotonic()+remaining  # before Popen; never renewed
        try:
            self.budget()
            self.holder = self.spawn(HOLDER_ARGV)  # register BEFORE pinning can fail
            self.pid = self.holder.pid
            self.start = m.proc_start(self.pid)
            self.pidfd = os.pidfd_open(self.pid)
            m.need(m.proc_start(self.pid) == self.start and
                   not select.select([self.pidfd],[],[],0)[0], 'ORIGINAL_HOLDER_PIN_REQUIRED')
            self.budget()
        except BaseException as primary:
            try: self.close()
            except BaseException as cleanup: primary.add_note('creator disposal: '+str(cleanup))
            raise

    @staticmethod
    def spawn(argv):
        return subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=CLEAN_ENV, bufsize=0)

    def budget(self, end=None):
        remaining = min(self.end, self.end if end is None else end)-time.monotonic()
        self.m.need(not self.cancelled and remaining > 0 and time.time() < self.p['deadline'], 'FINITE_INVOCATION_EXPIRED')
        return remaining

    def _streams(self):
        pairs = []
        for child, prefix in ((self.holder,'holder'),(self.settlement,'settlement')):
            if child is not None:
                for suffix in ('Stdout','Stderr'):
                    stream = getattr(child,suffix.lower())
                    key = prefix+suffix
                    if stream is not None and key not in self.eof: pairs.append((stream,key))
        return pairs

    def pump(self, end):
        pairs = self._streams()
        ready = select.select([stream for stream,_ in pairs],[],[],self.budget(end))[0]
        self.m.need(ready, 'FINITE_OPERATOR_IO_TIMEOUT')
        for stream,key in pairs:
            if stream not in ready: continue
            block = os.read(stream.fileno(),65536)
            if not block: self.eof.add(key)
            else:
                self.buffers[key].extend(block)
                self.m.need(len(self.buffers[key]) <= self.m.LIMIT, 'BOUNDED_FINITE_OUTPUT_REQUIRED')

    def holder_line(self):
        end = self.end
        while b'\n' not in self.buffers['holderStdout']:
            self.m.need('holderStdout' not in self.eof, 'ORIGINAL_HOLDER_OUTPUT_LOST')
            self.pump(end)
            if self.buffers['holderStdout'] and end == self.end:
                end = min(end,time.monotonic()+IO_SECONDS)
        line,_,tail = self.buffers['holderStdout'].partition(b'\n')
        self.buffers['holderStdout'] = bytearray(tail)
        return bytes(line)+b'\n'

    def command(self, operation):
        self.m.need(not self.closed and not self.handoff_attempted and
                    operation in ('observe','abandon','handoff'), 'FINITE_OPERATOR_SELECTION_REQUIRED')
        # Latch BEFORE writing: lost/partial handoff is never a replay permit.
        if operation == 'handoff': self.handoff_attempted = True
        end = min(self.end,time.monotonic()+IO_SECONDS)
        raw = (operation+'\n').encode('ascii')
        assert self.holder is not None and self.holder.stdin is not None
        while raw:
            self.m.need(select.select([],[self.holder.stdin],[],self.budget(end))[1], 'OPERATOR_INPUT_TIMEOUT')
            count = os.write(self.holder.stdin.fileno(),raw)
            self.m.need(count > 0, 'OPERATOR_INPUT_LOST')
            raw = raw[count:]

    def begin_handoff(self): self.command('handoff')

    def start_settlement(self):
        self.m.need(self.handoff_attempted and not self.settlement_attempted and not self.closed,
                    'ONE_PUBLIC_SETTLEMENT_REQUIRED')
        self.settlement_attempted = True
        self.budget()
        self.settlement = self.spawn(SETTLEMENT_ARGV)  # exact existing public entry
        self.settlement_pidfd = os.pidfd_open(self.settlement.pid)
        self.budget()

    def finish_settlement(self):
        self.m.need(self.settlement is not None and not self.finish_attempted and not self.closed,
                    'ONE_PUBLIC_SETTLEMENT_REQUIRED')
        self.finish_attempted = True
        assert self.settlement is not None and self.settlement_pidfd is not None
        assert self.holder is not None and self.pidfd is not None
        # Drain both real processes; holder EOF/death alone is NOT completion.
        while len(self.eof) != 4: self.pump(self.end)
        self.m.need(select.select([self.settlement_pidfd],[],[],self.budget())[0],
                    'PUBLIC_SETTLEMENT_EXIT_UNKNOWN')
        status = self.settlement.wait(timeout=self.budget())
        self.m.need(status == 0, 'PUBLIC_SETTLEMENT_UNKNOWN_RETAINED')
        # The fixed entry returns zero only after freshHandback's genuine public
        # ACK/readback and required bridge/DB cleanup. stdout is not a done flag.
        self.budget()
        self.public_completed = True
        self.m.need(select.select([self.pidfd],[],[],self.budget())[0], 'ORIGINAL_HOLDER_EXIT_UNKNOWN')
        holder_status = self.holder.wait(timeout=self.budget())
        self.m.need(holder_status == 0, 'ORIGINAL_HOLDER_EXIT_STATUS_UNKNOWN')
        self.budget()
        return {**{key:bytes(value) for key,value in self.buffers.items()},
                'holderExit':holder_status, 'settlementExit':status}

    def settle(self):
        self.start_settlement()
        return self.finish_settlement()

    def finish_abandon(self):
        self.m.need(not self.handoff_attempted and not self.finish_attempted,
                    'ONE_FINITE_COMPLETION_REQUIRED')
        self.finish_attempted = True
        while not {'holderStdout','holderStderr'} <= self.eof: self.pump(self.end)
        assert self.holder is not None and self.pidfd is not None
        self.m.need(select.select([self.pidfd],[],[],self.budget())[0], 'ORIGINAL_HOLDER_EXIT_UNKNOWN')
        self.m.need(self.holder.wait(timeout=self.budget()) == 0, 'ORIGINAL_HOLDER_EXIT_STATUS_UNKNOWN')
        self.budget()

    def _expiry_barrier(self):
        # A failed/timed-out public caller can leave the remote terminal request
        # pending. Do not guess that caller exit settled it. Preserve status until
        # the ORIGINAL plan deadline has excluded a later successful finish.
        while time.monotonic() < self.end:
            time.sleep(min(.05,max(.001,self.end-time.monotonic())))

    @staticmethod
    def _dispose_child(child, pidfd):
        errors = []
        # Called only AFTER the retention barrier. Exact own unreaped Popen is
        # registered even if pidfd acquisition failed; no historical PID reopen.
        if child is not None and child.returncode is None:
            try:
                if pidfd is None or not select.select([pidfd],[],[],0)[0]:
                    if pidfd is None: os.kill(child.pid,signal.SIGTERM)
                    else: signal.pidfd_send_signal(pidfd,signal.SIGTERM)
                try: child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    if pidfd is None: os.kill(child.pid,signal.SIGKILL)
                    else: signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                    child.wait(timeout=1)
            except BaseException as error: errors.append(error)
        if child is not None:
            for name in ('stdin','stdout','stderr'):
                stream = getattr(child,name); setattr(child,name,None)
                if stream is not None:
                    try: stream.close()
                    except BaseException as error: errors.append(error)
        if pidfd is not None:
            try: os.close(pidfd)
            except BaseException as error: errors.append(error)
        return errors

    def close(self):
        if self.closed: return
        self.closed = True
        errors = []
        if self.handoff_attempted and not self.public_completed:
            try: self._expiry_barrier()
            except BaseException as error:
                # A signal must not silently revoke the retention interval.
                errors.append(error)
                self._expiry_barrier()
        # Disposal remains independent: visit both registries after any fault.
        for child,fd in ((self.settlement,self.settlement_pidfd),(self.holder,self.pidfd)):
            errors.extend(self._dispose_child(child,fd))
        self.settlement_pidfd = self.pidfd = None
        if errors:
            for secondary in errors[1:]: errors[0].add_note('creator disposal: '+str(secondary))
            raise errors[0]


def load_network():
    """Checked-buffer bootstrap, no sys.path/env/runtime-selected source."""
    fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOATIME|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        parts = Path(NETWORK).parts[1:]
        s = os.fstat(fd)
        for index,part in enumerate(parts):
            flags = os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
            if index < len(parts)-1: flags |= os.O_DIRECTORY
            child = os.open(part,flags,dir_fd=fd)
            previous,fd = fd,child; os.close(previous)
            s = os.fstat(fd)
            if s.st_uid != 0 or s.st_gid != 0 or s.st_mode & 0o022 or os.listxattr(fd):
                raise RuntimeError('UNTRUSTED_INSTALLED_SOURCE')
        stable = lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > 131072:
            raise RuntimeError('INSTALLED_REGULAR_SOURCE_REQUIRED')
        raw = os.read(fd,131073)
        if stable(s) != stable(os.fstat(fd)) or hashlib.sha256(raw).hexdigest() != NETWORK_SHA256:
            raise RuntimeError('INSTALLED_SOURCE_PIN_REQUIRED')
    finally: os.close(fd)
    spec = importlib.util.spec_from_loader('c3_finite_invocation_network',loader=None)
    assert spec is not None
    m = importlib.util.module_from_spec(spec)
    exec(compile(raw,NETWORK,'exec'),m.__dict__)
    return m


def operator_pipe(m, fd, access):
    s = os.fstat(fd)
    m.need(s.st_uid == s.st_gid == 0 and not s.st_mode & 0o022 and
           stat.S_ISFIFO(s.st_mode) and s.st_nlink == 1 and
           os.readlink('/proc/self/fd/'+str(fd)) == 'pipe:['+str(s.st_ino)+']' and
           fcntl.fcntl(fd,fcntl.F_GETFL) & os.O_ACCMODE == access,
           'PREOPENED_ROOT_ANONYMOUS_OPERATOR_PIPES_REQUIRED')
    return (s.st_dev,s.st_ino)


def run(m):
    """Invoked root workflow: relay evidence/verbs, then existing public handback.

    Independent operator supplies only anonymous pipes, installs the separately
    issued lease and starts the existing server/Coordinator. No policy/lease
    publication, resource cleanup or caller-supplied executable/ack is accepted.
    """
    pins = [operator_pipe(m,fd,access) for fd,access in ((0,os.O_RDONLY),(1,os.O_WRONLY))]
    flags = [fcntl.fcntl(fd,fcntl.F_GETFL) for fd in (0,1)]
    invocation = None; primary = None
    previous = {sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
    cancelled = [False]
    def cancel(*_):
        cancelled[0] = True
        if invocation is not None: invocation.cancelled = True
    for sig in previous: signal.signal(sig,cancel)
    try:
        for fd in (0,1): os.set_blocking(fd,False)
        invocation = Invocation(m)
        invocation.cancelled = cancelled[0]
        assert invocation.holder is not None and invocation.pidfd is not None
        assert invocation.holder.stdout is not None and invocation.holder.stderr is not None
        def emit(raw):
            end = min(invocation.end,time.monotonic()+IO_SECONDS)
            while raw:
                m.need(select.select([],[1],[],invocation.budget(end))[1], 'OPERATOR_OUTPUT_TIMEOUT')
                count = os.write(1,raw); m.need(count > 0,'OPERATOR_OUTPUT_LOST'); raw = raw[count:]
        raw = invocation.holder_line()
        observation = m.decode(raw)
        m.need(observation.get('holder') == {'pid':invocation.pid,'start':invocation.start} and
               observation.get('deadline') == invocation.p['deadline'] and
               all(observation.get(key) is False for key in ('accepted','physicalAccepted','operationalGO')),
               'EXACT_UNACCEPTED_CHILD_OBSERVATION_REQUIRED')
        emit(raw)  # unaccepted actual child identity, before issuer
        emit(invocation.holder_line())  # actual prepared reply
        for _ in range(64):
            line = bytearray(); end = invocation.end
            while not line.endswith(b'\n'):
                m.need(pins == [operator_pipe(m,fd,a) for fd,a in ((0,os.O_RDONLY),(1,os.O_WRONLY))], 'OPERATOR_PIPE_DRIFT')
                ready = select.select([0,invocation.holder.stdout,invocation.holder.stderr,invocation.pidfd],[],[],invocation.budget(end))[0]
                m.need(ready, 'FINITE_OPERATOR_IO_TIMEOUT')
                m.need(invocation.pidfd not in ready, 'ORIGINAL_HOLDER_EXIT_UNKNOWN')
                if invocation.holder.stdout in ready: emit(invocation.holder_line())
                elif invocation.holder.stderr in ready: invocation.pump(end)
                if 0 not in ready: continue
                byte = os.read(0,1); m.need(byte,'OPERATOR_EOF_UNKNOWN_RETAINED')
                if not line: end = min(end,time.monotonic()+IO_SECONDS)
                line.extend(byte); m.need(len(line) <= 8,'CLOSED_OPERATOR_VERB_REQUIRED')
            operation = bytes(line[:-1]).decode('ascii')
            invocation.command(operation)
            if operation == 'handoff':
                result = invocation.settle()
                # Required creator cleanup precedes forwarding the public result.
                invocation.close()
                # No public result before required caller-pipe restoration.
                restore_flags,flags = flags,[]
                restore_errors = []
                for fd,original in enumerate(restore_flags):
                    try: fcntl.fcntl(fd,fcntl.F_SETFL,original)
                    except BaseException as error: restore_errors.append(error)
                restore_signals,previous = previous,{}
                for sig,value in restore_signals.items():
                    try: signal.signal(sig,value)
                    except BaseException as error: restore_errors.append(error)
                if restore_errors: raise restore_errors[0]
                m.need(len(result['holderStdout'])+len(result['settlementStdout']) <= 4096,
                       'BOUNDED_PUBLIC_RESULT_REQUIRED')
                emit(result['holderStdout']); emit(result['settlementStdout'])
                return
            emit(invocation.holder_line())
            if operation == 'abandon':
                invocation.finish_abandon()
                return
        m.need(False,'FINITE_OPERATOR_SELECTION_REQUIRED')
    except BaseException as error:
        primary = error; raise
    finally:
        errors = []
        if invocation is not None:
            try: invocation.close()
            except BaseException as error: errors.append(error)
        for fd,original in enumerate(flags):
            try: fcntl.fcntl(fd,fcntl.F_SETFL,original)
            except BaseException as error: errors.append(error)
        for sig,value in previous.items():
            try: signal.signal(sig,value)
            except BaseException as error: errors.append(error)
        if errors:
            if primary is not None:
                for error in errors: primary.add_note('creator required disposal: '+str(error))
            else: raise errors[0]


def main():
    if len(sys.argv) != 1 or not sys.flags.isolated or os.getresuid() != (0,0,0) or os.getresgid() != (0,0,0): return 75
    try: run(load_network())
    except BaseException:
        os.write(2,b'TEST_OWNER_SETTLEMENT_UNKNOWN_RETAINED; no automatic replay or rollback\n')
        return 75
    return 0


if __name__ == '__main__': sys.exit(main())
