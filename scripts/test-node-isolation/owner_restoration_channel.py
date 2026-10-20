#!/usr/bin/python3 -I
"""Finite root-only bridge to the EXISTING RestorationChannel protocol.

No finish/release verb. EOF/error closes the owner channel as UNKNOWN_RETAINED.
The five live node holds stay owned by the coordinator while checks are served.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import sys
import time
import types

CONFIG = '/etc/celerity/topology-test-owner-settlement.json'
SELF = '/usr/local/libexec/c3-test-owner-restoration-channel.py'
COORDINATOR = '/usr/local/libexec/c3-test-coordinated-restore.py'


def need(ok):
    if not ok:
        raise RuntimeError('OWNER_RESTORATION_CHANNEL_UNKNOWN_RETAINED')


def trusted_read(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = Path(path).parts[1:]
        for i, part in enumerate(parts):
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                            (os.O_DIRECTORY if i < len(parts)-1 else 0), dir_fd=fd)
            os.close(fd)
            fd = child
            st = os.fstat(fd)
            need(st.st_uid == 0 and st.st_gid == 0 and not st.st_mode & 0o022)
            need(stat.S_ISDIR(st.st_mode) if i < len(parts)-1 else stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
        raw = os.read(fd, 8*1024*1024 + 1)
        need(len(raw) <= 8*1024*1024)
        return raw
    finally:
        os.close(fd)


def serve(channel, reader=0, writer=1, *, lifetime=115):
    """Injection is programmatic only, for explicitly SIMULATED channel tests."""
    deadline, buffer = time.monotonic() + lifetime, b''
    while time.monotonic() < deadline:
        if not select.select([reader], [], [], .25)[0]:
            channel.check()
            continue
        raw = os.read(reader, 4097)
        need(raw)
        buffer += raw
        need(len(buffer) <= 4096)
        if b'\n' not in buffer:
            continue
        line, buffer = buffer.split(b'\n', 1)
        need(not buffer)
        def pairs(items):
            result = {}
            for k, v in items:
                need(k not in result)
                result[k] = v
            return result
        request = json.loads(line, object_pairs_hook=pairs)
        need(set(request) == {'version', 'op', 'nonce'} and type(request['version']) is int and
             request['version'] == 1 and request['op'] == 'check' and
             isinstance(request['nonce'], str) and len(request['nonce']) == 64 and
             all(c in '0123456789abcdef' for c in request['nonce']))
        channel.check()  # returns no receipt, boolean, GO or authority
        reply = json.dumps({**request, 'op': 'checked'}, separators=(',', ':')).encode() + b'\n'
        need(os.write(writer, reply) == len(reply))
    need(False)


def main():
    need(os.geteuid() == 0 and len(sys.argv) == 1)
    config = json.loads(trusted_read(CONFIG))
    source = trusted_read(COORDINATOR)
    need(hashlib.sha256(source).hexdigest() == config['coordinatorSha256'] and
         hashlib.sha256(trusted_read(SELF)).hexdigest() == config['bridgeSha256'])
    module = types.ModuleType('c3_owner_existing_coordinator')
    module.__file__ = COORDINATOR
    sys.modules[module.__name__] = module
    exec(compile(source, COORDINATOR, 'exec'), module.__dict__)
    signal.signal(signal.SIGALRM, lambda *_: need(False))
    signal.signal(signal.SIGTERM, lambda *_: need(False))
    signal.signal(signal.SIGHUP, lambda *_: need(False))
    signal.alarm(118)
    channel = module.RestorationChannel()
    try:
        channel.__enter__()
        serve(channel)
    finally:
        # Deliberately NOT __exit__: it sends finish, which would drop the
        # coordinator's actual flocks. This entry cannot request any handback.
        channel.close()


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print('OWNER_RESTORATION_CHANNEL_UNKNOWN_RETAINED', file=sys.stderr)
        raise SystemExit(75)
