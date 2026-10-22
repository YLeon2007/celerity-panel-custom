#!/usr/bin/python3 -I
"""Fixed isolated root entry; checked buffers only, no parameters or GO."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

PINS = {
    '/usr/local/libexec/c3-test-fresh-network.py': '6c6c5e3b528f12e5c2d578922c50fa2982906c1e97389948ecff7d55c4cb08ec',
    '/usr/local/libexec/c3-test-fresh-network-control.py': 'ced8d6264424f65f5f9d6f5c9b1f9de731953d196026e513ed6e3f13a0cd88ac',
    '/usr/local/libexec/c3-test-fresh-network-client.py': '847c123f9700044e4d83637cb051ff331ea0502a919b28f4e95aa9d9b54cb520',
}


def load(path):
    # Same bounded descriptor-walk contract as the unchanged server's entry.
    # path is selected solely by the three literals in main, never input/env.
    expected = PINS[path]
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = Path(path).parts[1:]
        for i, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            if i < len(parts)-1: flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = child
            s = os.fstat(fd)
            if s.st_uid != 0 or s.st_gid != 0 or s.st_mode & 0o022 or os.listxattr(fd):
                raise RuntimeError('UNTRUSTED_INSTALLED_SOURCE')
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > 131072:
            raise RuntimeError('INSTALLED_REGULAR_SOURCE_REQUIRED')
        raw = os.read(fd, 131073)
        after = os.fstat(fd)
        stable = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_uid, x.st_gid,
                            x.st_nlink, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        if stable(after) != stable(s) or hashlib.sha256(raw).hexdigest() != expected:
            raise RuntimeError('INSTALLED_SOURCE_PIN_REQUIRED')
    finally:
        os.close(fd)
    spec = importlib.util.spec_from_loader('c3_fixed_'+Path(path).stem.replace('-', '_'), loader=None)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, path, 'exec'), module.__dict__)
    module.__source_sha256__ = expected
    return module


def main():
    if len(sys.argv) != 1 or not sys.flags.isolated or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        return 1
    try:
        network = load('/usr/local/libexec/c3-test-fresh-network.py')
        control = load('/usr/local/libexec/c3-test-fresh-network-control.py')
        client = load('/usr/local/libexec/c3-test-fresh-network-client.py')
        client.run(network, control)
    except BaseException:
        # No secret traceback, unbounded diagnostic pipe or automatic recovery.
        return 1
    # Only a confirmed abandon and checked local disposal can reach zero.
    # This does not acknowledge the server's later unlink/terminal journal.
    return 0


if __name__ == '__main__':
    sys.exit(main())
