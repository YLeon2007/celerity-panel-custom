#!/usr/bin/python3 -I
"""Fixed root-only installed entry. No arguments/environment dispatch or GO."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

PINS = {
    '/usr/local/libexec/c3-test-fresh-network.py': '6c6c5e3b528f12e5c2d578922c50fa2982906c1e97389948ecff7d55c4cb08ec',
    '/usr/local/libexec/c3-test-fresh-network-control.py': 'ced8d6264424f65f5f9d6f5c9b1f9de731953d196026e513ed6e3f13a0cd88ac',
}


def load(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = Path(path).parts[1:]
        for i, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            if i < len(parts)-1:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = child
            s = os.fstat(fd)
            if s.st_uid != 0 or s.st_gid != 0 or s.st_mode & 0o022 or os.listxattr(fd):
                raise RuntimeError('UNTRUSTED_INSTALLED_SOURCE')
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > 131072:
            raise RuntimeError('INSTALLED_REGULAR_SOURCE_REQUIRED')
        raw = os.read(fd, 131073)
        if os.fstat(fd) != s or hashlib.sha256(raw).hexdigest() != PINS[path]:
            raise RuntimeError('INSTALLED_SOURCE_PIN_REQUIRED')
    finally:
        os.close(fd)
    # Execute the bytes actually checked, never reopen a pathname after the pin.
    spec = importlib.util.spec_from_loader('c3_fixed_'+Path(path).stem.replace('-', '_'), loader=None)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, path, 'exec'), module.__dict__)
    return module


def main():
    if len(sys.argv) != 1 or not sys.flags.isolated or os.getuid() != 0 or os.geteuid() != 0:
        print('FIXED_ROOT_NO_ARGUMENT_ENTRY_REQUIRED', file=sys.stderr)
        return 1
    try:
        network = load('/usr/local/libexec/c3-test-fresh-network.py')
        control = load('/usr/local/libexec/c3-test-fresh-network-control.py')
        control.run(network)
    except BaseException:
        # Never expose plan/config/credential bytes, arbitrary OS errors or traceback.
        print('NETWORK_REFUSED_UNKNOWN_RESOURCES_RETAINED', file=sys.stderr)
        return 1
    print('NETWORK_ABANDONED_NO_GO')
    return 0


if __name__ == '__main__':
    sys.exit(main())
