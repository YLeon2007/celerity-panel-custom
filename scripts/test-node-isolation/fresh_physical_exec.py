#!/usr/bin/python3 -I
"""Fixed root-only no-argument exec entry; no request/env path selection."""
import hashlib
import os
from pathlib import Path
import signal
import stat
import sys
import types
sys.dont_write_bytecode = True
MODULE = '/usr/local/libexec/c3-test-fresh-physical.py'
MODULE_SHA256 = '5a568eaa6ec890f937ca800a71e2747b2c9bc5c67d6ffed98f2abeed7f8f7405'


def main():
    if len(sys.argv) != 1 or (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
        raise RuntimeError('FIXED_ROOT_NO_ARGUMENT_ENTRY_REQUIRED')
    if Path('/proc/self/cgroup').read_text().strip() != '0::/system.slice/c3-test-fresh-classic.service':
        raise RuntimeError('FIXED_ROOT_UNIT_REQUIRED')
    fd = os.open('/', os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for index, part in enumerate(Path(MODULE).parts[1:]):
            child = os.open(part, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC|
                            (os.O_DIRECTORY if index < len(Path(MODULE).parts)-2 else 0), dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022 or os.listxattr(fd):
                raise RuntimeError('UNTRUSTED_FIXED_PHYSICAL_SOURCE')
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024*1024:
            raise RuntimeError('UNTRUSTED_FIXED_PHYSICAL_SOURCE')
        raw = os.read(fd, 1024*1024+1)
        if hashlib.sha256(raw).hexdigest() != MODULE_SHA256:
            raise RuntimeError('FIXED_PHYSICAL_SOURCE_PIN_REQUIRED')
    finally: os.close(fd)
    module = types.ModuleType('c3_fixed_physical'); module.__file__ = MODULE
    exec(compile(raw, MODULE, 'exec'), module.__dict__)
    pass  # The external watcher owns preaccept termination.
    module.exec_main()


if __name__ == '__main__':
    try: main()
    except BaseException as error:
        # Never print an exception path, input JSON, settings or environment.
        code = 'PHYSICAL_CLEANUP_UNKNOWN' if getattr(error, 'cleanup_errors', None) else (
            str(error) if isinstance(error, RuntimeError) and str(error).isupper() and
            all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_' for c in str(error)) else 'PHYSICAL_SETUP_REFUSED')
        print('REFUSAL '+code, file=sys.stderr)
        raise SystemExit(75)
