#!/usr/bin/python3 -I
"""Fixed root fresh composition. No flags, request/env activation or recovery."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types
sys.dont_write_bytecode = True

def trusted_read(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(Path(path).parts[1:]):
            final = index == len(Path(path).parts[1:]) - 1
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                            (0 if final else os.O_DIRECTORY), dir_fd=fd)
            os.close(fd); fd = child
            s = os.fstat(fd)
            if s.st_uid != 0 or s.st_gid != 0 or s.st_mode & 0o022:
                raise RuntimeError('UNTRUSTED_FRESH_ROOT_SOURCE')
            if final and (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > 8388608):
                raise RuntimeError('UNTRUSTED_FRESH_ROOT_FILE')
        return os.read(fd, 8388609)
    finally:
        os.close(fd)

def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise RuntimeError('FIXED_FRESH_ROOT_ENTRY_REQUIRED')
    accepted = json.loads(trusted_read('/etc/c3-test-fresh-classic.json'))
    path = '/usr/local/libexec/c3-test-coordinated-restore.py'
    raw = trusted_read(path)
    if hashlib.sha256(raw).hexdigest() != accepted['inventory']['sourceSha256']:
        raise RuntimeError('FRESH_ROOT_SOURCE_PIN_REQUIRED')
    module = types.ModuleType('c3_fixed_fresh_coordinator'); module.__file__ = path
    sys.modules[module.__name__] = module
    exec(compile(raw, path, 'exec'), module.__dict__)
    sys.argv = ['/usr/local/libexec/c3-test-coordinated-fresh-restore.py', 'restore']  # fixed internal composition; no caller command
    module.main(fresh=True)

if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        print(getattr(error, 'code', 'COORDINATED_RESTORE_UNKNOWN_RETAINED'), file=sys.stderr)
        raise SystemExit(75)
