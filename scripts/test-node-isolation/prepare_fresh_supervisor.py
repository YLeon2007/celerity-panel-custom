#!/usr/bin/python3 -I
"""Fixed dormant fresh supervisor preparation entry. No flags or inventory GO.

A root installer must separately provision and accept all resources. This entry
only opens the normal private lock, stops itself once, then consumes the FINAL
policy after external continuation. It cannot install or accept anything.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import types
sys.dont_write_bytecode=True
POLICY='/etc/c3-test-fresh-classic.json'
COORDINATOR='/usr/local/libexec/c3-test-coordinated-restore.py'
FRESH='/usr/local/libexec/c3-test-fresh-classic.py'


def trusted_read(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        parts=Path(path).parts[1:]
        for index,part in enumerate(parts):
            final=index==len(parts)-1
            child=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|
                          (0 if final else os.O_DIRECTORY),dir_fd=fd)
            os.close(fd);fd=child;s=os.fstat(fd)
            if s.st_uid!=0 or s.st_gid!=0 or s.st_mode & 0o022:
                raise RuntimeError('UNTRUSTED_PREPARATION_SOURCE')
            if final and (not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size>8*1024*1024):
                raise RuntimeError('UNTRUSTED_PREPARATION_FILE')
        raw=os.read(fd,8*1024*1024+1)
        if len(raw)>8*1024*1024:raise RuntimeError('PREPARATION_FILE_LIMIT')
        return raw
    finally:os.close(fd)


def main():
    if len(sys.argv)!=1 or os.geteuid()!=65531 or os.getegid()!=65531 or os.getgroups():
        raise RuntimeError('FIXED_PREPARATION_ENTRY_REQUIRED')
    # Initial independently pinned bootstrap policy contains final source pins,
    # not accepted live inventory. Never generate those pins from running self.
    bootstrap=json.loads(trusted_read(POLICY))
    payloads={path:trusted_read(path) for path in (COORDINATOR,FRESH)}
    for path,raw in payloads.items():
        if hashlib.sha256(raw).hexdigest()!=bootstrap['files'][path]:
            raise RuntimeError('PREPARATION_SOURCE_PIN_REQUIRED')
    c=types.ModuleType('c3_prepared_coordinator');c.__file__=COORDINATOR
    sys.modules[c.__name__]=c
    exec(compile(payloads[COORDINATOR],COORDINATOR,'exec'),c.__dict__)
    fresh=types.ModuleType('c3_prepared_fresh');fresh.__file__=FRESH;fresh.c=c
    sys.modules[fresh.__name__]=fresh
    exec(compile(payloads[FRESH],FRESH,'exec'),fresh.__dict__)
    fresh.supervise(socket.socket(fileno=3),fresh.PreparationSupervisorFiles(bootstrap['files']))


if __name__=='__main__':
    try:main()
    except BaseException:
        print('FRESH_PREPARATION_REFUSED',file=sys.stderr)
        raise SystemExit(75)
