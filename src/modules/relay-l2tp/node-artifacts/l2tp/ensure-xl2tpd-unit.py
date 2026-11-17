#!/usr/bin/env python3
"""Install the missing native xl2tpd unit; never replace a packaged/operator unit."""
import os
import stat
import sys

UNIT = b'''[Unit]
Description=xl2tpd L2TP daemon
After=network.target

[Service]
Type=simple
RuntimeDirectory=xl2tpd
RuntimeDirectoryMode=0755
ExecStart=/usr/sbin/xl2tpd -D
KillMode=control-group
Restart=on-failure

[Install]
WantedBy=multi-user.target
'''

def ensure(root='/'):
    target = os.path.join(root, 'etc/systemd/system/xl2tpd.service')
    os.makedirs(os.path.dirname(target), exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.fchmod(fd, 0o644)
        os.write(fd, UNIT)
        os.fsync(fd)
    finally:
        os.close(fd)

if __name__ == '__main__':
    try:
        ensure(sys.argv[1] if len(sys.argv) == 2 else '/')
    except FileExistsError:
        raise SystemExit(73)
