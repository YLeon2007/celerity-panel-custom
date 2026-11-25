#!/usr/bin/env python3
"""Private Xray fixture child: a real switch with a deliberately lost reply."""
from hashlib import file_digest
import json
import os
from pathlib import Path
import socket
import subprocess
import sys


def digest(path):
    with open(path, 'rb') as stream:
        return file_digest(stream, 'sha256').hexdigest()


def write_once(path, row):
    data = (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
    with open(path, 'xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    if Path(path).read_bytes() != data:
        raise RuntimeError('journal readback changed')


def main():
    os.umask(0o077)
    if (os.getcwd() != '/work' or Path('/etc/resolv.conf').exists()
            or socket.if_nameindex() != [(1, 'lo')]):
        raise RuntimeError('private fixture required')
    port, pid, parent_net = sys.argv[1:]
    net = os.readlink('/proc/self/ns/net')
    if net == parent_net or not port.isascii() or not port.isdecimal() or not 0 < int(port) < 65536:
        raise RuntimeError('invalid fixture endpoint')
    if not pid.isascii() or not pid.isdecimal() or int(pid) <= 1:
        raise RuntimeError('invalid fixture process')
    start = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
    intent = {'version': 1, 'step': 'switch_ingress', 'netns': net, 'pid': int(pid), 'started': start,
              'from': digest('staged-routes.json'), 'to': digest('desired-routes.json')}
    # A duplicate open is a hard refusal, before the real API dispatch.
    try:
        write_once('switch.intent.json', intent)
    except FileExistsError:
        return 76
    result = subprocess.run(['/tools/xray', 'api', 'adrules', f'--server=127.0.0.1:{port}', 'desired-routes.json'],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
    if result.returncode != 0 or result.stderr:
        return 75  # The parent may inspect, but may not assume a no-write refusal.
    # The live process accepted the mutation, but the writer dies before a
    # durable ACK or response can reach its caller. Do not clean up or retry.
    os._exit(77)


if __name__ == '__main__':
    sys.exit(main())
