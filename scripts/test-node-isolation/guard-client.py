#!/usr/bin/python3 -I
"""Local foreground responder for an independently pinned operator SSH channel.

Run only after parent-reviewed provisioning. Does not accept passwords or keys in
chat/env/JSON; key and known_hosts arguments are local file paths only.
"""
import json
import pathlib
import re
import subprocess
import sys

HOSTS = {'132.243.230.19', '94.103.2.186', '50.114.160.63', '104.143.201.72'}


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in HOSTS:
        raise SystemExit('usage: guard-client.py ALLOWLISTED_TEST_IP LOCAL_OPERATOR_KEY_FILE PINNED_KNOWN_HOSTS_FILE')
    key, known = (str(pathlib.Path(p).resolve(strict=True)) for p in sys.argv[2:])
    ssh = ['/usr/bin/ssh', '-T', '-p', '2222', '-i', key,
           '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'UserKnownHostsFile=' + known, '-o', 'GlobalKnownHostsFile=/dev/null',
           '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ClearAllForwardings=yes',
           '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
           'c3-test-operator@' + sys.argv[1],
           'sudo -n /usr/local/libexec/c3-test-node-isolation guard']
    child = subprocess.Popen(ssh, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdin is not None and child.stdout is not None
        for line in child.stdout:
            if len(line) > 4096:
                raise ValueError('oversized recovery response')
            obj = json.loads(line)
            if set(obj) == {'recoveryChallenge'} and isinstance(obj['recoveryChallenge'], str) and re.fullmatch(r'[a-f0-9]{64}', obj['recoveryChallenge']):
                child.stdin.write(json.dumps({'recoveryResponse': obj['recoveryChallenge']}) + '\n')
                child.stdin.flush()
            elif obj.get('guardReady') is True:
                print(line.rstrip(), flush=True)
            else:
                raise ValueError('unexpected recovery protocol')
        return child.wait()
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError):
        raise SystemExit('RECOVERY_CLIENT_FAILED; leave all maintenance/ownership retained') from None
