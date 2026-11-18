#!/usr/bin/python3.13
"""Offline-console rebind for a standalone panel host, never a selected node."""
import argparse
import base64
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import runpy
import tempfile
import uuid

P = runpy.run_path(str(Path(__file__).with_name('preflight.py')))
need, digest, decode, trusted, read_private = (P[name] for name in ('need', 'digest', 'decode', 'trusted', 'read_private'))
PROD = {'target': 'production', 'hostIdentity': 'lm1.infograd.online'}


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def replace_private(path, before, after, *, uid=0, root=Path('/')):
    trusted(path.parent, uid, root, private=True)
    need(read_private(path, uid, root) == before, 'POLICY_PREIMAGE_CHANGED')
    fd, temp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(after)
            out.flush()
            os.fsync(out.fileno())
        need(read_private(path, uid, root) == before, 'POLICY_PREIMAGE_CHANGED')
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.lexists(temp):
            os.unlink(temp)
    need(read_private(path, uid, root) == after, 'POLICY_PUBLICATION_UNKNOWN')


def validate_preimages(panel, host, host_sha, current):
    # Boot transition never changes the host's machine ID, raw ed25519 pin,
    # endpoint, original backend process tree, challenge or maintenance ID.
    pin = panel['host']
    physical = pin['physical']
    need(panel['executionContext'] == PROD and panel['admission']['serverContext'] == PROD
         and panel['version'] == 1 and panel['mode'] == 'runtime'
         and host['version'] == 1 and host['serverContext'] == PROD
         and host['kind'] == pin['kind'] == 'host' and len(host['guards']) == 1
         and pin['policySha256'] == host_sha and pin['endpoint'] == host['endpoint']
         and pin['maintenanceId'] == host['maintenanceId'] and physical == host['physical']
         and set(physical) == {'machineId', 'bootId', 'sshHostKeySha256'}
         and physical['machineId'] == current['machineId']
         and physical['sshHostKeySha256'] == current['sshHostKeySha256']
         and P['uuid_ok'](physical['bootId']) and P['uuid_ok'](current['bootId'])
         and physical['bootId'] != current['bootId'], 'UNSUPPORTED_OR_STALE_HOST_REBIND')
    need(panel['nodes'] and all(n['kind'] == 'node' and n['policySha256'] != host_sha
             and n['physical']['machineId'] != physical['machineId']
             and n['physical']['sshHostKeySha256'] != physical['sshHostKeySha256']
             and n['endpoint'] != pin['endpoint'] for n in panel['nodes']), 'SELECTED_NODE_OR_COHOST_REBIND_UNSUPPORTED')


def next_guard(before, host, accepted_boot, state):
    prior = host['guards'][0]
    P['validate_guard_policy'](before, host['physical']['bootId'])
    need(accepted_boot != before['bootId'] and P['uuid_ok'](accepted_boot)
         and before['generation'] == host['maintenanceId']
         and before['challengeSha256'] == host['guardChallengeSha256']
         and before['holderId'] == prior['holderId'] and before['socket'] == prior['socket']
         and before['lock'] == prior['lock']['path'], 'OLD_GUARD_POLICY_MISMATCH')
    holder = str(uuid.uuid5(uuid.UUID(before['holderId']), 'c3-panel-boot:' + accepted_boot))
    dest = state / 'guards' / holder
    return {**before, 'bootId': accepted_boot, 'holderId': holder,
            'lock': str(dest / 'lock'), 'journal': str(dest / 'journal'), 'socket': str(dest / 'socket')}


def next_policies(panel, host, new_guard, peer, accepted_boot):
    prior = host['guards'][0]
    need(new_guard['bootId'] == accepted_boot and peer['sources'] == prior['sources']
         and peer['executableSha256'] == prior['executableSha256'] and peer['argvSha256'] == prior['argvSha256']
         and peer['holderId'] == new_guard['holderId'] and peer['socket'] == new_guard['socket']
         and peer['lock']['path'] == new_guard['lock'], 'CHANGED_GUARD_EXECUTABLE_OR_UNBOUND_PEER')
    h = copy.deepcopy(host)
    h['guards'] = [peer]
    h['physical']['bootId'] = accepted_boot
    host_raw = canonical(h)
    p = copy.deepcopy(panel)
    p['host']['physical']['bootId'] = accepted_boot
    p['host']['policySha256'] = digest(host_raw)
    return host_raw, canonical(p)


def read_current(accepted_boot):
    boot = P['BOOT'].read_text().strip()
    need(boot == accepted_boot and P['uuid_ok'](boot), 'BOOT_APPROVAL_MISMATCH')
    pub = trusted('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
    need(pub[0] == 'ssh-ed25519', 'HOST_KEY_TYPE_CHANGED')
    return {'bootId': boot, 'machineId': trusted('/etc/machine-id').read_text().strip(),
            'sshHostKeySha256': digest(base64.b64decode(pub[1], validate=True))}


def apply(a):
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    state = P['STATE']
    trusted(state, private=True)
    lock = trusted(state / 'backend.launch.lock', private=True)
    # Same persistent lock as systemd's sanctioned backend entry. Docker inventory
    # is an additional barrier; exclusive admin custody is a prerequisite.
    with os.fdopen(os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb') as fp:
        need(os.path.samestat(os.fstat(fp.fileno()), lock.lstat()), 'LAUNCH_LOCK_REPLACED')
        fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = read_current(a.accept_boot)
        panel_raw, host_raw = [read_private(P[name]) for name in ('PANEL_POLICY', 'NODE_POLICY')]
        need(digest(panel_raw) == a.old_panel_sha and digest(host_raw) == a.old_host_sha,
             'PREIMAGE_NOT_INDEPENDENTLY_ACCEPTED')
        panel, host = decode(panel_raw), decode(host_raw)
        validate_preimages(panel, host, a.old_host_sha, current)
        need(digest(canonical(host['guardChallenge'])) == host['guardChallengeSha256']
             and host['guardChallenge']['serverContext'] == PROD, 'HOST_CHALLENGE_MISMATCH')
        installed = {str(P[n]): digest(read_private(P[n])) for n in ('CORE', 'EFFECTS', 'PHYSICAL')}
        need(host['codePins'] == installed, 'HOST_CODE_DRIFT')
        P['docker_exclusion'](a.project)
        boot = current['bootId']
        if a.phase == 'guard':
            need(P['main_pid'](P['GUARD_UNIT']) == 0, 'OLD_GUARD_STILL_RUNNING')
            guard_raw = read_private(P['GUARD_POLICY'])
            need(digest(guard_raw) == a.old_guard_sha, 'OLD_GUARD_NOT_ACCEPTED')
            proposal = next_guard(decode(guard_raw), host, boot, state)
            parent = trusted(state / 'guards', private=True)
            dest = Path(proposal['socket']).parent
            need(dest.parent == parent, 'UNSAFE_GENERATION_DIRECTORY')
            # Validate masks/kernel/installed sources BEFORE creating resources.
            P['isolation']({**proposal, 'socket': str(parent / 'socket'),
                            'lock': str(parent / 'lock'), 'journal': str(parent / 'journal')}, host)
            need(read_current(a.accept_boot) == current, 'BOOT_IDENTITY_DRIFT')
            dest.mkdir(mode=0o700)  # no reuse, no deletion on interruption
            directory = os.open(parent, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            replace_private(P['GUARD_POLICY'], guard_raw, canonical(proposal))
            print('C3_REBIND_GUARD_STAGED_BACKEND_CLOSED')
            return
        # Recompute the entire candidate guard policy from reviewed v2 bytes.
        # The phase-1 input is independently provided (not the new live policy).
        old_guard = Path(a.previous_guard_policy)
        need(old_guard.parent == P['CONFIG'] and old_guard != P['GUARD_POLICY'], 'PREVIOUS_POLICY_LOCATION')
        guard_preimage = read_private(old_guard)
        need(digest(guard_preimage) == a.old_guard_sha, 'OLD_GUARD_NOT_ACCEPTED')
        candidate = next_guard(decode(guard_preimage), host, boot, state)
        need(read_private(P['GUARD_POLICY']) == canonical(candidate), 'STAGED_GUARD_POLICY_CHANGED')
        P['isolation'](candidate, host)
        peer = P['guard_pin'](candidate)
        new_host, new_panel = next_policies(panel, host, candidate, peer, boot)
        if a.phase == 'inspect':
            print('C3_REBIND_CANDIDATE_HOST_POLICY_SHA256=' + digest(new_host))
            return
        need(digest(new_host) == a.accept_host_sha, 'NEW_HOST_POLICY_NOT_INDEPENDENTLY_ACCEPTED')
        P['docker_exclusion'](a.project)
        P['isolation'](candidate, host)
        need(read_current(a.accept_boot) == current and P['guard_pin'](candidate) == peer
             and read_private(P['GUARD_POLICY']) == canonical(candidate)
             and read_private(P['PANEL_POLICY']) == panel_raw, 'REBIND_IDENTITY_DRIFT')
        # Not a multi-file transaction. Publish endpoint policy first: on a crash
        # the backend's native observe gate rejects the mixed hash/boot pair.
        replace_private(P['NODE_POLICY'], host_raw, new_host)
        replace_private(P['PANEL_POLICY'], panel_raw, new_panel)
        print('C3_REBIND_HOST_PINS_PUBLISHED_NO_START')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='phase', required=True)
    for verb in ('guard', 'inspect', 'publish'):
        p = sub.add_parser(verb)
        for arg in ('project', 'accept-boot', 'old-panel-sha', 'old-host-sha', 'old-guard-sha'):
            p.add_argument('--' + arg, required=True)
        if verb != 'guard':
            p.add_argument('--previous-guard-policy', required=True)
        if verb == 'publish':
            p.add_argument('--accept-host-sha', required=True)
    try:
        apply(parser.parse_args())
        return 0
    except P['Refused'] as exc:
        print('C3_REBIND_REFUSED:' + str(exc))
    except Exception:
        print('C3_REBIND_REFUSED:HOST_CHECK_OR_PUBLICATION_FAILED')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
