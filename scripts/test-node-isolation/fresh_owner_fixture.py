"""Test-only same-holder fixture. No operational/root/SSH/kernel authority."""
import json
import os
from pathlib import Path
import socket
import sys

import coordinated_restore as c
import fresh_classic_launch as fresh
from test_prepared_resume import prepared_fixture as launch_fixture

BRIDGE_CODE = '''import os,sys
from pathlib import Path
import coordinated_restore as c
import owner_restoration_channel as bridge
import test_node_originals as t
fs=t.n.Files(t.n.Fixture(Path(sys.argv[1]),os.getuid(),os.getgid(),None))
channel=c.RestorationChannel(fs,fixture_socket=sys.argv[2])
primary=None
try:
 channel.__enter__()
 bridge.serve_fresh(channel,lifetime=60)
except BaseException as error:
 primary=error
 print(getattr(error,'code','UNKNOWN_RETAINED'),file=sys.stderr)
 raise
finally:
 channel.close(primary)
'''


def prepare(f):
    """Publish independent physical fixture facts, never owner/adoption DB rows."""
    pins = []
    for node in f.outer.fixtures:
        identity = f.outer.config['nodes'][node.node]['identity']
        accepted = node.accepted
        profile = accepted['profiles'][node.profile]
        pins.append({'nodeId': node.node, 'targetProfile': node.profile,
            'nodeIdentity': {k: identity[k] for k in ('machineId', 'sshHostKeySha256')},
            'endpoint': {'ip': identity['endpointIp'], 'port': 2222, 'username': 'c3-test-runner'},
            'maintenanceId': identity['maintenanceId'], 'bootId': identity['bootId'],
            'originalSnapshot': {'configSha256': profile['files']['config']['sha256'],
                'unitSha256': profile['files']['unit']['sha256'],
                'serviceActive': profile['service']['ActiveState'],
                'serviceEnabled': profile['service']['UnitFileState']}})
    return pins


def main():
    fault = sys.argv[1] if len(sys.argv) > 1 else ''
    with launch_fixture(fresh, fault=fault or None, bridge=True) as f:
        sock = f.outer.root/'o.sock'
        listener = socket.socket(socket.AF_UNIX); listener.bind(str(sock)); listener.listen(1)
        print(json.dumps({'root':str(f.outer.root), 'socket':str(sock), 'pins':prepare(f),
                          'preparedSupervisor':{'pid':f.supervisor.pid,'start':fresh.start(f.supervisor.pid)},
                          'proof':f.proof, 'port':f.port}), flush=True)
        if fault.startswith('guardloss:'):
            node = next(n for n in f.fixtures if n.node == fault.split(':', 1)[1])
            node.put('/fixture-live.json', c.canonical({'held': False, 'candidateFrozen': True}))
        if fault == 'cleanup':
            original = f.held.cleanup_channels
            def fail(primary=None):
                original(primary)
                if primary is None: raise OSError('SIMULATED cleanup failure after actual disposal')
            f.held.cleanup_channels = fail
        try:
            f.held.serve_fresh_owner(listener, platform=f.platform, socket_path=f.socket)
            listener.close()
            if fault == 'terminal-timeout':
                import time
                time.sleep(16)  # beyond actual JS terminal reply deadline; exec already happened
            if fault == 'ack-loss':
                f.held.complete_fresh_owner(RuntimeError('SIMULATED terminal acknowledgement loss'))
            else:
                f.held.complete_fresh_owner()
            print(json.dumps({'count':f.count(),'active':f.held.active,'completed':f.held.handoff_completed,
                              'commit':f.fs.read_json(c.COMMIT), 'candidateFrozen':all(n.fs.read_json('/fixture-live.json')['candidateFrozen'] for n in f.fixtures)}), flush=True)
            # Test harness keeps the actual child alive until explicit disposal.
            sys.stdin.readline()
        except BaseException as error:
            f.held.complete_fresh_owner(error)
            print(json.dumps({'count':f.count(),'error':getattr(error,'code',str(error)),
                              'candidateFrozen':all(n.fs.read_json('/fixture-live.json')['candidateFrozen'] for n in f.fixtures)}), flush=True)
            raise
        finally:
            listener.close()
            if fault == 'cleanup': f.held.cleanup_channels = original

if __name__ == '__main__':
    main()
