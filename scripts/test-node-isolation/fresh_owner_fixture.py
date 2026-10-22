"""Test-only same-holder fixture. No operational/root/SSH/kernel authority."""
import json
import os
from pathlib import Path
import socket
import sys
import fcntl
import http.client
import time

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


def launch_flock_held(f):
    with (f.outer.root/'state/launch.lock').open('rb') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: return True
    return False


def replay_readback(f):
    """Read actual proc/protocol witnesses, never fabricate an application writer."""
    def rows(name):
        file=f.root/name
        return [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []
    def optional(name): return None if f.fs.absent(name) else f.fs.read_json(name)
    controller=rows('controller.jsonl'); signals=rows('signals.jsonl')
    row={'signals':signals,'spawns':rows('spawns.jsonl'),'commitsSent':sum(e['event']=='sendmsg' for e in controller),
         'flockHeld':launch_flock_held(f),'supervisorState':Path(f'/proc/{f.supervisor.pid}/stat').read_text().rsplit(')',1)[1].split()[0],
         'commit':optional(c.COMMIT),'attempt':optional(fresh.ATTEMPT),'supervisorJournal':optional(fresh.SUPERVISOR_ATTEMPT),
         'serving':None}
    markers=list(f.root.glob('serving-*.json'))
    if markers:
        pid=json.loads(markers[0].read_text())['pid']
        row['serving']={'pid':pid,'start':fresh.start(pid),'exe':os.readlink(f'/proc/{pid}/exe')}
        if hasattr(f,'bundle'):
            evidence=Path(f.bundle['evidence']); evidence.mkdir(parents=True,exist_ok=True)
            for fd,name in ((1,'application.stdout.log'),(2,'application.stderr.log')):
                try: (evidence/name).write_bytes(Path(f'/proc/{pid}/fd/{fd}').read_bytes())
                except OSError: pass
        row['elapsedSincePopen']=time.monotonic()-row['spawns'][0]['at']
        try: row['serving']['observed']=fresh.observe(pid,'127.0.0.1',f.port)
        except BaseException as error:
            row['serving']['observeError']=str(error)
            if getattr(f, 'bundle', {}).get('startupDiagnostic'):
                # After the irreversible bounded failure ONLY. Never feeds the
                # accepted serving result, journal, supervisor, or protocol.
                diagnostic={'accepted':False,'initialFailureAt':time.monotonic(),
                            'initialError':str(error),'eventualReady':None}
                end=time.monotonic()+15
                while time.monotonic()<end:
                    try:
                        observed=fresh.observe(pid,'127.0.0.1',f.port)
                        diagnostic['eventualReady']={'at':time.monotonic(),'serving':observed}
                        break
                    except (OSError,RuntimeError,http.client.HTTPException) as later:
                        diagnostic['lastError']=str(later)
                    time.sleep(.05)
                diagnostic['elapsedSincePopen']=time.monotonic()-row['spawns'][0]['at']
                diagnostic['supervisorJournalAfter']=optional(fresh.SUPERVISOR_ATTEMPT)
                row['startupDiagnostic']=diagnostic
                for fd,name in ((1,'application.stdout.log'),(2,'application.stderr.log')):
                    try: (Path(f.bundle['evidence'])/name).write_bytes(Path(f'/proc/{pid}/fd/{fd}').read_bytes())
                    except OSError: pass
            return row
        for name,url in (('ready','/classic-ready'),('health','/health')):
            conn=http.client.HTTPConnection('127.0.0.1',f.port,timeout=.5)
            try:
                conn.request('GET',url); reply=conn.getresponse()
                row[name]={'status':reply.status,'body':reply.read(65537).decode()}
            finally: conn.close()
        observed=rows('observed.jsonl')
        row['bootSeconds']=observed[0]['at']-row['spawns'][0]['at']
        listening=next(e for e in controller if e['event']=='_control_listening' and e['value'] is True)
        row['listenSeconds']=listening['at']-signals[0]['at']
    return row


def main():
    fault = sys.argv[1] if len(sys.argv) > 1 else ''
    bundle = json.loads(sys.argv[2]) if len(sys.argv) > 2 else None
    with launch_fixture(fresh, fault=fault or None, bridge=True, bundle=bundle) as f:
        if bundle: f.bundle=bundle
        sock = f.outer.root/'o.sock'
        listener = socket.socket(socket.AF_UNIX); listener.bind(str(sock)); listener.listen(1)
        print(json.dumps({'root':str(f.outer.root), 'socket':str(sock), 'pins':prepare(f),
                          'preparedSupervisor':{'pid':f.supervisor.pid,'start':fresh.start(f.supervisor.pid)},
                          'proof':f.proof, 'port':f.port,
                          **({'bundle':{'manifestSha256':bundle['manifestSha256'],'settingsSha256':bundle['settingsSha256']},
                              'preparedFlockHeld':launch_flock_held(f)} if bundle else {})}), flush=True)
        if bundle and fault == 'settings-pin-drift':
            with Path(bundle['settings']).open('ab') as out: out.write(b'\n')  # same JSON, changed exact pinned bytes
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
                              'commit':f.fs.read_json(c.COMMIT), 'candidateFrozen':all(n.fs.read_json('/fixture-live.json')['candidateFrozen'] for n in f.fixtures),
                              **(replay_readback(f) if bundle else {})}), flush=True)
            # Test harness keeps the actual child alive until explicit disposal.
            sys.stdin.readline()
        except BaseException as error:
            f.held.complete_fresh_owner(error)
            print(json.dumps({'count':f.count(),'error':getattr(error,'code',str(error)),'cause':str(error),
                              'candidateFrozen':all(n.fs.read_json('/fixture-live.json')['candidateFrozen'] for n in f.fixtures),
                              **(replay_readback(f) if bundle else {})}), flush=True)
            if bundle: sys.stdin.readline()
            else: raise
        finally:
            listener.close()
            if fault == 'cleanup': f.held.cleanup_channels = original
    if bundle: print(json.dumps({'cleanup':f.cleanup}),flush=True)

if __name__ == '__main__':
    main()
