"""Private installed-host model for the neighboring-link coordinator test.

Only native observations/effects and shell file operations are modeled. DIRECT
receives the original stdin bytes and runs its own parser, flock and file CAS.
"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace

Fixture = runpy.run_path(str(Path(__file__).parents[1] / 'rebuildRelayDirectReattestHost.py'))['RuntimeReattest']


class Host(Fixture):
    def seed(self, info, main, bridge):
        self.setUp()
        h = self.h
        self.node, self.machine = info['node'], info['rebuildMachineId']
        self.manifest['machineId'] = self.machine
        original = self.manifest['before']['units']
        for units in (self.units, original):
            units[h['X']].update(User='xray', Group='xray')
        self.manifest['before']['units'] = h['install_unit_pins'](original)
        self.boot = self.old_boot
        self.manifest['runtime']['invocations'] = [self.units[n]['InvocationID'] for n in self.watch]
        assert bridge is None  # installed relays start without a BRIDGE unit
        self.put(h['MAIN'], main.encode(), 0o600)
        record = h['read'](h['MAIN'])
        self.manifest['after']['main'] = {**record, 'data': h['digest'](h['raw'](record))}
        self.manifest['runtime']['files']['main'] = h['remove_generation'](h['MAIN'])
        self.stage_pinned_network()
        self.restarts = 0
        self.cut_final = False
        self.rows = [row for row in self.rows if row[3] != ['11']]
        self.listeners('11')
        h['xray_users'] = self.xray_users
        x = self.watch[0]
        h['in_cgroup'] = lambda pid, u: pid == self.units[x]['MainPID'] if u['ControlGroup'] == '/xray' else pid in u['ModelCgroup']
        original_command = h['command']

        def command(*argv, **opts):
            if argv == (h['XRAY'], 'api', 'inbounduser', '--server=127.0.0.1:10085', '-tag=vless-in'):
                return b'{}'  # paired with an empty modeled subscriber inventory
            return original_command(*argv, **opts)

        original_sc = h['sc']

        def sc(*argv, **opts):
            if argv != ('restart', x):
                return original_sc(*argv, **opts)
            old = self.units[x]['MainPID']
            self.rows = [row for row in self.rows if row[3] != [old]]
            self.restarts += 1
            pid = str(20 + self.restarts)
            self.starts[pid] = 200 + self.restarts
            self.units[x].update(MainPID=pid, InvocationID=f'{200 + self.restarts:032x}')
            self.listeners(pid)

        original_write = h['write']

        def write(path, before, after, *args, **kw):
            if self.cut_final and path == self.manifest_path and after is not None:
                value = json.loads(h['raw'](after))
                if 'currentApply' in value and 'applyPending' not in value:
                    raise OSError('modeled terminal manifest write failure')
            return original_write(path, before, after, *args, **kw)

        h.update(command=command, sc=sc, write=write)

    def listeners(self, pid):
        for row in json.loads(self.physical(self.h['MAIN']).read_bytes())['inbounds']:
            self.rows.append(('tcp', row.get('listen', '0.0.0.0'), row['port'], [pid]))
            if row['protocol'] == 'socks' or row['tag'].startswith('relay-l2tp-'):
                self.rows.append(('udp', row.get('listen', '0.0.0.0'), row['port'], [pid]))

    def direct(self, wire):
        self.h.update(REATTEST_ENTERED=False, REMOVE_ENTERED=False, CHAP_ENTERED=False, NETWORK_UPGRADE_ENTERED=False)
        old_in = sys.stdin
        sys.stdin = SimpleNamespace(buffer=io.BytesIO(wire.encode()))
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = self.h['main']()
        finally:
            sys.stdin = old_in
        assert not self.unexpected, self.unexpected
        return dict(code=code, stdout=out.getvalue(), stderr=err.getvalue())

    def reboot(self):
        self.boot = '12345678-1234-1234-1234-123456789abb'
        pids = {'15': '35'}
        for n, pid, invocation in zip(self.watch, ('31', '32', '33', '0'), '4567'):
            pids[self.units[n]['MainPID']] = pid
            self.units[n].update(MainPID=pid, InvocationID=invocation * 32, ModelCgroup=[pid])
        self.units[self.watch[2]]['ModelCgroup'].append('35')
        self.starts.update({str(pid): pid + 100 for pid in (31, 32, 33, 35)})
        self.rows = [(p, a, n, [pids[pid] for pid in ids]) for p, a, n, ids in self.rows]

    def snapshot(self):
        h = self.h
        def pin(path):
            record, generation = h['apply_profile_read'](path)
            return None if record is None else h['file_pin'](record, generation)
        raw = self.physical(self.manifest_path).read_bytes()
        return dict(manifest=json.loads(raw), manifestDigest=hashlib.sha256(raw).hexdigest(),
                    manifestGeneration=h['remove_generation'](self.manifest_path),
                    files={key: pin(h[key.upper()]) for key in ('main', 'bridge')}, restarts=self.restarts)

    def dispatch(self, op, *args):
        if op == 'file':
            p = self.physical(args[0])
            return p.read_text() if p.is_file() else None
        if op == 'stage':
            assert not self.physical(args[0]).exists()
            self.put(args[0], args[1].encode(), 0o600)
        elif op == 'cleanup':
            for path in args:
                self.physical(path).unlink(missing_ok=True)
        elif op == 'enable-main':
            self.units[self.watch[0]]['UnitFileState'] = 'enabled'
        elif op == 'direct':
            return self.direct(*args)
        elif op == 'reboot':
            self.reboot()
        elif op == 'snapshot':
            return self.snapshot()
        elif op == 'cut-final':
            self.cut_final = True
        elif op == 'legacy-receipt':
            # Same installed receipt shape as an old shell replacement: newly
            # live files, but only immutable install file pins to qualify them.
            m = self.h['read_manifest'](self.token)[2]
            assert 'currentApply' in m and 'applyPending' not in m
            for info in self.manifest['before']['units'].values():
                info.pop('User', None)
                info.pop('Group', None)
            self.save_manifest()
        else:
            raise AssertionError(op)


hosts = {}
try:
    for line in sys.stdin:
        node, op, *args = json.loads(line)
        if op == 'seed':
            host = hosts[node] = Host()
            result = host.seed(*args)
        else:
            result = hosts[node].dispatch(op, *args)
        print(json.dumps(result), flush=True)
finally:
    for host in hosts.values():
        host.doCleanups()
