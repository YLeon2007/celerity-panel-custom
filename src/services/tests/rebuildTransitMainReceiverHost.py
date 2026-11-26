"""Packaged receiver admission with only modeled manager and native fixtures."""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rebuildTransitMainHost as host
import rebuildTransitMainReceiver as receiver
import rebuildTransitMainRuntime as runtime
from rebuildTransitMainRuntimeHost import profile
from rebuildTransitMainSession import AUTHORITY
from rebuildTransitMainWindow import UNIT, XRAY, WindowError

ELF = b'\x7fELFprivate-fixture'
ROUTE = dict(inboundTag='vless-in', network='tcp', targetPort=443, outboundTag='selected', targetIP='127.0.0.1')


def scope_row(name, props, **values):
    baseline = dict(Id=name, LoadState='loaded', NeedDaemonReload='no', ActiveState='active', SubState='running',
                    Type='simple', KillMode='control-group', PrivateNetwork='no', StopWhenUnneeded='no', ControlPID='0',
                    **dict.fromkeys(host._SCOPE_NONE, 'none'))
    return ''.join(f'{key}={values.get(key, baseline.get(key, ""))}\n' for key in props)


class PackagedReceiver(unittest.TestCase):
    def test_scope_joins_inactive_pid_zero_without_a_substate_requirement(self):
        deadline = time.monotonic() + 5
        props = host._SCOPE_PROPS

        for active, substate, pid, allowed in (
            ('inactive', 'dead-resources-pinned', '0', True),
            ('inactive', 'dead', '41', False),
            ('failed', 'failed', '0', False),
        ):
            with self.subTest(active=active, substate=substate, pid=pid):
                def run(end, args, timeout):
                    if args == host._JOBS:
                        return ''
                    if args == host._show(UNIT, props):
                        return scope_row(UNIT, props, ActiveState=active, SubState=substate, MainPID=pid)
                    self.assertEqual(args, host._show(XRAY, props))
                    return scope_row(XRAY, props, MainPID='52')

                # This scope check doesn't replace AgentWindow's separate
                # exact cgroup, invocation, and successful-shutdown checks.
                with patch.object(host, '_run', side_effect=run), patch.object(host, '_layout'), \
                     patch.object(host, '_check_dependencies'):
                    if allowed:
                        self.assertEqual(host.verify_manager_scope(deadline)['SubState'], substate)
                    else:
                        with self.assertRaisesRegex(WindowError, '^' + AUTHORITY + '$'):
                            host.verify_manager_scope(deadline)

    def test_no_local_machine_id_dependency_without_existing_pin(self):
        flock = SimpleNamespace(check=lambda: None)
        deadline = time.monotonic() + 5
        pin = ((1, 2, 3), (0o600, 0, 0))
        ordinary = receiver._Authority(flock, deadline, None, {'vless-in'})
        granted = receiver._Authority(flock, deadline, 'f' * 32, {'vless-in'})
        with patch.object(receiver.os, 'geteuid', return_value=0), \
             patch.object(receiver, '_trusted_file', return_value=(b'{}', pin)), \
             patch.object(receiver, '_exec_identity', return_value=pin), \
             patch.object(receiver, '_boot', side_effect=[b'boot-a', b'boot-a', b'boot-b', b'boot-a', b'boot-a']), \
             patch.object(receiver, '_machine', side_effect=FileNotFoundError) as machine:
            self.assertIs(ordinary.check(), True)
            self.assertIs(ordinary.check(), True)
            with self.assertRaisesRegex(WindowError, '^' + AUTHORITY + '$'):
                ordinary.check()  # boot drift still vetoes the same hold
            machine.assert_not_called()
            with self.assertRaisesRegex(WindowError, '^' + AUTHORITY + '$'):
                granted.check()
            machine.assert_called_once_with()
            machine.side_effect = None
            machine.return_value = 'f' * 32
            self.assertIs(granted.check(), True)
            machine.return_value = 'e' * 32
            with self.assertRaisesRegex(WindowError, '^' + AUTHORITY + '$'):
                granted.check()

    def test_scope_checks_jobs_and_activating_neighbors_including_indirect_edges(self):
        seen = []
        deadline = time.monotonic() + 5
        for fault in ('', 'queued', 'PartOf', 'ConsistsOf', 'OnSuccess', 'inactive dependency',
                      'shutdown propagation', 'Debian sysinit conflicts', 'Debian firstboot skipped',
                      'Debian local-fs failure hook'):
            with self.subTest(fault=fault):
                def run(end, args, timeout):
                    self.assertEqual((end, timeout), (deadline, 4))
                    self.assertEqual(host._command(args)[0], args)
                    seen.append(args)
                    if args == host._JOBS:
                        return '2 foreign.service start waiting\n' if fault == 'queued' else ''
                    if args == host._show(UNIT, host._SCOPE_PROPS):
                        fields = {fault: 'foreign.service'} if fault in ('PartOf', 'ConsistsOf', 'OnSuccess') else {}
                        return scope_row(UNIT, host._SCOPE_PROPS, Requires='sysinit.target', **fields)
                    if args == host._show(XRAY, host._SCOPE_PROPS):
                        return scope_row(XRAY, host._SCOPE_PROPS, Requires='-.mount system.slice')
                    props = host._ANCHOR_PROPS
                    roster = {name: scope_row(name, props) for name in ('-.mount', 'system.slice')}
                    roster['sysinit.target'] = scope_row('sysinit.target', props, Wants='stock.service')
                    roster['stock.service'] = scope_row('stock.service', props,
                                                        ActiveState='inactive' if fault == 'inactive dependency' else 'active')
                    # Independent cases from the Debian 13 vendor boot graph.
                    # Model `show`, never start a manager or any of these units.
                    if fault == 'Debian sysinit conflicts':
                        roster['sysinit.target'] = scope_row('sysinit.target', props,
                            Wants='stock.service', Conflicts='emergency.service emergency.target')
                    if fault == 'Debian firstboot skipped':
                        roster['sysinit.target'] = scope_row('sysinit.target', props, Wants='systemd-firstboot.service')
                        roster['systemd-firstboot.service'] = scope_row('systemd-firstboot.service', props,
                            ActiveState='inactive', Wants='first-boot-complete.target')
                    if fault == 'Debian local-fs failure hook':
                        roster['sysinit.target'] = scope_row('sysinit.target', props, Wants='local-fs.target')
                        roster['local-fs.target'] = scope_row('local-fs.target', props,
                            Conflicts='shutdown.target', OnFailure='emergency.target')
                    roster['shutdown.target'] = scope_row('shutdown.target', props, ActiveState='inactive',
                        PropagatesStopTo='foreign.service' if fault == 'shutdown propagation' else '')
                    return '\n'.join(roster[name] for name in args[args.index('--') + 1:])

                seen.clear()
                with patch.object(host, '_run', side_effect=run), patch.object(host, '_layout'):
                    if fault:
                        with self.assertRaisesRegex(WindowError, '^REBUILD_MAIN_AUTHORITY_UNPROVED$'):
                            host.verify_manager_scope(deadline)
                        self.assertTrue(all(args == host._JOBS or args[1] == 'show' for args in seen))
                    else:
                        self.assertEqual(host.verify_manager_scope(deadline)['Id'], UNIT)
                        self.assertEqual(seen[-1], host._JOBS)
                        self.assertIn(host._dependencies_show(['stock.service']), seen)

    def test_bootstrap_uses_existing_machine_authority_and_one_absolute_deadline(self):
        ordinary = dict(machineId=None, managed=['vless-in'], direct=None, routes=[ROUTE])
        grant = dict(backupId='b' * 32, nodeId='c' * 24, network={})
        direct = SimpleNamespace(DEADLINE=1, routing=lambda network: network)
        end = time.monotonic() + 5

        def held(_wire, read_fd, write_fd, *, deadline, lock_factory, verify_hold):
            self.assertEqual((read_fd, write_fd, deadline), (0, 1, end))
            self.assertIs(lock_factory(), lock_factory())
            self.assertEqual(direct.DEADLINE, end if granted else 1)
            return 17

        with patch.object(receiver.HostMainWire, 'serve_held', held):
            granted = False
            self.assertEqual(receiver.serve(ordinary, ELF, None, deadline=end), 17)
            self.assertEqual(receiver.serve(ordinary, ELF, None, deadline=end - 6), 1)
            self.assertEqual(receiver.serve({**ordinary, 'direct': grant}, ELF, direct, deadline=end), 1)
            granted = True
            self.assertEqual(receiver.serve({**ordinary, 'machineId': 'a' * 32, 'direct': grant}, ELF, direct, deadline=end), 17)
            self.assertEqual(direct.DEADLINE, 1)

    def test_ip_if_nonmatch_probes_literal_context_without_domain(self):
        config = profile()
        config['routing']['domainStrategy'] = 'IPIfNonMatch'
        data = json.dumps(config).encode()
        route = runtime.RouteCheck('vless-in', 'tcp', 443, 'selected', target_ip='127.0.0.1')
        frame, _ = runtime._plan(data, {'vless-in'}, (route,))
        self.assertEqual(json.loads(frame)['routes'][0]['context'],
                         dict(inboundTag='vless-in', network='tcp', targetPort=443, targetIP='127.0.0.1'))
        with self.assertRaises(WindowError):
            runtime._plan(data, {'vless-in'}, (route._replace(target_domain='fixture.invalid'),))

    def test_private_proof_cleanup_on_success_and_failed_child(self):
        # Model ownership only. Staging/cleanup and mode checks are real; the
        # child seam never executes the synthetic ELF or opens a socket.
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            old_fstat = os.fstat
            def file_info(fd):
                s = old_fstat(fd)
                return SimpleNamespace(**{k: getattr(s, k) for k in
                    ('st_nlink', 'st_size', 'st_mode', 'st_gid', 'st_dev', 'st_ino', 'st_ctime_ns')}, st_uid=0)

            def identity(path, production):
                self.assertTrue(production)
                s = path.lstat()
                return runtime._file_generation(s), (stat.S_IMODE(s.st_mode), 0, s.st_gid)

            def native(argv, frame, timeout, limit):
                path = Path(argv[0])
                self.assertEqual(path.parent.parent, run)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
                self.assertEqual((path.read_bytes(), frame, timeout, limit),
                                 (ELF, b'frame', runtime.PROOF_TIMEOUT, runtime.RECEIPT_LIMIT))
                if fails:
                    raise WindowError('fixture')
                return b'answer'

            def directory_identity(path, *, private=False):
                s = path.lstat()
                self.assertTrue(stat.S_ISDIR(s.st_mode))
                if private:
                    self.assertEqual(stat.S_IMODE(s.st_mode), 0o700)
                return runtime._id(s)

            with patch.object(runtime, '_RUN', run), patch.object(runtime, '_run_identity', directory_identity), \
                 patch.object(runtime, '_exec_identity', identity), patch.object(os, 'fstat', file_info):
                proof = runtime._PackagedProof(ELF)
                fails = False
                self.assertEqual(proof.execute(native, b'frame', time.monotonic() + 5), b'answer')
                self.assertEqual(list(run.iterdir()), [])
                fails = True
                with self.assertRaisesRegex(WindowError, 'fixture'):
                    proof.execute(native, b'frame', time.monotonic() + 5)
                self.assertEqual(list(run.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
