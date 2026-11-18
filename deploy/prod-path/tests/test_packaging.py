import ast
import copy
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

HERE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class PackagingTests(unittest.TestCase):
    def test_real_peer_pidfd(self):
        load('preflight').probe_kernel()

    def test_unavailable_peer_pidfd_is_refusal_not_fallback(self):
        class Unsupported:
            def getsockopt(self, level, option):
                self.option = option
                raise OSError('unsupported')
        peer = Unsupported()
        with self.assertRaises(OSError):
            load('preflight').probe_peer_pidfd(peer)
        self.assertEqual(peer.option, getattr(socket, 'SO_PEERPIDFD', 77))

    def test_listening_identity_is_not_just_a_socket_path(self):
        preflight = load('preflight')
        with tempfile.TemporaryDirectory() as tmp, socket.socket(socket.AF_UNIX) as sock:
            path = str(Path(tmp) / 'guard.sock')
            sock.bind(path)
            self.assertFalse(preflight.owns_listener(Path('/proc/self'), path))
            sock.listen()
            self.assertTrue(preflight.owns_listener(Path('/proc/self'), path))
            self.assertFalse(preflight.owns_listener(Path('/proc/self'), path + '-other'))
            sock.close()
            self.assertFalse(preflight.owns_listener(Path('/proc/self'), path))

    def test_real_held_flock_matches_exact_inode(self):
        preflight = load('preflight')
        with tempfile.TemporaryFile() as lock, tempfile.TemporaryFile() as other:
            fcntl.flock(lock, fcntl.LOCK_EX)
            proc = Path('/proc/self')
            self.assertTrue(preflight.owns_flock(proc, os.getpid(), os.fstat(lock.fileno())))
            self.assertFalse(preflight.owns_flock(proc, os.getpid(), os.fstat(other.fileno())))
            fcntl.flock(lock, fcntl.LOCK_UN)
            self.assertFalse(preflight.owns_flock(proc, os.getpid(), os.fstat(lock.fileno())))

    def test_production_python_stack_has_python_310_grammar(self):
        root = HERE.parents[1]
        for path in ('scripts/prod-maintenance/authority_helper.py', 'scripts/prod-maintenance/exclusion_guard.py',
                     'scripts/production-topology-physical.py', 'scripts/test-node-isolation/original_effects.py'):
            with self.subTest(path=path):
                ast.parse((root / path).read_text(), filename=path, feature_version=(3, 10))
        script = (root / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh').read_text()
        ast.parse(script.split("<<'FENCE_PY'\n", 1)[1].split('\nFENCE_PY\n', 1)[0], feature_version=(3, 10))

    def test_backend_container_requires_exact_stopped_restart_no(self):
        preflight = load('preflight')
        isolated = {'Name': '/hysteria-backend', 'Id': 'f' * 64,
                    'Config': {'Labels': {'com.docker.compose.project': 'existing',
                                          'com.docker.compose.service': 'backend'}},
                    'HostConfig': {'RestartPolicy': {'Name': 'no'}},
                    'State': {'Status': 'exited', 'Pid': 0, 'Running': False,
                              'Paused': False, 'Restarting': False, 'Dead': False}}
        self.assertTrue(preflight.stopped_backend(isolated, 'existing'))
        self.assertFalse(preflight.stopped_backend(isolated, 'wrong'))
        for section, key, value in [('State', 'Running', True), ('State', 'Pid', 123),
                                    ('State', 'Status', 'dead'), ('State', 'Paused', True),
                                    ('HostConfig', 'RestartPolicy', {'Name': 'always'})]:
            with self.subTest(section=section, key=key, value=value):
                unsafe = copy.deepcopy(isolated)
                unsafe[section][key] = value
                self.assertFalse(preflight.stopped_backend(unsafe, 'existing'))

    def test_known_updater_must_be_absent_not_just_stopped(self):
        preflight = load('preflight')
        # Docker ls --all reports the updater even if stopped. No docker calls here.
        with patch.object(preflight, 'run', return_value=b'f' * 64 + b'\n') as run:
            with self.assertRaisesRegex(preflight.Refused, 'UPDATER_STILL_PRESENT'):
                preflight.docker_exclusion('existing')
            self.assertIn('--all', run.call_args.args[0])
        with patch.object(preflight, 'run', side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):
                preflight.docker_exclusion('existing')
        with patch.object(preflight, 'run', return_value=b''):
            preflight.docker_exclusion('existing')

    def test_rendered_backend_gates_updater_mount_roles_and_restart(self):
        preflight = load('preflight')
        image = 'fixture@sha256:' + '1' * 64
        root = HERE.parents[1]
        base = {'services': {'backend': {
            'image': image, 'restart': 'no', 'pull_policy': 'never', 'user': '0:0',
            'entrypoint': ['/bin/sh', '-ec', 'node /app/deploy/prod-path/preflight-ssh.cjs && exec node /app/index.js'],
            'environment': {'UPDATER_URL': '', 'UPDATER_SECRET': '', 'PANEL_DOMAIN': 'lm1.infograd.online',
                            'L2TP_EXECUTION_ENABLED': 'true', 'L2TP_MIGRATIONS_ENABLED': 'true',
                            'TOPOLOGY_PRODUCTION_EXECUTION_ENABLED': 'true', 'TOPOLOGY_TEST_EXECUTION_ENABLED': 'false',
                            'TOPOLOGY_TEST_STARTUP_MODE': '', 'L2TP_PRODUCTION_EXECUTION_ENABLED': 'false'},
            'volumes': [{'type': 'bind', 'source': '/etc/celerity', 'target': '/etc/celerity', 'read_only': True,
                         'bind': {'create_host_path': False}},
                        {'type': 'volume', 'source': 'caddy_data', 'target': '/caddy_data', 'read_only': True},
                        *[{'type': 'bind', 'source': str(root / leaf), 'target': '/app/' + leaf}
                          for leaf in ('logs', 'backups', 'data')]]}, 'mongo': {}, 'redis': {}, 'caddy': {}}}
        preflight.backend_model(base, image)
        updater = copy.deepcopy(base)
        updater['services']['updater'] = {}
        with self.assertRaisesRegex(preflight.Refused, 'UNSAFE_COMPOSE_MODEL'):
            preflight.backend_model(updater, image)
        for change in (lambda b: b['volumes'][0].update(read_only=False),
                       lambda b: b['environment'].update(TOPOLOGY_TEST_EXECUTION_ENABLED='true'),
                       lambda b: b.update(restart='always'), lambda b: b.update(network_mode='host'),
                       lambda b: b['volumes'].append({'target': '/var/run/docker.sock'})):
            drift = copy.deepcopy(base)
            change(drift['services']['backend'])
            with self.assertRaisesRegex(preflight.Refused, 'UNSAFE_COMPOSE_MODEL'):
                preflight.backend_model(drift, image)

    def test_publication_is_exact_and_refuses_changed_preimage(self):
        rebind = load('rebind-boot')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'pin.json'
            path.write_bytes(b'old')
            path.chmod(0o600)
            rebind.replace_private(path, b'old', b'new', uid=os.getuid(), root=Path(tmp))
            self.assertEqual(path.read_bytes(), b'new')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(Exception):
                rebind.replace_private(path, b'old', b'next', uid=os.getuid(), root=Path(tmp))
            self.assertEqual(path.read_bytes(), b'new')
            self.assertEqual(list(Path(tmp).iterdir()), [path])

    def test_staged_rebind_uses_exact_pins_and_never_rebinds_selected_nodes(self):
        self.exercise_rebind()

    def test_interrupted_pair_publication_keeps_old_panel_pin_and_refuses_replay(self):
        self.exercise_rebind(interrupt=True)

    def exercise_rebind(self, interrupt=False):
        rb = load('rebind-boot')
        boot_old = '10000000-0000-4000-8000-000000000001'
        boot_new = '20000000-0000-4000-8000-000000000002'
        generation = '30000000-0000-4000-8000-000000000003'
        holder = '40000000-0000-4000-8000-000000000004'
        uid = os.getuid()
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as output:
            root = Path(tmp)
            config, state = root / 'cfg', root / 'state'
            cfg = {key: config / key for key in ('GUARD_POLICY', 'NODE_POLICY', 'PANEL_POLICY')}
            code = {key: root / key for key in ('CORE', 'GUARD', 'PHYSICAL', 'EFFECTS')}
            config.mkdir(mode=0o700)
            (state / 'guards').mkdir(parents=True, mode=0o700)
            state.chmod(0o700)

            def write(path, raw):
                path.write_bytes(raw)
                path.chmod(0o600)

            for key, path in code.items():
                write(path, key.encode())
            write(state / 'backend.launch.lock', b'')
            previous = config / 'previous-policy'
            challenge = {'serverContext': rb.PROD}
            physical = {'machineId': '1' * 32, 'sshHostKeySha256': '2' * 64, 'bootId': boot_old}
            fresh = {**physical, 'bootId': boot_new}
            old_guard = {'version': 2, 'generation': generation, 'holderId': holder, 'bootId': boot_old,
                         'challengeSha256': rb.digest(rb.canonical(challenge)), 'socket': '/old/socket',
                         'journal': '/old/journal', 'lock': '/old/lock',
                         'maskedWriters': [{'unit': 'legacy.service', 'cgroup': '/system.slice/legacy.service'}]}
            sources = [{'path': str(code[n]), 'sha256': rb.digest(code[n].read_bytes())} for n in ('CORE', 'GUARD')]
            old_peer = {'holderId': holder, 'lock': {'path': '/old/lock', 'device': 1, 'inode': 2}, 'pid': 101,
                        'startTicks': '3003', 'socket': '/old/socket', 'executableSha256': '3' * 64,
                        'argvSha256': '4' * 64, 'sources': sources}
            pin = {'kind': 'host', 'physical': physical, 'maintenanceId': generation,
                   'endpoint': {'ip': '192.0.2.1', 'port': 22, 'username': 'root'}}
            host = {**pin, 'version': 1, 'serverContext': rb.PROD, 'guards': [old_peer], 'guardChallenge': challenge,
                    'guardChallengeSha256': old_guard['challengeSha256'], 'oldBackend': {'sentinel': 'preserved'},
                    'codePins': {str(code[n]): rb.digest(code[n].read_bytes()) for n in ('CORE', 'PHYSICAL', 'EFFECTS')}}
            host_raw = rb.canonical(host)
            panel = {'version': 1, 'executionContext': rb.PROD, 'mode': 'runtime', 'admission': {'serverContext': rb.PROD},
                     'host': {**pin, 'policySha256': rb.digest(host_raw)},
                     'nodes': [{'kind': 'node', 'policySha256': '5' * 64, 'endpoint': {'ip': '192.0.2.2'},
                                'physical': {'machineId': '8' * 32, 'sshHostKeySha256': '9' * 64, 'bootId': boot_old},
                                'originalScope': {'sentinel': 'do not rebind this'}}]}
            panel_raw, guard_raw = rb.canonical(panel), rb.canonical(old_guard)
            for path, raw in ((cfg['NODE_POLICY'], host_raw), (cfg['PANEL_POLICY'], panel_raw),
                              (cfg['GUARD_POLICY'], guard_raw), (previous, guard_raw)):
                write(path, raw)
            a = SimpleNamespace(project='fixture', phase='guard', accept_boot=boot_new,
                                old_panel_sha=rb.digest(panel_raw), old_host_sha=rb.digest(host_raw),
                                old_guard_sha=rb.digest(guard_raw), previous_guard_policy=str(previous))
            candidate = rb.next_guard(old_guard, host, boot_new, state)
            peer = {**old_peer, 'holderId': candidate['holderId'], 'pid': 102, 'startTicks': '7009',
                    'socket': candidate['socket'], 'lock': {'path': candidate['lock'], 'device': 1, 'inode': 3}}
            new_host, new_panel = rb.next_policies(panel, host, candidate, peer, boot_new)
            mutations = []
            native_replace = rb.replace_private

            def replacing(path, before, after):
                if interrupt and path == cfg['PANEL_POLICY']:
                    raise OSError('power loss fixture')
                native_replace(path, before, after, uid=uid, root=root)
                mutations.append(path)

            def live(accepted):
                rb.need(accepted == boot_new, 'BOOT_APPROVAL_MISMATCH')
                return fresh

            cohost = copy.deepcopy(panel)
            cohost['nodes'][0]['physical']['machineId'] = physical['machineId']
            with self.assertRaisesRegex(rb.P['Refused'], 'COHOST_REBIND_UNSUPPORTED'):
                rb.validate_preimages(cohost, host, a.old_host_sha, fresh)
            with self.assertRaisesRegex(rb.P['Refused'], 'STALE_HOST_REBIND'):
                rb.validate_preimages(panel, host, a.old_host_sha, physical)
            with patch.dict(rb.P, {**cfg, **code, 'CONFIG': config, 'STATE': state,
                                  'main_pid': lambda _: 0, 'isolation': lambda *args: None,
                                  'docker_exclusion': lambda _: None, 'guard_pin': lambda _: peer}), \
                 patch.object(rb, 'trusted', lambda path, *_args, **kw: rb.P['trusted'](path, uid, root, **kw)), \
                 patch.object(rb, 'read_private', lambda p, *_args: rb.P['read_private'](p, uid, root)), \
                 patch.object(rb, 'read_current', live), patch.object(rb, 'replace_private', replacing), \
                 patch.object(rb.os, 'geteuid', return_value=0):
                a.accept_boot = boot_old
                with self.assertRaisesRegex(rb.P['Refused'], 'BOOT_APPROVAL_MISMATCH'):
                    rb.apply(a)
                a.accept_boot = boot_new
                rb.apply(a)
                self.assertEqual(mutations, [cfg['GUARD_POLICY']])
                self.assertEqual(cfg['PANEL_POLICY'].read_bytes(), panel_raw)
                self.assertEqual(rb.decode(cfg['GUARD_POLICY'].read_bytes()), candidate)
                a.phase = 'inspect'
                rb.apply(a)
                self.assertIn(rb.digest(new_host), output.getvalue())
                self.assertEqual(mutations, [cfg['GUARD_POLICY']])
                a.phase = 'publish'
                a.accept_host_sha = '0' * 64
                with self.assertRaisesRegex(rb.P['Refused'], 'NEW_HOST_POLICY_NOT_INDEPENDENTLY_ACCEPTED'):
                    rb.apply(a)
                self.assertEqual(mutations, [cfg['GUARD_POLICY']])
                a.accept_host_sha = rb.digest(new_host)
                if interrupt:
                    with self.assertRaisesRegex(OSError, 'power loss fixture'):
                        rb.apply(a)
                    self.assertEqual(cfg['NODE_POLICY'].read_bytes(), new_host)
                    self.assertEqual(cfg['PANEL_POLICY'].read_bytes(), panel_raw)
                    self.assertNotEqual(panel['host']['policySha256'], rb.digest(new_host))
                    with self.assertRaisesRegex(rb.P['Refused'], 'PREIMAGE_NOT_INDEPENDENTLY_ACCEPTED'):
                        rb.apply(a)
                else:
                    rb.apply(a)
                    self.assertEqual(cfg['PANEL_POLICY'].read_bytes(), new_panel)
                    self.assertEqual(json.loads(new_panel)['nodes'], panel['nodes'])
                    self.assertEqual(json.loads(new_host)['oldBackend'], host['oldBackend'])


if __name__ == '__main__':
    unittest.main()
