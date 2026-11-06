"""Current fixed-loader closure, distinct from immutable historical pack proof.

Real descriptor walks/hash/compile, files, pidfds, AF_UNIX and finite children.
Only root ownership, installed-root rebasing and host/kernel/Docker facts are
modeled. No acceptance pin is rebound; no privileged network operation runs.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
FROZEN_REVISION = 'f82426071dd1d505f4293b036efa1659abbe586a'
FROZEN_PINS = {
    'fresh_network.py': '6c6c5e3b528f12e5c2d578922c50fa2982906c1e97389948ecff7d55c4cb08ec',
    'fresh_network_control.py': 'ced8d6264424f65f5f9d6f5c9b1f9de731953d196026e513ed6e3f13a0cd88ac',
    'fresh_network_exec.py': '5fdb07e09177ce1b616d8506d325089e48e50560fee9a03757e4bc0850760167',
    'fresh_network_client.py': '847c123f9700044e4d83637cb051ff331ea0502a919b28f4e95aa9d9b54cb520',
    'fresh_network_client_exec.py': 'c3cecc3f64cb945b898717d87d7ae149911047c58bbe15f1dfda32582421df81',
}
INSTALLED = {
    name: '/usr/local/libexec/c3-test-'+name.replace('_', '-')
    for name in FROZEN_PINS
}


def load(name):
    spec = importlib.util.spec_from_file_location(name+'_entry_test', HERE/(name+'.py'))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def frozen_bytes(name):
    """Read original Git blobs, never replace a current acceptance global."""
    raw = subprocess.check_output([
        '/usr/bin/git', '-C', str(REPO), 'show',
        FROZEN_REVISION+':scripts/test-node-isolation/'+name], timeout=5)
    if hashlib.sha256(raw).hexdigest() != FROZEN_PINS[name]:
        raise AssertionError('FROZEN_ORIGINAL_BLOB_DRIFT:'+name)
    return raw


def frozen_module(name):
    import types
    module = types.ModuleType('historical_'+name)
    exec(compile(frozen_bytes(name+'.py'), '<frozen-original:'+name+'>', 'exec'), module.__dict__)
    return module


legacy = load('test_fresh_network_client')


class RootStat:
    st_uid = st_gid = 0
    def __init__(self, original): self.original = original
    def __getattr__(self, name): return getattr(self.original, name)
    def __eq__(self, other):
        return isinstance(other, RootStat) and self.original == other.original


@contextmanager
def installed_walk(entry, root):
    """Only root path/ownership modeled; actual unchanged loader does all IO."""
    real_open, real_fstat = os.open, os.fstat
    def open_source(path, *args, **kwargs):
        return real_open(root if path == '/' else path, *args, **kwargs)
    with patch.object(entry.os, 'open', side_effect=open_source), \
         patch.object(entry.os, 'fstat', side_effect=lambda fd: RootStat(real_fstat(fd))):
        yield


def populate(root, historical=False):
    for name, installed in INSTALLED.items():
        path = root/installed.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(frozen_bytes(name) if historical else (HERE/name).read_bytes())
        path.chmod(0o750)
    for path in (root, root/'usr', root/'usr/local', root/'usr/local/libexec'):
        path.chmod(0o755)


def fixture_server(root):
    """Real server main/load -> real control.run -> modeled Linux effects."""
    root = Path(root)
    entry = load('fresh_network_exec')
    real_load = entry.load
    def checked_load(path):
        with installed_walk(entry, root/'installed'):
            module = real_load(path)
        if path == INSTALLED['fresh_network.py']:
            legacy.m = module
        else:
            legacy.control = module
            real_run = module.run
            def run(network):
                if network is not legacy.m: raise AssertionError('CHECKED_NETWORK_REQUIRED')
                # The unchanged fixture calls the original real control.run.
                module.run = real_run
                legacy.fixture_server(root)
            module.run = run
        return module
    with patch.object(entry, 'load', side_effect=checked_load), \
         patch.object(entry.os, 'getuid', return_value=0), \
         patch.object(entry.os, 'geteuid', return_value=0), \
         patch.object(entry.sys, 'argv', [INSTALLED['fresh_network_exec.py']]):
        code = entry.main()
    raise SystemExit(code)


class FixedServerHarness(legacy.Harness):
    def __enter__(self):
        super().__enter__()
        # Current B132 policy, still synthetic boot/netns and modeled host facts.
        self.p['machine'] = '03ab697936cc4040aa9357936e136744'
        self.raw = legacy.m.encode(self.p)
        (self.root/'plan').write_bytes(self.raw)
        return self

    def server(self):
        self.child = subprocess.Popen([
            sys.executable, '-I', '-B', str(Path(__file__)), '--server', str(self.root)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return self.child


class FixedEntryTests(unittest.TestCase):
    def test_current_server_loader_accepts_exact_network_and_control(self):
        entry = load('fresh_network_exec')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); populate(root)
            with installed_walk(entry, root):
                network = entry.load(INSTALLED['fresh_network.py'])
                control = entry.load(INSTALLED['fresh_network_control.py'])
            self.assertEqual(network.B132_MACHINE, '03ab697936cc4040aa9357936e136744')
            self.assertTrue(callable(control.run))
            self.assertEqual(entry.PINS, {INSTALLED[name]: hashlib.sha256((HERE/name).read_bytes()).hexdigest()
                                         for name in ('fresh_network.py', 'fresh_network_control.py')})

    def holder_inputs(self, root):
        entry = load('fresh_network_client_exec')
        with installed_walk(entry, root):
            network, control, client = [entry.load(INSTALLED[name]) for name in
                ('fresh_network.py', 'fresh_network_control.py', 'fresh_network_client.py')]
        network.INPUT = str(root/'plan')
        p = legacy.existing.plan()
        p['machine'] = '03ab697936cc4040aa9357936e136744'
        (root/'plan').write_bytes(network.encode(p))
        real_open = os.open
        network.trusted_fd = lambda path, directory=False: real_open(
            root/path.lstrip('/') if path.startswith('/usr/local/libexec/') else path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if directory else 0))
        self.assertEqual(client.__source_sha256__, hashlib.sha256((HERE/'fresh_network_client.py').read_bytes()).hexdigest())
        return network, control, client

    def test_current_client_loader_injects_self_pin_and_reaches_real_holder_host_boundary(self):
        class HostBoundary(RuntimeError): pass
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); populate(root)
            network, control, client = self.holder_inputs(root)
            with patch.object(client, '_host', side_effect=HostBoundary('ACTUAL_HOLDER_HOST_BOUNDARY')) as host:
                with self.assertRaisesRegex(HostBoundary, '^ACTUAL_HOLDER_HOST_BOUNDARY$'):
                    client.Holder(network, control)
            host.assert_called_once()
            self.assertEqual(host.call_args.args[1]['machine'], network.B132_MACHINE)

    def test_loader_wrong_missing_changed_sources_refuse_before_execution(self):
        for entry_name in ('fresh_network_exec', 'fresh_network_client_exec'):
            for name in ('fresh_network.py', 'fresh_network_control.py', *(
                    ('fresh_network_client.py',) if entry_name.endswith('client_exec') else ())):
                for fault in ('wrong', 'missing', 'changed'):
                    with self.subTest(entry=entry_name, source=name, fault=fault), tempfile.TemporaryDirectory() as d:
                        root = Path(d); populate(root); entry = load(entry_name)
                        target = root/INSTALLED[name].lstrip('/')
                        if fault == 'missing': target.unlink()
                        elif fault == 'wrong': target.write_bytes(b'raise AssertionError("MUST_NOT_EXECUTE")\n')
                        else: target.write_bytes(target.read_bytes()+b'\nraise AssertionError("MUST_NOT_EXECUTE")\n')
                        with installed_walk(entry, root):
                            if fault == 'missing':
                                with self.assertRaises(FileNotFoundError): entry.load(INSTALLED[name])
                            else:
                                with self.assertRaisesRegex(RuntimeError, '^INSTALLED_SOURCE_PIN_REQUIRED$'):
                                    entry.load(INSTALLED[name])

    def test_holder_wrong_missing_changed_all_four_inputs_refuse_before_host_or_socket(self):
        for name in ('fresh_network.py', 'fresh_network_control.py', 'fresh_network_exec.py', 'fresh_network_client.py'):
            for fault in ('wrong', 'missing', 'changed'):
                with self.subTest(source=name, fault=fault), tempfile.TemporaryDirectory() as d:
                    root = Path(d); populate(root)
                    network, control, client = self.holder_inputs(root)
                    target = root/INSTALLED[name].lstrip('/')
                    if fault == 'missing': target.unlink()
                    elif fault == 'wrong': target.write_bytes(b'wrong fixed input\n')
                    else: target.write_bytes(target.read_bytes()+b'\n# source drift\n')
                    with patch.object(client, '_host') as host, patch.object(client.socket, 'socket') as channel:
                        if fault == 'missing':
                            with self.assertRaises(FileNotFoundError): client.Holder(network, control)
                        else:
                            with self.assertRaisesRegex(network.Refusal, '^INSTALLED_SOURCE_PIN_REQUIRED$'):
                                client.Holder(network, control)
                        host.assert_not_called(); channel.assert_not_called()

    def test_server_and_client_main_reject_bad_inputs_before_control_or_holder_host(self):
        for entry_name, names in (
            ('fresh_network_exec', ('fresh_network.py', 'fresh_network_control.py')),
            ('fresh_network_client_exec', ('fresh_network.py', 'fresh_network_control.py', 'fresh_network_client.py'))):
            for name in names:
                for fault in ('missing', 'changed'):
                    with self.subTest(entry=entry_name, source=name, fault=fault), tempfile.TemporaryDirectory() as d:
                        root = Path(d); populate(root); entry = load(entry_name)
                        target = root/INSTALLED[name].lstrip('/')
                        if fault == 'missing': target.unlink()
                        else: target.write_bytes(target.read_bytes()+b'\n# drift\n')
                        # A successful input load is still real, but dispatch must never run.
                        real_load = entry.load; dispatched = []
                        def checked(path):
                            module = real_load(path)
                            if path != INSTALLED['fresh_network.py']:
                                module.run = lambda *args: dispatched.append(path)
                            return module
                        with installed_walk(entry, root), patch.object(entry, 'load', side_effect=checked), \
                             patch.object(entry.os, 'getuid', return_value=0), \
                             patch.object(entry.os, 'geteuid', return_value=0), \
                             patch.object(entry.os, 'getresuid', return_value=(0, 0, 0)), \
                             patch.object(entry.os, 'getresgid', return_value=(0, 0, 0)), \
                             patch.object(entry.sys, 'argv', [INSTALLED[entry_name+'.py']]):
                            self.assertEqual(entry.main(), 1)
                        self.assertEqual(dispatched, [])

    def test_historical_original_loaders_accept_only_their_original_tuple(self):
        for entry_name in ('fresh_network_exec', 'fresh_network_client_exec'):
            with self.subTest(entry=entry_name), tempfile.TemporaryDirectory() as d:
                root = Path(d); populate(root, historical=True); entry = frozen_module(entry_name)
                for installed in entry.PINS:
                    with installed_walk(entry, root): module = entry.load(installed)
                    self.assertIsNotNone(module)
                target = root/INSTALLED['fresh_network.py'].lstrip('/')
                target.write_bytes((HERE/'fresh_network.py').read_bytes())
                with installed_walk(entry, root):
                    with self.assertRaisesRegex(RuntimeError, '^INSTALLED_SOURCE_PIN_REQUIRED$'):
                        entry.load(INSTALLED['fresh_network.py'])

    def test_immutable_producers_keep_current_source_refusals_not_silent_repins(self):
        revision = subprocess.check_output(['/usr/bin/git', '-C', str(REPO), 'rev-parse', 'HEAD'],
                                           text=True, timeout=5).strip()
        source = 'scripts/test-node-isolation/fresh_network.py'
        product = load('fresh_install_source_pack')
        self.assertEqual(product.NETWORK_SOURCE_PINS[source], FROZEN_PINS['fresh_network.py'])
        fd = product.open_directory(str(REPO))
        try:
            with self.assertRaisesRegex(product.Refusal, '^NETWORK_SOURCE_DRIFT$'):
                product.source_bytes(str(REPO), fd, revision, source)
        finally: os.close(fd)
        for name in ('fresh_install_source_pack_9e_v1', 'fresh_install_source_pack_b7_v1',
                     'fresh_install_source_pack_runner_v2_v1', 'fresh_install_source_pack_runner_v2_v2'):
            with self.subTest(producer=name):
                product = load(name)
                self.assertEqual(product.NETWORK_SOURCE_PINS[source], FROZEN_PINS['fresh_network.py'])
                fd = product.open_directory(str(REPO))
                try:
                    with self.assertRaisesRegex(product.Refusal, '^FIXED_SOURCE_REQUIRED$'):
                        product.source_bytes(str(REPO), fd, revision, source)
                finally: os.close(fd)

    def test_fixed_both_loaders_real_lifecycle_observe_cutover_return_abandon(self):
        with patch.object(legacy, 'Harness', FixedServerHarness):
            legacy.ClientTests.test_h4_distinct_child_rendezvous_cutover_not_terminal_and_zero_authority_writes(self)

    def test_fixed_both_loaders_partial_operator_line_is_finite_nonrenewable(self):
        with patch.object(legacy, 'Harness', FixedServerHarness):
            legacy.ClientTests.test_h4_partial_operator_line_has_finite_nonrenewable_bound(self)

    def test_fixed_both_loaders_idle_heartbeat_preserves_original_deadline(self):
        with patch.object(legacy, 'Harness', FixedServerHarness):
            legacy.ClientTests.test_h4_real_idle_heartbeat_keeps_original_absolute_deadline(self)

    def test_fixed_both_loaders_operator_eof_invalid_and_cutover_eof_retain(self):
        with patch.object(legacy, 'Harness', FixedServerHarness):
            legacy.ClientTests.test_h4_operator_eof_invalid_verb_and_cutover_eof_never_cleanup(self)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--server': fixture_server(sys.argv[2])
    else: unittest.main()
