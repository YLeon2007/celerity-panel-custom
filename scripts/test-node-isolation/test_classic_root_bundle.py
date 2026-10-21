"""RED->GREEN fault tests for the offline classic root candidate producer.

Everything runs inside a disposable fixture workspace under the Hermes scratch
directory; no live host paths, no network, no installation. The lock-exact
node_modules and the pinned Node executable are read-only evidence inputs.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent
MODULE_PATH = HERE / "classic_root_bundle.py"
SCRATCH = pathlib.Path("/home/leon/.hermes/cache/scratch")
LOCK_SOURCE = SCRATCH / "c3-lock-exact-20261021/source"
NODE = "/home/leon/.hermes/node/bin/node"
FIXTURE_COMMIT = "675ac7d014d0b1bb4a982943293b6feddfe8d66f"

spec = importlib.util.spec_from_file_location("classic_root_bundle", MODULE_PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


class Fixture:
    def __init__(self, test):
        self.test = test
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="c3-crb-test-", dir=str(SCRATCH)))

    def path(self, *parts):
        return self.base.joinpath(*parts)

    def write(self, rel, raw, mode=None):
        target = self.path(rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(raw, str):
            raw = raw.encode()
        target.write_bytes(raw)
        if mode is not None:
            os.chmod(target, mode)
        return target

    def write_default(self, rel, raw, mode=None):
        """Write a default input only when the test has not supplied one."""
        target = self.path(rel)
        if target.exists():
            return target
        return self.write(rel, raw, mode=mode)

    def json(self, rel, data, mode=None):
        return self.write(rel, json.dumps(data, sort_keys=True), mode=mode)

    def build_args(self, output, **overrides):
        args = {
            "source_allowlist": str(self.write_default("inputs/source-allowlist.json",
                json.dumps({"repo": str(HERE.parents[1]), "commit": FIXTURE_COMMIT,
                            "files": ["/app/index.js"]}, sort_keys=True))),
            "node_modules": str(self.path("inputs/node_modules")),
            "package_lock": str(self.write_default("inputs/package-lock.json",
                json.dumps({"packages": {
                    "": {"version": "1.0.0", "integrity": "sha512-dGVzdA=="},
                    "node_modules/dep-a": {"version": "1.2.3", "integrity": "sha512-ZGVwLTQ=="},
                }}, sort_keys=True))),
            "snapshot_index": str(self.path("inputs/snapshot.json")),
            "elf_allowlist": str(self.write_default("inputs/elf-allowlist.json", "{}")),
            "node_executable": str(self.write_default("inputs/node", b"\x7fELF fake node fixture")),
            "node_digest": None,
            "settings": str(self.write_default("inputs/classic.json",
                json.dumps(self.settings(), sort_keys=True), mode=0o600)),
            "output": str(output),
        }
        if args["node_digest"] is None:
            args["node_digest"] = sha256(self.path("inputs/node"))
        args.update(overrides)
        return type("Args", (), args)()

    @staticmethod
    def settings():
        flags = ['L2TP_EXECUTION_ENABLED', 'L2TP_MIGRATIONS_ENABLED',
                 'TOPOLOGY_TEST_EXECUTION_ENABLED', 'TOPOLOGY_PRODUCTION_EXECUTION_ENABLED',
                 'L2TP_PRODUCTION_EXECUTION_ENABLED']
        return {"version": 1, "context": "test.infograd.online", "stateDirectory": "/state",
                "listenAddress": "212.119.42.100", "environment": {
                    "PANEL_DOMAIN": "test.infograd.online", "ACME_EMAIL": "local@example.invalid",
                    "ENCRYPTION_KEY": "e"*32, "SESSION_SECRET": "s"*32,
                    "MONGO_URI": "mongodb://127.0.0.1/classic_local",
                    "REDIS_URL": "redis://127.0.0.1", "USE_CADDY": "true", "PORT": "3000",
                    **{flag: 'false' for flag in flags}}}

    def dependency_tree(self):
        nm = self.path("inputs/node_modules")
        (nm / "dep-a" / "bin").mkdir(parents=True)
        self.write("inputs/node_modules/dep-a/package.json",
                   json.dumps({"name": "dep-a", "version": "1.2.3"}))
        self.write("inputs/node_modules/dep-a/lib.js", "module.exports = 1;\n")
        self.write("inputs/node_modules/dep-a/bin/tool", "#!/bin/sh\necho ok\n")
        index = {}
        for base, _dirs, files in os.walk(nm):
            for name in files:
                src = pathlib.Path(base) / name
                rel = "/app/node_modules/" + src.relative_to(nm).as_posix()
                index[rel] = {"sha256": sha256(src), "size": src.lstat().st_size}
        self.json("inputs/snapshot.json", index)
        return nm

    def expect_refusal(self, code, **overrides):
        output = self.path("out/candidate")
        args = self.build_args(output, **overrides)
        with self.test.assertRaises(m.Refusal) as ctx:
            m.build(args)
        self.test.assertEqual(str(ctx.exception), code)
        leftovers = [p for p in self.base.glob("out/candidate.partial-*")]
        self.test.assertEqual(leftovers, [], "partial staging must be cleaned")
        return output


class BuildHappyPathTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture(self)
        self.fx.dependency_tree()

    def tearDown(self):
        shutil.rmtree(self.fx.base, ignore_errors=True)

    def test_happy_path_materializes_manifest_report_and_private_image(self):
        output = self.fx.path("out/candidate")
        manifest_path = m.build(self.fx.build_args(output))
        self.assertEqual(manifest_path, output / "manifest.json")
        info = output.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
        manifest = json.loads(manifest_path.read_bytes())
        self.assertEqual(list(manifest), sorted(manifest))
        self.assertIn("/runtime/node", manifest)
        self.assertIn("/app/index.js", manifest)
        self.assertIn("/etc/classic.json", manifest)
        self.assertIn("/app/node_modules/dep-a/lib.js", manifest)
        self.assertNotIn(m.POLICY_PATH, manifest)
        self.assertTrue(all(len(pin) == 64 for pin in manifest.values()))
        for root_path, pin in manifest.items():
            if root_path == "/etc/classic.json":
                expected_mode = 0o644  # settings stay readable inside the private image
            else:
                expected_mode = 0o755 if root_path == '/runtime/node' else 0o644
            disk = output / "root" / root_path.lstrip("/")
            self.assertEqual(sha256(disk), pin, root_path)
            self.assertEqual(stat.S_IMODE(disk.stat().st_mode), expected_mode, root_path)
        settings_bytes = (output / "root/etc/classic.json").read_bytes()
        self.assertEqual(json.loads(settings_bytes)["stateDirectory"], "/state")
        report = json.loads((output / "report.json").read_bytes())
        self.assertTrue(report["candidate"])
        self.assertFalse(report["physicalAccepted"])
        self.assertFalse(report["acceptance"]["physicalAccepted"])
        self.assertEqual(report["settingsMode"], "TEST")
        self.assertEqual(report["ingress"], {"ip": "212.119.42.100", "port": 3000})
        self.assertEqual(report["statePath"], "/state")
        self.assertTrue(report["policyManifestExcluded"])
        self.assertEqual(report["settingsMetadata"]["environment"]["SESSION_SECRET"],
                         {"type": "str"})
        for base, dirs, _ in os.walk(output/'root'):
            self.assertEqual(stat.S_IMODE(pathlib.Path(base).stat().st_mode), 0o755)
        report_text = (output / "report.json").read_text()
        self.assertNotIn("TEST-MODE-ONLY", report_text)

    def test_materialized_link_file_points_inside_dependency_root(self):
        nm = self.fx.path("inputs/node_modules")
        os.symlink("tool", nm / "dep-a" / "bin" / "alias")
        index = json.loads(self.fx.path("inputs/snapshot.json").read_bytes())
        alias_payload = (nm / "dep-a/bin/tool").read_bytes()
        index["/app/node_modules/dep-a/bin/alias"] = {
            "sha256": hashlib.sha256(alias_payload).hexdigest(), "size": len(alias_payload)}
        self.fx.json("inputs/snapshot.json", index)
        output = self.fx.path("out/candidate")
        m.build(self.fx.build_args(output))
        link_file = output / "root/app/node_modules/dep-a/bin/alias"
        self.assertEqual(link_file.read_bytes(), alias_payload)

    def test_lock_exact_real_tree_versions_match_real_lock(self):
        packages, lock_roots = m.lock_package_entries(str(LOCK_SOURCE / "package-lock.json"))
        self.assertEqual(sha256(LOCK_SOURCE/'package-lock.json'),
            '5298202cf6ca2ce8da44f0578bd54c1146def29fd698c41bc62ac3b5982e6eac')
        self.assertEqual(len(lock_roots)-1,409)
        self.assertEqual(m.verify_lock_versions(str(LOCK_SOURCE / "node_modules"), packages, lock_roots),399)
        self.assertEqual(sum(m.platform_optional_absent(packages[k],'linux','x64') for k in lock_roots if k),10)

    def test_actual_settings_reader_accepts_producer_settings(self):
        settings = self.fx.json("settings-reader.json", self.fx.settings(), mode=0o600)
        m.load_settings(settings)
        source = HERE.parents[1] / 'src/classicSettings.js'
        result = subprocess.run([NODE, '-e', "require(process.argv[1]); console.log('accepted')", str(source)],
                                env={'C3_SETTINGS': str(settings)}, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, 'actual settings reader must accept fixture')
        self.assertEqual(result.stdout.strip(), b'accepted')

    def test_real_node_binary_happy_path(self):
        output = self.fx.path("out/candidate")
        args = self.fx.build_args(output,
                                  node_executable=NODE, node_digest=sha256(NODE))
        manifest = json.loads(m.build(args).read_bytes())
        self.assertEqual(manifest["/runtime/node"], sha256(NODE))

    def test_main_cli_prints_manifest_path(self):
        output = self.fx.path("out/candidate")
        self.fx.build_args(output)  # materialize default input fixtures
        argv = ["--source-allowlist", str(self.fx.path("inputs/source-allowlist.json")),
                "--node-modules", str(self.fx.path("inputs/node_modules")),
                "--package-lock", str(self.fx.path("inputs/package-lock.json")),
                "--snapshot-index", str(self.fx.path("inputs/snapshot.json")),
                "--elf-allowlist", str(self.fx.path("inputs/elf-allowlist.json")),
                "--node-executable", str(self.fx.path("inputs/node")),
                "--node-digest", sha256(self.fx.path("inputs/node")),
                "--settings", str(self.fx.path("inputs/classic.json")),
                "--output", str(output)]
        result = subprocess.run([sys.executable, "-B", "-I", str(MODULE_PATH), *argv],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(str(output / "manifest.json"), result.stdout.decode())


class DependencyClosureTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture(self); self.fx.dependency_tree()
    def tearDown(self):
        shutil.rmtree(self.fx.base, ignore_errors=True)

    def test_empty_file_and_directory_link_materialize_exact_bytes(self):
        nm = self.fx.path('inputs/node_modules')
        (nm/'dep-a/bin/empty').write_bytes(b'')
        (nm/'dep-a/alias-dir').symlink_to('bin', target_is_directory=True)
        index = {}
        for rel in ['dep-a/package.json', 'dep-a/lib.js', 'dep-a/bin/tool', 'dep-a/bin/empty',
                    'dep-a/alias-dir/tool', 'dep-a/alias-dir/empty']:
            src = nm/rel
            index['/app/node_modules/'+rel] = {'sha256':sha256(src), 'size':src.stat().st_size}
        self.fx.json('inputs/snapshot.json', index)
        output = self.fx.path('out/candidate')
        manifest = json.loads(m.build(self.fx.build_args(output)).read_bytes())
        self.assertEqual(set(k for k in manifest if k.startswith(m.DEP_ROOT+'/')), set(index))
        self.assertEqual((output/'root/app/node_modules/dep-a/alias-dir/empty').read_bytes(), b'')
        self.assertFalse((output/'root/app/node_modules/dep-a/alias-dir').is_symlink())

    def test_extra_snapshot_entry_refused(self):
        index = json.loads(self.fx.path('inputs/snapshot.json').read_bytes())
        index['/app/node_modules/ghost'] = {'sha256':'0'*64, 'size':1}
        self.fx.json('inputs/snapshot.json', index)
        self.fx.expect_refusal('SNAPSHOT_INDEX_UNEXPECTED')

    def test_directory_cycle_refused(self):
        (self.fx.path('inputs/node_modules/dep-a/back')).symlink_to('..', target_is_directory=True)
        self.fx.expect_refusal('DEPENDENCY_DIRECTORY_CYCLE')

    def test_change_while_copying_refuses_or_preserves_pinned_bytes(self):
        src = self.fx.path('inputs/node_modules/dep-a/lib.js')
        original = m.read_beneath
        hits = []
        def mutated(root, relative):
            result = original(root, relative)
            if pathlib.Path(root)/relative == src:
                hits.append(True); src.write_bytes(b'changed-after-pinned-read')
            return result
        output = self.fx.path('out/candidate')
        with patch.object(m, 'read_beneath', side_effect=mutated):
            with self.assertRaisesRegex(m.Refusal, '^DEPENDENCY_TREE_DRIFT$'):
                m.build(self.fx.build_args(output))
        self.assertEqual(hits, [True], 'mutation must actually reach dependency read')
        self.assertFalse(output.exists())


class MissingInputFaultTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture(self)
        self.fx.dependency_tree()

    def tearDown(self):
        shutil.rmtree(self.fx.base, ignore_errors=True)

    def test_missing_settings_file_refuses(self):
        self.fx.expect_refusal("INVALID_SETTINGS_FILE",
                               settings=str(self.fx.path("inputs/absent.json")))

    def test_missing_node_executable_refuses(self):
        self.fx.expect_refusal("NODE_EXECUTABLE_MISSING",
                               node_executable=str(self.fx.path("inputs/absent-node")))

    def test_missing_elf_input_refuses(self):
        self.fx.json("inputs/elf-allowlist.json",
                     {"/runtime/lib/ld.so": {"source": "/nonexistent/ld.so",
                      "sha256": "0" * 64}})
        self.fx.expect_refusal("ELF_INPUT_MISSING")
    def test_malformed_package_lock_refuses(self):
        self.fx.expect_refusal("INVALID_PACKAGE_LOCK",
                               package_lock=str(self.fx.path("inputs/missing-lock.json")))

    def test_missing_snapshot_entry_refuses(self):
        index = json.loads(self.fx.path("inputs/snapshot.json").read_bytes())
        del index["/app/node_modules/dep-a/lib.js"]
        self.fx.json("inputs/snapshot.json", index)
        self.fx.expect_refusal("SNAPSHOT_INDEX_MISSING")


class SourceAndDependencyDriftFaultTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture(self)
        self.fx.dependency_tree()

    def tearDown(self):
        shutil.rmtree(self.fx.base, ignore_errors=True)

    def test_source_not_committed_refuses(self):
        allowlist = {"repo": str(HERE.parents[1]), "commit": FIXTURE_COMMIT,
                     "files": ["/app/definitely-not-committed.js"]}
        self.fx.expect_refusal("SOURCE_NOT_COMMITTED",
                               source_allowlist=self.fx.json("inputs/source-allowlist.json", allowlist))

    def test_gitlink_source_entry_refuses(self):
        allowlist = {"repo": str(HERE.parents[1]), "commit": FIXTURE_COMMIT,
                     "files": ["/app/cc-agent"]}
        self.fx.expect_refusal("SOURCE_MUST_BE_COMMITTED_REGULAR_FILE",
                               source_allowlist=self.fx.json("inputs/source-allowlist.json", allowlist))

    def test_untracked_source_copy_refuses(self):
        allowlist = {"repo": str(HERE.parents[1]), "commit": FIXTURE_COMMIT,
                     "files": ["/app/../.env"]}
        self.fx.expect_refusal("INVALID_SOURCE_ALLOWLIST_FILES",
                               source_allowlist=self.fx.json("inputs/source-allowlist.json", allowlist))

    def test_installed_version_drift_refuses(self):
        self.fx.write("inputs/node_modules/dep-a/package.json",
                      json.dumps({"name": "dep-a", "version": "9.9.9"}))
        self.fx.expect_refusal("INSTALLED_VERSION_DRIFT:node_modules/dep-a")

    def test_dependency_integrity_drift_refuses(self):
        self.fx.write("inputs/node_modules/dep-a/lib.js", "tampered();\n")
        self.fx.expect_refusal("DEPENDENCY_INTEGRITY_DRIFT")

    def test_unexpected_installed_package_refuses(self):
        extra = self.fx.write('inputs/node_modules/not-in-lock/package.json', json.dumps({'version':'1.0.0'}))
        index = json.loads(self.fx.path('inputs/snapshot.json').read_bytes())
        index['/app/node_modules/not-in-lock/package.json'] = {'sha256':sha256(extra),'size':extra.stat().st_size}
        self.fx.json('inputs/snapshot.json', index)
        self.fx.expect_refusal('UNEXPECTED_INSTALLED_PACKAGE')

    def test_node_digest_drift_refuses(self):
        self.fx.expect_refusal("NODE_EXECUTABLE_DIGEST_DRIFT", node_digest="0" * 64)

    def test_elf_digest_drift_refuses(self):
        ld = self.fx.write("inputs/ld.so", b"\x7fELF fake loader")
        self.fx.json("inputs/elf-allowlist.json",
                     {"/runtime/lib/ld-linux.so": {"source": str(ld),
                      "sha256": "1" * 64}})
        self.fx.expect_refusal("ELF_INPUT_DIGEST_DRIFT")


class LinkFaultTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture(self)

    def tearDown(self):
        shutil.rmtree(self.fx.base, ignore_errors=True)

    def test_escaping_dependency_link_refuses(self):
        nm = self.fx.dependency_tree()
        os.symlink("/etc/passwd", nm / "dep-a" / "bin" / "alias")
        self.fx.expect_refusal("DEPENDENCY_LINK_ESCAPES_ROOT")

    def test_link_cannot_escape_and_reenter_selected_root(self):
        nm = self.fx.dependency_tree()
        outside = self.fx.path('outside-alias')
        outside.symlink_to(nm/'dep-a/lib.js')
        (nm/'dep-a/bin/alias').symlink_to(outside)
        index = json.loads(self.fx.path('inputs/snapshot.json').read_bytes())
        source = nm/'dep-a/lib.js'
        index['/app/node_modules/dep-a/bin/alias'] = {'sha256':sha256(source),'size':source.stat().st_size}
        self.fx.json('inputs/snapshot.json',index)
        self.fx.expect_refusal('DEPENDENCY_LINK_ESCAPES_ROOT')

    def test_dangling_dependency_link_refuses(self):
        nm = self.fx.dependency_tree()
        os.symlink("../missing-target", nm / "dep-a" / "bin" / "alias")
        self.fx.expect_refusal("DEPENDENCY_LINK_DANGLING")

    def test_cyclic_dependency_link_refuses(self):
        nm = self.fx.dependency_tree()
        os.symlink("loop-b", nm / "dep-a" / "loop-a")
        os.symlink("loop-a", nm / "dep-a" / "loop-b")
        self.fx.expect_refusal("DEPENDENCY_LINK_DANGLING")


class SettingsFaultTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture(self)
        self.fx.dependency_tree()

    def tearDown(self):
        shutil.rmtree(self.fx.base, ignore_errors=True)

    def test_consumer_incompatible_settings_encodings_refuse_before_publication(self):
        source = HERE.parents[1] / 'src/classicSettings.js'
        text = json.dumps(self.fx.settings(), ensure_ascii=False, sort_keys=True)
        plain = self.fx.write('inputs/plain-utf8.json', text.encode('utf-8'), mode=0o600)
        self.assertEqual(m.settings_bytes(plain)[0], text.encode('utf-8'))
        def consumer(file):
            return subprocess.run([NODE, '-e', 'require(process.argv[1])', str(source)],
                env={'C3_SETTINGS': str(file)}, capture_output=True, timeout=10).returncode
        self.assertEqual(consumer(plain), 0, 'actual consumer positive control')
        for encoding in ('utf-8-sig', 'utf-16', 'utf-32', 'utf-16-le', 'utf-16-be'):
            with self.subTest(encoding=encoding):
                file = self.fx.write('inputs/settings-'+encoding+'.json', text.encode(encoding), mode=0o600)
                self.assertNotEqual(consumer(file), 0, 'actual consumer rejects incompatible bytes')
                output = self.fx.path('out/candidate-'+encoding)
                with self.assertRaisesRegex(m.Refusal, '^INVALID_SETTINGS_FILE$'):
                    m.build(self.fx.build_args(output, settings=str(file)))
                self.assertFalse(output.exists())
                self.assertEqual(list(output.parent.glob(output.name+'.partial-*')), [])

    def test_unknown_settings_key_refuses(self):
        settings = self.fx.settings()
        settings['environment']['PASSWORD'] = 'never-print-this-value'
        self.fx.expect_refusal("INVALID_SETTINGS_SCHEMA",
                               settings=str(self.fx.json("inputs/classic-secret.json", settings, mode=0o600)))

    def test_non_test_mode_refuses(self):
        settings = self.fx.settings()
        settings["context"] = "production.invalid"
        self.fx.expect_refusal("SETTINGS_MODE_MUST_BE_TEST",
                               settings=str(self.fx.json("inputs/classic-settings_mode_must_be_test.json", settings, mode=0o600)))

    def test_true_flag_refuses(self):
        settings = self.fx.settings()
        settings["environment"]["L2TP_EXECUTION_ENABLED"] = "true"
        self.fx.expect_refusal("SETTINGS_FLAGS_MUST_BE_FALSE",
                               settings=str(self.fx.json("inputs/classic-settings_flags_must_be_false.json", settings, mode=0o600)))

    def test_wrong_state_path_refuses(self):
        settings = self.fx.settings()
        settings["stateDirectory"] = "/var/lib/state"
        self.fx.expect_refusal("SETTINGS_STATE_PATH_FIXED",
                               settings=str(self.fx.json("inputs/classic-settings_state_path_fixed.json", settings, mode=0o600)))

    def test_wrong_ingress_refuses(self):
        settings = self.fx.settings()
        settings["environment"]["PORT"] = "8080"
        self.fx.expect_refusal("SETTINGS_INGRESS_FIXED",
                               settings=str(self.fx.json("inputs/classic-settings_ingress_fixed.json", settings, mode=0o600)))

    def test_report_and_errors_never_leak_settings_values(self):
        settings = self.fx.settings()
        sentinel = "c3-fixture-sentinel-value-7391"
        settings["environment"]["SESSION_SECRET"] = sentinel + 'x'*32
        settings_path = self.fx.json("inputs/classic-leak.json", settings, mode=0o600)
        output = self.fx.path("out/candidate")
        args = self.fx.build_args(output, settings=str(settings_path))
        try:
            m.build(args)
        except m.Refusal as error:
            raise AssertionError("build must not refuse clean fixture settings: %s" % error)
        report_text = (output / "report.json").read_text()
        self.assertNotIn(sentinel, report_text)


class RuntimeAndPublicationTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture(self); self.fx.dependency_tree()
    def tearDown(self):
        shutil.rmtree(self.fx.base, ignore_errors=True)

    def test_late_report_failure_publishes_nothing_and_redacts_oserror(self):
        output = self.fx.path('out/candidate')
        original = json.dump
        def fail_report(obj, stream, **kwargs):
            if 'report.json' in stream.name: raise OSError('mongodb://private-secret@local/db')
            return original(obj, stream, **kwargs)
        with patch.object(m.json, 'dump', side_effect=fail_report):
            with self.assertRaises(m.Refusal) as ctx: m.build(self.fx.build_args(output))
        self.assertNotIn('private-secret', str(ctx.exception))
        self.assertFalse(output.exists())
        self.assertEqual(list(output.parent.glob('*.partial-*')), [])

    def test_racing_empty_output_is_not_overwritten(self):
        output = self.fx.path('out/candidate')
        real_dump = json.dump
        raced = []
        def race(obj, stream, **kwargs):
            result = real_dump(obj, stream, **kwargs)
            if 'report.json' in stream.name:
                output.mkdir(); raced.append(output.stat().st_ino)
            return result
        with patch.object(m.json, 'dump', side_effect=race):
            with self.assertRaises(m.Refusal): m.build(self.fx.build_args(output))
        self.assertEqual(output.stat().st_ino, raced[0])
        self.assertEqual(list(output.iterdir()), [])

    def test_real_runtime_and_committed_supervisor_closure(self):
        repo = str(HERE.parents[1])
        commit = subprocess.check_output(['git','-C',repo,'rev-parse','HEAD']).decode().strip()
        targets = {'/usr/local/libexec/c3-test-coordinated-restore.py':'coordinated_restore.py',
                   '/usr/local/libexec/c3-test-fresh-classic.py':'fresh_classic_launch.py',
                   '/usr/local/libexec/c3-test-fresh-prepare.py':'prepare_fresh_supervisor.py'}
        pins = {target:sha256(HERE/name) for target,name in targets.items()}
        allow = self.fx.json('inputs/source-allowlist.json', {'repo':repo,'commit':commit,
              'files':['/app/index.js', *targets], 'pins':pins})
        output = self.fx.path('out/candidate')
        args = self.fx.build_args(output, source_allowlist=str(allow),
            runtime_inputs='/home/leon/celerity-prod-release-20261019/active-enable-20261021/runtime-inputs/actual-runtime-inputs.json',
            node_executable=NODE, node_digest=sha256(NODE))
        manifest = json.loads(m.build(args).read_bytes())
        self.assertIn('/lib64/ld-linux-x86-64.so.2', manifest)
        self.assertIn('/usr/bin/python3', manifest)
        for target,pin in pins.items(): self.assertEqual(manifest[target],pin)
        sys.path.insert(0,str(HERE))
        import fresh_classic_launch as consumer
        consumer.verify_files({'files':manifest}, lambda name: output/'root'/name.lstrip('/'))
        self.assertEqual(stat.S_IMODE((output/'root/runtime/node').stat().st_mode),0o755)
        self.assertFalse(json.loads((output/'report.json').read_bytes())['physicalAccepted'])

    def test_final_payload_corruption_is_rejected_before_publication(self):
        output = self.fx.path('out/candidate')
        original = json.dump
        def corrupt(obj, stream, **kwargs):
            result = original(obj, stream, **kwargs)
            if 'report.json' in stream.name:
                (pathlib.Path(stream.name).parent/'root/app/index.js').write_bytes(b'corrupt')
            return result
        with patch.object(m.json, 'dump', side_effect=corrupt):
            with self.assertRaisesRegex(m.Refusal, '^FINAL_IMAGE_MANIFEST_DRIFT$'):
                m.build(self.fx.build_args(output))
        self.assertFalse(output.exists())

    def test_copied_manifest_version_must_match_lock_after_copy(self):
        package = self.fx.path('inputs/node_modules/dep-a/package.json')
        original = m.materialize_dependencies
        def corrupt_versions(*args):
            package.write_text(json.dumps({'name':'dep-a','version':'9.9.9'}))
            snapshot = dict(args[1]); snapshot['/app/node_modules/dep-a/package.json'] = {
                'sha256':sha256(package),'size':package.stat().st_size}
            return original(args[0],snapshot,args[2])
        with patch.object(m, 'materialize_dependencies', side_effect=corrupt_versions):
            self.fx.expect_refusal('INSTALLED_VERSION_DRIFT:node_modules/dep-a')

    def test_source_environment_and_logs_are_forbidden(self):
        for name in ['/app/.env', '/app/logs/combined.log', '/app/.git/config']:
            allow = self.fx.json('inputs/source-allowlist.json', {'repo':str(HERE.parents[1]),
                 'commit':FIXTURE_COMMIT, 'files':['/app/index.js',name]})
            with self.assertRaises(m.Refusal): m.load_source_allowlist(allow)


class OutputSafetyFaultTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture(self)
        self.fx.dependency_tree()

    def tearDown(self):
        shutil.rmtree(self.fx.base, ignore_errors=True)

    def test_existing_output_fails_closed(self):
        output = self.fx.path("out/candidate")
        output.mkdir(parents=True)
        self.fx.expect_refusal("OUTPUT_EXISTS_FAIL_CLOSED")

    def test_partial_failure_never_leaves_output_or_staging(self):
        self.fx.json("inputs/elf-allowlist.json",
                     {"/runtime/lib/ld.so": {"source": "/nonexistent/ld.so",
                      "sha256": "0" * 64}})
        self.fx.expect_refusal("ELF_INPUT_MISSING")

    def test_refusal_message_contains_no_input_path_or_value(self):
        settings = self.fx.settings()
        settings["environment"]["L2TP_EXECUTION_ENABLED"] = "true"
        settings_path = self.fx.json("inputs/classic-leak.json", settings, mode=0o600)
        args = self.fx.build_args(self.fx.path("out/candidate"), settings=str(settings_path))
        with self.assertRaises(m.Refusal) as ctx:
            m.build(args)
        message = str(ctx.exception)
        self.assertNotIn(str(settings_path), message)
        self.assertNotIn("classic.json", message)


if __name__ == "__main__":
    unittest.main()
