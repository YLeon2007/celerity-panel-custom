"""Local-only maintenance preflight/drill tests; no real Docker or cgroups."""
import copy
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "panel-maintenance-guard.py"


def load_guard():
    spec = importlib.util.spec_from_file_location("panel_guard", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot():
    rows = []
    boot = "95ea5402-65fb-45cc-a5fd-8c372249f2a9"
    for i, role in enumerate(("backend", "updater", "caddy"), 1):
        cid = str(i) * 64
        rows.append({
            "name": "hysteria-" + role, "id": cid, "image": "sha256:" + str(i + 3) * 64,
            "imageRef": "fake:" + role, "pid": 100 + i, "startTicks": str(1000 + i),
            "bootId": boot, "cgroup": f"/system.slice/docker-{cid}.scope",
            "startedAt": "2026-10-19T00:00:00Z", "restartCount": 0,
            "service": role, "project": "fixture", "restartPolicy": "always",
            "restartMaximumRetryCount": 0,
            "state": {"running": True, "paused": False, "restarting": False, "dead": False},
            "frozen": "0", "freezeRequested": "0", "populated": "1",
            "processes": [{"pid": 100 + i, "startTicks": str(1000 + i), "exe": "node"}],
        })
    return {"schema": 1, "containers": rows, "errors": []}


class CaptureTest(unittest.TestCase):
    def test_capture_uses_only_read_only_docker_and_fake_proc_cgroup(self):
        guard = load_guard()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            proc, cg = root / "proc", root / "cgroup"
            (proc / "sys/kernel/random").mkdir(parents=True)
            (proc / "sys/kernel/random/boot_id").write_text(snapshot()["containers"][0]["bootId"])
            docker_rows = []
            for c in snapshot()["containers"]:
                pid = proc / str(c["pid"])
                pid.mkdir()
                fields = ["S"] + ["0"] * 18 + [c["startTicks"]]
                (pid / "stat").write_text(f'{c["pid"]} (node with ) parens) ' + " ".join(fields))
                (pid / "cgroup").write_text("0::" + c["cgroup"] + "\n")
                (pid / "exe").symlink_to("/usr/local/bin/node")
                group = cg / c["cgroup"].lstrip("/")
                group.mkdir(parents=True)
                (group / "cgroup.procs").write_text(str(c["pid"]) + "\n")
                (group / "cgroup.events").write_text("populated 1\nfrozen 0\n")
                (group / "cgroup.freeze").write_text("0\n")
                docker_rows.append({"Id": c["id"], "Name": "/" + c["name"], "Image": c["image"],
                                    "Config": {"Image": c["imageRef"], "Env": ["SECRET=never-print"],
                                               "Labels": {"com.docker.compose.service": c["service"],
                                                          "com.docker.compose.project": c["project"]}},
                                    "State": {"Running": True, "Paused": False, "Restarting": False,
                                              "Dead": False, "Pid": c["pid"], "StartedAt": c["startedAt"]},
                                    "RestartCount": 0,
                                    "HostConfig": {"RestartPolicy": {"Name": "always", "MaximumRetryCount": 0}}})
            calls = []
            def fake_docker(args):
                calls.append(args)
                if args == ["container", "ls", "--all", "--quiet", "--no-trunc"]:
                    return "\n".join(c["Id"] for c in docker_rows)
                self.assertEqual(args, ["container", "inspect"] + sorted(c["Id"] for c in docker_rows))
                return json.dumps(docker_rows)
            result = guard.capture(fake_docker, proc, cg)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["containers"], snapshot()["containers"])
            self.assertNotIn("never-print", json.dumps(result))
            self.assertEqual(len(calls), 4)
            # A nested updater cgroup is part of the updater's in-flight tree.
            updater = snapshot()["containers"][1]
            child = cg / updater["cgroup"].lstrip("/") / "worker"
            child.mkdir()
            (child / "cgroup.procs").write_text("999\n")
            (proc / "999").mkdir()
            (proc / "999/stat").write_text("999 (docker) " + " ".join(["S"] + ["0"] * 18 + ["9999"]))
            (proc / "999/cgroup").write_text("0::" + updater["cgroup"] + "/worker\n")
            (proc / "999/exe").symlink_to("/usr/bin/docker")
            in_flight = guard.capture(fake_docker, proc, cg)
            self.assertIn("UPDATER_IN_FLIGHT_OR_UNKNOWN", guard.assess(in_flight, result)["findings"])
            (child / "cgroup.procs").write_text("")
            # Directly changing the fake freezer is visible, never adopted as ours.
            (cg / snapshot()["containers"][0]["cgroup"].lstrip("/") / "cgroup.events").write_text("populated 1\nfrozen 1\n")
            paused = guard.capture(fake_docker, proc, cg)
            self.assertIn("PREEXISTING_PAUSE_OR_UNKNOWN_FREEZE", guard.assess(paused, result)["findings"])
            (cg / snapshot()["containers"][0]["cgroup"].lstrip("/") / "cgroup.events").write_text("populated 1\nfrozen 0\n")
            inspect_calls = 0
            def drifting_docker(args):
                nonlocal inspect_calls
                raw = fake_docker(args)
                if args[:2] == ["container", "inspect"]:
                    inspect_calls += 1
                    if inspect_calls == 2:
                        rows = json.loads(raw)
                        rows[0]["State"]["StartedAt"] = "recreated-mid-observation"
                        return json.dumps(rows)
                return raw
            self.assertEqual(guard.capture(drifting_docker, proc, cg)["errors"], ["OBSERVATION_DRIFT"])
            (proc / "101/cgroup").write_text("0::/unrelated.scope\n")
            self.assertEqual(guard.capture(fake_docker, proc, cg)["errors"], ["INCOMPLETE_LOCAL_CAPTURE"])

    def test_docker_adapter_rejects_all_mutation_commands(self):
        guard = load_guard()
        with mock.patch.object(guard.subprocess, "run") as run:
            for command in (["pause", "hysteria-backend"], ["container", "kill", "1" * 64],
                            ["container", "inspect", "short-id"], ["compose", "up", "-d"],
                            ["update", "--restart=no", "1" * 64], ["exec", "1" * 64, "true"]):
                with self.subTest(command=command), self.assertRaises(guard.Refusal):
                    guard.docker_read(command)
            run.assert_not_called()
            run.return_value.stdout = "fixture"
            self.assertEqual(guard.docker_read(["container", "ls", "--all", "--quiet", "--no-trunc"]), "fixture")
            self.assertEqual(run.call_args.args[0][:3], ["docker", "--host", "unix:///var/run/docker.sock"])
            self.assertEqual(run.call_args.kwargs["timeout"], 10)


class DrillTest(unittest.TestCase):
    OWNER = "11111111-2222-3333-4444-555555555555"

    def test_offline_hold_freeze_and_rollback_restore_exact_snapshot(self):
        guard = load_guard()
        original = snapshot()
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory) / "drill"
            receipt = guard.drill("begin", state, self.OWNER, original, copy.deepcopy(original))
            self.assertTrue(receipt["hold"])
            self.assertEqual(receipt["mode"], "offline-drill-only")
            for _ in guard.STEPS:
                receipt = guard.drill("step", state, self.OWNER)
            self.assertEqual(receipt["phase"], "simulated-panel-frozen")
            self.assertEqual(receipt["nodeState"], "unknown")
            self.assertFalse(receipt["dispatchAuthorized"])
            self.assertTrue(all(c["frozen"] == "1" for c in receipt["simulated"]["containers"]))
            receipt = guard.drill("rollback", state, self.OWNER)
            self.assertEqual(receipt["simulated"], original)
            self.assertEqual(receipt["phase"], "aborted-before-node-mutation")
            self.assertFalse(receipt["hold"])
            self.assertEqual(guard.drill("status", state, self.OWNER), receipt)


    def test_missing_expected_or_drift_pause_and_updater_work_refuse_without_receipt(self):
        guard = load_guard()
        baseline = snapshot()
        self.assertIn("NO_INDEPENDENT_EXPECTED_CAPTURE", guard.assess(baseline)["findings"])
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(guard.Refusal):
            guard.drill("begin", pathlib.Path(directory) / "drill", self.OWNER, baseline, None)
        changes = [
            ("CAPTURE_IDENTITY_DRIFT", lambda s: s["containers"][0].update(id="a" * 64)),
            ("PREEXISTING_PAUSE_OR_UNKNOWN_FREEZE", lambda s: s["containers"][0]["state"].update(paused=True)),
            ("PREEXISTING_PAUSE_OR_UNKNOWN_FREEZE", lambda s: s["containers"][1].update(frozen="1")),
            ("UPDATER_IN_FLIGHT_OR_UNKNOWN", lambda s: s["containers"][1]["processes"].append(
                {"pid": 999, "startTicks": "99999", "exe": "docker"})),
            ("ALTERNATE_REPLICA", lambda s: s["containers"].append(dict(s["containers"][0], name="shadow-backend", id="b" * 64))),
            ("UNKNOWN_CAPTURE", lambda s: s["errors"].append("OBSERVATION_DRIFT")),
        ]
        for expected_code, mutate in changes:
            with self.subTest(expected_code=expected_code), tempfile.TemporaryDirectory() as directory:
                current = copy.deepcopy(baseline)
                mutate(current)
                self.assertIn(expected_code, guard.assess(current, baseline)["findings"])
                with self.assertRaises(guard.Refusal):
                    guard.drill("begin", pathlib.Path(directory) / "drill", self.OWNER, current, baseline)
                self.assertFalse((pathlib.Path(directory) / "drill/receipt.json").exists())

    def test_separate_destructive_phase_only_empties_fake_backend_and_keeps_hold(self):
        guard = load_guard()
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory) / "drill"
            fixture = snapshot()
            fixture["containers"][0]["processes"].append({"pid": 987, "startTicks": "9870", "exe": "ssh"})
            guard.drill("begin", state, self.OWNER, fixture, copy.deepcopy(fixture))
            with self.assertRaises(guard.Refusal):
                guard.drill("terminate", state, self.OWNER, acknowledgement="SIMULATED_DESTRUCTION_ONLY")
            for _ in guard.STEPS:
                guard.drill("step", state, self.OWNER)
            with self.assertRaises(guard.Refusal):
                guard.drill("terminate", state, self.OWNER)
            result = guard.drill("terminate", state, self.OWNER, acknowledgement="SIMULATED_DESTRUCTION_ONLY")
            self.assertEqual(result["phase"], "simulated-old-cgroup-empty")
            self.assertTrue(result["hold"])
            self.assertFalse(result["dispatchAuthorized"])
            self.assertEqual(result["nodeState"], "unknown")
            backend, updater, caddy = result["simulated"]["containers"]
            self.assertEqual(backend["processes"], [])
            self.assertEqual(backend["populated"], "0")
            self.assertEqual(result["terminatedIdentity"]["id"], snapshot()["containers"][0]["id"])
            self.assertEqual(updater["frozen"], "1")
            self.assertEqual(caddy["frozen"], "1")
            with self.assertRaises(guard.Refusal):
                guard.drill("rollback", state, self.OWNER)

    def test_foreign_owner_concurrent_owner_and_restart_preserve_receipt(self):
        guard = load_guard()
        other = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory) / "drill"
            first = guard.drill("begin", state, self.OWNER, snapshot(), snapshot())
            saved = (state / "receipt.json").read_bytes()
            with self.assertRaises(guard.Refusal):
                guard.drill("step", state, other)
            with self.assertRaises(guard.Refusal):
                guard.drill("begin", state, self.OWNER, snapshot(), snapshot())
            with guard.ledger(state):
                with self.assertRaises(guard.Refusal):
                    guard.drill("step", state, self.OWNER)
            self.assertEqual((state / "receipt.json").read_bytes(), saved)
            self.assertEqual(load_guard().drill("status", state, self.OWNER), first)

    def test_interrupted_simulation_keeps_unknown_hold_and_refuses_rollback(self):
        guard = load_guard()
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory) / "drill"
            guard.drill("begin", state, self.OWNER, snapshot(), snapshot())
            actual = guard.simulate
            # Count zero is the read-only identity check; interrupt after durable step intent.
            def interrupt(original, count):
                if count == 1:
                    raise KeyboardInterrupt
                return actual(original, count)
            with mock.patch.object(guard, "simulate", side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt):
                    guard.drill("step", state, self.OWNER)
            result = load_guard().drill("status", state, self.OWNER)
            self.assertEqual(result["phase"], "unknown")
            self.assertEqual(result["pending"], "freeze-updater")
            self.assertTrue(result["hold"])
            with self.assertRaises(guard.Refusal):
                guard.drill("rollback", state, self.OWNER)

    def test_real_signal_to_isolated_drill_process_retains_durable_intent(self):
        import signal
        guard = load_guard()
        harness = '''
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("guard", sys.argv[1])
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
actual = g.simulate
def interrupted_model(original, count):
    if count == 1:
        os.kill(os.getpid(), int(sys.argv[4]))
    return actual(original, count)
g.simulate = interrupted_model
sys.exit(g.main(["drill", "step", "--state-dir", sys.argv[2], "--owner", sys.argv[3]]))
'''
        for sig in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signal=sig), tempfile.TemporaryDirectory() as directory:
                state = pathlib.Path(directory) / "drill"
                guard.drill("begin", state, self.OWNER, snapshot(), snapshot())
                child = subprocess.run([sys.executable, "-c", harness, str(SCRIPT), str(state), self.OWNER, str(sig)],
                                       capture_output=True, text=True, timeout=5)
                self.assertEqual(child.returncode, 2 if sig == signal.SIGTERM else -signal.SIGKILL, child.stderr)
                result = guard.drill("status", state, self.OWNER)
                self.assertEqual(result["phase"], "unknown")
                self.assertTrue(result["hold"])
                self.assertEqual(result["pending"], "freeze-updater")
                with self.assertRaises(guard.Refusal):
                    guard.drill("rollback", state, self.OWNER)

    def test_rollback_at_every_known_partial_step(self):
        guard = load_guard()
        for count in range(len(guard.STEPS) + 1):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                state = pathlib.Path(directory) / "drill"
                guard.drill("begin", state, self.OWNER, snapshot(), snapshot())
                for _ in range(count):
                    guard.drill("step", state, self.OWNER)
                result = guard.drill("rollback", state, self.OWNER)
                self.assertEqual(result["simulated"], snapshot())
                self.assertFalse(result["nodeMutation"])
                self.assertFalse(result["hold"])

    def test_corrupt_receipt_and_symlinks_never_enable_recovery(self):
        guard = load_guard()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            state = root / "drill"
            guard.drill("begin", state, self.OWNER, snapshot(), snapshot())
            receipt = state / "receipt.json"
            saved = receipt.read_text()
            envelope = json.loads(saved)
            envelope["receipt"]["hold"] = False
            receipt.write_text(json.dumps(envelope))
            with self.assertRaises(guard.Refusal):
                guard.drill("status", state, self.OWNER)
            receipt.write_text(saved)
            alias = root / "alias"
            alias.symlink_to(state, target_is_directory=True)
            with self.assertRaises(OSError):
                guard.drill("status", alias, self.OWNER)
            receipt.unlink()
            victim = root / "victim.json"
            victim.write_text(saved)
            receipt.symlink_to(victim)
            with self.assertRaises(OSError):
                guard.drill("status", state, self.OWNER)
            self.assertEqual(victim.read_text(), saved)

    def test_nonregular_json_inputs_and_receipts_refuse_without_blocking(self):
        guard = load_guard()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fifo = root / "input.fifo"
            os.mkfifo(fifo)
            with self.assertRaises(guard.Refusal):
                guard.load_json(fifo)
            state = root / "drill"
            guard.drill("begin", state, self.OWNER, snapshot(), snapshot())
            (state / "receipt.json").unlink()
            os.mkfifo(state / "receipt.json")
            with self.assertRaises(guard.Refusal):
                guard.drill("status", state, self.OWNER)

    def test_failed_rollback_publication_keeps_unknown_hold(self):
        guard = load_guard()
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory) / "drill"
            guard.drill("begin", state, self.OWNER, snapshot(), snapshot())
            guard.drill("step", state, self.OWNER)
            actual_save = guard.save_receipt
            def failed_publication(fd, receipt):
                if receipt["phase"] == "aborted-before-node-mutation":
                    raise OSError("simulated disk failure")
                return actual_save(fd, receipt)
            with mock.patch.object(guard, "save_receipt", side_effect=failed_publication):
                with self.assertRaises(OSError):
                    guard.drill("rollback", state, self.OWNER)
            result = guard.drill("status", state, self.OWNER)
            self.assertEqual(result["phase"], "unknown")
            self.assertTrue(result["hold"])
            self.assertEqual(result["pending"], "rollback-before-node-mutation")
            self.assertFalse(result["dispatchAuthorized"])

    def test_model_identity_drift_retains_hold(self):
        guard = load_guard()
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory) / "drill"
            result = guard.drill("begin", state, self.OWNER, snapshot(), snapshot())
            result["simulated"]["containers"][0]["id"] = "a" * 64
            with guard.ledger(state) as fd:
                guard.save_receipt(fd, result)
            observed = guard.drill("status", state, self.OWNER)
            self.assertEqual(observed["phase"], "unknown")
            self.assertTrue(observed["hold"])
            with self.assertRaises(guard.Refusal):
                guard.drill("step", state, self.OWNER)
            result = guard.drill("status", state, self.OWNER)
            self.assertEqual(result["phase"], "unknown")
            self.assertTrue(result["hold"])


class CliTest(unittest.TestCase):
    def test_default_command_does_not_create_or_change_any_receipt(self):
        guard = load_guard()
        output = io.StringIO()
        with mock.patch.object(guard, "capture", return_value=snapshot()) as capture, \
                mock.patch.object(guard, "drill") as drill, mock.patch.object(guard, "save_receipt") as save, \
                mock.patch("sys.stdout", output), mock.patch.object(guard.signal, "signal"):
            self.assertEqual(guard.main([]), 2)
            capture.assert_called_once_with()
            drill.assert_not_called()
            save.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["mode"], "precheck-only")

    def test_offline_drill_cli_has_no_docker_or_other_command_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "fixture.json"
            source.write_text(json.dumps(snapshot()))
            env = dict(os.environ, PATH="", PYTHONDONTWRITEBYTECODE="1")
            common = ["--state-dir", str(root / "receipt"), "--owner", DrillTest.OWNER]
            def run(action, extra=()):
                command = [sys.executable, str(SCRIPT), "drill", action] + common + list(extra)
                child = subprocess.run(command, capture_output=True, text=True, env=env, timeout=5)
                self.assertEqual(child.returncode, 2, child.stderr)
                result = json.loads(child.stdout)
                self.assertEqual(result["mode"], "offline-drill-only", result)
                self.assertFalse(result["dispatchAuthorized"])
                self.assertEqual(result["nodeState"], "unknown")
                return result
            run("begin", ["--snapshot", str(source), "--expected", str(source)])
            for _ in load_guard().STEPS:
                run("step")
            self.assertEqual(run("status")["phase"], "simulated-panel-frozen")
            self.assertFalse(run("rollback")["hold"])
            self.assertTrue(run("status")["holdRequired"])

    def test_malformed_input_is_redacted_unknown_and_never_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "bad.json"
            for raw in ('{"schema":1,"schema":2,"password":"DO_NOT_ECHO_ME"}',
                        '{"schema":1,"containers":"DO_NOT_ECHO_ME"}',
                        'null', '{"schema":NaN}', 'DO_NOT_ECHO_ME'):
                with self.subTest(raw=raw):
                    source.write_text(raw)
                    child = subprocess.run([sys.executable, str(SCRIPT), "--snapshot", str(source)],
                                           capture_output=True, text=True, timeout=5)
                    self.assertEqual(child.returncode, 2)
                    result = json.loads(child.stdout)
                    self.assertFalse(result["dispatchAuthorized"])
                    self.assertEqual(result["nodeState"], "unknown")
                    self.assertTrue(result["holdRequired"])
                    self.assertNotIn("DO_NOT_ECHO_ME", child.stdout + child.stderr)

    def test_offline_cli_always_exits_nonready_without_external_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "capture.json"
            source.write_text(json.dumps(snapshot()))
            completed = subprocess.run([sys.executable, str(SCRIPT), "precheck", "--snapshot", str(source),
                                        "--expected", str(source)], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 2, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertFalse(result["dispatchAuthorized"])
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["nodeState"], "unknown")


class GuardTest(unittest.TestCase):
    def test_every_exact_pin_drift_is_refused_without_normalization(self):
        guard = load_guard()
        baseline = snapshot()
        changes = {"id": "a" * 64, "image": "sha256:" + "a" * 64, "pid": 999,
                   "startTicks": "999", "bootId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                   "cgroup": "/unexpected.scope", "startedAt": "different-start", "restartCount": 1}
        for key, value in changes.items():
            with self.subTest(key=key):
                current = snapshot()
                current["containers"][0][key] = value
                self.assertIn("CAPTURE_IDENTITY_DRIFT", guard.assess(current, baseline)["findings"])
        for key, value in (("id", "a" * 63), ("image", "sha256:not-a-digest"),
                           ("pid", True), ("startTicks", "١٢٣"), ("bootId", [baseline["containers"][0]["bootId"]])):
            with self.subTest(malformed=key):
                current = snapshot()
                current["containers"][0][key] = value
                self.assertIn("INVALID_EXACT_IDENTITY", guard.assess(current, baseline)["findings"])
        invalid_expected = snapshot()
        invalid_expected["schema"] = "1"
        self.assertIn("INVALID_EXPECTED_CAPTURE", guard.assess(snapshot(), invalid_expected)["findings"])
        malformed_pin = snapshot()
        malformed_pin["containers"][0]["restartCount"] = False  # Python False == 0 must not enroll it.
        self.assertIn("INVALID_EXPECTED_CAPTURE", guard.assess(snapshot(), malformed_pin)["findings"])

    def test_default_cli_is_read_only_and_never_authorizes(self):
        guard = load_guard()
        result = guard.assess({"schema": 1, "containers": [], "errors": []})
        self.assertFalse(result["dispatchAuthorized"])
        self.assertEqual(result["nodeState"], "unknown")
        self.assertEqual(result["mode"], "precheck-only")
        self.assertIn("MISSING_ALLOWLIST_MEMBER", result["findings"])
        self.assertIn("DOCKER_EXCLUSIVITY_UNPROVEN", result["blockers"])


if __name__ == "__main__":
    unittest.main()
