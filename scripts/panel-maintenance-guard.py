#!/usr/bin/env python3
"""Operator-invoked, precheck-only panel guard. No host mutation capability."""
import argparse
import copy
import fcntl
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

ALLOWLIST = {
    "hysteria-backend": "backend",
    "hysteria-updater": "updater",
    "hysteria-caddy": "caddy",
}
HEX = re.compile(r"[0-9a-f]{64}\Z")
DIGITS = re.compile(r"[0-9]+\Z")
BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
BLOCKERS = [
    "DOCKER_EXCLUSIVITY_UNPROVEN",
    "UPDATER_DAEMON_WORK_UNPROVEN",
    "REMOTE_WRITERS_UNFENCED",
    "REAL_ARM_AND_TERMINATE_NOT_IMPLEMENTED",
]
PIN_KEYS = ("name", "id", "image", "imageRef", "pid", "startTicks", "bootId",
            "cgroup", "startedAt", "restartCount", "service", "project")


class Refusal(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def load_json(path):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise Refusal("DUPLICATE_JSON_KEY")
            obj[key] = value
        return obj
    def invalid_constant(_):
        raise Refusal("INVALID_JSON")
    source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(source, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Refusal("REGULAR_JSON_FILE_REQUIRED")
        raw = stream.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise Refusal("INPUT_TOO_LARGE")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def pins(container):
    return {key: container[key] for key in PIN_KEYS}


def valid_pin(c):
    return (isinstance(c, dict) and all(k in c for k in PIN_KEYS)
            and isinstance(c["name"], str)
            and isinstance(c["id"], str) and HEX.fullmatch(c["id"])
            and isinstance(c["image"], str) and c["image"].startswith("sha256:")
            and HEX.fullmatch(c["image"][7:])
            and isinstance(c["imageRef"], str) and bool(c["imageRef"])
            and type(c["pid"]) is int and c["pid"] > 0
            and isinstance(c["startTicks"], str) and DIGITS.fullmatch(c["startTicks"])
            and isinstance(c["bootId"], str) and BOOT.fullmatch(c["bootId"])
            and isinstance(c["cgroup"], str)
            and c["cgroup"] == f'/system.slice/docker-{c["id"]}.scope'
            and isinstance(c["startedAt"], str) and bool(c["startedAt"])
            and type(c["restartCount"]) is int and c["restartCount"] >= 0
            and all(isinstance(c[k], str) for k in ("service", "project")))


def assess(snapshot, expected=None):
    findings = set()
    containers = snapshot.get("containers", []) if isinstance(snapshot, dict) else []
    if (not isinstance(snapshot, dict) or type(snapshot.get("schema")) is not int
            or snapshot["schema"] != 1 or not isinstance(containers, list)
            or snapshot.get("errors") != []):
        findings.add("UNKNOWN_CAPTURE")
    if not isinstance(containers, list):
        containers = []
    selected = {}
    for name, service in ALLOWLIST.items():
        rows = [c for c in containers if isinstance(c, dict) and c.get("name") == name]
        if len(rows) != 1:
            findings.add("MISSING_ALLOWLIST_MEMBER" if not rows else "DUPLICATE_ALLOWLIST_MEMBER")
            continue
        c = rows[0]
        selected[name] = c
        if not valid_pin(c) or c.get("service") != service or not c.get("project"):
            findings.add("INVALID_EXACT_IDENTITY")
        state = c.get("state", {})
        if (not isinstance(state, dict) or state.get("running") is not True
                or state.get("restarting") is not False or state.get("dead") is not False):
            findings.add("NOT_STABLE_RUNNING")
        if not isinstance(state, dict) or state.get("paused") is not False or c.get("frozen") != "0":
            findings.add("PREEXISTING_PAUSE_OR_UNKNOWN_FREEZE")
        if c.get("populated") != "1" or c.get("freezeRequested") != "0":
            findings.add("UNKNOWN_CGROUP_STATE")
        if (c.get("restartPolicy") not in ("no", "always", "unless-stopped", "on-failure")
                or type(c.get("restartMaximumRetryCount")) is not int or c["restartMaximumRetryCount"] < 0):
            findings.add("UNKNOWN_RESTART_POLICY")
        processes = c.get("processes")
        if (not isinstance(processes, list) or not processes
                or any(not isinstance(p, dict) or type(p.get("pid")) is not int
                       or not isinstance(p.get("startTicks"), str)
                       or not DIGITS.fullmatch(p["startTicks"]) or not isinstance(p.get("exe"), str)
                       or not p["exe"] for p in (processes if isinstance(processes, list) else []))):
            findings.add("UNKNOWN_PROCESS_TREE")
        elif not any(p["pid"] == c.get("pid") and p["startTicks"] == c.get("startTicks")
                     for p in processes):
            findings.add("PROCESS_IDENTITY_MISMATCH")
        elif service == "updater" and (len(processes) != 1 or processes[0]["exe"] != "node"):
            findings.add("UPDATER_IN_FLIGHT_OR_UNKNOWN")
    if len({c.get("bootId") for c in selected.values() if isinstance(c.get("bootId"), str)}) != 1:
        findings.add("HOST_BOOT_MISMATCH")
    if len({c.get("project") for c in selected.values() if isinstance(c.get("project"), str)}) != 1:
        findings.add("COMPOSE_PROJECT_MISMATCH")
    ids = [c.get("id") for c in containers if isinstance(c, dict) and isinstance(c.get("id"), str)]
    if len(ids) != len(set(ids)):
        findings.add("DUPLICATE_CONTAINER_ID")
    for c in containers:
        if not isinstance(c, dict):
            findings.add("UNKNOWN_INVENTORY")
            continue
        if isinstance(c.get("name"), str) and c["name"] in ALLOWLIST:
            continue
        if c.get("service") in ALLOWLIST.values() or any(
            c.get("image") == own.get("image") or c.get("imageRef") == own.get("imageRef")
            for own in selected.values()
        ):
            findings.add("ALTERNATE_REPLICA")
    if expected is None:
        findings.add("NO_INDEPENDENT_EXPECTED_CAPTURE")
    elif (not isinstance(expected, dict) or type(expected.get("schema")) is not int
          or expected["schema"] != 1 or expected.get("errors") != []
          or not isinstance(expected.get("containers"), list)):
        findings.add("INVALID_EXPECTED_CAPTURE")
    else:
        try:
            for name in ALLOWLIST:
                rows = [c for c in expected["containers"] if isinstance(c, dict) and c.get("name") == name]
                if len(rows) != 1 or not valid_pin(rows[0]):
                    findings.add("INVALID_EXPECTED_CAPTURE")
            # Include entire inventory: unrelated container creation is conservative drift too.
            before = sorted([pins(c) for c in expected["containers"]], key=lambda c: c["id"])
            after = sorted([pins(c) for c in containers], key=lambda c: c["id"])
            if before != after:
                findings.add("CAPTURE_IDENTITY_DRIFT")
        except (KeyError, TypeError):
            findings.add("INVALID_EXPECTED_CAPTURE")
    return {"mode": "precheck-only", "dispatchAuthorized": False, "nodeState": "unknown",
            "panelState": "observed-only", "holdRequired": True,
            "findings": sorted(findings), "blockers": list(BLOCKERS),
            "snapshotDigest": digest(snapshot)}


def docker_read(args):
    """Only two read-only Docker operations exist; force the local Unix socket."""
    if args != ["container", "ls", "--all", "--quiet", "--no-trunc"] and not (
        args[:2] == ["container", "inspect"] and 2 < len(args) <= 130
        and all(HEX.fullmatch(cid) for cid in args[2:])
    ):
        raise Refusal("NON_READ_ONLY_DOCKER_COMMAND")
    return subprocess.run(["docker", "--host", "unix:///var/run/docker.sock"] + args,
                          check=True, capture_output=True, text=True, timeout=10).stdout


def read_process(proc, pid, group):
    base = proc / str(pid)
    stat = (base / "stat").read_text()
    # /proc comm may contain spaces and parentheses. Field 22 follows final ')'.
    start = stat.rsplit(")", 1)[1].split()[19]
    membership = (base / "cgroup").read_text().strip()
    path = membership.removeprefix("0::")
    if (len(membership.splitlines()) != 1 or membership != "0::" + path
            or not (path == group or path.startswith(group + "/"))):
        raise Refusal("PROCESS_CGROUP_MISMATCH")
    return {"pid": pid, "startTicks": start, "exe": Path(base.joinpath("exe").readlink()).name}


def capture(docker=docker_read, proc=Path("/proc"), cgroup=Path("/sys/fs/cgroup")):
    """Two full observations, no Docker exec/top/HTTP request or cgroup write.

    Injectable read function and paths are library-only seams for disposable fakes.
    No CLI option can redirect the real-host command to SSH/a remote Docker host.
    """
    def observe():
        boot = (proc / "sys/kernel/random/boot_id").read_text().strip()
        ids = sorted(docker(["container", "ls", "--all", "--quiet", "--no-trunc"]).split())
        if not ids or len(ids) > 128 or len(set(ids)) != len(ids) or not all(HEX.fullmatch(i) for i in ids):
            raise Refusal("INVALID_OR_OVERSIZE_DOCKER_INVENTORY")
        rows = json.loads(docker(["container", "inspect"] + ids))
        if not isinstance(rows, list) or sorted(c["Id"] for c in rows) != ids:
            raise Refusal("DOCKER_INVENTORY_DRIFT")
        result = []
        for row in sorted(rows, key=lambda c: c["Id"]):
            state, config = row["State"], row["Config"]
            policy = row["HostConfig"]["RestartPolicy"]
            labels = config.get("Labels") or {}
            cid, pid = row["Id"], state["Pid"]
            name = row["Name"].removeprefix("/")
            group = f"/system.slice/docker-{cid}.scope"
            item = {"name": name, "id": cid, "image": row["Image"], "imageRef": config["Image"],
                    "pid": pid, "startTicks": None, "bootId": boot, "cgroup": group,
                    "startedAt": state["StartedAt"], "restartCount": row["RestartCount"],
                    "service": labels.get("com.docker.compose.service", ""),
                    "project": labels.get("com.docker.compose.project", ""),
                    "restartPolicy": policy["Name"], "restartMaximumRetryCount": policy["MaximumRetryCount"],
                    "state": {k.lower(): state[k] for k in ("Running", "Paused", "Restarting", "Dead")}}
            if name in ALLOWLIST:
                directory = cgroup / group.lstrip("/")
                events = dict(line.split() for line in (directory / "cgroup.events").read_text().splitlines())
                pids = set()
                # Include all descendant cgroups, not only the root's cgroup.procs.
                for procs in directory.rglob("cgroup.procs"):
                    pids.update(int(p) for p in procs.read_text().split())
                if len(pids) > 4096:
                    raise Refusal("OVERSIZE_PROCESS_TREE")
                processes = [read_process(proc, p, group) for p in sorted(pids)]
                root = read_process(proc, pid, group)
                item.update(startTicks=root["startTicks"], processes=processes,
                            frozen=events["frozen"], populated=events["populated"],
                            freezeRequested=(directory / "cgroup.freeze").read_text().strip())
            result.append(item)
        return {"schema": 1, "containers": result, "errors": [],
                "mode": "precheck-only", "dispatchAuthorized": False,
                "nodeState": "unknown", "holdRequired": True}
    try:
        first = observe()
        second = observe()
        if first != second:
            second["errors"].append("OBSERVATION_DRIFT")
        return second
    except (OSError, ValueError, KeyError, TypeError, IndexError, Refusal, subprocess.SubprocessError):
        # Never expose raw Docker inspect, config/env, command stderr, or file paths.
        return {"schema": 1, "containers": [], "errors": ["INCOMPLETE_LOCAL_CAPTURE"],
                "mode": "precheck-only", "dispatchAuthorized": False,
                "nodeState": "unknown", "holdRequired": True}


# These are *model transitions*, never Docker/cgroup operations.
STEPS = ("freeze-updater", "freeze-backend", "disable-restart-updater",
         "disable-restart-backend", "freeze-caddy", "disable-restart-caddy", "verify-frozen")


def simulate(original, count):
    model = copy.deepcopy(original)
    rows = {c["name"]: c for c in model["containers"]}
    for step in STEPS[:count]:
        if step == "verify-frozen":
            continue
        action, role = step.rsplit("-", 1)
        row = rows["hysteria-" + role]
        if action == "freeze":
            row["state"]["paused"] = True
            row["frozen"] = row["freezeRequested"] = "1"
        else:
            row["restartPolicy"] = "no"
            row["restartMaximumRetryCount"] = 0
    return model


@contextmanager
def ledger(directory, create=False):
    directory = Path(directory)
    if create:
        directory.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise Refusal("RECEIPT_DIRECTORY_NOT_PRIVATE")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal("CONCURRENT_RECEIPT_OWNER") from None
        yield fd
    finally:
        os.close(fd)


def read_receipt(fd):
    try:
        source = os.open("receipt.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return None
    with os.fdopen(source, "r") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise Refusal("UNSAFE_RECEIPT_FILE")
        raw = stream.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise Refusal("UNKNOWN_RECEIPT")
    envelope = json.loads(raw)
    receipt = envelope["receipt"]
    if (envelope["digest"] != digest(receipt) or type(receipt["schema"]) is not int or receipt["schema"] != 1
            or receipt["mode"] != "offline-drill-only"
            or receipt["dispatchAuthorized"] is not False or receipt["nodeState"] != "unknown"
            or receipt["holdRequired"] is not True
            or receipt["realHostEffects"] != [] or receipt["nodeMutation"] is not False
            or type(receipt["hold"]) is not bool
            or receipt["phase"] not in ("simulated-hold", "simulated-panel-frozen", "unknown",
                                        "aborted-before-node-mutation", "simulated-old-cgroup-empty")
            or not isinstance(receipt["owner"], str) or not BOOT.fullmatch(receipt["owner"])
            or type(receipt["step"]) is not int or not 0 <= receipt["step"] <= len(STEPS)
            or (receipt["hold"] is False and receipt["phase"] != "aborted-before-node-mutation")):
        raise Refusal("UNKNOWN_RECEIPT")
    return receipt


def save_receipt(fd, receipt):
    payload = canonical({"digest": digest(receipt), "receipt": receipt}) + "\n"
    if len(payload) > 4 * 1024 * 1024:
        raise Refusal("RECEIPT_TOO_LARGE")
    name = ".receipt-" + str(uuid.uuid4())
    target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    with os.fdopen(target, "w") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(name, "receipt.json", src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)
    if read_receipt(fd) != receipt:
        raise Refusal("RECEIPT_READBACK_FAILED")


def drill(action, directory, owner, snapshot=None, expected=None, acknowledgement=None):
    """Durable offline rehearsal only. No host-control adapter exists here."""
    if not isinstance(owner, str) or not BOOT.fullmatch(owner):
        raise Refusal("EXACT_OWNER_UUID_REQUIRED")
    with ledger(directory, create=action == "begin") as fd:
        receipt = read_receipt(fd)
        if action == "begin":
            if receipt is not None:
                raise Refusal("RECEIPT_ALREADY_EXISTS")
            result = assess(snapshot, expected)
            if result["findings"]:
                raise Refusal("PRECHECK_REFUSED")
            receipt = {"schema": 1, "mode": "offline-drill-only", "owner": owner,
                       "dispatchAuthorized": False, "nodeState": "unknown", "nodeMutation": False,
                       "holdRequired": True,
                       "realHostEffects": [], "hold": True, "phase": "simulated-hold",
                       "original": copy.deepcopy(snapshot), "simulated": copy.deepcopy(snapshot),
                       "snapshotDigest": digest(snapshot), "step": 0, "pending": None, "journal": []}
            save_receipt(fd, receipt)
            return receipt
        if receipt is None or receipt["owner"] != owner:
            raise Refusal("MISSING_OR_FOREIGN_OWNER")
        if action == "status":
            # A crash may leave a durable intent. Even status may never clear it.
            result = copy.deepcopy(receipt)
            if (result["pending"] is not None
                    or result["snapshotDigest"] != digest(result["original"])
                    or result["phase"] in ("simulated-hold", "simulated-panel-frozen")
                    and result["simulated"] != simulate(result["original"], result["step"])):
                result["phase"], result["hold"] = "unknown", True
            return result
        if not receipt["hold"] or receipt["pending"] is not None or receipt["phase"] == "unknown":
            raise Refusal("UNKNOWN_OR_CLOSED_HOLD")
        if receipt["phase"] == "simulated-old-cgroup-empty":
            raise Refusal("DESTRUCTIVE_PHASE_CANNOT_ROLL_BACK")
        count = receipt["step"]
        if (type(count) is not int or not 0 <= count <= len(STEPS)
                or receipt["snapshotDigest"] != digest(receipt["original"])
                or receipt["simulated"] != simulate(receipt["original"], count)):
            receipt.update(phase="unknown", hold=True)
            save_receipt(fd, receipt)
            raise Refusal("SIMULATED_IDENTITY_DRIFT")
        if action == "step":
            if count == len(STEPS):
                raise Refusal("SEPARATE_DESTRUCTIVE_PHASE_REQUIRED")
            intent = STEPS[count]
        elif action == "rollback":
            intent = "rollback-before-node-mutation"
        elif action == "terminate":
            if count != len(STEPS) or acknowledgement != "SIMULATED_DESTRUCTION_ONLY":
                raise Refusal("EXPLICIT_SIMULATED_DESTRUCTION_REQUIRED")
            intent = "terminate-exact-frozen-backend-cgroup"
        else:
            raise Refusal("UNSUPPORTED_DRILL_ACTION")
        receipt["pending"] = intent
        save_receipt(fd, receipt)  # Intent precedes any (simulated) effect.
        try:
            if action == "step":
                receipt["simulated"] = simulate(receipt["original"], count + 1)
                receipt["step"] = count + 1
                receipt["phase"] = "simulated-panel-frozen" if count + 1 == len(STEPS) else "simulated-hold"
            elif action == "rollback":
                # Final equality only; intermediate real-host rollback ordering is unimplemented.
                receipt["simulated"] = copy.deepcopy(receipt["original"])
                receipt.update(hold=False, phase="aborted-before-node-mutation")
            else:
                backend = next(c for c in receipt["simulated"]["containers"] if c["name"] == "hysteria-backend")
                receipt["terminatedIdentity"] = pins(backend)
                backend.update(pid=0, startTicks=None, processes=[], populated="0", frozen="0", freezeRequested="0")
                backend["state"].update(running=False, paused=False)
                receipt["phase"] = "simulated-old-cgroup-empty"
                # Empty fake local cgroup says nothing about real remote descendants.
            receipt["journal"].append(intent)
            receipt["pending"] = None
            save_receipt(fd, receipt)
        except BaseException:
            # SIGKILL cannot run this: the earlier intent still retains the hold.
            receipt.update(phase="unknown", hold=True, pending=intent)
            save_receipt(fd, receipt)
            raise
        return receipt


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    precheck = commands.add_parser("precheck", help="read-only; default command")
    precheck.add_argument("--snapshot", help="offline JSON; omitted means local read-only capture")
    precheck.add_argument("--expected", help="independently retained capture; never auto-adopted")
    commands.add_parser("capture", help="emit local read-only observation JSON, not authority")
    rehearsal = commands.add_parser("drill", help="offline JSON state machine; no host effects")
    rehearsal.add_argument("action", choices=("begin", "step", "status", "rollback", "terminate"))
    rehearsal.add_argument("--state-dir", required=True, type=Path, help="private local rehearsal receipt directory")
    rehearsal.add_argument("--owner", required=True, help="exact lower-case owner UUID")
    rehearsal.add_argument("--snapshot", help="required for begin; offline only")
    rehearsal.add_argument("--expected", help="required for begin; independently accepted snapshot")
    rehearsal.add_argument("--ack", help="SIMULATED_DESTRUCTION_ONLY; never enables real destruction")
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith("--") and argv[0] != "--help":
        argv.insert(0, "precheck")
    args = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if args.command == "capture":
            result = capture()
        elif args.command == "precheck":
            observation = load_json(args.snapshot) if args.snapshot else capture()
            result = assess(observation, load_json(args.expected) if args.expected else None)
        else:
            if args.action == "begin" and (not args.snapshot or not args.expected):
                raise Refusal("BOTH_OFFLINE_CAPTURES_REQUIRED")
            if args.action != "begin" and (args.snapshot or args.expected):
                raise Refusal("CAPTURES_ONLY_ALLOWED_FOR_BEGIN")
            if args.action != "terminate" and args.ack:
                raise Refusal("ACK_ONLY_ALLOWED_FOR_SIMULATED_TERMINATE")
            result = drill(args.action, args.state_dir, args.owner,
                           load_json(args.snapshot) if args.snapshot else None,
                           load_json(args.expected) if args.expected else None, args.ack)
        print(canonical(result))
        return 2  # Never a ready/authorization exit code, even for a successful drill.
    except (OSError, ValueError, TypeError, KeyError, IndexError, Refusal, KeyboardInterrupt) as error:
        code = str(error) if isinstance(error, Refusal) else "UNKNOWN_OR_UNREADABLE_STATE"
        print(canonical({"mode": "precheck-only", "error": code,
                         "dispatchAuthorized": False, "nodeState": "unknown", "holdRequired": True}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
