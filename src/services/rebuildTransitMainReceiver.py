"""Packaged held MAIN writer; invoked only by the authenticated SSH bootstrap.

The panel owns durable intent, per-frame authority and artifact authentication.
The host keeps the original DIRECT flock and validates its local stock writer
scope. Neither is an exclusion claim against independently acting root.
"""
import math
import os
from pathlib import Path
import re
import time

from rebuildTransitDirectReceipt import direct_main_wire
from rebuildTransitMainHost import _trusted_file, create_main_session, verify_manager_scope
from rebuildTransitMainRuntime import (
    MAX_INBOUNDS, MAX_ROUTES, MainRuntimeObserver, RouteCheck, _PackagedProof,
    _alive, _bounded_read, _exec_identity,
)
from rebuildTransitMainSession import AUTHORITY, HostMainFlock
from rebuildTransitMainWindow import (
    INVOCATION, PID, TAG, WindowError, _file_generation, _file_metadata, managed_inbounds, parse_json, require,
)
from rebuildTransitMainWire import HostMainWire

LIFETIME = 30 * 60
_MACHINE = Path('/etc/machine-id')
_BOOT = Path('/proc/sys/kernel/random/boot_id')
_AGENT = Path('/usr/local/bin/cc-agent')
_AGENT_CONFIG = Path('/etc/cc-agent/config.json')


def _hex(value, size):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % size, value) is not None


def _bootstrap(bootstrap, direct):
    require(type(bootstrap) is dict and bootstrap.keys() == {'machineId', 'managed', 'direct', 'routes'}, AUTHORITY)
    machine = bootstrap['machineId']
    tags = bootstrap['managed']
    grant = bootstrap['direct']
    routes = bootstrap['routes']
    require(machine is None or _hex(machine, 32), AUTHORITY)
    require(type(tags) is list and 0 < len(tags) <= MAX_INBOUNDS
            and all(type(tag) is str and TAG.fullmatch(tag) for tag in tags) and len(set(tags)) == len(tags), AUTHORITY)
    require((direct is None) == (grant is None), AUTHORITY)
    if grant is not None:
        require(machine is not None and type(grant) is dict and grant.keys() == {'backupId', 'nodeId', 'network'}
                and _hex(grant['backupId'], 32) and _hex(grant['nodeId'], 24) and type(grant['network']) is dict, AUTHORITY)
        grant = dict(backup_id=grant['backupId'], node_id=grant['nodeId'], network=direct.routing(dict(grant['network'])))
    require(type(routes) is list and 0 < len(routes) <= MAX_ROUTES, AUTHORITY)
    checks = []
    fields = {'inboundTag', 'network', 'targetPort', 'outboundTag'}
    for route in routes:
        require(type(route) is dict and fields <= route.keys() <= fields | {'targetDomain', 'targetIP'}
                and bool(route.keys() & {'targetDomain', 'targetIP'}) and type(route['inboundTag']) is str
                and route['inboundTag'] in tags and route['network'] in ('tcp', 'udp')
                and type(route['targetPort']) is int and 0 < route['targetPort'] <= 65535
                and type(route['outboundTag']) is str and TAG.fullmatch(route['outboundTag'])
                and all(type(route[key]) is str for key in route.keys() - fields), AUTHORITY)
        checks.append(RouteCheck(route['inboundTag'], route['network'], route['targetPort'], route['outboundTag'],
                                 route.get('targetDomain'), route.get('targetIP')))
    require(len({(r.inbound_tag, r.network, r.target_port, r.target_domain, r.target_ip) for r in checks})
            == len(checks), AUTHORITY)
    return machine, frozenset(tags), grant, tuple(checks)


def _machine():
    raw, _ = _trusted_file(_MACHINE, 33)
    machine = raw.removesuffix(b'\n').decode('ascii')
    require(_hex(machine, 32) and machine != '0' * 32, AUTHORITY)
    return machine


def _boot():
    boot = _bounded_read(_BOOT, 37)
    require(re.fullmatch(rb'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\n', boot), AUTHORITY)
    return boot


class _Authority:
    def __init__(self, flock, deadline, machine, managed):
        self.flock, self.deadline = flock, deadline
        self.expected_machine, self.managed = machine, managed
        self.pin = None

    def _live(self):
        require(os.geteuid() == 0 and time.monotonic() < self.deadline, AUTHORITY)
        self.flock.check()

    def check(self):
        self._live()
        try:
            machine = _machine() if self.expected_machine is not None else None
            require(machine == self.expected_machine, AUTHORITY)
            config, config_pin = _trusted_file(_AGENT_CONFIG, 65536)
            observed = machine, _boot(), config_pin, _exec_identity(_AGENT, True)
            if self.pin is None:
                cfg = parse_json(config)
                require(managed_inbounds(cfg) == self.managed and cfg.get('xray_api', '127.0.0.1:61000') == '127.0.0.1:61000'
                        and all(key.casefold() not in ('xray_api', 'http_mutation_policy') or key == 'xray_api'
                                for key in cfg), AUTHORITY)
                self.pin = observed
            require(observed == self.pin, AUTHORITY)
        except (OSError, ValueError, WindowError):
            raise WindowError(AUTHORITY) from None
        self._live()
        return True

    def _loaded_agent(self, row):
        # The fixed ExecStart and manager's invocation alone do not prove
        # this process loaded the pinned config. Reject post-birth edits,
        # mount aliases, replaced executables and a stopped/recycled PID.
        require(PID.fullmatch(row['MainPID']) and INVOCATION.fullmatch(row['InvocationID'])
                and row['InvocationID'] != '0' * 32, AUTHORITY)
        pid = int(row['MainPID'])
        root = Path('/proc') / str(pid)
        fd = os.pidfd_open(pid)
        try:
            pin = self.pin
            if pin is None:
                raise WindowError(AUTHORITY)
            _alive(fd)
            prefix, sep, suffix = _bounded_read(root / 'stat', 4096).rpartition(b') ')
            stat = suffix.split()
            require(sep and prefix.startswith(f'{pid} ('.encode('ascii')) and len(stat) > 19
                    and stat[0] not in (b'Z', b'X', b'x', b'T', b't') and stat[19].isdigit(), AUTHORITY)
            require((root / 'exe').readlink() == _AGENT
                    and _bounded_read(root / 'cmdline', 4096) == os.fsencode(_AGENT) + b'\0', AUTHORITY)
            binary = (root / 'exe').stat()
            config = (root / 'root' / _AGENT_CONFIG.relative_to('/')).stat()
            require((_file_generation(binary), _file_metadata(binary)) == pin[3]
                    and (_file_generation(config), _file_metadata(config)) == pin[2], AUTHORITY)
            btime = re.findall(rb'^btime ([1-9][0-9]{0,19})$', _bounded_read(Path('/proc/stat'), 1 << 20), re.M)
            require(len(btime) == 1 and int(stat[19]) > 0, AUTHORITY)
            # btime rounds down. Do not accept a post-birth generation.
            born = int(btime[0]) * 10**9 + int(stat[19]) * 10**9 // os.sysconf('SC_CLK_TCK')
            require(pin[2][0][2] <= born, AUTHORITY)
            _alive(fd)
        finally:
            os.close(fd)

    def scope(self, deadline, *, active=False):
        require(deadline == self.deadline and self.check() is True, AUTHORITY)
        row = verify_manager_scope(deadline)
        try:
            if row['ActiveState'] == 'active':
                self._loaded_agent(row)
            else:
                require(not active, AUTHORITY)
        except (OSError, ValueError, WindowError):
            raise WindowError(AUTHORITY) from None
        return self.check()


def serve(bootstrap, proof_bytes, direct, *, deadline=None):
    """Borrow raw SSH fd 0/1, return the original wire's process status.

    If the loader reads a preamble first, pass its original monotonic start
    plus LIFETIME; this entry does not renew that budget. A null machineId
    uses the existing ordinary NodeSSH peer and the held boot identity.
    DIRECT must provide its existing granted machineId.
    """
    now = time.monotonic()
    try:
        if deadline is None:
            deadline = now + LIFETIME
        require(type(deadline) in (int, float) and math.isfinite(deadline) and now < deadline <= now + LIFETIME, AUTHORITY)
        machine, managed, grant, routes = _bootstrap(bootstrap, direct)
        proof = _PackagedProof(proof_bytes)
        flock = HostMainFlock()
        authority = _Authority(flock, deadline, machine, managed)

        def routes_for(phase, snapshot):
            return routes

        def factory(end, held):
            require(held is flock and end == deadline, AUTHORITY)
            return create_main_session(end, held, managed=managed, routes_for=routes_for, packaged_proof=proof,
                                       verify_authority=authority.check, verify_manager_scope=authority.scope)

        def verify_hold(end):
            return authority.scope(end, active=True)

        if grant is None:
            wire = HostMainWire(factory, on_verify=lambda _snapshot, end: verify_hold(end))
            return wire.serve_held(0, 1, deadline=deadline, lock_factory=lambda: flock, verify_hold=verify_hold)

        final_observer = MainRuntimeObserver(managed, routes_for, deadline=deadline, packaged_proof=proof)

        def prove_final(snapshot, end):
            return (verify_hold(end) is True and final_observer('reconcile', snapshot) is True
                    and verify_hold(end) is True)

        wire = direct_main_wire(factory, direct=direct, machine_id=machine, **grant,
                                verify_writers=authority.check, prove_final=prove_final)
        original_deadline = direct.DEADLINE
        try:
            direct.DEADLINE = deadline  # The loaded DIRECT observers use this same absolute end.
            return wire.serve_held(0, 1, deadline=deadline, lock_factory=lambda: flock, verify_hold=verify_hold)
        finally:
            direct.DEADLINE = original_deadline
    except Exception:
        # Never print bootstrap contents, credentials or a private observer error.
        return 1
