"""Stage b only: advance a settled DIRECT receipt inside a held MAIN step.

This is neither the DIRECT CLI nor a recovery/adoption path. Use the original
HostMainSession, in order: read -> capture receipt -> stop -> capture MAIN ->
check_drained -> publish/restart/start/reconcile MAIN -> advance receipt. An
inverse is a *new* held step against the current predecessor, never a replay
of this capability or restoration of old manifest bytes. The caller retains
its operation intent and treats any failure after stop as unresolved.

Stock finalize-apply-profiles produces currentApply, but doesn't advance
runtime. Only a settled canonical MAIN-owned Apply with a fully attested live
boot/PID/invocation vector is supported here, in either installed CHAP phase.
No install-only or historically split Install, no pending operations, no
legacy Requires= policy (restart can stop NET/VPN). No topology-only rebase
of a client/agent rewrite, even a byte-identical replacement. A startup log
is not an exclusion fence. Nothing here upgrades NET, reattests stale state,
backs up/restores MAIN, or alters CHAP/Install ownership or preimages.

Remove and reattest consume the current Apply pins; the old install-only
rollback/verify path still consumes the original Install preimages. This
companion deliberately doesn't make an applied layout install-rollbackable.
"""
import os
import re
from typing import Any, NamedTuple

from rebuildTransitMainSession import HostMainSession, MainPublication, MainSnapshot, WindowError, require

UNPROVED = 'REBUILD_DIRECT_RECEIPT_UNPROVED'
LAYOUT = 'REBUILD_DIRECT_RECEIPT_LAYOUT_UNSUPPORTED'
LEGACY_NET = 'REBUILD_DIRECT_RECEIPT_REQUIRES_NETWORK'
MAIN_DRIFT = 'REBUILD_DIRECT_RECEIPT_MAIN_DRIFT'
WRITERS = 'REBUILD_DIRECT_RECEIPT_WRITER_EXCLUSION_UNPROVED'
FINAL = 'REBUILD_DIRECT_RECEIPT_FINAL_UNPROVED'
UNCONFIRMED = 'REBUILD_DIRECT_RECEIPT_WRITE_UNCONFIRMED'


class ManifestPin(NamedTuple):
    sha256: str
    generation: tuple[int, int, int]


class _Observation(NamedTuple):
    preserved: tuple
    framework: dict
    binary: list
    units: dict
    starts: dict
    policy: dict
    listeners: list


class DirectReceipt:
    """Process-local, single-use companion; no new lock or default backend.

    `direct` is the trusted original DIRECT namespace (including its bounded
    read-only observers, mounted file layout and current absolute DEADLINE).
    `verify_writers()` must return literal True for continuous exclusion of
    independent writers to the protected state, including queued/background
    agent writes even after START; a sample of unchanged MAIN doesn't prove
    this. Both callbacks must be bounded, synchronous, read-only, and must not
    reenter either object. Session authority is checked independently.

    `capture` reads the predecessor (`predecessor` exposes only its pin).
    `check_drained` checks the exact session publication before MAIN publish.
    `advance` requires successful session reconcile *and* `prove_final(final)`
    for the exact authorized artifact and live MAIN generation; return the new
    manifest pin only after the original DIRECT writer's durable readback.
    """

    @classmethod
    def capture(cls, session, baseline, *, direct, machine_id, backup_id, node_id, network, verify_writers):
        require(type(session) is HostMainSession, UNPROVED)
        with session._action(('ready',)):
            require(type(baseline) is MainSnapshot and baseline is session._baseline and callable(verify_writers), UNPROVED)
            require(all(type(v) is str and re.fullmatch('[a-f0-9]{%d}' % n, v)
                        for v, n in ((machine_id, 32), (backup_id, 32), (node_id, 24))), UNPROVED)
            try:
                return cls(session, baseline, direct, machine_id, backup_id, node_id, network, verify_writers)
            except WindowError:
                raise
            except Exception:
                raise WindowError(UNPROVED) from None

    def __init__(self, session, baseline, direct: Any, machine_id, backup_id, node_id, network, verify_writers):
        require(session._busy and session._state == 'ready', UNPROVED)  # internal to capture
        self._session, self._direct = session, direct
        self._baseline, self._verify_writers = baseline, verify_writers
        self._publication: MainPublication | None = None
        self._request = dict(machineId=machine_id, backupId=backup_id, nodeId=node_id, network=direct.routing(dict(network)))
        self._authority()
        self._path = direct.manifest_path(backup_id)
        self._vault = self._vault_identity()
        self._generation = direct.remove_generation(self._path)
        path, self._manifest, self._backup, self._intent = direct.owned_installation(self._request)
        backup = self._backup
        require(path == self._path and self._generation is not None
                and self._manifest == direct.entry(direct.encode(backup)), UNPROVED)
        self._require_only_manifest()
        applied, runtime = backup.get('currentApply'), backup['runtime']
        require(set(backup) <= {'machineId', 'backupId', 'before', 'after', 'network', 'phase', 'runtime',
                               'currentApply', 'currentChap', 'nativePrepared', 'bootEnrollment', 'swanStart',
                               'swanGeneration', 'preparedSockets', 'modulePersistence', 'foreignJournal'}
                and set(runtime) in ({'nft', 'invocations', 'files', 'boot', 'pids'},
                                     {'nft', 'invocations', 'files', 'boot', 'pids', 'bootEnrollment'})
                and 'bridge' not in backup['after']
                and type(applied) is dict and set(applied) == {'nodeId', 'files', 'bridgeActive', 'bridgeUnit', 'tcp'}
                and set(applied['files']) == {'main', 'bridge'} and type(applied['bridgeActive']) is bool
                and applied['nodeId'] == node_id, LAYOUT)
        record = direct.read(direct.NET, 65536)
        self._kind = direct.network_kind(record, self._request['network'], False, backup_id, backup['after']['nft']['data'])
        require(self._kind != 'requires', LEGACY_NET)
        self._old_main = direct.reattest_files(backup)['main']
        self._owned = self._owned_profile(self._old_main)
        self._observed = self._sample(backup, baseline)
        self._boundary(backup, baseline, self._observed, self._manifest, self._generation)
        self.predecessor = ManifestPin(direct.digest(direct.raw(self._manifest)), tuple(self._generation))

    def _authority(self):
        s, d = self._session, self._direct
        s._check_authority()
        require(self._verify_writers() is True, WRITERS)
        s._check_lock()
        require(d.time.monotonic() < d.DEADLINE, UNPROVED)
        d.require_machine(self._request['machineId'])
        d.install_lock_identity(s._fd)

    def _vault_identity(self):
        d = self._direct
        with d.directory(d.VAULT, private=True) as vault, d.directory(os.path.dirname(self._path), private=True) as owner:
            return tuple((st.st_dev, st.st_ino) for st in (os.fstat(vault), os.fstat(owner)))

    def _require_only_manifest(self):
        # An orphaned stage is evidence, not a file to ignore or delete.
        self._direct.recovery_scan(os.path.dirname(self._path), lambda name: name != 'manifest.json', private=True)

    def _record(self, snapshot):
        image = snapshot.main
        mode, uid, gid = image.metadata
        return self._direct.entry(image.data, mode, gid, uid)

    def _owned_profile(self, main):
        d, request = self._direct, self._request
        bridge, generation = d.apply_profile_read(d.BRIDGE)
        require(d.encode(d.file_pin(bridge, generation)) ==
                d.encode(self._backup['currentApply']['files']['bridge']), UNPROVED)
        current, side = d.unique_profile(main), d.unique_profile(bridge)
        reserved = d.follow_relay_reserved
        own = ([row for row in current['inbounds'] if reserved(row.get('tag'))],
               [row for row in current['outbounds'] if reserved(row.get('tag'))],
               [row for row in current['routing']['rules'] if reserved(row.get('outboundTag'))])
        d.subtract_follow_relay(main, current, side, request['nodeId'], request['network']['tproxyPort'])
        return d.encode(own)

    def _sample(self, backup, main):
        d, s = self._direct, self._session
        d.require_network_observers()
        require(d.ppp_device() is True and d.ppp_registered(), UNPROVED)
        d.removal_owned_dirs()
        epoch, units, processes, connections, policy, listeners = d.reattest_sample(self._request, backup)
        runtime = backup['runtime']
        require(d.encode(epoch) == d.encode({k: runtime[k] for k in ('boot', 'invocations', 'pids')}), UNPROVED)
        x, b, net = units[d.X], d.unit(d.B), units[d.NET_UNIT]
        records = d.reattest_files(backup)
        d.removal_units({**units, d.B: b}, d.runtime_before(backup), runtime, False, False, records['net'])
        require(not x['RequiredBy'] and not any(x[k] for k in ('BoundBy', 'ConsistsOf', 'PropagatesStopTo'))
                and not any(units[n].get(k) for n in (d.NET_UNIT, d.XL, d.IKE)
                            for k in ('BindsTo', 'PartOf', 'PropagatesStopTo'))
                and set(net['RequiredBy'].split()) == {d.XL}, UNPROVED)
        applied = backup['currentApply']
        bridge_unit = applied['bridgeUnit']
        require(d.apply_bridge_state(b, applied['bridgeActive']) == bridge_unit
                and (d.bridge_unit_absent(b) if bridge_unit is None else
                     bridge_unit[0]['data'] == d.APPLY_BRIDGE_UNIT_SHA), UNPROVED)
        rows = d.sock_rows()
        require(d.apply_tcp_pin(rows, x, b) == applied['tcp']
                and d.encode(d.file_pin(self._record(main), list(main.main.generation))) == d.encode(applied['files']['main'])
                and (x['MainPID'], x['InvocationID']) == (str(main.xray.pid), main.xray.invocation_id)
                and s._sample(main=main.main) == main, MAIN_DRIFT)
        binary = d.remove_generation(d.XRAY)  # Same pin as Remove; do not read an unbounded ELF.
        require(binary is not None, UNPROVED)
        framework = (*(units[n]['FragmentPath'] for n in (d.X, d.XL, d.IKE)), *x['DropInPaths'].split())
        files = {p: d.file_pin(*d.apply_profile_read(p)) for p in framework}
        # Use the DIRECT roster codec; preserve BRIDGE's TCP subset separately,
        # since replacing the combined TCP hash would otherwise hide its drift.
        bridge_tcp = d.apply_tcp_pin(rows, b)
        fixed = (files, binary, {k: x.get(k) for k in ('FragmentPath', 'DropInPaths', 'User', 'Group', 'UnitFileState',
                                             'Type', 'ControlGroup', 'KillMode', 'PrivateNetwork')},
                 {**{n: row for n, row in units.items() if n != d.X}, d.B: b},
                 {p: tick for p, tick in processes.items() if p != x['MainPID']},
                 connections, policy, [row for row in listeners if x['MainPID'] not in row[3]], bridge_tcp)
        return _Observation(fixed, files, binary, {**units, d.B: b}, processes, policy, listeners)

    def _boundary(self, backup, main, observed, record, generation=None):
        d, s = self._direct, self._session
        self._authority()
        require(self._vault_identity() == self._vault and d.directory_absent(self._intent), UNPROVED)
        d.foreign_no_pending()
        d.package_no_pending()
        d.check_runtime_boot(backup)
        records = d.reattest_files(backup)
        require(d.checked_installed_policy(backup, self._kind, exact_flags=True) == observed.policy, UNPROVED)
        d.no_jobs(d.UNITS)
        units = observed.units
        by_pid = {row['MainPID']: row for row in units.values()}
        require(all(d.unit(n) == info for n, info in units.items())
                and all(d.reattest_process(p, by_pid.get(p, units[d.IKE])) == tick for p, tick in observed.starts.items())
                and all(d.file_pin(*d.apply_profile_read(p)) == pin for p, pin in observed.framework.items())
                and d.remove_generation(d.XRAY) == observed.binary
                and d.apply_bridge_state(units[d.B], backup['currentApply']['bridgeActive']) ==
                    backup['currentApply']['bridgeUnit'], UNPROVED)
        rows = d.sock_rows()
        d.vpn_listener_ownership(rows, units, require_xl_listener=True)
        d.apply_udp_check(records, rows, units[d.X], units[d.B], self._request['network']['tproxyPort'])
        ports = {row[2] for row in observed.listeners}
        require(sorted(row for row in rows if row[2] in ports) == observed.listeners, UNPROVED)
        require(s._sample(main=main.main) == main
                and d.apply_tcp_pin(rows, units[d.X], units[d.B]) == backup['currentApply']['tcp'], MAIN_DRIFT)
        require(d.read(self._path, 2 * d.MAX_FILE) == record
                and (generation is None or d.remove_generation(self._path) == generation)
                and d.time.monotonic() < d.DEADLINE, UNPROVED)
        s._check_lock()
        return record

    def check_drained(self, publication):
        s, d = self._session, self._direct
        with s._action(('captured',)):
            try:
                require(type(publication) is MainPublication and self._publication is None and publication is s._publication
                        and publication.before == self._baseline.main, MAIN_DRIFT)
                # Never rebase the receipt onto an agent's shutdown rewrite.
                s._window.require_quiet()
                self._require_only_manifest()
                self._boundary(self._backup, self._baseline, self._observed, self._manifest, self._generation)
                desired = {**self._old_main, 'data': d.b64(publication.desired)}
                require(self._owned_profile(desired) == self._owned, MAIN_DRIFT)
                self._publication = publication
            except WindowError:
                raise
            except Exception:
                raise WindowError(UNPROVED) from None

    def advance(self, final, *, prove_final):
        s, d = self._session, self._direct
        entered = False
        try:
            with s._action(('reconciled',), 'reconciled'):
                publication = self._publication
                if publication is None:
                    raise WindowError(FINAL)
                require(publication is s._publication
                        and self._baseline is s._baseline and type(final) is MainSnapshot
                        and final.main == s._written and final.main.data == publication.desired
                        and final.xray.invocation_id != self._baseline.xray.invocation_id
                        and final.xray.pid != self._baseline.xray.pid, FINAL)
                self._publication = None  # Consume before the independent proof, including on failure.
                self._authority()
                require(prove_final(final) is True, FINAL)
                self._authority()
                s._check_started()
                require(s._sample(main=final.main) == final, FINAL)
                require(d.read(self._path, 2 * d.MAX_FILE) == self._manifest
                        and d.remove_generation(self._path) == self._generation, UNPROVED)
                main = self._record(final)
                require(self._owned_profile(main) == self._owned, MAIN_DRIFT)
                apply, runtime = self._backup['currentApply'], self._backup['runtime']
                x, b = d.unit(d.X), d.unit(d.B)
                updated = {**self._backup,
                           'currentApply': {**apply, 'files': {**apply['files'], 'main': d.file_pin(main, list(final.main.generation))},
                                            'tcp': d.apply_tcp_pin(d.sock_rows(), x, b)},
                           'runtime': {**runtime, 'pids': [str(final.xray.pid), *runtime['pids'][1:]],
                                       'invocations': [final.xray.invocation_id, *runtime['invocations'][1:]]}}
                observed = self._sample(updated, final)
                require(observed.preserved == self._observed.preserved, UNPROVED)
                # Structural proof above is read-only. Until replacing the
                # manifest, every call to the writer's reader checks the old
                # bytes+generation even though live MAIN is now the new image.
                replacement = d.entry(d.encode(updated))
                require(len(d.raw(replacement)) <= 2 * d.MAX_FILE, UNPROVED)
                self._require_only_manifest()
                self._boundary(updated, final, observed, self._manifest, self._generation)
                reads = 0

                def reader(path):
                    nonlocal reads
                    reads += 1  # DIRECT write: pre-stage, pre-rename, readback.
                    require(path == self._path and reads <= 3, UNCONFIRMED)
                    if reads != 2:  # The second read sees our own unlinked-on-return stage.
                        self._require_only_manifest()
                    s._check_started()
                    record, generation = (self._manifest, self._generation) if reads < 3 else (replacement, None)
                    return self._boundary(updated, final, observed, record, generation)

                entered = True
                generation = d.write(self._path, self._manifest, replacement, generation=self._generation, witness=True, reader=reader)
                require(reads == 3 and generation is not None, UNCONFIRMED)
                return ManifestPin(d.digest(d.raw(replacement)), tuple(generation))
        except Exception as error:
            if entered:
                raise WindowError(UNCONFIRMED) from None
            if isinstance(error, WindowError):
                raise
            raise WindowError(UNPROVED) from None
