# Durable TEST node originals — конечный примитив, не handback

## Integrated review corrections

Every capture, restore preparation, restore effect and held-scope checkpoint now
passes the current operator session to the actual recovery guard check and pins
that operator identity for the scope. The recovery session is not an operator
channel. Losing or changing the independent operator session cannot repair a
failed held scope. This is source-tested, not live SSH proof.

`node_originals.py` действительно сохраняет и восстанавливает байты файлов и
metadata, затем перечитывает их и состояние сервиса. Он **не** снимает маски,
не размораживает host, не возвращает старых writers, не меняет Mongo owner,
node locks/admissions и никогда не удаляет/открывает restore admission.
Успех означает только `NODE_ORIGINALS_RESTORED_RETAINED`, не право на handback.

На этой ветке нет установки, SSH/live/systemd/root-мутаций. Production CLI требует отдельно проверенной установки: integrated isolation
теперь экспортирует `RESTORE_ADMISSION_VERSION = 1` и реально закрывает dispatch
при любом marker/unfinished marker. Parent проверяет эти installed bytes/pins;
сам source export не является live authority. Positive local integration проходит
реальные `Engine.close_dispatch → NodeOriginals.restore`, сохраняя marker и hold.

## Fixed surface

После отдельной проверенной установки единственные команды:

```text
/usr/local/libexec/c3-test-node-originals.py capture
/usr/local/libexec/c3-test-node-originals.py restore
```

Обе требуют root, реальную независимую maintenance SSH session, установленный
`/usr/local/libexec/c3-test-node-isolation`, его fixed config/Engine (включая
настоящий shared Engine при shared mode), physical identity и live recovery
nonce/PID/start/root-peer через `Engine.assert_held`. Fake-root/env/executable/
path/stdin/remote request overrides у CLI отсутствуют. Python `Fixture` — явно
внедряемая **тестовая симуляция**, не operational authority. Библиотечный вызов
с пользовательским facade также не является authority для панели.

Allowlist — четыре dedicated TEST nodes из `isolation.TEST_NODES` и отдельно
проверяемый shared TEST `6ab189dc63913ebd4a917399`, `212.119.42.100`, main.
Для main: `/usr/local/etc/xray/config.json`,
`/etc/systemd/system/xray.service`, `xray.service`.
Для bridge: `/usr/local/etc/xray-bridge/config.json`,
`/etc/systemd/system/xray-bridge.service`, `xray-bridge.service`.
На `104.143.201.72` обязательны **оба** профиля: snapshot, restore и полный
readback обоих Xray units/runtime. Это не режим «остановить native main ради
bridge». PPP paths/services вообще не выбираются и не изменяются.

Поддерживаются только существующие root:root regular files без symlink/hardlink,
trusted root-owned ancestors без group/world-write, unit без drop-ins и с exact
FragmentPath, `LoadState=loaded`, `NeedDaemonReload=no`, `Job=`, active/inactive,
enabled/disabled. Иные layouts/states/absence не нормализуются, а отказывают.
Каждый config/unit <=512 KiB, xattrs <=64 KiB JSON, bundle <=8 MiB.
Modes/UID/GID/все xattrs входят в accepted pins и exact readback; special mode
bits запрещены. Systemctl использует только fixed show/stop/restart/
daemon-reload/enable/disable, с bounded subprocess deadline. CLI имеет общий
150-second alarm; неизвестный системный job не считается отменённым.

## Независимо принятые pins (не экспорт наблюдения в authority)

Root заранее устанавливает `/etc/c3-test-node-originals.json`. Это **описание
схемы**, не готовые реальные значения:

```text
version: 1
context,nodeId,endpointIp,targetProfile,machineId,bootId,sshHostKeySha256,maintenanceId:
  exact independently accepted fields of the isolation plan
planHash: exact SHA256 of canonical isolation plan, as calculated by real Engine
isolationSha256: independently reviewed installed isolation helper bytes, SHA256
xraySha256: independently pinned /usr/local/bin/xray bytes, SHA256
profiles:
  <exact fixed profile set>:
    files:
      config,unit:
        sha256: exact original bytes, lowercase 64-hex
        mode: integer POSIX permission mode
        uid,gid: 0 in production
        xattrs: exact name -> canonical base64 value object (empty only if absent)
    service:
      Id,LoadState,FragmentPath,DropInPaths,ActiveState,UnitFileState,Job,NeedDaemonReload:
        exact independent original systemctl observation
    runtimeSha256: SHA256 of canonical normalized actual runtime snapshot below
```

`capture` independently reads fixed files/metadata, loaded/service state before
and after, actual runtime users where needed, checks every pin, and rereads
files. It acquires the existing outer `STATE/lock` with NONBLOCK and requires
held isolation with `dispatchCount=0`, no in-flight dispatch. Thus adoption of
already changed candidate bytes is forbidden. It does not require the closed
restore marker at capture time. Parent must schedule and require successful
capture **before first candidate mutation**; this slice does not silently patch
another writer's dispatch path to enforce that orchestration.

Store: `/var/lib/c3-test-node-isolation/originals`, root:root 0700;
`originals.json`, root:root 0600. Bundle contains identity, exact live guard
identity, accepted-pins digest, secret file bytes/metadata and runtime users.
Exclusive `.next` creation, file fsync, no-overwrite publication and directory
fsync complete before successful capture; exact bundle bytes are read back.
No original cache is needed to restore in a separate process. Re-capture never
overwrites an existing or uncertain backup. Never print/tee/log the private
bundle or runtime RPC bodies. Public results contain only codes/digest/retention.

## Restore admission, locks и current-head validation

Parent/B writer first durably closes admission at the exact fixed path:
`/var/lib/c3-test-node-isolation/restore-admission.json`, root-owned:

```text
{ version:1, planHash, maintenanceId, nodeId, bootId, state:"closed" }
```

All fields and the scalar integer version must match the accepted isolation
identity exactly; no extra fields. Marker is **never** removed or reopened here.
Its existence must prohibit **every** application dispatch, including future
forced commands, across restoration and later parent reconciliation. A caller
boolean, historical receipt or a facade's alleged drain is not a substitute.
Candidate/DB drain and closure authority belong to parent/B, not this primitive.

Independent root `/etc/c3-test-node-originals-restore.json` schema:

```text
version: 1
<same exact identity fields plus planHash>
bundleSha256: independently accepted exact durable bundle-byte SHA256
profiles:
  <same exact profile set>:
    files: exact currently accepted config/unit sha256/mode/uid/gid/xattrs
    service: exact current loaded/service observation, same fields as above
    journalSha256: exact accepted CURRENT runner journal-byte SHA256
```

This prevents unknown current-file/service drift being overwritten just because
the original backup exists. Current pins are separately accepted, not invented
from the observation by the restorer. Before effects it independently acquires
NONBLOCK both outer isolation lock and each relevant runner's actual global
profile flock `/var/lib/celerity/topology/fences/<profile>/lock`. Locks are held
through all effects and readback, inherited by bounded invoked subprocesses,
and inode identity is rechecked. Missing lock/journal is a refusal, not creation
of a fake terminal fence; on `.72` this deliberately requires both real fences.

Under those locks it reads the **current head**, exact journal checksum,
node/context/boot, every generation closed and command completed, and the exact
actual runner close receipt grammar/binding (`terminal=true`, known terminal
outcome/systemd completion). A historical terminal receipt while a successor
head exists cannot pass. `.next`, running/unknown head, wrong boot, missing
close or bad receipt refuse before stop/write. No journal is synthesized.

## Отдельный минимальный hook для владельца isolation.py

Source hook интегрирован и закрыт actual-dispatch/actual-restore regression
`test_originals_dispatch_integration.py`. Ниже зафиксирован minimal contract;
production restore всё равно требует независимо accepted installed helper SHA256:

```python
# Export ONLY after actual dispatch exclusion is implemented and tested.
RESTORE_ADMISSION_VERSION = 1

# At the very start of Engine.dispatch(), before any runner call/effect:
need(not os.path.lexists(self.directory / 'restore-admission.json'),
     'RESTORE_ADMISSION_CLOSED_RETAINED')
```

Existence, including corrupt file or symlink, must reject dispatch; do not parse
it to decide whether reopening is allowed. The primitive checks the version
export **and the independently accepted SHA256 of the installed helper**. The
export is a reviewed-installation compatibility contract, not caller authority.
Absent hook on the assigned base explicitly refuses. Parent must exercise the
actual forced dispatcher with the durable marker; these tests do not claim an
unintegrated hunk has already closed real dispatch. No extra SSH force-command,
SFTP operation or runner grammar is proposed. Existing operator transport may
invoke the separately installed fixed root CLI only after separate review.

## Actual finite restoration and runtime users

After *all* profiles pass preflight, `restore.json` is fsynced as
`restoring-retained` before first stop/write. Each target service is stopped,
known inactive/no-job is read back; original bytes/owners/modes/xattrs are
atomically replaced with fsync and exact accepted-current checks. Fixed
`daemon-reload`, enable/disable only if needed, and restart only for originally
active service follow. Final readback checks exact loaded/service state,
metadata and bytes for every profile, then runtime users and unchanged runner
heads. Guard/admission/accepted pins/bundle/intent/lock identity are rechecked
around individual effects and file replacements. Only then the durable phase
becomes `verified-retained`. Original isolation journal remains held unchanged.

Active VLESS runtime users are **not inferred from config clients**. The fixed
pinned Xray binary executes only `api inbounduser`, `rmu`, `adu`, against a
loopback HandlerService API derived from accepted original config with the
exact API_INBOUND/routing structure. All VLESS inbound tags are included,
including static and empty subscription inbounds. Capture normalizes actual
UUID/email/level/flow, sorted by email; snapshot is
`{mode:"rpc",inbounds:{<tag>:[{id,email,level:0,flow}]}}`, or
`{mode:"none",inbounds:{}}` only when there are no VLESS inbounds. Inactive
VLESS also refuses rather than guessing that no lingering runtime clients exist.
Max 64 inbounds,
4096 users per inbound; only VLESS level 0 and empty/xtls-rprx-vision flow are
supported. Unknown protocols/layout/account fields, missing API/readback or
unsupported binary refuse **before claiming original capture/full restore**.
This includes active static VLESS bridges lacking an exact readable Handler API;
there is intentionally no config-only approximation of their runtime state.

After original-service restart, current users are read, removed, empty-state
read back, original users added, and exact UUID/email/flow/level set read back.
Zero exit from `adu` alone is never success. RPC outputs use anonymous private
memfds with kernel RLIMIT_FSIZE, byte bounds and deadlines, never logs/files.
Configuration and RPC credentials/user UUIDs stay in the private bundle/channel.

Any signal/timeout/guard loss/drift/partial restore preserves the backup, closed
marker and held external isolation. An existing restore intent, even verified,
is never automatically replayed; independent reconciliation is required. There
is no finally-unmask/thaw/restart of old writers or admission cleanup. A timed-out
systemctl may have left a job; retained state is deliberate, not cancellation.

## Evidence and explicit remaining gates

Tests run actual descriptor-walks, atomic bytes/metadata writes, xattrs, fsync,
NONBLOCK/inherited descendant flocks, real runner-generated close journals,
separate-process restoration and exact readback. A real disposable loopback
Xray preserves a nonempty RPC-only user (including vision flow) through restart;
an exit-zero/no-add simulation still fails its real RPC readback. UID,
physical/kernel/recovery SSH, dispatch-hook presence and systemd observations
are **explicitly simulated**. No real installed helper, host services or database
are mutated by these tests. No skips or force-exit.

```sh
PYTHONDONTWRITEBYTECODE=1 C3_XRAY=/path/to/pinned/local/xray \
  C3_ORIGINALS_TEST_XRAY=/path/to/pinned/local/xray \
  python3 -m unittest discover -s scripts/test-node-isolation -p 'test_*.py' -v
```

Still parent-owned: install/review/hook integration, mandatory capture ordering,
candidate effect drain, Mongo exact owner/lock/admission transition, serving
rollback, shared-host coordinated handback and old-writer resume. Existing
`physical_attestor.py` / eeb owner controller remain read-only/process-local;
this helper neither reconstructs their private adoption cache after controller
restart nor exports an `external-maintenance-v1` proof. Successful restoration
must be freshly observed by that independently held authority before owner
transfer. Source tests do not prove operational reachability or live restoration.
