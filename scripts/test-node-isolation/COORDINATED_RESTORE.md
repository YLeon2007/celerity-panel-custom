# Пять foreground restore-holds — не handback

`coordinated_restore.py` реализует отсутствовавшую операционную **source-path**:
пять свежих непулированных SSH foreground helpers, реальные outer + все runner
flocks, вызов настоящего `NodeOriginals` и exact readback, пока **все пять**
helpers продолжают владеть своими дескрипторами. Исторические `close-dispatch`
receipts и файлы с пятью старыми ответами не используются как authority.

**В этой работе не выполнялись установка, SSH, root/kernel/systemd/live-мутации,
Mongo settlement, thaw или запуск старых writers. Независимо принятые реальные
pins не создавались и не обновлялись из наблюдений.** Непровиженный CLI закрыт:
exit 75, `COORDINATED_RESTORE_UNKNOWN_RETAINED`. Это не готовое разрешение live.

## Фиксированный root-only CLI после отдельной принятой установки

```text
/usr/local/libexec/c3-test-coordinated-restore.py restore
/usr/local/libexec/c3-test-coordinated-restore.py node-hold
```

Нет CLI/env root/path/endpoint/config/key/command overrides. `restore` запускается
вне замороженной candidate-панели и принимает только фиксированный root-owned
`/etc/c3-test-coordinated-restore.json`. `node-hold` доступен независимому
`c3-test-operator` через существующий maintenance SSH и sudo, **не** application
forced dispatcher. Изменения sudoers/sshd/install остаются parent-owned.

Каждое соединение: `/usr/bin/ssh -F /dev/null -T`, порт 2222, строго один
`c3-test-operator@<fixed TEST IP>`, одна константная remote command
`sudo -n /usr/local/libexec/c3-test-coordinated-restore.py node-hold`.
Нет shell interpolation пользовательских значений, SFTP, pooling, proxy,
password/interactive/agent fallback, forwarding или LocalCommand. Только
public-key auth и raw Ed25519 host-key pin, StrictHostKeyChecking=yes.

Ровно пять ID/IP/profile — тот же фиксированный allowlist, что у originals.
Для `104.143.201.72` обязательны main **и** bridge locks/configs/units/runtime;
остальные узлы используют свой fixed profile. PPP не выбирается и не меняется.

## Принимаемые независимо pins: схема, не готовая конфигурация

Общий root-owned конфиг на coordinator и всех пяти узлах:

```text
version: integer 1
context: test.infograd.online
lifetimeSeconds: integer 80..120 (не daemon; общий finite budget)
origin:
  machineId: exact 32 lowercase hex
  bootId: exact canonical boot UUID
  cgroup: exact /proc/self/cgroup строка отдельного root coordinator
  uid: integer 0
keySha256: independently accepted SHA256 of fixed operator private-key bytes
nodes:
  <каждый из ровно пяти fixed node IDs>:
    identity:
      context,nodeId,endpointIp,targetProfile,machineId,bootId,
      sshHostKeySha256,maintenanceId,planHash:
        exact independently accepted isolation identity
    profiles: exact ordered fixed list (main,bridge на .72)
    guard: exact independently accepted live recovery guard identity
    hostKey: canonical base64 SSH Ed25519 public wire blob (не PEM)
    files:
      self: SHA256 installed c3-test-coordinated-restore.py
      originals: SHA256 installed c3-test-node-originals.py
      isolation: SHA256 installed c3-test-node-isolation
      accepted: SHA256 exact /etc/c3-test-node-originals.json bytes
      restoreAccepted: SHA256 exact /etc/c3-test-node-originals-restore.json bytes
      shared: SHA256 installed c3-test-shared-host.py (только shared node)
      freezer: SHA256 installed c3-panel-host-freezer.py (только shared node)
```

`self` и `originals` должны быть одним принятым build на всех узлах. Machine IDs
и raw key hashes не могут alias друг друга. Raw wire key проверяется по полной
Ed25519 структуре и SHA256; known_hosts строится **из принятых pins**, не из
ssh-keyscan/live output. Plan/current journal/config/unit/runtime pins не
нормализуются и не пере-принимаются restorer-ом.

Пути coordinator:

* `/etc/c3-test-coordinated-restore/operator-key`: root:root 0600, SHA256 pin;
* `/var/lib/c3-test-node-isolation`: существующий root:root 0700;
* `coordinated-restore.lock`: заранее отдельно созданный root:root 0600 flock;
* `coordinated-known-hosts`: private no-overwrite pin-derived known_hosts;
* `coordinated-restore.json`: fsynced no-overwrite transition intent;
* `coordinated-restore.sock`: root:root 0600 AF_UNIX control channel.

Trusted source loader descriptor-проверяет каждый ancestor, owner/mode/link,
проверяет pin **именно исполняемых** source bytes и не читает unpinned `.pyc`.
Shared helper и freezer pins проверяются отдельно; installed isolation plan
дополнительно обязан пройти его реальные dedicated/shared validators.

## Порядок и реальные границы удержания

1. Нужны уже закрытый candidate, живые original maintenance/recovery holds,
   sticky closed admission на каждом узле, captured private originals и отдельно
   принятые current-head/current-file/service pins. Helper ничего из этого не
   создаёт задним числом. Shared node дополнительно выполняет реальный
   `shared.check_hold` и требует `candidateClosure` под независимым host guard.
2. Coordinator fsync/readback intent `acquiring-retained` **до** SSH launch.
   Каждый node helper проверяет установленный source, identity, operator SSH
   session, physical/boot/key, nonce/guard, accepted pin files. Затем один раз
   NONBLOCK захватывает настоящий outer lock и все нужные profile runner locks.
3. `NodeOriginals.restoration_hold()` сохраняет реальный `ExitStack`/OFDs.
   Предварительная проверка bundle, закрытого admission, exact current journal
   head/всех closed generations и current bytes/services выполняется **до**
   первого эффекта на любом из пяти узлов. Нет второго self-conflicting flock.
4. Когда открыты все пять foreground channels, coordinator ещё раз challenges
   каждый. Для каждого restore сначала fsync/readback `inFlightNode`; настоящий
   `held.restore()` выполняет прежние stop/file fsync/reload/service/runtime RPC
   действия с теми же FDs, наследуемыми bounded subprocesses. После ответа
   fsync-ится `restoredNodes`; неопределённый in-flight узел не объявляется clean.
5. Все helpers продолжают держать outer+runner locks. Проверяются реальные
   original bytes/metadata/loaded service/runtime users каждого профиля, затем
   fresh challenges всех пяти. Только живой scope достигает `restored-held`.
6. Coordinator держит channels/locks через конечный root-peer owner scope.
   В момент выхода capability отзывается, но **не** открываются admission,
   DB fences, candidate или старые writer fences. `scope-closed-retained` —
   историческая фаза, не handback. CLI не печатает transferable JSON GO.

Входящие/исходящие frames closed-world, bounded newline JSON без duplicate keys,
с точными integer version/sequence, новым coordinator nonce, новым node nonce,
новым challenge на каждый запрос, origin PID/start/physical/cgroup identity,
remote root-helper PID/start, operator SSH PID/start и guard/pin digest.
Replay, extra fields, bool-as-int, foreign origin и arbitrary op запрещены.

Пока ожидается ответ одного узла, readable/EOF **любого другого** channel
прерывает ожидание; зависший restore не скрывает смерть idle peer. На node side
EOF/unsolicited input проверяется перед/после отдельных эффектов через checkpoint.
Idle helper также перечитывает guard/pins. Сигналы/общий alarm, ошибки, drift,
partial, timeout и owner EOF необратимо отзывают positive capability; исправление
файлов внутри старого scope не восстанавливает её. Старый intent никогда не
replay-ится автоматически, даже если он содержит verified phase.

При смерти guard оперативные flocks могут закрыться; sticky closed admission
продолжает запрещать application dispatch. Незавершённый systemd job/потомок —
unknown, не «отменён». Никакого автоматического thaw/unmask/reopen/cleanup нет.
Socket/known_hosts/intent сохраняются как sticky reconciliation state; следующее
CLI выполнение отказывает, а не удаляет чужие или неопределённые остатки.

## API следующему trusted owner orchestrator (не панели)

`RestorationChannel()` подключается только к fixed root AF_UNIX path, проверяет
SO_PEERCRED root PID/start **из текущего intent**, accepted pins и fresh server
nonce. Контекст держится всё время будущего owner settlement. `check()` выполняет
новый roundtrip, заставляющий coordinator перечитать все пять узлов, и возвращает
`None`, **не** boolean, receipt, callback или JSON permission. Ошибка закрывает
канал и необратимо отзывает объект; после context exit `check()` отказывает.

Будущая privileged owner реализация должна challenges до/после своих awaited
границ и сохранять собственные DB owner/lock/admission fences при любой потере.
Здесь её нет: ни Mongo операции, ни DB handback, ни host-thaw/legacy-resume не
реализованы. Root diagnostics всегда имеют `handbackAllowed:false`. `finish`
закрывает только этот конечный restore scope, не возвращает старым writers право
писать. Arbitrary application callable не принимается ни сервером, ни клиентом.

## Локальная проверка и оставшиеся gates

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/test-node-isolation -p test_coordinated_restore.py -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts/test-node-isolation \
  python3 -m unittest test_node_originals.SafetyTests -v
```

Реальны: пять отдельных subprocess channels, UDS/SO_PEERCRED/PID/start framing,
filesystem/metadata/fsync, flock contention, настоящий runner, который создаёт
closed journals, реставрация/повторный readback обоих профилей, sticky admission,
запрет replay, partial/EOF/revocation и смерть другого peer во время blocked
restore. **Явно симулированы** UID/root, SSH handshake/transport, physical,
recovery/kernel/freezer и systemd; тестовые injections доступны только через
Python constructors, не через production CLI/environment.

Runtime восстановление не заменено: сохраняется настоящий `NodeOriginals`
`inbounduser/rmu/adu` и exact nonempty UUID/email/flow readback. В этой slice
запускались только light/no-RPC tests, чтобы не конкурировать с parent drill.
Parent должен согласованно serial повторить существующие real loopback RPC tests
`test_node_originals.OriginalsTests` на принятом Xray binary и assembled integration.
Положительная пятиузловая fixture сама по себе не доказывает live SSH/root/
physical/systemd/RPC reachability или DB owner handback.

Durable RED/GREEN logs: `/home/leon/celerity-prod-release-20261019/` +
`evidence-coordinated-restore-20261020/`. Parent отдельно принимает installation,
реальные private bundles/current profile pins, topology/owner channel wiring,
full settlement, serving rollback и будущий nondestructive host handback.
