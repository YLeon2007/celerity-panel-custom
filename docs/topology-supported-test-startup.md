Поддерживаемая dedicated TEST activation (opt-in)

PANEL_DOMAIN остаётся test.infograd.online. TOPOLOGY_TEST_STARTUP_MODE=
dedicated-runtime-v1 разрешён только для явно выделенных task-owned Linux/
systemd runtime. Общие host MAIN/BRIDGE и старый native stand не используются.
PROD selectors и разрешения не меняются.

Приватный /etc/celerity/topology-test-dedicated.json привязывает конечный
inventory к app/provision SHA, endpoint, уникальным machine/SSH host-key,
maintenance ID и завершённому предыдущему bootstrap app. Настоящий host /proc
должен быть read-only смонтирован в /hostproc. Отсутствие mount — отказ.
Node observer проверяет настоящий nspawn PID/mount runtime, machine/boot,
точные sshd/authorized_keys и профили, журнал и отсутствие journal.next.
Ключи, пользователи и runtime при resume не пересоздаются.

HTTP-контракт

  POST {} /api/cascade/topology-test/activate
    nodes:write + обычная auth/CSRF. Создаёт или присоединяет единственную
    host-owned задачу. 202 + activationId + statusUrl — только ACK.
    Inventory/proof/generation из запроса не принимаются.

  POST {} /api/cascade/topology-test/resume
    То же, но отсутствие одной из existing owner/enrollment — отказ,
    а не разрешение создать новую пару. Это не replay старого UNKNOWN.

  GET /api/cascade/topology-test/status
    nodes:read. Только ограниченный локальный снимок, без SSH/DB ожиданий.
    reconciliation_required / reconciling / active / retained / stopped.
    Новая app instance получает новый activationId и не наследует прежний
    HTTP-success. active означает подтверждённое согласование enrollment
    и запуск consumers, НЕ применённый каскад и НЕ PPP/client readiness.

Задача принадлежит host lifecycle: stop сначала запрещает поздний start и
fence-ит оба consumer scheduler, затем присоединяет activation/drains.
Частичный execution.start + recovery.start failure останавливает оба lifecycle;
ошибка сохраняется, повторной adoption и автоматического retry нет.
Consumers запускаются внутри последней held physical reconciliation; active
публикуется лишь после окончательного выхода всех authority checks.

Новая пара выполняет прежнюю цепь initializeClassic → adopt → preEnroll с
CAS/majority. Existing пара выполняет отдельный reconcile-pristine challenge:
exact Owner/Enrollment/HyNode, поколение и receipts, endpoint/identity/profile,
свежий реальный boot, current originalSnapshot и отсутствие журналов,
bindings/operations/locks. Повторных initializeClassic/adopt/preEnroll нет.
Owner/HyNode CAS и точное enrollment-состояние проверяются в транзакции;
после commit требуются majority confirmation и свежие authority checks.

Перезапуск guest не выдаётся за сохранение boot. Только для pristine TEST,
predecessorGeneration=none и отсутствия перечисленных execution records,
разрешён узкий audited boot transition. Исходные enrollmentId, bootId,
provisioningReceipt, ownerGeneration и ключи неизменны. Отдельное поле
pristineBootResume хранит initialBootId, наблюдённый runtime boot, proof,
maintenance ID, время и прежние boot ID. Запись — exact CAS прежней строки
в той же fenced транзакции, максимум восемь переходов. Это не возможность
возобновления после уже выполненных/неопределённых node commands.
Обычный immutable model ABI и CAS/fences не отключаются.

Отсутствующий admission singleton создаётся только после такой held
сверки и транзакционного доказательства пустых operational collections:
links/groups/relay state/operations/bindings/locks/admissions/intents/queue.
Начальные revision/counters=0 — инициализация пустого TEST, не ready state.
Существующие неполные counters, reservations и drains не сбрасываются.

После активации используется обычный cascade API → intent → coordinator →
materializer/composer → v2 worker/executor → finalizer. Bootstrap executor
требует не только exec SSH, но и рабочий SFTP subsystem для upload runner.
Наличие sshd active этого не доказывает. Первоначальный R→B1 остановился
bootstrap-unavailable; эта история UNKNOWN и отдельная подтверждённая
cancellation сохранены. Последующее исправление SFTP не превращает прежнюю
команду в успешную.

Узкое продолжение reservations до первого dispatch

  POST {"operationId":"<existing ID>"} /api/cascade/topology-test/resume-bindings

Только тот же opt-in TEST, authenticated session + nodes:write + CSRF. ACK202
не означает успех. Маршрут подключён к существующему host/authority/worker
lifecycle, а не запускает отдельный writer. Принимается только queued attempt1
link.apply из двух pending xray-bridge профилей с пустыми backupId, существующими
uncertain locks и без binding rows. Физический observer заново доказывает
отсутствие generation/operation/backup и живого runner; проверяется точный
cancelled initial predecessor и current originalSnapshot, enrollment/boot,
owner/HyNode/selected plan. Транзакция CAS продлевает только существующие locks
и claim; attempt/operation/job/generation не заменяются, admission не снимается.
После majority confirmation тот же worker резервирует bindings и исполняет
prepare/commit/verify/close/finalizer. Audit bindingReservationContinuation
используется реальным lifecycle; повторный/частично исполненный случай отказан.

Это НЕ recovery неизвестной mutating-команды. Для единственного retained
non-activating verify добавлен POST {"operationId":"<existing ID>"}
/api/cascade/topology-test/resume-verification с прежними auth/session/CSRF.
Тот же held lifecycle проверяет exact owner/enrollment/boot/epoch/binding,
исходные completed prepare/commit и единственный UNKNOWN verify; runner под
исходным flock создаёт отдельный observe-verify outcome с provenance. Старый
verify остаётся running/UNKNOWN и status по его ID не меняется. B132 commit не
повторяется. R185 original commit разрешён только после физического доказательства
его отсутствия; original prepare/binding/attempt/generation/IDs не заменяются.
Нормальные close/status/CAS/majority/V2 finalizer сохраняются. При closure до
remote close разрешена только узкая сверка этого же verified suffix, без replay.
Пустой, физически не настроенный PPP получает явный absent epoch в native claim
transaction при отсутствии users/operations; это не установка и не PPP readiness.
После settled операции startup может read-only подтвердить exact closed journals
и terminal proofs перед запуском consumers, без новой adoption.

Каталоги dedicated guest создаёт scripts/topology-test-dedicated-layout.py:
только traversal битами0711, без recursive chmod или изменения secrets/User.
В живой проверке actual UID65534 получил доступ, B132 listener24101 появился.
Для dedicated TEST on-demand health использует held node-readback и настоящий TCP,
не записывает вымышленные legacy-agent heartbeats и не заменяет traffic proof.

Живая operation9b1bef58cf83a88dd71703c0 завершилась succeeded/attempt1 через
оба original close и native settlement; historical UNKNOWN сохранён. Дальнейший
panel L2TP install operation1c2690a03de0b30e0399f6c0 принят, затем штатно failed
CLASSIC_CONFIG_WRITE_OWNER_VETO до remote dispatch. Root L2TP preparation пока
classic-only и не имеет совместимого writer contract для topology-owned узла.
Guard/owners не отключались, handback/re-adopt не выполнялись. PPP/DNS/HTTPS и
остальная live matrix НЕ подтверждены. Generic recovery здесь не добавлен.


Все результаты unit/modelled, реального Mongo/SSH, API, PPP и lifecycle
разделяются в execution receipts. Старые UNKNOWN не переоцениваются.
Shared-node import/handback и PROD migration остаются на прежних контрактах.
