# Changelog

## Unreleased

- Для цепочек Rebuild каждому узлу MAIN нужен один обычный Apply после обновления; панель подскажет в предпросмотре. Запись цепочек в штатной панели пока закрыта: проверка области изменений systemd не проходит на штатных зависимостях Debian 13.
- Xray setup fails if the final authenticated agent probe confirms the runtime API is down after a requested restart. No cascade redeploy or wizard completion follows that failure. Setup without a restart can still complete while Xray is offline.
- Missing or unusable Xray health proof is reported as `unknown`, not as an outage. Setup reports an explicit warning; the node does not show as online, its online-user count is cleared, and no `node.offline` webhook is emitted for an unsupported or invalid probe.

## v1.6.41 — Локальный Caddyfile / Local Caddyfile

- Source-updater: локальные настройки Caddy можно вынести из Git в `Caddyfile.local` и указать его через `CADDYFILE` в `.env`. Без переменной используется штатный файл. [Памятка оператора](docs/release-v1.6.41.ru.md).
- Source updater: keep custom Caddy settings in an untracked `Caddyfile.local` and select it with `CADDYFILE` in `.env`. The stock file remains the default.

## v1.6.40 — Установка и восстановление L2TP / L2TP install and recovery

- На странице L2TP допуск, установка, проверка результата и удаление обновляют состояние без ручной перезагрузки. При установке видны процент, этап и конкретная причина сбоя.
- The L2TP page updates admission, installation, recovery and removal status without a manual reload. Install shows progress, the current stage and the specific failure reason.
- На релее с допуском из базы известные чужие настройки удаляются только после отдельного одноразового подтверждения. Активный VPN, занятые порты, PPP-сессии и непроверенные настройки блокируют изменения.
- On a relay with database-backed admission, known foreign settings are removed only after separate, one-time consent. Active VPN, occupied ports, PPP sessions and unverified settings block changes.
- При подтверждённом откате панель сообщает причину и, если применимо, что исходные настройки восстановлены. При неизвестном исходе установка не повторяется автоматически. [Памятка оператора: выкладка и откат](docs/release-v1.6.40.ru.md).
- Confirmed rollback reports the reason and, when applicable, restoration of the original settings. An unconfirmed outcome never triggers an automatic Install retry.

## v1.6.39 — Обновление L2TP / L2TP overview refresh

- После подтверждения допуска обзор L2TP обновляется автоматически. Когда действия заблокированы, причина видна рядом с релеем.
- The L2TP overview refreshes automatically after admission confirmation. If actions are locked, the affected relay row explains why.
- Проверка хоста видна сразу после Install. Итоги установки, восстановления и допуска видны и вверху, и в строке релея; при отказе там остаётся причина, при сверке результата — обратный отсчёт.
- Install shows the host check immediately. Install, recovery and admission results appear at the top and in the relay row, including refusal reasons and the reconciliation countdown.

## v1.6.38 — Свой выход портала / Per-portal exits

- На одном общем Rebuild-релее каждый портал может выбрать свой бридж и решить, использовать ли шлюз РФ. Выбор сохраняется по ноде, а канал определяется приоритетом. [Заметки о выпуске](docs/release-v1.6.38.ru.md).
- Portals sharing one Rebuild relay can select their own exit node and opt in or out of the relay’s geo routes. The active link is selected by priority. [Release notes](docs/release-v1.6.38.md).

## v1.6.37 — Длительные подключения Xray / Long-lived Xray connections

- Открытые подключения не исчезают по возрасту последнего подключения. cc-agent 1.6.1 отличает пустой список клиентов портала от отсутствия данных учёта. [Заметки о выпуске](docs/release-v1.6.37.ru.md).
- Open connections no longer expire based on their start time. cc-agent 1.6.1 distinguishes an empty portal client list from unavailable tracking data. [Release notes](docs/release-v1.6.37.md).

## v1.6.36 — Счётчик клиентов на карте / Map client count

- Новая карта обновляет топологию каждые 10 с на видимой вкладке и сразу сверяет счётчик с открытым списком клиентов. [Заметки о выпуске](docs/release-v1.6.36.ru.md).
- The modern map polls every 10 s while visible and updates the count immediately from the open client list. [Release notes](docs/release-v1.6.36.md).

## v1.6.35 — IP подключённых клиентов на карте / Client IPs on the map

- Администратор видит IP, регион и организацию ASN при наведении на счётчик клиентской Xray-ноды. Нужны cc-agent 1.6.0 и политика `statsUserOnline`. [Заметки о выпуске](docs/release-v1.6.35.ru.md).
- An administrator can see client IPs, regions and ASN organizations from a client-facing Xray node's count. Requires cc-agent 1.6.0 and `statsUserOnline`. [Release notes](docs/release-v1.6.35.md).

## v1.6.34 — Исправление счётчика клиентов / Client count fix

- Счётчик клиентов на дашборде снова показывает подключённых клиентов, даже если журнал доступа Xray выключен. [Заметки о выпуске](docs/release-v1.6.34.ru.md).
- The dashboard client count shows connected clients again, even when Xray access logging is disabled. [Release notes](docs/release-v1.6.34.md).

## v1.6.33 — Reality Guard, VLESS Encryption, mKCP и карта Rebuild / Reality Guard, VLESS Encryption, mKCP and the Rebuild map

Нумерация: номер версии форка = последняя версия оригинала CELERITY, из которой перенесены функции, + 0.0.1. Эта версия основана на оригинале 1.6.32 (новая карта сети) и заменяет внутренний номер 1.5.0.
Numbering: fork version = the latest upstream CELERITY version whose features were ported, + 0.0.1. This release is based on upstream 1.6.32 (new network map) and supersedes the internal number 1.5.0.

### RU

- **Reality Guard:** уведомляет о подтверждённых сбоях публичных целей REALITY на подходящих клиентских нодах `standalone` и `portal`. По умолчанию выключен глобально и на каждой ноде; цели автоматически не меняются.
- **VLESS Encryption:** включается отдельно для клиентских входов Xray. Для аутентификации сервера доступны X25519 и, при наличии поддержки, ML-KEM-768. Без включения подписки не меняются. Сохранение ноды и Apply не меняют шифрование защищённых входов Rebuild.
- **Связи mKCP в Rebuild:** UDP, Xray 26.6.1+ на обоих концах, защита `none` или TLS, не REALITY. Сохраните черновик, проверьте Preview и подтвердите Apply. `cc-agent` 1.5.1 не подтверждает работу mKCP.
- **Карта Rebuild:** Цепочки, Граф и Карта. Новая связь сначала сохраняется как черновик; отмена Preview его не удаляет. Применение только по явному подтверждению. Статус «не проверено» отличается от ошибки и онлайн. В инспекторе можно изменить активную связь. Отмена Preview оставляет правку на карте с пометкой «Есть неприменённые изменения».
- **Firefox и CSRF:** `Referrer-Policy: same-origin` не передаёт реферер вовне. Защищённые операции записи с `Origin: null` требуют `Sec-Fetch-Site: same-origin` и действительный CSRF-токен.

[Памятка оператора](docs/release-v1.6.33.ru.md).

### EN

- **Reality Guard:** reports confirmed failures of public REALITY targets on eligible `standalone` and `portal` client nodes. Off globally and on every node by default; targets are never replaced automatically.
- **VLESS Encryption:** opt-in per Xray client inbound, with X25519 and, where supported, ML-KEM-768 for server authentication. Existing subscriptions stay unchanged when it is off. Node Save and Apply do not change encryption on protected Rebuild inbounds.
- **mKCP links in Rebuild:** UDP, Xray 26.6.1+ at both endpoints, `none` or TLS security, not REALITY. Save the draft, review Preview, and confirm Apply. `cc-agent` 1.5.1 cannot verify mKCP at runtime.
- **Rebuild map:** Chains, Graph, and Map views. New links are saved as drafts; canceling Preview keeps the draft. Apply requires explicit confirmation. Unverified is distinct from error and online. Edit active links in the inspector. Canceling Preview keeps the edit on the map as an unapplied change.
- **Firefox and CSRF:** `Referrer-Policy: same-origin` keeps referrers off external requests. Protected writes with `Origin: null` require `Sec-Fetch-Site: same-origin` and a valid CSRF token.

[Operator release notes](docs/release-v1.6.33.md).

## v1.4.2 — Rebuild, L2TP, API и MCP / Rebuild, L2TP, API and MCP

### RU

- **Второй выход через бридж:** исправление рассчитано только на точную штатную пустую заглушку Xray. Для этого случая не нужна переустановка L2TP ни после новой установки, ни на релеях с L2TP, установленным в v1.4.1. Если заглушку нельзя подтвердить, не заменяйте неизвестный профиль.
- **Результаты действий в панели:** панель показывает подтверждённый результат и обновляет данные запросами на чтение. При неизвестном исходе проверяет его около пяти минут; если подтверждения нет, кнопки остаются заблокированными. Не повторяйте операцию.
- **Install:** показывает реальные этапы, в том числе распаковку и настройку пакетов по отметкам APT. До резервирования установки и действий APT проверяет применённую связь от релея к бриджу и совпадение профиля MAIN с отпечатком Apply. Старым связям без такого подтверждения может понадобиться обычный Apply.
- **Допуск релея:** через консоль провайдера сверяйте фактический тип публичного ключа SSH, SHA-256 от его декодированных байтов и идентификатор машины. Секреты для сверки не нужны.
- **Настройка Xray через API и MCP** использует те же сценарии по ролям, что и панель. Бридж остаётся только выходом (exit-only), без установки `cc-agent` и запуска службы при настройке.
- **MCP:** лимит JSON-запроса не изменился (100 КиБ). HTTP `413` теперь явно просит уменьшить размер запроса.

`cc-agent` остаётся на версии **1.5.1**. [Памятка оператора](docs/release-v1.4.2.ru.md).

### EN

- **Second bridge exit:** the fix is limited to the exact canonical empty Xray placeholder. This case does not require reinstalling L2TP on either new installations or relays installed under v1.4.1. Do not replace an unknown profile if the placeholder cannot be verified.
- **Panel action outcomes:** the panel acknowledges confirmed results and refreshes with read-only requests. If an outcome is uncertain, it checks for about five minutes; if unconfirmed, controls stay locked. Do not retry the operation.
- **Install:** shows actual stages, including unpacking and setup milestones from APT. Before reserving the installation or touching APT, it checks for an applied relay-to-bridge link and a MAIN profile that matches the Apply fingerprint. Older links without that proof may need a normal Apply.
- **Relay admission:** use the provider console to compare the actual SSH public key type, the SHA-256 digest of its decoded bytes, and the machine ID. The comparison needs no secrets.
- **API and MCP Xray setup** follows the same role-specific path as the panel. Bridge setup remains exit-only, without installing `cc-agent` or starting the service.
- **MCP:** the JSON request limit remains 100 KiB. HTTP `413` now tells clients to send a smaller request.

`cc-agent` stays at **1.5.1**. [Operator release notes](docs/release-v1.4.2.md).

## v1.4.1 — Rebuild и L2TP / Rebuild and L2TP

### RU

- **Карта Rebuild:** сохранение связи создаёт черновик. Перед Apply панель показывает, какие профили изменятся. Статус `deployed` означает, что конфигурация применена, а не что трафик клиента уже проходит.
- **L2TP-релеи:** одна учётная запись работает на установленных релеях; адрес клиент получает из пула конкретного релея. Действие «Разрешить L2TP» проверяет SSH-ключ хоста и идентификатор машины. Допуск не запускает Install.
- **Install из панели** может подготовить недостающие пакеты VPN на поддерживаемом Debian 13 amd64 при допуске из БД. **Remove** снимает L2TP с выбранного релея, не удаляя общий справочник учёток. Удаление самой ноды — отдельное действие с предпросмотром и подтверждением последствий для клиентов.
- **cc-agent 1.5.1** сохраняет пользователей Xray при повреждении локального `users.json` и не теряет свежую активность reverse-связи при сбросе счётчиков. Обновление панели не обновляет агентов на нодах.

[Переход с 1.3.3.12: настройки и проверка после обновления](docs/release-v1.4.1.ru.md).

### EN

- **Rebuild map:** saving a link creates a draft. Preview shows which profiles will change before Apply. `deployed` means the configuration was applied, not that client traffic has been verified.
- **L2TP relays:** one account works across installed relays; each relay assigns an address from its own pool. “Allow L2TP” checks the SSH host key and machine ID. Granting admission does not run Install.
- **Install from the panel** can prepare missing VPN packages on supported Debian 13 amd64 relays with a database-backed grant. **Remove** uninstalls L2TP from one relay without deleting the shared account directory. Deleting the node itself has a separate preview and confirmation of client impact.
- **cc-agent 1.5.1** preserves Xray users when the local `users.json` is damaged and retains fresh reverse-link activity evidence across a counter reset. Upgrading the panel does not upgrade node agents.

[Upgrading from 1.3.3.12: settings and post-upgrade checks](docs/release-v1.4.1.md).

## CC Agent 1.5.1

- Preserve Xray users when `users.json` is missing, invalid, or conflicts with the managed clients at startup. Recovery requires a successful full panel `/sync`; `users.json` saves are atomic.
- Preserve fresh reverse-link activity evidence when `/stats` resets billing counters mid-sample. Draining an old balance alone does not establish activity.
- The agent build uses `cc-agent-v1.5.1`, separate from panel `v1.4.1`, and produces Actions artifacts only.

## CC Agent 1.5.0

- **CC Agent 1.5.0** adds authenticated `GET /xray-health`. It checks the local Xray runtime API without resetting traffic counters. `GET /health` still reports agent liveness only.

See the [local Xray status rollout note](docs/xray-runtime-status-rollout.md) for release sequencing.
