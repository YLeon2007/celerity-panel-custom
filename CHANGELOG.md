# Changelog

## Unreleased

- Xray setup fails if the final authenticated agent probe confirms the runtime API is down after a requested restart. No cascade redeploy or wizard completion follows that failure. Setup without a restart can still complete while Xray is offline.
- Missing or unusable Xray health proof is reported as `unknown`, not as an outage. Setup reports an explicit warning; the node does not show as online, its online-user count is cleared, and no `node.offline` webhook is emitted for an unsupported or invalid probe.

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
