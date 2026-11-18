# Режим rebuild

`C3_REBUILD_ENABLED=true` — отдельный режим запуска панели. По умолчанию он
выключен (`false` или переменная не задана). Другие значения отклоняются.
Проверка выполняется после загрузки `.env`, до подключения MongoDB и старта
сервисов. Режим читается из окружения процесса, не из HTTP-запроса.

При включении следующие флаги должны быть не заданы либо равны `false`:

- `L2TP_EXECUTION_ENABLED`, `L2TP_MIGRATIONS_ENABLED`, `L2TP_PRODUCTION_EXECUTION_ENABLED`;
- `TOPOLOGY_TEST_EXECUTION_ENABLED`, `TOPOLOGY_PRODUCTION_EXECUTION_ENABLED`;
- `CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED`, `CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED`.

`TOPOLOGY_TEST_STARTUP_MODE` и `C3_SETTINGS` должны быть не заданы. Последний
включает отдельный режим с зафиксированной схемой настроек; rebuild не входит
в этот контракт. Неактивные параметры (например, список разрешённых связей)
сами по себе ничего не включают.

В rebuild не запускаются L2TP/topology bootstrap, миграции, проверка и
автоматическое создание их схем, admission/recovery workers, физическая
authority или возобновление привязок. HTTP отклоняет строгие пути деплоя,
операций, замены, transfer, активации/возобновления, проверку порта scoped deploy
и L2TP; MCP отклоняет `manage_cascade`. Обычные сервисы запуска, опрос агентов,
cron и `/health` не выключаются. Чтение графа и подписок остаётся доступно;
проверки владельцев конфигурации не отменяются. `/health` не подтверждает
готовность rebuild-writers или передачу владения.

**До интеграции rebuild-writers режим не готов к эксплуатации.** Apply/Delete,
создание/редактирование связей, изменения групп маршрутов и legacy undeploy
пока отклоняются, не переходя в старые обработчики. Запись через старый
`withClassicNodeConfigWrite` также отклоняется, а не идёт по ветке без блокировки;
записи полных профилей Xray через этот шлюз пока недоступны. Режим не выполняет
handback, не снимает существующие блокировки и не меняет защищённость classic
при выключенном флаге.

## Точки интеграции writers

- `src/routes/cascadeTopologyDeploy.js`: Apply и reconcile идут через
  `POST /api/cascade/topology/deploy`; остальные strict-пути не разблокировать.
- `src/routes/cascadeLinks.js`: CRUD и auto-apply; `src/routes/cascade.js` и
  `src/mcp/tools/cascade.js`: альтернативные входы удаления/undeploy.
- `src/services/syncService.js`: `updateXrayNodeConfig` →
  `withClassicNodeConfigWrite`; отдельные callers того же шлюза есть в
  `cascadeService.js` и `accessLogs/provisionService.js`. Для выбора нового
  writer используйте `isRebuildEnabled()` из `src/services/rebuildMode.js`.
- `src/routes/cascadeRouteGroups.js`: отдельная точка интеграции, если нужна
  запись групп без strict lifecycle.
