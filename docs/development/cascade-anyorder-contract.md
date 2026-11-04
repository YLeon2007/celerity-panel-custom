# C³ any-order: минимальный контракт реализации

Статус: **контракт для локальной реализации, не реализованная возможность и не разрешение PROD**.
Нормативный источник — «C³: каскадные связи в произвольном порядке», v1.0 от 04.11.2026, SHA256 `eee6de838596972d10aba559bfaf52a228676c32e281ac35942cba35e983a282`. Требования ТЗ сохраняются; этот документ выбирает существующие точки изменения, а не добавляет архитектуру.

## 1. Исходная точка и один рекомендуемый путь

- Проверенная локальная база: `ef3f04773271e01b0011e8164ae7b5fdc62760e6`.
- Ранее проверенный serving-source: `5ffd42ca210609006c5855d1f75b50e532e710da`. По ТЗ там выбран **classic**, native topology выключен. Свежий снимок PROD в этой работе не получался.
- Наличие `TopologyOperationCoordinator`, worker, native executor и recovery в исходниках **не означает**, что этот путь включён или принят на PROD. `src/modules/relay-l2tp/index.js:createTopologyDeploymentService()` выбирает classic при его явной конфигурации; иначе строит native runtime. Ошибка native не разрешает fallback на classic.

**Рекомендация:** расширять имеющийся scoped topology-operation pipeline для выбранных ресурсов: HTTP → долговечное намерение → `TopologyOperationCoordinator.queue()` → `TopologyOperationPlanMaterializer.materialize()` → `composeFrozenTopologyDeploymentPlan()` → существующие worker/executor/finalizer. Сохранить classic для ещё не переданных ресурсов. Не строить второй any-order executor поверх `deployLink()`/`deployChain()` и не превращать их в скрытый full Sync.

Это путь реализации кода, а не команда включить native флаг. Передача существующих профилей и обратный handback — отдельная ограниченная миграция по §8 ТЗ после стенда. Использовать существующие ownership/binding/runner API без нового controller, namespace, security layer, очередного фонового recovery-сервиса или смены инфраструктуры. Если выбранный профиль ещё принадлежит classic, native не получает право записи от HTTP-флага, смены роли или наличия строки операции.

### Что именно даёт delta `5ffd42… → ef3f047…`

| Подготовленное изменение | Переиспользование и граница |
| --- | --- |
| `classicPortalBridgeAdmission.js:withScopedClassicNodeLocks()`, `createScopedClassicExecutionContext()`; `classicNodeConfigWrite.js:withHeldScopedClassicConfigWrites()` | Общие node locks, проверка поколения, вложенный held-контекст, разделение предdispatch/неизвестного результата. Это механизм исключения writers, не новый durable job и не разрешение на topology adoption. |
| `classicScopedCascadeDeploymentService.js:runQueue()` independent-ветка; `cascadeService.js:deployScopedClassicLink()` / `removeScopedClassicLink()` | Только standalone root portal → terminal bridge, reverse, без затронутого L2TP/route group. Другая роль, transit, второй исходящий участок релея и forward не становятся поддержанными от удаления `throw`. `CLASSIC_DEPLOY_NODE_BUSY` сейчас отказ, не очередь. |
| `classicPortalBridgeBootstrap.js`, вызовы из `cascadeService.js` | Подготовка отсутствующего bridge-профиля; сохранение MAIN, checked receipts/readback, preflight provenance. Не переносить bootstrap механически в native executor; использовать его собственный существующий prepare. |
| `topologyDraftRepository.js:mutationNodeIds()`, `isStandaloneClassicMutation()`, `commitDraft()`; factory в `topologyDraftWriteService.js` | Вычисление изменяемых node dependencies и исключение draft-writer. Обход глобального fence разрешён только доказанно standalone classic-компоненту; он не распространяется автоматически на R/L2TP. |
| Route error projections, `network.js`, шаблоны/assets | Сохранить безопасные публичные ошибки и отсутствие ложного native job у синхронного classic. Они не доказывают any-order или клиентскую готовность. |

Конфликты при переносе: независимая classic-ветка повторно проверяет собственные pins, но native admission/finalization всё ещё привязаны к singleton revision/count. Их нужно менять согласованно, а не копировать исключение только в один запрос. Classic допускает terminal Hysteria bridge через `classicScopedEndpointSupport.js`, тогда как native metadata-фильтры рассчитаны на Xray: не менять тип узла ради обхода и не объявлять эту совместимость автоматически перенесённой.

## 2. Фактические seams и конкретные пробелы

Все пути ниже относительно корня C³; `M/` означает `src/modules/relay-l2tp/`.

| Слой | Существующий API | Требуемая дельта |
| --- | --- | --- |
| HTTP create/save | `src/routes/cascadeLinks.js:createCascadeLinksRouter()`, POST/PUT, `queueAutoDeploy()` | Сейчас classic сохраняет draft и применяет синхронно через временную creation capability; native `TopologyIntentService.accept()` пока сохраняет payload намерения, а строку связи создаёт consumer позже. Нужны атомарные link+intent и общий контракт Auto/manual. |
| HTTP manual/delete | `src/routes/cascadeTopologyDeploy.js`, POST `/deploy`, GET `/operations/:operationId`; DELETE links | Manual уже передаёт `scope:{kind:'link.apply',linkId,linkIds}`. Native DELETE сейчас вызывает draft-only `deleteLink()`; полноценного `link.delete` в operation kinds нет. |
| Выбор baseline | `cascadeLinks.js:selectLinkApplyBaselineLinkIds()`, `M/services/topologyIntentConsumer.js:baselineIds()`, `M/services/topologyOperationCoordinator.js:applyScopeToTopology()` | Уже исключают чужие pending и обходят confirmed-соседей. Но статус не хранит последнюю применённую версию параметров; три реализации не должны расходиться. |
| Admission/operation | `M/repositories/topologyDeploymentRepository.js:admitTopology()`, coordinator `queueOnce()`, `M/repositories/topologyOperationRepository.js:createFrozen()` | Операция и admission уже сохраняются в одной Mongo-транзакции, до запуска worker. Сейчас долгий глобальный fence требует `remoteAdmissionCount:0`, `topologyAdmissionCount:0`; заменить для новых selected-операций, сохранив legacy-ветку. |
| Граф/план | `M/domain/topologyDraft.js:buildCandidate()`, validator/compiler; materializer `projectPinnedSnapshot()`; frozen composer | Materializer требует портал; staged разрешён только bridge-less `link.apply`; composer умеет prefix, fan-in, geo и mixed, но не общий source-less suffix/удаление. `coordinator.nodeIdsByRef()` также ходит от портала: починка composer без этого seam недостаточна. |
| Apply/recovery | `M/workers/topologyOperationWorker.js:run()`, `durablePlan()`, `acquireLocks()`, prepare/commit/verify/rollback; `M/runtime/createTopologyOperationRecoveryLifecycle.js` | Переиспользовать frozen plan, backup IDs, exact lock generations и recovery scan. Не создавать второй механизм retry удалённой записи. |
| Settlement | `M/services/topologyOperationFinalizer.js`; `M/repositories/topologyOperationFinalizationRepository.js:finalizeSucceeded()` / `finalizeRolledBack()`; `M/repositories/topologyV2Settlement.js` | Scoped success уже не продвигает глобальный `deployedRevision`, однако обе ветки settlement ещё требуют exact global revision/count. Добавить selected-resource publication и delete, не ослабляя terminal readback. |
| Runtime | `M/runtime/createTopologyOperationRuntime.js:createTopologyOperationRuntime()`, `src/modules/createL2tpPanelHost.js` | Уже собирает реальные user-resync, PPP и attach gates, executor и worker; host связывает intent consumer с recovery. Новые seams обязаны доходить сюда, не существовать только в тестовом coordinator. |

## 3. Общее состояние: desired ≠ applied ≠ health

### Минимальная модель, без нового хранилища/сервиса

1. **Desired** остаётся в `CascadeLink` и `CascadeRouteGroup`. Save-only изменяет только это состояние; ни remote apply, ни переключение установленного PPP-пути не запускаются. `autoDeploy:true` не является постоянным разрешением применить строку после рестарта.
2. **Applied baseline** — последний подтверждённый snapshot конфигурационно значимых узлов/связей/политик и профилей выбранной области. Хранить private `baselineTopology` и `effectiveTopology` в существующей `TopologyOperation` рядом с frozen candidates; ссылки на последний settled operation использовать из существующего `src/models/topologyConfigOwnerModel.js:lastSettledOperation`. Не заводить параллельную таблицу applied-graph. Snapshot содержит именно параметры применённой версии, а не перечень ID, повторно гидратируемый из изменяемого desired.
3. **Новые private поля операции:** `admissionScope:'selected'`, `resourceNodeIds`, `baselineTopology`, `effectiveTopology`, pin/version затрагиваемых desired и owner/route-group данных. Идентичность плана/поколений/backup и `admissionFingerprint` переиспользуются. Отсутствие `admissionScope` означает старый глобальный протокол, а не автоматически selected.
4. Для save-only edit уже применённого ребра соседний Deploy использует его **старый applied descriptor**, не новые desired-параметры. Сохранённая правка не стирает applied snapshot. `pending`, `offline`, `error` не доказывают отсутствия прежнего dispatch; deployed/online/staged сами по себе не заменяют readback/settled baseline.
5. Старый classic профиль без такого snapshot импортируется только при ограниченной сверке реально управляемых элементов. Отсутствующий `lastSettledOperation` не разрешает считать текущий desired подтверждённым. Не изобретать фиктивную успешную операцию/клиентский probe.
6. Операционная успешность, применённость конфига, tunnel state, полнота маршрута и клиентская проверка — разные поля. Глобальные `revision/deployedRevision` остаются snapshot/UI-номерами; scoped success не означает, что вся панель применена.

### Единственная функция отбора effective topology

В `topologyOperationCoordinator.js` расширить/выделить чистую функцию из `applyScopeToTopology()`; HTTP/consumer передают намерение, а не авторитетный список разрешённых соседей. Контракт результата: `{baselineTopology,effectiveTopology,resourceNodeIds,affectedGroupIds,routeState}`. `nodeIdsByRef()` и materializer используют один порядок/идентичность из этого результата, без независимой догадки о portal-root.

- Взять подтверждённый applied component/profile baseline.
- Наложить **одну явную мутацию**: apply указанной версии выбранного ребра либо remove выбранного ребра. `domain.reconcile` остаётся отдельной явной командой.
- Включить все уже применённые участки, входы и route groups, необходимые для сохранения общих профилей. Чужие сохранённые pending, отключённые и неприменённые правки соседей не активировать.
- Область — объединение старого и нового графа/профилей. Для удаления она не уменьшается до оставшегося ребра и не теряет оторванные endpoint/suffix.
- Полный desired-граф проверять при сохранении на реальные структурные ошибки. Неполнота допустима. Перед apply проверять effective graph и политики; глобальные циклы проверять по всем рёбрам, включая geo, а не только внутри paths групп.
- `P→R` без выхода применяется с block для каскадного трафика. `R→B` без P применяется как подготовленный suffix; PPP на R может иметь полный собственный путь. Наличие роли bridge не делает любой вход ready.
- Несколько выходов используют существующие priority/geo/route-group policy. Сохранять явные `pathKey`, приоритеты и порядок политики, не выбирать default по случайному link/operation ID. `routePolicy.selectActivePath()` сейчас блокирует duplicate priority: это неоднозначность, не разрешение случайно выбрать выход. Не вводить новый алгоритм балансировки/failover. При неоднозначности сохранить/подготовить ветку, сохранить допустимый старый default либо block и показать причину.
- Forward/reverse вычисляются по ребру; listener — target для forward, source для reverse. Не менять роли/ключи/режимы неизменённых связей. Semantic comparison в тестах исключает случайные ID, но не изменение exit policy.

## 4. Selected-resource admission и все writers

**Первый допустимый granularity — целый физический узел**, включая MAIN/bridge профили, общие services/listeners и меняемые сетевые правила. Не вводить сейчас новый универсальный resource-lock framework. Route group расширяет union до её реально затронутых owners/путей; другие owners той же группы не переписываются. Физическая идентичность берётся из существующих node execution/owner данных (`nodeIdentity`), а не из имени/IP; известные aliases одного сервера не должны занять независимые lock slots.

Порядок для новых selected-операций:

1. До remote-write claim: формат/права, узлы/версии, структура и политика, вычисление union, ownership, генерация candidate и предсказуемые несовместимости. Read-only SSH/port preflight — вне Mongo-транзакции; недоступность не означает «свободен».
2. Короткая транзакция регистрирует durable intent/operation и её selected pin. Занятый пересекающийся ресурс означает сохранённое ожидание, а не потерю принятого запроса. Глобальная DB CAS допустима только для короткой сериализации.
3. Worker получает existing `NodeOperationLockService` locks в стабильном порядке и проверяет каждый результат: нынешний `acquireMany()` возвращает общий `ok:true` даже при конфликте отдельного acquire. Не принимать общий флаг за факт получения всего union; уже взятые, доказанно недиспетчеризованные locks освобождать корректно.
4. Под locks повторить mutable version/ownership/baseline и listener-проверки. До dispatch можно ограниченно пересобрать ещё не отправленный план по новому независимому snapshot. После возможной записи frozen plan не подменять.
5. Фиксировать dispatch до первой изменяющей команды, включая stage/bootstrap. При подтверждённом no-dispatch отказе отпустить свои ресурсы; после неизвестного результата удержать **свои конфликтующие** ресурсы и read-only reconcile существующим recovery. Возраст/lease timeout не доказательство завершения.
6. После exact readback публиковать effective applied snapshot и settled pointer только затронутых профилей/политик. Независимое изменение global revision не делает эту публикацию ложной. Не снижать и не обнулять чужие legacy admission counters/reservations.

**Согласованные изменения обязательны** в `topologyDeploymentRepository.admitTopology()`, `topologyDraftRepository.commitDraft()`, consumer `claim()/consume()/settle()`, operation/finalization repositories и `topologyV2Settlement.js` (включая `checked()`, `settle()` и `probe()`), а не только в route filter locks. `TopologyOperationRepository.findPublicById()` и `cascadeLinks.readLinkSnapshot()` также должны проверять актуальность selected proof по затронутому snapshot, не объявлять его stale от любой независимой revision и не переносить proof на изменённый ресурс.

Точный ограниченный перечень конкурирующих writers, которым нужен тот же node/profile admission:

- `src/services/syncService.js` и `src/services/cascadeService.js` через `classicNodeConfigWrite.js` / `topologyConfigOwnership.js`;
- `src/modules/l2tpRuntimeLifecycleHook.js`, `M/services/l2tpSimpleService.js`, `M/repositories/remoteAdmissionRepository.js` для install/uninstall/sync-users;
- topology worker, recovery и `autoL2tpPathMaintenance.js` / draft route-group writers.

Сохранить существующие permanent owner veto и held-lock adapters. В `remoteAdmissionRepository` заменить глобальное исключение topology только в доказанно selected-ветке с node conflict checks; старый глобальный admission не переинтерпретировать. Миграционный drain остаётся явным глобальным режимом, не обычным CRUD. Не фильтровать одну `exists({})` и оставлять остальных writers с несовместимым допуском.

## 5. Create intent, manual apply и очередь

Расширять `TopologyIntentService.accept()` / `TopologyIntentConsumer`, модели `topologyCreateIntentModel.js` и `topologyIntentQueueStateModel.js`; новую очередь/брокер не создавать. Для новых записей использовать явный versioned payload (`version:2`, `kind:'link.create'|'link.apply'|'link.delete'`, `linkId`, запрошенная desired-version); существующие `version:1` остаются create-only и обрабатываются по их прежнему контракту, не создавая связь повторно.

- Auto create: одна транзакция валидирует/сохраняет desired-link через существующий draft service **и** intent с тем же `createdLinkId`. Consumer больше не создаёт второй экземпляр ссылки. Ответ после durable commit содержит ID ссылки и job; operation ID добавляется после materialization. Нельзя ответить `desiredSaved:true`, пока сохранён только payload.
- Manual Deploy: тот же admission/consumer/worker для `{kind:'link.apply',linkId,desiredVersion}` без link.create. PUT с явным AutoDeploy регистрирует такое же намерение; обычный PUT не запускает apply. `queue()` остаётся внутренней точкой материализации, не отдельным синхронным any-order обходом.
- Идемпотентность — persisted request key + нормализованный пользовательский payload, до случайной генерации UUID/REALITY. Повтор возвращает те же link/job/operation IDs; другое содержимое с тем же ключом — 409. Не полагаться на `operationsByIdempotencyKey` Map или classic creation capability после рестарта.
- До принятия устаревшая форма/переполнение очереди дают понятный отказ без принятого job. После принятия независимая global revision не уничтожает intent; пересчитать ещё не отправленный baseline. Изменение самой запрошенной версии даёт видимый version conflict, не скрытое применение новых параметров.
- Сохранить имеющиеся capacity/maxAttempts/backoff. Очередь упорядочивает пересекающиеся ресурсы; consumer выбирает ограниченное число earliest eligible jobs, не останавливает всю панель на одном busy/blocked head. Ожидание ресурса не расходует attempts удалённой записи. Для одного общего ресурса порядок принятых явных действий не меняется.
- Job → operation binding, транзакционная атомарность и majority-readback неизвестного commit сохраняются. Worker стартует только после commit; existing recovery подбирает принятые операции после рестарта. Автоповторы разрешены для чтений/генерации/известного transaction abort до dispatch, не для неизвестного remote commit.

## 6. Delete/recreate — та же операция, не draft-only обход

Добавить `link.delete` в scoped kind allowlists `topologyOperationModel.js`, coordinator, operation repository, materializer, worker durable scope, finalizer/settlement и публичную projection. Не путать `linkIds` effective candidate с удаляемым `linkId`: последний может отсутствовать в итоговом графе, а after-graph может быть пустым.

- **Доказанно никогда не применённый draft:** можно удалить транзакционно без SSH только после проверки applied snapshot, операций и dispatch history. Один `status:'pending'` этого не доказывает. Не удалять draft с ожидающим accepted apply без явного согласованного результата этого intent.
- **Применённый/имеющий dispatch-history:** атомарно сохранить delete intent и служебную tombstone, исключить ребро из desired-effective, оставить прежние applied descriptors/профили до settlement. Использовать небольшой явный lifecycle marker на `src/models/cascadeLinkModel.js` (ссылка на delete job), не перегружать tunnel health `status`.
- Скомпоновать состояние без ребра для **всего старого/new union**, включая detached nodes и очистку последнего ребра. Пустой after-graph требует cleanup-кандидатов по старому профилю, а не ошибки «нет портала/связей» и не отсутствия плана.
- Генерация удаляет только принадлежащие ребру listener/tags/routes; сохраняет все соседние связи, пользователей, чужие фрагменты и используемые службы. No-op не restart. Проверить отсутствие удалённых элементов и сохранность оставшихся до физического удаления строки/finalization.
- Удаление среднего ребра оставляет остальные применёнными, но маршрут неполным; удаление единственного выхода после предупреждения ставит block, не скрытый direct и не вечный last-known-good удалённого пути. Fallback допустим только по существующей политике.
- При timeout/пропавшем узле tombstone и job остаются видимыми; conflicting recreate ждёт сверки. После подтверждённой очистки строка может исчезнуть, операция остаётся доказательством. Recreate с новым request key на прежнем или другом свободном порту не наследует orphan fragments/старый job.
- `topologyDraft.buildCandidate()` сейчас запрещает удаление installed-route link через `assertLinkNotInInstalledRoute()`. Оставить запрет у чистого draft writer, но дать operation-owned delete подготовить candidate/route-group effects и завершить их атомарно после readback. Публичный `force` для обхода не добавлять.

## 7. L2TP — вход в effective graph, не глобальный veto

Переиспользовать `l2tpSimpleService.prepareConfiguredRelayIngress()`, coordinator `deriveScopedAttach()` / `link.attach` / `link.replace`, composer `relayPathIngress()`, `topologyAttachIngressGate.js`, `topologyPppReadinessGate.js`, `topologyUserResync.js`. Их существующая форма покрывает ограниченный attach/replacement, не все изменения каскада.

- Сохранить route-group ID/`activePathKey`, других owners общей группы, PPP users/credentials/PSK/pools/DNS/firewall/install state, Xray пользователей и назначения. Обычный CRUD не вызывает uninstall/install либо ручной Sync users.
- Нынешний `prepareConfiguredRelayIngress()` отказывает установленному пути с `PREPARED_INGRESS_REQUIRED`, а `maintainAutoL2tpPaths()` всегда откладывает изменение установленного пути (`ingressPrepared=false`), включая пустой. Починка maintenance без runtime handoff не завершает FR-09.
- Для установленного owner строить proposed path в той же selected operation, подготовить соответствующий ingress и проверить его существующими gates. Только finalizer публикует затронутый path и `appliedTopologyRevision` под owner/credential versions; не переписывает всю `paths` общей группы. Пока новый путь проверяется, сохранить допустимый прежний applied путь.
- Явный delete последнего выхода — исключение из сохранения старого пути: операция применяет блокирующий маршрут, сохраняет установленную группу/пользователей и фиксирует «нет выхода». Это успешное удаление конфигурации, не failed Deploy из-за невозможности PPP Internet probe.
- Source-less `R→B` не означает «PPP не проверять»: на R уже может быть L2TP. Недостающий portal-вход и недостающий PPP-egress — разные причины. Расширение `staged` не должно безусловно пропускать PPP gate, как для нынешнего bridge-less prefix.
- MAIN и bridge профили на одном сервере не должны одновременно захватывать клиентские listeners/API/порты. Native composer уже отделяет role-profile и strip server inbounds; сохранить этот контракт и неизменённый профиль при совместной композиции.
- Save-only не вызывает path cutover. Maintenance остаётся ограниченным desired-maintenance, не самостоятельным переключателем установленного маршрута. L2TP на независимом X не мешает A/B. Не удалять same-profile ownership veto до доказанной композиции.
- Отдельные результаты проверки Xray/VLESS/REALITY и PPP; серверный SOCKS не заменяет настоящий PPP-клиент. Применённая конфигурация может быть unverified; нулевой downtime не обещается.

## 8. Минимальный API/UI-контракт

Сохранить `/api/cascade/links`, `/api/cascade/topology/deploy`, существующие job/operation polling endpoints. Добавления ниже — **целевой контракт**, не описание уже возвращаемых полей.

| Событие | Ответ/поведение |
| --- | --- |
| Save-only create/update | 201/200, существующий snapshot + `createdLinkId` при create, `desiredSaved:true`; никаких job/apply/cutover. |
| Auto create / manual Deploy / applied DELETE принято | 202; `linkId` (для create также `createdLinkId`), `desiredSaved`, `job:{jobId,kind,linkId,status}`; `operationId` только когда действительно существует. Auto create сохраняет совместимый `autoDeployJob` alias с тем же jobId, без второй задачи. |
| Ожидание/работа | Job polling возвращает точную job identity, затем bound operation ID. Operation polling: существующие `status`, `topologyRevision`, отдельно `phase`, `waitingReason`, `nodeId/linkId`, `nextAction`. `status` enum worker сохраняется; «waiting/reconcile» не маскируются как failed/ready. |
| Итог/список links | Безопасная projection `applicationState` (`not_applied/applying/applied/deleting/reconcile_required`), `routeState` (`complete/no_portal_input/no_bridge_exit/policy_ambiguous`), `tunnelState` (`unknown/connected/disconnected`), существующий `clientReadiness` и отдельные PPP/Xray proof outcomes. Поля связаны с applied operation/pin, не с любой последней revision панели. |
| Delete завершён | 200 для доказанно draft-only либо terminal job после физического удаления; до этого стрелка/tombstone видна как «Удаляется»/«Ожидает сверки». Повтор DELETE с тем же ключом возвращает тот же результат. |
| Отказ до принятия | 400/409/503 с безопасными `code`, `phase`, затронутым ID и `nextAction`; переполнение не выдаётся за accepted. Ни SSH text, ни config/секреты/stack в HTTP. |

В `public/js/network.js` адаптировать `onAddLinkSubmit()`, `handleLinkAutoDeploy()`, `startIntentPolling()`, `deployTopology()`, operation polling и delete action. После принятия — polling точного ID, не повтор POST и не общий Sync. Статус incomplete нейтральный/предупреждающий: «Применено; нет входящего пути от портала» / «Применено; нет выхода к бриджу». Удаление единственного выхода/пути пользователей предупреждает о последствиях; роли и L2TP не переустанавливаются. Сохранить позиции/масштаб карты. Обновить реально используемые локализации/шаблоны и сгенерировать `public/js/network.min.js` штатным assets build. API/MCP callers адаптируются к 202/delete job, синхронный legacy classic результат не переименовывать в выдуманную queued operation.

## 9. Ограниченные implementation slices и зависимости

| Срез | Владелец файлов / конкретный выход | Зависит от |
| --- | --- | --- |
| G: pure graph/composition | `M/domain/topologyDraft.js`, `topologyValidator.js`, `topologyCompiler.js`, `topologyReplacement.js`; `M/services/topologyOperationPlanMaterializer.js`, `frozenTopologyDeploymentPlanComposer.js`. Source-less suffix, prefix, multi-exit, mixed, block при отсутствии выхода; стабильная политика; cleanup из before/after union. Отдельные pure regression fixtures. | Этот контракт; можно выполнять первым. |
| R: selected scope/applied/admission | `M/services/topologyOperationCoordinator.js` (включая `nodeIdsByRef`), `M/models/topologyOperationModel.js`; `M/repositories/topologyDeploymentRepository.js`, `topologyOperationRepository.js`, `topologyDraftRepository.js`, `topologyOperationFinalizationRepository.js`, `topologyV2Settlement.js`; `M/workers/topologyOperationWorker.js` (`durablePlan()/acquireLocks()` используют полный resource union), existing node lock service, `remoteAdmissionRepository.js`, `src/services/classicNodeConfigWrite.js`, `topologyConfigOwnership.js` и названные writer callers только для общего admission. Сохраняемый before/after, явный selected marker, независимые узлы не блокируются чужой операцией, legacy fences не обнуляются. | G для плана; без независимой правки finalization в параллель. |
| I: durable create/manual intents + HTTP | `M/services/topologyIntentService.js`, `topologyIntentConsumer.js`; обе intent models; `src/routes/cascadeLinks.js`, `cascadeTopologyDeploy.js`; `src/modules/createL2tpPanelHost.js`, `M/runtime/createTopologyOperationRuntime.js`, existing recovery lifecycle — только wiring. Атомарные link+intent, идемпотентность, per-resource ожидание без head-of-line всей панели; один путь Auto/manual. | Общий output R; route/consumer не дублируют effective selector. |
| D: delete/recreate | `src/models/cascadeLinkModel.js` tombstone; route DELETE; kind/scope extension в coordinator/model/repositories/worker/finalizer; G cleanup hooks. Durable remove, empty after-graph, readback до row delete, повтор/recreate без сирот. | G+R+I. Те же coordinator/finalization/route файлы — последовательный merge, не отдельные одновременные владельцы. |
| L: installed L2TP cutover | `M/services/autoL2tpPathMaintenance.js`, `l2tpSimpleService.js`, `topologyAttachIngressGate.js`, `topologyPppReadinessGate.js`, `topologyUserResync.js`; composer ingress и finalizer handoff, runtime wiring по согласованному merge. Existing owner-aware protocol для proposed suffix/delete, сохранность PPP/REALITY. | Pure preservation tests параллельно; runtime cutover после G+R, delete outcome после D. |
| U: UI/совместимость | `public/js/network.js`, `network.min.js`, фактические шаблоны/locales; `scripts/test-network-anyorder-ui.js`, существующие layout/UI tests; module selector tests. Реальные Auto/manual/delete jobs, truthful readiness, layout и classic compatibility. | API shape I/D фиксируется до продуктовых UI edits. |

Не включать в эти срезы массовую миграцию, эксплуатационный recovery PROD, новый controller/runner transport, kernel/netns, смену credentials или общего security perimeter. При обнаружении несовместимости указать конкретный требуемый сценарий и seam; не запускать отдельный широкий аудит.

## 10. Проверка и граница завершения

Для документа выполнена проверка исходных seams и delta; продуктовые тесты/SSH/БД/браузер здесь не запускались. `git diff --check` — обязательная локальная проверка артефакта.

Работники реализации запускают **узкие изменённые suites**, а не повторяют неизменённый полный набор. Минимальный локальный выход: фактические POST/manual/DELETE service seams в `cascadeAnyOrderLifecycle.test.js` / `cascadeAnyOrderDeletion.test.js`; все перестановки G1–G3, включая `R→B1; R→B2; P→R`, save-only/pending exclusion, удаление каждого ребра/recreate, стабильная policy, mixed modes, L2TP preservation, independent busy и неизвестный dispatch. Проверить runtime wiring, не только прямой composer вызов. Для selected admission/finalization требуются изолированные transactional Mongo fixtures, без production env.

Остальные G4–G7 и аварийные случаи остаются матрицей ТЗ; этот контракт их не отменяет. Реальные Xray/SSH, браузер, VLESS/REALITY, настоящий PPP, migration/rollback — отдельные явно разрешённые стендовые этапы. Зелёный pure/modelled тест не закрывает их и не означает «PROD исправлен».
