# L2TP Follow Relay v1: контракт rebuild

`follow-relay` — режим маршрутизации **установленного** PPP на relay. Он не устанавливает L2TP и не делает профиль готовым к трафику. Обычные клиенты relay и PPP используют один локальный SOCKS-вход в `xray-bridge`: ветки domain/geoip и default определяет один набор правил графа.

## Выбор режима и зависимости

- Без `routingMode`/`routingVersion` или с `routingMode: 'route-group'` без версии остаётся строгий legacy. Для него установленному состоянию по-прежнему нужен `routeGroup`.
- Rebuild выбирает `{ routingMode: 'follow-relay', routingVersion: 1 }` явной парой. Неподдерживаемая пара отклоняется (`L2TP_ROUTING_SELECTION_INVALID`). `routeGroup` и `activePathKey` существующей записи не надо стирать: они нужны для идентификации прежнего фрагмента и отката, а не для выбора нового выхода. Для follow-relay без прежней группы `routeGroup` необязателен.
- `TopologyDraftRepository.readDraft(session, { rebuildL2tp: true })` возвращает `followRelayStates` отдельно от `activeRouteGroupIds`, `installedRouteGroupIds` и `installedRouteOwners` legacy. Список `groups` не меняется. `partitionRebuildL2tpStates(states)` делает то же разделение для уже прочитанных записей. Оно не даёт права менять/удалять группы, которые могут использоваться другими политиками, и не заменяет независимые проверки installed PPP, пользователей и ревизий. `readDraft(session)` сохраняет прежний контракт.

## Вызов компоновщиком rebuild

```js
const {
    applyFollowRelay, REBUILD_RELAY_INGRESS_TAG, FOLLOW_RELAY_OUTBOUND_TAG,
} = require('./src/modules/relay-l2tp/services/l2tpFollowRelay');

const result = applyFollowRelay({
    nodeId, state, main, bridge, routeState,
    ingressTag: REBUILD_RELAY_INGRESS_TAG,
    controlPlaneAddresses,
});
```

| Аргумент | Контракт |
|---|---|
| `nodeId`, `state` | Идентификатор relay и его запись (`node`, `status`, `desiredState`, `secretRevision`, `tproxyPort`, `routingMode`, `routingVersion`, возможно `routeGroup`, `activePathKey`). Для follow-relay должны совпадать `node` и `nodeId`, оба статуса должны быть `installed`; также нужны положительная credential revision и корректный TPROXY-порт. |
| `main`, `bridge` | Разобранные JSON-объекты кандидатов, не байты и не строки. Кандидат bridge формируется из **нового** графа, а не восстановлением ранее выбранных правил. При `detached` `bridge` может быть `null`; если он есть, в нём уже не должно быть общего ingress. |
| `routeState` | `egress_configured`: shared policy с единственным завершающим правилом на явный туннель или reverse portal; `no_bridge_exit`: блок PPP в MAIN и всего общего ingress в bridge; `detached`: блок PPP в MAIN, без локального SOCKS-outbound L2TP. Это состояния конфига, не статусы трафика и не результат проверки линка. |
| `ingressTag` | Явный стабильный тег от владельца графа, по умолчанию `rebuild-relay-ingress`. Для подключённого relay владелец графа выпускает в bridge ровно один SOCKS `127.0.0.1:<стабильный порт>` (`auth: 'noauth', udp: true, ip: '127.0.0.1'`), привязывает policy к этому тегу и маршрутизирует обычных клиентов MAIN на тот же listener через свой отдельный outbound. Порт не должен зависеть от ID линка; коллизии кандидатов проверяются, а выбор/резервирование порта между поколениями остаётся обязанностью графа. |
| `controlPlaneAddresses` | Непустой список известных адресов управления: IPv4/IPv6, CIDR и имена хостов ASCII. Передавайте и имя, и известные IP адреса соответствующего endpoint; helper не обнаруживает их сам. IP и домены блокируются раздельными правилами, защищёнными также от совпадения с reverse control. |

При legacy вызов возвращает неизменённые `{ main, bridge, applied: false }` и не интерпретирует новые параметры. При follow-relay возвращаются `{ main, bridge, applied: true, inboundTag, routeState }` на копиях. Ошибка `L2TP_FOLLOW_RELAY_*` означает, что кандидаты не должны публиковаться. Существующий TPROXY сохраняется; в чистом MAIN он может быть восстановлен по установленному состоянию. Стабильный SOCKS-outbound в MAIN — `rebuild-l2tp-handoff`. Выход выбирает bridge, в котором включается локальный sniffing HTTP/TLS/QUIC с `routeOnly: true` и `IPOnDemand`. Метаданные sniffing из другого процесса не считаются переданными через SOCKS. Reverse control на своих входах не переписывается.

MAIN-правила, относящиеся к прежнему PPP-входу, заменяются, а не дополняются; у общих правил сохраняются остальные `inboundTag`. Удаляется только распознанный старый per-path SOCKS, если ни одно оставшееся правило на него не ссылается. Остальное — серверные inbounds с их пользователями, PPP/CHAP и PSK, pools, firewall, `fwmark` и `routeTable` — helper не меняет.

## Проверка и границы интеграции

Локальные тесты покрывают first-match для обоих входов, domain/IP/default, private/control-plane, reverse, повторную композицию, замену выхода, `no_bridge_exit` и `detached`, сохранение серверного ingress/TPROXY и отделение legacy-групп. First-match в тесте — модель маршрутов, не Xray-процесс. Не проверялись парсер Xray, реальный DNS/SOCKS UDP, PPP/IPsec, REALITY или фактический egress.

Здесь нет вызова из глобального composer/API, активации режима в БД, оркестрации выкладки двух профилей, readback или миграции. Интегратор обязан сохранить fenced проверки PPP и legacy-групп, исключить legacy writers для переключённого relay и не считать конфиг доказательством трафика. Для выхода из `no_bridge_exit`/`detached` необходимо заново сгенерировать bridge из актуального графа; старый policy не восстанавливается.
