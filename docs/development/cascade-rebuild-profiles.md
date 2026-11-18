# Pure rebuild profile contract

`src/modules/relay-l2tp/services/rebuildTopologyComposer.js` exports the synchronous
`composeRebuildProfiles({ nodes, links, usersByNode, affectedNodeIds, panelTls })`.
It uses the normal Xray client generator and the topology hop primitives, not the
strict frozen-deployment planner. It performs no environment, certificate-file,
database, service or network I/O; it does not grant authority to apply a profile.

## Inputs

- `nodes`: hydrated plain/lean Xray descriptors (`id` or `_id`, `type: 'xray'`,
  `role` or `cascadeRole`, `ip`, `port`, `xray`, and any deny ACLs). Preserve the
  actual `xray` settings, including `extraInbounds`, and listener ports. Edges go
  from a portal/relay to a relay/bridge; only bridge nodes terminate the cascade.
- `links`: explicitly admitted **desired** descriptors (`id`/`_id`, `source` and
  `target` or persisted `portalNode` and `bridgeNode`), with real `tunnelUuid`,
  `tunnelPort`, and tunnel settings. String and BSON ObjectId keys work; populated
  endpoint references may contain `id`/`_id`. Reverse is the default; mixed
  forward/reverse is per edge. `active: false` and `lifecycle.state: 'deleting'`
  links are skipped. `status` and `autoDeploy` are **not** admission: pass pending
  links only when explicitly selected for rebuild, not via an all-active query.
- `affectedNodeIds`: exact array of IDs to emit, or omit to select all provided
  nodes. Every desired edge incident to an affected node must have **both** ends
  in scope. The caller supplies the full relevant link inventory and includes
  old endpoints that were detached by the edit. Disjoint components not in scope
  are not emitted. Input array order does not affect graph decisions or output.
- `usersByNode`: a `Map` or object keyed by node ID. Values are already resolved,
  enabled/assigned Xray users with `xrayUuid` and `userId`; a missing key means
  no users. Enrollment, assignment/group resolution and subscription filtering
  remain the caller's responsibility. Users are placed only in real VLESS MAIN
  inbounds, never in tunnel listeners. The normal transport, REALITY/TLS,
  fallback handshake, flow and API generation still applies.
- `panelTls`: if needed, pass the already resolved `{ serverName, certificate,
  key }` (PEM line arrays), obtained outside the pure function. Required for
  `tlsSource: 'panel'` client listeners or tunnel TLS when `tlsServerName` matches
  the supplied panel name. Supply the actual panel name when using TLS tunnels
  so the generator can distinguish panel TLS from remote cert-file TLS. Manual
  node TLS comes from the descriptor; ACME/self-signed modes emit node-local
  cert paths. Treat inputs and output configurations as sensitive.

## Routing semantics

Smaller `CascadeLink.priority` wins (the existing persisted default is `100`).
Each portal/relay applies domain/IP geo rules before its default rule. Geo ties
are ordered by link ID; assign distinct priorities to overlapping geo policies
when priority must decide the winner. Geo-enabled edges need at least one
nonempty selector; they cannot become defaults. Dead geo edges block matching
traffic when there is another usable exit. A default uses the existing
`selectActivePath` duplicate-priority refusal for eligible non-geo successors;
structurally dead successors cannot win. An upstream hop to a geo-only relay can
carry geo traffic, but the relay blocks its own unmatched traffic. No live
health probes, balancing, or automatic failover are performed. `IPOnDemand` is
used for emitted geo IP rules; fully closed nodes omit geo rules and do not
resolve destinations for geo selection. Domain-based policies downstream of a
reverse hop require preserving sniffed hostnames in the actual destination, so
where needed upstream client/forward-hop sniffing uses `routeOnly: false`.

Blackhole is the first outbound. No classic direct/proxy ACL is carried into a
managed profile; only rejects are retained. The only explicit freedom is on a
connected bridge's internal transit, not its MAIN clients. Reverse control
rules are scoped to their link tags before payload policy. Invalid topology,
partial scope and collisions throw; no partial profile array is returned.

## Return value and L2TP handoff

The exact result is `Array<{nodeId: string, profile: 'main' | 'bridge', config:
object}>`: one MAIN and one BRIDGE per affected node. The order is deterministic
but is **not** a deployment order.

| Node | `main` | `bridge` |
| --- | --- | --- |
| Portal / relay | Client/API listeners, all its graph artifacts and routing | Inert cleanup config |
| Connected bridge | Client/API listeners; client traffic blocked | Internal tunnels and explicit transit egress |
| Detached node | Client/API listeners; client traffic blocked | Inert cleanup config |

An inert BRIDGE contains blackhole only and no listeners, reverse blocks or
forward/dialer outbounds. The caller should replace/remove old owned fragments
on **both** profiles, without starting an unnecessary sidecar. In particular,
a relay previously running its graph in BRIDGE requires an owned listener
handoff before starting replacements in MAIN. Physical co-location, port claims
outside these two profiles, compatibility with the installed Xray binary, and
atomicity/rollback of service application are not decided here.

For L2TP: use the affected relay's **MAIN** config. Add the actual local packet
inbound tag to each rule's `inboundTag` whose `ruleTag` starts with exported
`REBUILD_POLICY_RULE_PREFIX` (`rebuild-policy-`), including
`rebuild-policy-default` even when it points to `block`. Prepend any L2TP ingress
protective rules, and give the actual local inbound route sniffing as appropriate
(e.g. copy the relay client inbound's sniffing semantics for downstream domain
routing). Do not add the tag to API/control/legacy ACL rules, do not route it to
a separately selected cascade outbound, and do not include it in the VLESS
user-management inbound list. No L2TP listeners or service changes are made by
this composer.
