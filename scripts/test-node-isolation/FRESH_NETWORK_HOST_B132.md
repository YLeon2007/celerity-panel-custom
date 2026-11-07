# B132 host-Caddy network candidate (wave83, source only)

This extends the **existing** closed version1 network plan/constructor, not the
serving panel, physical launcher, shared-host policy or an immutable source-pack
profile. It does not authorize deployment, issue a lease, start an application or
create an acceptance record. The older bridge contract remains supported.

## Exact selected layout

Only source-fixed B132 machine-id with `peers.caddy.address == "127.0.0.1"`
selects host-Caddy semantics. That address is a layout discriminator, **not** a
claimed Docker IP. The independent existing `inspectSha256` still hashes the
complete original projection: id, PID/start, image/restart count, nsfs identity and
NetworkSettings.Networks. In addition, inspection requires HostConfig.NetworkMode
`host`, exactly the `host` network with empty IPAddress, and equality with the
accepted current host namespace. Retained pidfd/nsfd checks stay mandatory.
Mongo/Redis must remain separately pinned nonhost peers with their actual Docker
addresses. Bridge Caddy still requires its real Docker IP and nonhost namespace.

The only accepted config difference is exactly one reverse-proxy dial
`127.0.0.1:3000` → `212.119.42.100:3000` for this host layout; bridge keeps
`backend:3000` as its old dial. Any second match or unrelated type/value/config
change refuses. No Caddy config is written during preparation. Internal212 exists
only as fresh lo/32; it is never a historical remote host destination.

The Caddy peer veth is already born in the host namespace, so only its fresh end
is moved. The exact owned table39303/priority10303 TCP dport3000 destination
internal212/32 route/rule lives in **host** for this layout (in Caddy for bridge).
No main/default route, existing interface, host NAT or global sysctl is modified.
Both host/caddy observation aliases evolve together during exact cleanup. Owned
veth indices/aliases, complete remaining routes/rules and checked Caddy restoration
remain prerequisites. Only measured bridge countdown fields are excluded from
snapshots: bridge gc/hello/tcn/topology_change timers and bridge-port
forward_delay/hold/message_age timers. Configuration such as ageing_time, bridge
identity, links, addresses and routes stays exact. This also removes those
non-authoritative floating timers from the existing integer-only holder codec.

## Preserved runtime settings and executable path

`IP` now names the measured regular `/usr/bin/ip`; plan.executables must pin that
literal and `/usr/sbin/nft`. `/usr/sbin/ip` is not followed or accepted as an alias.
The nofollow trusted-path walker and installed-source hash loaders are unchanged.
Both current entries and the holder's transitive source pins are updated together;
all historical fixed profiles remain byte-for-byte unchanged and reject this
source as before.

For host layout only, fresh nft contains exactly two local TCP OUTPUT DNAT rules:
127.0.0.1:27017 → pinned Mongo-IP:27017 and127.0.0.1:6379 → pinned Redis-IP:6379.
Exact postrouting SNAT gives only those tuples their corresponding fresh p2p
source. There is no masquerade, PREROUTING, proxy process or host NAT. The existing
fresh default-drop input/output/forward policy and no-default-route property stay.
Only the newly owned fresh data interfaces receive route_localnet=1; that value
is rechecked for their lifetime and disappears with their deletion. Each sysctl
is journaled and fenced before/after through the existing finite dispatcher.
The complete private nft ruleset remains sealed until the namespace is disposed.

Preflight reads and retains exact `/var/lib/c3-test-fresh-input/root/etc/classic.json`
bytes. It requires numeric loopback Mongo27017/Redis6379 and measured Mongo query
`authSource=admin&replicaSet=rs0&directConnection=true`; drift or discovery-mode
substitution refuses. Private settings/credentials are not rewritten or logged.
The existing Mongo driver's topologyTypeFromOptions selects Single for
`directConnection` before considering replicaSet, so advertised replica-set host
names are not a discovery dependency of this accepted application URI. No rs/DB
command was used and actual advertised endpoint values are not claimed here.
This is not a change to separately owned maintenance/owner DB clients.

## Runtime-file handoff

The existing consumer requires a regular independently accepted
`/var/lib/c3-test-fresh-input/root/etc/hosts` with exact plan.hostsSha256. Minimum
content is `127.0.0.1 localhost\n`; no numeric DB remapping via hosts is required.
The network consumer imposes no resolver/CA content format; the application root
should independently deliver regular conventional `/etc/resolv.conf` and
`/etc/ssl/certs/ca-certificates.crt` bytes in its complete manifest, never host
symlink adoption. This network grants no general DNS/Internet egress and makes no
outbound application TLS readiness promise. `/run/netns` remains the unit's
explicit trusted-directory install precondition; it is not auto-created here.

## Published-loopback return binding (wave84, source-only)

The current optional **version1 return file** stays at
`/etc/c3-test-fresh-network-return.json`. Its original fields remain mandatory:
`version, context, generation, container, inspectSha256, address, serving`.
Only host-Caddy additionally requires this closed `published` object:

```json
{"pid":582004,"start":"10493593","listenerInode":"1882662","executableSha256":"98272bbbd6c1c35bd27d0d089252c710107f5334125cd37eb22d5415a077ae09"}
```

These are **observed B132 values, not an accepted input or permission to act**.
The independently held input/old-writer owner must accept and revalidate them for
its actual boot/generation/deadline; this consumer never creates that authority.
Missing published proof still refuses
`HOST_CADDY_RETURN_LOOPBACK_PID_BINDING_REQUIRED`; bridge files reject the extra
field and keep their unchanged DNS→original-PID tuple proof.

A bounded read-only inspection found the actual host listener is Docker's
userland proxy PID582004/start10493593, owned socket1882662 on127.0.0.1:3000.
Its exact argv is:

```
/usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 3000 -container-ip 172.19.0.5 -container-port 3000 -use-listen-fd
```

Installed regular root-owned mode0755 executable SHA256 is shown above. Docker's actual configured and effective
3000/tcp bindings both equal127.0.0.1:3000; all other effective ports are null.
The inspected OUTPUT nat jump explicitly excludes127/8: a DOCKER DNAT rule also
exists, but its mere presence is **not** evidence that loopback uses kernel NAT.

A single nonmutating GET provided both actual proxy-owned new ESTABLISHED
sockets: client127.0.0.1:45524→proxy127.0.0.1:3000, and proxy172.19.0.1:39658→
backend172.19.0.5:3000. The reversed second tuple is an IPv4-mapped TCP6 socket
owned by original backend PID581974/start10493548. Its original owned LISTEN is
TCP6 wildcard port3000 (socket1883585), not the IPv4-exact listener assumed by
the bridge helper. Container/image/restart/nsfs pins remain independently checked.

Host return now retains that proxy's pidfd/nsfd in the **existing target hold**
alongside original container/serving processes. Every held check brackets a
fresh loopback keepalive with exact proxy root principal/cgroup/host namespace,
argv, installed/running executable inode+digest, original listener inode and
Docker port bindings. The actual new inbound socket must match the probe's
client tuple; exactly one new outbound socket must target the original backend,
and its reversed tuple must intersect that backend PID's owned socket FDs.
Both graph edges are rechecked before closing the connection. Preexisting,
foreign, missing, wrong-port/peer, ambiguous concurrent and changed sockets
refuse; no direct-IP or same-body fallback exists. Kernel-NAT-only publishing is
unsupported and refuses. The normal existing held/lease checks run before and
after exact Caddy restoration and all final observations; drift is sticky.
No controller/daemon, new authority family, host firewall writer or proxy is added.

### Independent readiness blocker retained — not combined PASS

The actual one-shot B132 GET `/classic-ready` returned **HTTP404**, with keepalive,
15 response bytes, SHA256
`2d857a3660e0240bac3ae9f98e2287f46eb6aebf724775fe130af2a6c7dfc3c4`.
The existing return readiness predicate remains **HTTP200 plus exact READY bytes**;
this change does not reinterpret404 or matching response bodies as readiness.
Therefore an actual return is still refused with
`ACTUAL_KEEPALIVE_READINESS_REQUIRED`. Resolving that original-backend HTTP
contract is separate work, not permission to deploy, restore Caddy or alter the
working panel. Public HTTPS also retains its original exact readiness predicate.

Tests cover actual return-consumer lifecycle/journal/retained local PID/nsfds and
real current entry loaders. Captured tuple projections are replayed through the
real socket parser/FD-owner predicates over explicitly synthetic proc files;
positive HTTP200/READY, Docker and physical host metadata are **modeled**, not
physical acceptance. Exact baseline9ef8 refusal→source GREEN and the complete
current suite are recorded under `test-network-return-wave84` outside Git.
No live setns, namespace/veth/route/firewall/service/application/DB write, lease,
hold, import, deployment or cutover is performed. Fresh kernel NAT packet proof
and complete host eligibility remain unverified. Wave82 facts and wave83 evidence
and author checkout remain unchanged.

## Finite selected node-control egress (wave94, source-only candidate)

This optional extension is in the same constructor and original held lease. It
does not add request permissions, an authority service, a controller daemon or a
terminal ownership-transfer protocol. Omission (or an explicit empty endpoint
list) keeps legacy firewall/routes unchanged. No active input is published.

The additive ROOT-trusted plan field is a closed object:

```json
"nodeControlEgress": {
  "endpoints": [
    {"nodeId":"6aecd36265572a55acf7c677","address":"10.203.61.2","protocol":"tcp","port":2222},
    {"nodeId":"6aecd36265572a55acf7c677","address":"10.203.61.2","protocol":"tcp","port":62080},
    {"nodeId":"6aed089795ea4b863887d717","address":"10.203.61.1","protocol":"tcp","port":2222}
  ],
  "hostRulesetSha256": "INDEPENDENTLY_ACCEPTED_64_LOWER_HEX_DIGEST_REQUIRED"
}
```

The placeholder is deliberately **not a valid executable plan**. The complete
nonempty set above is the only currently source-supported set: no missing,
duplicate, other IP/port/protocol, hostname, range or request-selected tuple.
Fixtures/provenance are in `fixtures/node_control_wave94.json`. Retained actual
selected worker records (wave66 final rollback-check SHA466aa1ef...) and the
unchanged wave82/92 accepted inventory both select **WireGuard** .2/.1:2222.
P104's public104.143.201.72 maintenance identity is not that worker endpoint.
P is Xray, with an agent token present and agentPort62080/TLS; B is Xray without
an agent token. The actual `nodeSSH` and `syncService` consumers therefore need
the three TCP tuples, not guessed22/8080/9999 or B62080. Both records' statsPort9999
does not select Hysteria HTTP because their type is Xray. No selected hostname
requires DNS; no public resolver or CA/environment change is introduced.
These are retained observations, **not fresh live endpoint acceptance**; the
independent operator must revalidate their current configuration before use.

Actor/hops: the temporary backend's explicit worker SSH and selected agent
health/stats/online requests originate in the fresh namespace, pass only the
three exact OUTPUT accepts and two /32 routes over existing c3nc→c3pc, then enter
the already-pinned host namespace. B10.203.61.1:2222 is host-local INPUT; replies
use the connected p2p return path. P10.203.61.2 uses the already-existing
`c3test61` /32 route. The fresh source is not an accepted remote WG peer return
address, so exactly those two P TCP tuples receive host postrouting SNAT to
10.203.61.1, scoped by c3pc, c3test61, fresh source, destination and dport. Replies
reverse that conntrack mapping and reach fresh via the existing p2p link. There
is no new default/main host route, global sysctl write, forwarding-policy write,
masquerade, proxy, application flag/schema/credential change or public-address
assignment. The scoped optional SNAT is the sole exception to the older
sections' no-host-NAT description; numeric DB DNAT/SNAT and Caddy selectors stay
byte-for-byte equivalent apart from the three additional private OUTPUT lines.

The host table `ip c3nodecontrol` must be absent. Atomic `create table` refuses
adoption; a generation comment and exact observed table seal remain checked at
every dispatch. Cleanup deletes only that table under the original intent,
holder/pidfd/lease fences and evolving seals. Missing/replaced/extended owned
tables or foreign-policy drift retain all uncertain resources. No flush or
foreign filter-rule deletion exists. Existing host WG address/route and
ip_forward=1 must already exist and remain checked; the constructor never
enables forwarding. Current server/holder/entry source pins close together; no
historical immutable producer pins change.

**New independent trust input / partial physical RED:** retained packets do not
contain a current accepted host forwarding firewall. `hostRulesetSha256` must
come from independent review of the actual preexisting host ruleset which
already permits both directions of these exact forwards and B INPUT/replies.
Hash the `encode({"nftables": rows})` result of fixed `nft -s -j list ruleset`,
excluding tool metainfo only, with c3nodecontrol absent. The constructor rechecks
that exact stateless foreign policy throughout; adding its own table is the only
allowed delta. A matching digest is an integrity check, **not a semantic proof
that a foreign Docker/FORWARD DROP permits the traffic**. NAT accept does not
override filter drop. No permission to weaken that policy is implied; if the
actual accepted host cannot forward, this candidate remains physically blocked.
Host firewall acceptance, privileged namespace/NAT/reply packet proof, combined
freeze ordering and post-lease terminal ownership remain separate unmet gates.
Model tests are not physical/server acceptance, PPP evidence or deployment GO.

## Exact existing-DROP-path permission (wave98, source-only; supersedes wave94's host-forward prerequisite)

The observed wave95 host **denies** P forwarding: `ip filter FORWARD`, handle2,
filter hook priority0, policyDROP. Its DOCKER-USER and DOCKER-FORWARD branches return
for c3pc↔c3test61. POSTROUTING SNAT and an earlier separate base-chain ACCEPT cannot
bypass this DROP. This revision implements one bounded mechanism: insert **four
iptables-nft compatibility rules at position1 of that existing FORWARD chain**.
No foreign rule, chain, hook, default policy or Docker object is edited/flushed.

For each remote P port2222/62080, the owned outbound ACCEPT matches TCP, exact
accepted fresh p2p source/32, destination10.203.61.2/32, ingressc3pc,
egressc3test61 and conntrack NEW/ESTABLISHED. Its reply ACCEPT matches TCP,
source10.203.61.2/32, exact fresh destination/32 after reverse-SNAT,
ingressc3test61, egressc3pc, corresponding source port and ESTABLISHED only.
No RELATED, unsolicited reverse NEW, wrong interface/IP/port or arbitrary veth
traffic is granted. B10.203.61.1:2222 remains host INPUT with **no new grant**.
The existing scoped SNAT, private three OUTPUT rules and two /32 routes remain.
There is no ip_forward enable, default route, DNS/9999 grant or new daemon.

### Independently accepted ROOT inputs, never observation-as-authority

Nonempty `nodeControlEgress` can additionally contain this closed field:

```json
"forwardPolicy": {
  "mode": "docker-forward-v1",
  "compatPolicySha256": "INDEPENDENT_COMPLETE_CANONICAL_SAVE_DIGEST_REQUIRED",
  "executables": {
    "/usr/sbin/xtables-nft-multi": "INDEPENDENT_EXECUTABLE_DIGEST_REQUIRED",
    "/usr/sbin/xtables-legacy-multi": "INDEPENDENT_EXECUTABLE_DIGEST_REQUIRED"
  },
  "wireguardLinkSha256": "INDEPENDENT_COMPLETE_LINK_ROW_DIGEST_REQUIRED"
}
```

These invalid placeholders deliberately create **no executable ROOT plan/lease**.
The existing raw-plan lease and in-memory immutable capability cover this whole
object. The literal regular multicall binaries are nofollow/hash checked, with
backend exactly `iptables v1.8.10 (nf_tables)`; common symlink aliases are not
followed. The existing IP/NFT executable pins remain unchanged in shape. The WG
pin hashes `encode` of the complete existing `snapshot('host').links` row for
c3test61, including ifindex/type; the existing .1/32, .2 route and ip_forward=1
readbacks remain required. The accepted generation still owns its newly created
c3pc/c3nc pair and retains original host/peer nsfds and pidfds.

`hostRulesetSha256` continues to hash the complete stateless foreign nft JSON,
excluding **metainfo only** at collection and subtracting only fully measured
owned effects. It retains all foreign handles, chain identities, hook priorities,
order, expressions and all families. A second finite shape pin admits only the
captured wave95 ruleset structure (ignoring handles for recognition, not acceptance).
The fixed IPv4 complete-save semantic pin admits only the captured raw/filter/nat
policy. Changed/unknown hooks/tables/parameters refuse, not generalize.

`compatPolicySha256` hashes `encode` of the closed object with string fields
`ipv4, ipv6, legacy4, legacy6`. The collector uses fixed multicall argv:
`xtables-nft-multi iptables-save -c -t raw`, then filter/nat;
`xtables-nft-multi ip6tables-save -c -t nat`, then filter; and both full legacy
saves through xtables-legacy-multi (required empty). The canonical codec removes
only numeric rule/chain counters and exact v1.8.10 generated timestamp headers,
then losslessly canonicalizes shell-token quoting. It retains every option and
operand, NAT/addrtype/conntrack parameters, comment bytes, policy and rule order.
Only the precisely measured owned IPv4 FORWARD prefix is subtracted. In particular,
identical opaque nft JSON with changed hidden compat parameters is rejected.
The companion IPv6 grammar is fixed to the matching Docker structure; only its
nonsemantic comment operand varies and is still bound by the complete ROOT pin.

The original wave95 capture did not include ip6tables-save, and its former
synthetic incomplete IPv6 fixture was rejected in the wave99 review. Wave100
retains that RED evidence and replaces only the fixture input with the exact
canonical projection of real TEST wave99 v1.8.10 `(nf_tables)` per-table saves.
The finite `node_compat_wave99.json` fixture also retains their actual raw stdout,
including numeric counters and C-locale generated/completed timestamps. The
closed IPv6 recognizer now requires all producer chains, including empty ACCEPT
`nat/INPUT`, `nat/POSTROUTING` and `filter/OUTPUT`; it does not drop them or admit
missing/unknown chains, altered policies or extra rules. Header normalization
requires the literal backend/version and a complete C-locale ctime timestamp;
arbitrary comments or trailing header text refuse.

The wave99 IPv4 canonical digest still matches the fixed policy; both actual
legacy saves are empty. Capture provenance/digests are observations, **not accepted
ROOT plan or executable-pin authority**. A real caller must independently review
and accept those inputs. No observation digest has been inserted into an active
ROOT plan. Missing `forwardPolicy` still leaves
old nonopaque fixture behavior alone, but cannot authorize opaque xt policy:
it refuses `COMPLETE_COMPAT_BINDING_REQUIRED`. Absent/empty endpoint lists retain
legacy byte-equivalent private policy/routes with no host compatibility IO.

### Ownership, readback, intent and cleanup

Each insertion has its own original dispatcher durable intent, guard/lease check
after fsync, joined-child check immediately before exec, readback and confirmation.
It uses fixed `iptables -w 1 -t filter -I FORWARD 1 ... -m comment --comment
c3:<generation>:P:<port><out|reply> -j ACCEPT` via the pinned multicall binary.
Readback correlates the one new head rule's **unique table-scoped nft handle** to
the exact full compatibility rule (the comment may be opaque in nft JSON).
Subtracting that measured rule plus prior owned rules must restore both accepted
foreign projections exactly before registering the new seal. Comment-only
adoption, an existing generation collision, unmeasured insertion or second
installation is not accepted. The existing outer competing-network-writer
exclusion contract is mandatory throughout; these readers do not mint it.

Cleanup first removes the sealed FORWARD prefix **one measured handle at a time**
with `delete rule ip filter FORWARD handle N`, then deletes the still-exact owned
SNAT table. It never deletes foreign rules by index/comment/guess. Every guard
checks complete foreign projections, full owned nft rows and complete compat
rows; each successful readback advances only that exact deletion's expected seal.
Missing/replaced/extended/reordered rules, changed comments/compat parameters,
partial cleanup drift, lost ACK, lost holder or failed journal confirmation are
sticky unknown-retained, with no next mutation, retry, adoption or cleanup.
No changes to Controller lease/Fence, freeze protocol, public settlement or durable
ordinary-network ownership are made here. Post-lease ownership remains separately
owned work, not an indefinite new process or implied permission to release fences.

### Evidence qualification

The new focused suite first evaluated the exact baseline SNAT-only proposal
against real captured Docker tokens and failed **DROP != ACCEPT**, not a schema
error. The same captured policy plus actual generated four-rule proposal models
ACCEPT for both P flows and established replies, DROP for the negative tuple/state
matrix, and preservation of unrelated foreign Docker behavior. It exercises actual
command builders/dispatcher/journal/readers/cleanup with explicitly modeled kernel
and root trust seams, plus ordinary files/processes/pidfds/loaders. These are
**not real kernel packets** or physical forwarding/NAT/endpoint authentication.

No deployment, privileged network/service command, new login/remote API/SSH,
installation, active plan/lease or GO occurred. The historical two TEST login
POSTs wrote lastLogin/session metadata; that exception remains historical and was
not repeated or reclassified. Independent source review, complete actual trust
inputs, combined freeze/ordinary-owner design and privileged request/reply proof
are still required before any operational use.
