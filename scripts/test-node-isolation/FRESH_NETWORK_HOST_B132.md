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
