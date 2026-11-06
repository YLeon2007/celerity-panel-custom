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

## Concrete remaining boundary — not combined PASS

Host-layout optional `return` now refuses explicitly with
`HOST_CADDY_RETURN_LOOPBACK_PID_BINDING_REQUIRED`, before reading a return pin or
contacting DNS/HTTP. The existing bridge return proves Docker embedded DNS and
an old backend PID-owned TCP tuple. Actual B132 uses a host-loopback published
endpoint and a bridge backend (wave82 Docker-IP172.19.0.5). A direct backend-IP
probe or equal HTTP body cannot substitute for a PID-bound proof of that
published loopback path. No such authority is invented here. **Do not perform
host-layout cutover on the strength of this candidate; combined reversible
cutover/handback remains blocked on that one concrete proof contract.** Existing
bridge return and checked config loads/restoration are unchanged. Prepared-only
observe/abandon is covered through actual current loaders/holder/control entry.

Tests use redacted wave82 measured config/peer/network records from
`fixtures/network_b132_wave82.json`, with origin hash. Generation/deadline/p2p
subnets are explicitly synthetic test inputs. Real file/codec/pidfd/child/socket
execution is distinct from modeled kernel/Docker/HTTP observations: **no live
setns, route, firewall, namespace, service, application or database operation**
is exercised. Kernel NAT syntax/packet delivery and physical host eligibility
remain unverified. Causal baseline REDs and final natural-exit suite receipts are
outside Git at `test-network-layout-wave83` in the parent's execution directory.
