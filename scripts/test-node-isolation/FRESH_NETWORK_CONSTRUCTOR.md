# Fixed TEST private network constructor — source closure, not physical GO

## Status and scope

These **new files only** implement construction/control source. They have not been
installed or run privileged. No SSH, remote HTTP/Docker request, Docker execution,
namespace/mount/route/firewall/service mutation, or production operation was run
while producing this change. Tests use real disposable files/processes, pidfds,
AF_UNIX protocol/credentials and explicitly modeled kernel/Docker/HTTP seams.
Neither a namespace observation nor these tests is physical acceptance.

The implementation deliberately chooses **three private point-to-point veth
pairs**, not a new Docker bridge. Each joins the new fresh namespace directly to
one independently pinned Caddy/Mongo/Redis network namespace. It never joins a
Docker bridge, manually allocates from Docker IPAM, creates Docker networks,
connects/recreates containers, or uses host forwarding/NAT. Thus there is no
unreserved manual address racing the Docker allocator. Three independently
accepted, mutually distinct RFC1918 `/30`s are required; no sample accepted
subnets or nsfs integers are shipped. Existing host/endpoint routes and every
Docker network's IPv4 subnets are checked for overlap before effects.

This is a **narrow ingress + local data-control closure**, not full C³ operational
networking. There is no default route in the fresh namespace. Remote-node SSH,
external DNS/ACME/API/WebSocket destinations, VPN egress, and any additional
application-control tuples are deliberately unavailable unless separately
implemented/reviewed. Do not activate the complete panel/worker runtime on the
strength of this slice.

## Consumer contract traced from the unchanged physical/launch sources

* `fresh_physical.py` requires `/run/netns/c3-test-fresh-classic`, nsfs
  `NS_GET_NSTYPE == CLONE_NEWNET`, an identity different from PID1's netns, and
  independently accepted positive `networkNamespace:{device,inode}` in
  `/var/lib/c3-test-fresh-input/resource-plan.json`. Both constructor/watchdog
  join this object **before creating control sockets**. This helper creates the
  actual bind-mounted namespace object; its unaccepted observation does not
  publish that resource plan or an acceptance file.
* The launcher requires an IPv4 listener **owned by the real serving PID** at
  `212.119.42.100:3000`, exact `/classic-ready` response
  `c3-classic-ready-v1\n`, and a keepalive TCP tuple intersecting that PID's FDs.
  The public address is installed `/32` on **fresh lo only**, never on host
  `eth0`, a host bridge, or an external L2 interface. The controller must be
  independently arranged to join this same netns before its literal direct
  observation; its host PID/mount/other namespace requirements remain unchanged.
  This slice does not modify its entry, launch probe, policy or Coordinator.
* The helper's cutover does the same real PID/FD-bound literal HTTP observation
  inside fresh, then literal HTTP inside the pinned Caddy netns. Only after both
  pass does it atomically ask Caddy's local admin API to load the independently
  accepted new JSON config. It reads config back, probes ordinary certificate-
  verified `https://test.infograd.online/classic-ready`, repeats the bound direct
  probe, and checks identities again. This is not a proxy/NAT substituted for
  the launcher's direct observation.
* Public Caddy is the **same container and PID/start/netns throughout**. The admin
  IPv4 127.0.0.1:2019 listener must intersect that exact PID's actual socket FDs
  before and after each config read/write; namespace membership alone is not
  accepted as admin endpoint ownership. Its old
  config is unchanged during preparation. Canonical JSON bytes (not Python
  bool/int/float-coercing equality) bind validation and every config readback.
  Accepted old/new configs may differ
  only in exactly one reverse-proxy upstream `backend:3000` →
  `212.119.42.100:3000`; other layouts refuse, not heuristic rewriting. A private
  Caddy table 39303 and priority 10303 TCP/dport-3000/to-212.119.42.100/32 rule
  reach fresh over its new point-to-point interface. Caddy's existing local rule
  0, main/default routes, original interfaces, published 80/443 and container
  identity remain untouched. No host route/rule is installed.
* Mongo/Redis use their actual independently pinned Docker addresses via separate
  `/32` routes in fresh and separate private links. Database reply traffic uses
  the source address on that link; neither daemon/container is restarted and no
  host forwarding is used. Fresh nft input/output/forward default-drop precedes
  bringing any veth up. Only fresh loopback, established replies, Caddy's exact
  private peer→public:3000, and Mongo:27017 / Redis:6379 control traffic are allowed.
  There is no forwarding or direct VPN/internet egress.
* Existing Caddy global `rp_filter` must be 0 or 2. Global strict mode 1 refuses;
  it is never relaxed. Only the newly owned interfaces get per-interface
  `rp_filter=0` and IPv6 addrgenmode none. Actual kernel reverse-path/ARP behavior
  still requires physical rehearsal.

## Independently accepted root inputs (none generated here)

Root-owned, no-symlink, non-group/world-writable paths, no xattrs, bounded regular
single-link files are required. The fixed isolated no-argument entry loads only
its two digest-pinned installed modules:

| Source | Fixed installed destination |
|---|---|
| `fresh_network.py` | `/usr/local/libexec/c3-test-fresh-network.py` |
| `fresh_network_control.py` | `/usr/local/libexec/c3-test-fresh-network-control.py` |
| `fresh_network_exec.py` | `/usr/local/libexec/c3-test-fresh-network-exec.py` |

The independently provisioned directories `/run/netns` and
`/var/lib/c3-test-fresh-network` must already be trusted. No installer/unit or
source-pack inclusion is claimed. The original source pack is unchanged.

`/etc/c3-test-fresh-network.json` is a closed object with:

* `version:1`, `context:"test.infograd.online"`, exact accepted `machine`
  (machine-id, must equal source-fixed TEST `7fa266f995fe4aa69e96cf7d01359e34`),
  `boot` (canonical boot-id), `hostNetns:[device,inode]`, fresh lowercase
  32-hex `generation`, integer absolute Unix `deadline` (maximum 600 seconds).
* `daemon:{socket:[device,inode],id,root}` pins the actual fixed
  `/run/docker.sock`, Docker `/info` ID and DockerRootDir. Docker API access is
  **GET only**, fixed socket, no CLI/context/environment endpoint selection.
* `executables` is exactly the accepted SHA-256 map for `/usr/sbin/ip` and
  `/usr/sbin/nft`; no command/path comes from the protocol. Host Python/ELF/kernel
  runtime closure remains an independent installation acceptance gate.
* `peers` is exactly `caddy,mongo,redis`. Each is exactly
  `{id,inspectSha256,subnet,address}`. `id` is the full container ID; `subnet` is
  its independently accepted private `/30`; `address` must equal an actual
  inspected Docker IPv4 address. `inspectSha256` hashes this module's `encode`
  of `{id,pid,start,netns:[device,inode],image,restartCount,networks}`, where
  `networks` is the **complete** NetworkSettings.Networks object and start is the
  actual `/proc/PID/stat` start string. Three separate namespaces are required.
  Retained namespace FDs and pidfds, not names/reused PIDs, bind subsequent writes.
* `hostsSha256` pins the exact independently accepted
  `/var/lib/c3-test-fresh-input/root/etc/hosts` bytes. They must also be included
  in the physical payload's independently accepted files map. Supply correct
  Mongo replica-set advertised names and Redis names in those bytes; this code
  neither invents them nor claims a hash alone proves their semantic correctness.
* `oldConfig,newConfig` contain the full independently accepted Caddy JSON
  objects with the one exact upstream change described above. They are private
  root inputs; responses/logs contain only config digests, not these bytes.

`/etc/c3-test-fresh-network-lease.json` is exactly
`{version,context,generation,boot,planSha256,holder:{pid,start},deadline,operations}`.
Version/context/generation/boot/deadline must match the plan; `planSha256` pins the
**raw input bytes**, not a reserialization. `operations` is exactly
`["observe","cutover","return","abandon"]`. The independently accepted holder
must be a live root process with exact start time; a retained pidfd and unchanged
input bytes are rechecked before/after effects. Loss is latched. The issuer must
independently retain exclusion of competing network/config writers and cleanup/
resume authorities throughout. A root-owned file is not proof of that external
exclusion. No lease/acceptance publisher is supplied.

After the actual fresh app exists,
`/etc/c3-test-fresh-network-serving.json` is exactly
`{version,context,generation,serving:{pid,start}}`. The code requires that live
PID's exact namespace, UID65531, fixed classic cgroup, exact IPv4 listener, owned
keepalive tuple and response. It never starts the application or accepts a fake
integer as serving evidence.

Optional explicit `return` additionally requires a new independently accepted
`/etc/c3-test-fresh-network-return.json`:
`{version,context,generation,container,inspectSha256,address,serving:{pid,start}}`.
It pins the old backend's full actual Docker projection, exact namespace/cgroup,
backend DNS resolution and owned ready TCP tuple before/after loading old Caddy
config and through final confirmation. Exact raw return-pin bytes, both original
container/serving pidfds and namespace FDs are retained for the entire operation;
DNS, Docker projection, process/start/namespace and tuple-bound readiness are
rechecked. The same immutable serving-pin/process hold spans cutover. Replacement
is refusal, never implicit reauthorization. Successful command observation closes
only these operation-scoped descriptors, not network resources. It never
thaws/restarts an old writer. A frozen/not-ready old backend
refuses before changing Caddy. Old backend must support the same witness; this
source does not silently substitute `/health` or a fake success receipt.

## Finite root protocol, ownership and failure semantics

The entry requires root, isolated Python, no arguments, host PID/mount/net
namespaces. It exclusively creates a fresh generation directory and
`/run/c3-test-fresh-network.sock` (mode0600), refusing leftovers. Only the exact
leased PID via actual SO_PEERCRED can connect. No network construction starts
before that connection. The initial reply is an unaccepted prepared observation.

Frames are 4-byte big-endian lengths followed by strict JSON. Requests ≤4096 bytes
are exactly `{generation,sequence,operation}`; sequence must increment by one.
Only `observe`, `cutover`, `return`, `abandon` exist. No shell, path, command argv,
user/UI command, environment dispatch, install, GO or lease-extension verb exists.
The holder must keep the one connection alive (observe heartbeat at most 30s;
absolute lease ≤600s). There is no request/reconnect retry after refusal/EOF.

Every request and each individual external mutation intent is journaled/fsynced
before dispatch: each ip command, rtnetlink send, interface sysctl write, mount,
nft apply, Caddy load, unmount and exact unlink has a held dispatch boundary.
Lease/holder and retained target checks run again in the joined child before a
write and after checked command/ACK/result return. Observation work and intent
fsync cannot extend the lease. Unshare is bounded child-local preparation with
checks on both sides before the persistent mount. No next step is dispatched
after authority loss, expiry, failed ACK/readback or uncertainty. Normal
preparation does not change public config. Full constructed
host/fresh/endpoint link/address/route/rule snapshots and fresh nft rules are
retained and rechecked before later mutations. Target veth names are exclusively
created while down, tagged with generation-specific aliases, and moved by actual
`IFLA_NET_NS_FD` rtnetlink serialization. No `replace`, `flush`, PID-selected move,
existing-path takeover or IPAM adoption occurs.

Unknown mutation/timeout/death/input drift/guard loss is sticky retained. There is
**no automatic old-config reload, old-writer rollback, cleanup, reconnect or
recovery adoption**. Any failed entry leaves generation and socket tombstones;
re-running it refuses. Physical cutover failure may already have loaded new
config; retaining it is intentional, not proof of success. Separate reviewed
exact-target recovery is required for unknown/partial construction.

Normal abandon is allowed only from prepared/confirmed-returned, with old Caddy
config still exact, no task occupying the fresh namespace, unchanged sealed
network/firewall state, exact two veth aliases/indices per pair, and retained
namespace identity. Its exact expected seal evolves by each checked rule, route
and paired-link deletion; it is never disabled for the remaining teardown.
The unmounted namespace FD stays held through entry cleanup. It deletes only its
exact Caddy rule/route and own veths,
proves complete original host/endpoint snapshots restored, normally unmounts the
owned nsfs mount, verifies the original exclusive mountpoint inode, unlinks it,
then removes only its exact control socket. No lazy/forced unmount, broad route
flush or tree deletion. Directory tombstones remain as no-replay evidence.
Unknowns/replacements are retained. External namespace/socket FD holders and
competing privileged resumers cannot be excluded atomically by a `/proc` scan;
independent held exclusion is a mandatory gate, not inferred from an empty scan.

## Verification and exact remaining physical gates

`python3 -B -m unittest test_fresh_network -v` covers actual generation files,
fsync/no-replay/replacement refusal, real child-process framed AF_UNIX exchange,
EOF/duplicate/oversize rejection, real SO_PEERCRED refusal, real pidfd death,
fixed-entry argument refusal, actual ip/rtnetlink command serialization and
modeled construct/cutover/return/abandon, every connect/removal dispatch boundary,
post-join guard loss, expiry, durable-intent loss, malformed/error/sequence ACKs,
return pin/DNS/container/process/namespace replacement across write/confirmation,
real retained pidfd death, JSON bool/int and int/float drift, and sticky unknown
cases. N1/N2/N3 each has recorded vertical RED→GREEN evidence. Another independent
review of this exact repaired commit/tree is required before parent integration.
Root UIDs/nsfs/mounts/veths/nft/Docker/admin/HTTP facts are modeled;
**no TCP/HTTP or privileged network operation is exercised by these tests**.

Still unexercised/unimplemented externally:

1. Independently accept actual TEST machine/boot/daemon/container/network/source
   pins, nonconflicting `/30`s, lease/holder/writer exclusion, config layout/admin
   availability, rp_filter eligibility and installed Python/ip/nft runtime closure.
2. Install/rehearse real privileged namespace/veth/nft creation and exact-owned
   abandonment; kernel rtnetlink ACKs, route selectors, reverse path, source
   selection, Caddy reload atomicity, database reply reachability and failure
   injection have not run physically.
3. Independently publish observed nsfs identity into a **new** physical resource
   plan; accept `/etc/hosts`, replica-set names and actual settings semantics.
   Arrange controller entry into fresh netns without weakening its other host
   namespace predicates. Include this new source in a new accepted installation
   artifact; no reviewed source-pack/unit/physical file was modified here.
4. The parent already independently reviewed/integrated the physical-only
   disk-backed `/var/lib` staging and explicit bootstrap `fchmod(0644)` fix
   (parent `578750770d514d2ef5c8985cd0226a6a19aac0f9`). The obsolete `/run`
   capacity/umask blocker is not a new network blocker. No physical file or
   rejected ancestor is imported by this five-file repair.
5. Actual application startup, PID/socket-bound literal observation from the
   real controller, Mongo/Redis and remote-node control compatibility, untouched
   public Caddy identity, ordinary public HTTPS fresh-classic return, all-five
   hold/handback and independent final acceptance remain open. Remote-node
   control destinations are not implemented by this deliberately narrow network.
6. Serving lifetime supervision/cleanup after accepted cutover, crash/partial
   generation recovery and installed unit/source-pack composition are not
   implemented. The root entry exits retained on lost connection/lease; it never
   claims that retained serving state is accepted or an operational GO.

No `provisioningImplemented:true`, `physicalAccepted:true`, operational GO or
production readiness is emitted. PROD and the existing candidate are unchanged.
