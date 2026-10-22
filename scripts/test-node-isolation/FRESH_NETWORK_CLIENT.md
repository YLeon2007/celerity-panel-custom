# Finite exact-PID root network holder — source only, no GO

## Boundary

This additive client closes ONE missing call: the actual leased root PID creates
and connects one AF_UNIX socket to the unchanged `fresh_network_control.run`
server, through its actual `Lease.peer` and `Controller.prepare`. It does not
publish, install, authorize, prepare physical resources, resume a supervisor,
instantiate a Coordinator, invoke all-five SSH, perform CAS/COMMIT, or solve
post-lease serving ownership. Existing server, schemas, units, physical watcher,
preparer, launcher, Coordinator, JS, profiles, source packs and pins are unchanged.

Only these new sources are proposed for a later separately accepted installation:

| Source | Fixed destination |
| --- | --- |
| `fresh_network_client.py` | `/usr/local/libexec/c3-test-fresh-network-client.py` |
| `fresh_network_client_exec.py` | `/usr/local/libexec/c3-test-fresh-network-client-exec.py` |

The fixed invocation is `/usr/bin/python3 -I -B /usr/local/libexec/c3-test-fresh-network-client-exec.py`,
with NO arguments. This is a manual invocation contract, not an installed command
or a new unit. The entry descriptor-walks root-controlled non-symlink ancestors,
checks bounded regular single-link source bytes against literal SHA256 pins and
executes those checked buffers, not reopened pathnames. It loads the existing
network/control helpers and this one client; no import path or callback is chosen
by input. The client separately retains/rechecks exact installed network/control,
server-entry and client bytes/inodes. Entry/runtime installation itself, host
Python/loader/stdlib, loaded server unit/entry and privileged writer exclusion
must be independently accepted. Source hashes do NOT certify installed facts.

## Existing authority, not a new permissive control schema

The independent operator must already have selected the exact TEST machine/boot,
host namespaces, Docker/peer/network/config/source/hosts facts and excluded all
competing writers, cleanup authorities and resumers. Root-owned files or a current
scan do not prove that selection or exclusion. The client cannot supply it.

The operator supplies **anonymous pipes** as fd0 (read-only) and fd1 (write-only)
from its trusted root invocation. Their real FIFO type, `pipe:[inode]`, ownership,
mode, direction and identity are checked. A terminal, regular file, named FIFO,
socket, pathname, environment variable or UI request is not a command source.
Pipe inode ownership does not identify every retained writer: sole trusted root
operator provenance/exclusion remains an explicit external prerequisite. Do not
pass an untrusted/UI pipe through a root wrapper and infer authorization from it.
No operator broker or authority issuer is invented by this slice.

fd0 accepts ONLY the exact ASCII lines `observe\n`, `cutover\n`, `return\n`,
`abandon\n`. At most 64 explicit lines; at most 8 bytes/line; each partial line
has one absolute three-second completion budget. There is no JSON policy schema,
path/argv/command, target, shell, callback, GO, acceptance, resume, install,
renewal or extension operation. These lines select only the existing protocol
operations already listed in the independently installed lease. EOF, invalid or
partial input is refusal, never implicit abandon. fd1 emits bounded newline-JSON
observations and checked server replies with bounded nonblocking writes. Failure
to drain it refuses; it is not an acceptance channel.

## Exact holder / independent issuer rendezvous

1. FIRST independently install `/etc/c3-test-fresh-network.json` using the
   unchanged closed schema. Its integer absolute Unix `deadline` must already be
   positive and at most 600 seconds away. The client captures the corresponding
   monotonic ceiling **once, before any waiting**. Neither clock rollback, waiting
   for lease/server, observations nor heartbeat resets it.
2. Start the real finite client with the trusted pipes. It verifies the fixed
   plan and source buffers, root real/effective/saved IDs and all four proc UIDs
   and GIDs, accepted machine/boot, host PID/mount/net namespaces and host net pin.
   It retains its own real pidfd. It emits `{version,context,generation,holder:
   {pid,start},deadline,accepted:false,physicalAccepted:false,operationalGO:false}`.
   This actual identity is explicitly UNACCEPTED evidence, not a lease or grant.
3. The **separate issuer**, not this client, may install the existing lease
   `/etc/c3-test-fresh-network-lease.json` naming exactly that already-live PID
   and start, with matching boot/generation, SHA256 of RAW plan bytes, identical
   deadline and operations exactly `[observe,cutover,return,abandon]`. No sample
   accepted facts, publisher or self-issued exclusion are supplied. Alternatively,
   an independently accepted same-PID exec preserves PID/start; fork/proxy does not.
4. The separate operator starts the unchanged fixed server while both processes
   still fit the ORIGINAL deadline. The client waits only for absence; a present
   malformed/drifting lease refuses. It retains the root-owned socket inode and
   waits for the existing kernel `/proc/self/net/unix` listening flag, without a
   probe connection (bind is visible before listen). The server's accept budget
   is still its existing three seconds; timely external orchestration is required.
5. This same client PID creates and attempts exactly ONE connection to the fixed
   `/run/c3-test-fresh-network.sock`. Even a failed attempted connect is terminal:
   no reconnect, retry, inode adoption or transferred FD. Root server credentials
   come from real SO_PEERCRED. Its observed PID/start/pidfd are retained, NOT
   elevated into an invented accepted server-PID schema. The existing accepted
   root socket/installation/exclusion is the authority. The peer must execute the
   exact fixed server Python argv and remain root in host PID/mount/net views.

Before each dispatch and after each ACK the client rechecks retained raw plan,
lease and installed sources, inode/mtime-ns/ctime-ns/ownership/modes/xattrs through
trusted descriptor walks, exact holder/root/host/deadline, original socket and
server peer/pidfd/start. Own read-atime changes are not writes to authority;
mtime/ctime changes and same-byte inode replacements refuse. Existing `Lease`
validation is reused, not relaxed. No authority bytes are written by the client.

## Unchanged wire and finite lifecycle

Wire frames are four-byte big-endian lengths followed by JSON. Requests remain
exactly `{generation,sequence,operation}`, <=4096 bytes; replies are bounded by
the existing 1 MiB ceiling. Fragmented headers/payloads are accumulated under one
absolute three-second I/O budget. UTF8, duplicate keys, nonfinite numbers, exact
closed top-level/observation/snapshot shapes, recursive JSON types (no floats),
positive non-bool namespace integers, generation, sequence, expected phase and
literal `false` GO/acceptance flags are checked. Recursive work is capped at
32 levels / 100000 nodes. Kernel snapshot row fields remain opaque JSON evidence,
not independently accepted semantic policy. Initial snapshots/namespace become
an immutable type-exact byte baseline for later replies, never acceptance; the
config digest must match the phase's already accepted old/new config.

Initial reply is sequence 0 / prepared. Each serial operation increments once.
Transitions: prepared→cutover→returned→abandoned, or prepared→abandoned; observe
preserves the current phase. Cutover is NOT terminal. The same PID/socket remains
alive waiting for explicit work, sending only read-only observe heartbeats after
10 idle seconds, below the unchanged server's 30-second idle bound. Total requests
are capped at 128 and every wait shares the original <=600-second deadline.
There is no daemon, heartbeat extension or success exit on cutover/return.

The server's EXISTING abandon ACK is deliberately only
`{phase:"abandoned",operationalGO:false}`; it has no generation/sequence fields.
It is correlated solely to the single outstanding explicit abandon on the
original authenticated stream. No fields or server verbs were added. After that
validated ACK only, normal server socket unlink/exit is permitted; original peer
credentials, holder lease/inputs/deadline and local disposal are still checked.
The ACK precedes server unlink/terminal-journal cleanup, so client exit zero means
**confirmed abandon operation + checked local descriptor disposal only**, NOT a
proof of the server's subsequent natural terminal completion. This explicit
qualification also avoids treating legitimate post-ACK unlink as a new lifetime
failure. Extra reply bytes still refuse; only terminal EOF is allowed then.

Every other EOF, unsolicited/duplicate frame, oversize/truncation, wrong type,
phase/sequence/generation drift, lost ACK, input/identity drift, death, timeout or
close fault is sticky unknown-retained. No next mutation, automatic return,
abandon, rollback, SIGCONT, unlink, recovery, retry or resource cleanup follows.
Local descriptor disposal is not resource cleanup. A failed cutover may already
have changed Caddy. Resource ownership after finite lease/cutover/crash remains
an OPEN external serving-lifetime/recovery contract; keeping heartbeats forever
would conceal rather than solve it.

## Verification scope / H1–H8

`python3 -B -m unittest test_fresh_network_client test_fresh_network test_fresh_physical.AcceptanceTests -v`
uses only ordinary scratch files, real disposable processes, pidfds, anonymous
pipes, one AF_UNIX stream, actual SO_PEERCRED PID and the actual unchanged
control.run→Lease.peer→Controller.prepare path. UID/GID root, accepted host/boot,
PID1 namespace accessibility, installed-root ownership, kernel/Docker/nsfs/nft/
Caddy/HTTP effects are explicitly modeled. It is not a privileged rehearsal.

* H1/H2: real prepare/observe/abandon; delayed listen without consuming a probe
  connection; distinct client child publishes UNACCEPTED identity before the
  separate test-parent issuer writes a lease; exact peer PID is observed by the
  server; same client PID creates the sole AF_UNIX socket. Foreign/stale/typed
  lease, bad peer UID/GID, same-byte replacement, source drift and real dead pidfd
  refuse without adoption.
* H3: real request/reply fragmentation, closed phase/sequence/type validation,
  duplicate/oversize/truncated/EOF/UTF16/invalid UTF8/nonfinite/deep/float/drifting
  nested bool-int replies, unsolicited frames and bounded slow fragments.
* H4: actual idle heartbeat, original-deadline expiry during absent lease/server,
  cutover stays live, lost cutover ACK/input drift, invalid operator verbs/EOF/
  partial lines, close faults, and deterministic normal post-abandon unlink race.
* H5: the actual client child audit hook forbids file writes, fork/subprocesses
  and signals during construction/control. Only stdout/stderr observations are
  written. The unchanged physical verify_input separately consumes an explicitly
  preselected fixture map, rejects map and namespace-type drift; the client never
  copies its namespace observation into resource-plan or physical acceptance.
* H6/H7: unchanged physical acceptance tests retain the stopped/manual barrier;
  source surface checks exclude Coordinator/resume/COMMIT/all-five entry calls.
  Acceptance-file existence is NOT watcher natural-success/release evidence.
* H8: literal new client pin, checked-buffer fixed entry exercised in a disposable
  installed-root fixture, changed-source refusal, RED→GREEN/intermediate logs,
  exact commit/tree/file hashes and independent review are required evidence.

Independent operator intended-policy/exclusion selection, accepted installed
runtime/server, physical manual resource/full-policy publication, natural watcher
success before resume, same Coordinator/all-five authority, post-cutover lifetime,
strict Popen-inclusive 3s, DNS/remote-node SSH/egress, real public HTTPS and full
TEST/PROD operation remain OPEN. No installed, physicalAccepted,
networkPhysicalAccepted, strict3sAccepted, TESTGO or PRODGO claim is made. A NEW
source pack/profile is deferred until complete source closure and independent
review; no existing fixed profile/pin/artifact is rebuilt or weakened here.
