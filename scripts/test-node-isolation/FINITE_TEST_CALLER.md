# Selected TEST finite caller connections

`finite_test_caller.py` supplies four small connections for an **existing trusted
ROOT caller**, not an end-to-end controller, issuer, installed entry replacement,
or operational GO. Import its reviewed/hash-bound bytes in that caller. The only
subprocess CLI it adds is its finite, read-only `observer-child` implementation.
No installation, SSH, API, database, hold, freeze or network-service activation was
performed to qualify this slice.

The separately accepted policy repair is `1d76324817a4ea017356e140abe70e16be3781cb`;
this caller-only branch does not import its five disjoint changed blobs. Final
caller regression uses a private exact Git export with those five policy blobs,
preserving all three caller blobs and checking the current observer pin closure.
This addition does not change historical source pins or any installed artifact,
and policy compatibility alone does not authorize a physical run. Final physical acceptance still follows
current restore acceptance and the **final canonical restore-config** pin;
original capture/enrollment precedes mutation. Existing same-Coordinator
COMMIT → serving → resource handoff → required disposal → terminal ACK is unchanged.

## 1. Recovery transport

`recovery_argv(accepted_inventory_node, carrier=..., key=..., known_hosts=...,
known_hosts_sha256=...)` maps only the selected inventory endpoints:

| Node | Accepted endpoint | Explicit carrier choices |
| --- | --- | --- |
| P `6aecd36265572a55acf7c677` | `10.203.61.2:2222` | `P-private`, `P-public` (`104.143.201.72:2222`) |
| B `6aed089795ea4b863887d717` | `10.203.61.1:2222` | `B-private`, `B-public` (`132.243.230.19:2222`), `B-private-via-P` |

Pass the same **full node** returned by the existing
`isolation.validate_inventory` → `isolation.inventory_node` path, without
projecting or editing its endpoint. Both endpoints have exactly `ip`, integer
`port: 2222`, and `username: "c3-test-runner"`. Missing/extra keys, another
username, or a changed selected ID/IP/port are refused before the known-host read.
The inventory username identifies the restricted runner account, **not** the
recovery login: recovery always uses `c3-test-operator@CARRIER_IP` for the existing
independent operator-session guard. It never logs in as the inventory runner,
root, or a caller-selected recovery username. The port-22 jump account remains
a separate explicit input, not a substitution for either maintenance account.

Carrier reachability/NAT and authentication must be independently accepted, not
inferred from that table. No fallback is selected. `B-private-via-P` requires an
explicit separately accepted `jump={"user": ..., "key": "/absolute/path", "port":
22}` for **P `104.143.201.72:22`**. The maintenance sshd on P port 2222 disables
forwarding and is deliberately not used as a jump server. If P's separate port-22
forwarding carrier is not accepted/available, this choice is unavailable; use
another explicitly accepted listed carrier or stop.

Use plain exact known-host records `[CARRIER_IP]:2222`, plus `104.143.201.72` for
the port-22 jump. Hashed/aliased known-host records are not silently normalized.
Only accepted key **paths** are passed to SSH; this code never reads key contents.
The known-host file is noatime/nofollow read and checked against ROOT's supplied
raw-byte digest. Keep those accepted paths immutable and under the independently
exclusive operator window for the whole transport lifetime. SSH uses `-F
/dev/null`, strict host-key verification, a pinned known-host file, no global
host-key file, no multiplexing and no interactive/password fallback. The remote
command remains the existing `sudo -n ... c3-test-node-isolation guard`, never an
alternate shell/recovery command.

Run `serve_recovery(argv, end=ORIGINAL_MONOTONIC_END, on_ready=record_observation)`
in a finite foreground caller scope. It owns/reaps only its SSH Popen. Keep this
responder promptly draining throughout the scope (a blocking `on_ready` can
consume the server's two-second budget). It echoes the original 64-hex nonce via
the existing `recoveryResponse` protocol; it does not reset the server deadline or
replace the server's actual independent-maintenance-SSH ancestry checks. Forwarded
`identity`/`session` are observations, not accepted authority. Loss/EOF/expiry
never thaws or retries anything.

## 2. First greeting → independent ROOT lease → prepared

Use the **existing** `fresh_network_invocation.Invocation(network)` API in its
sole original parent, loaded from independently reviewed current pins with the
existing checked source loader. It retains its real holder Popen, stdin/stdout,
pidfd and original absolute budget. Do not invoke its CLI and then also construct
a second creator. Do not run another child reaper or install `SIGCHLD=SIG_IGN`.

The following is the relevant connection, not a full lifecycle example:

```python
invocation = creator.Invocation(network)  # existing sole original parent
raw_greeting = caller.holder_greeting(invocation)
# STOP at this boundary for independent ROOT review/issuance.
# ROOT supplies accepted_greeting_sha256, accepted_lease_raw and its independent
# accepted_lease_sha256. No function here constructs that accepted lease.
raw_prepared = caller.lease_then_prepare(
    invocation, network_control, raw_greeting,
    accepted_greeting_sha256=accepted_greeting_sha256,
    accepted_lease_raw=accepted_lease_raw,
    accepted_lease_sha256=accepted_lease_sha256,
    start_network=explicit_bounded_start_of_existing_network_service,
)
# Keep invocation and its original creator lifetime for the already supported
# literal handoff/public settlement; this adapter does not reap its holder.
```

`explicit_bounded_start_of_existing_network_service` is ROOT's explicit action
for `/usr/bin/systemctl start c3-test-fresh-network.service`, using
`invocation.budget()` as the unchanged remaining timeout. It must not retry an
unknown start. No start callback is called before accepted lease publication.

The exact existing lease schema is checked by the actual
`fresh_network_control.Lease`, against real original PID/start/pidfd, original
raw-plan hash, boot/generation/deadline and closed operations. Before publication,
only its lease-byte read is projected from ROOT's supplied accepted bytes; all
other checks remain actual. Publication uses a fixed sibling `.finite-next`,
file fsync, Linux `renameat2(RENAME_NOREPLACE)` and directory fsync, then actual
fixed-path readback through `Lease.check`. A visible incomplete file is never
used as the rendezvous. Existing targets and uncertain staging/publication are
not replaced, deleted, retried or relabeled as success.

Only then does the explicit network start occur and the creator consume its
actual holder's prepared line. This avoids the lease/prepared deadlock. The raw
first greeting remains `accepted:false`; no accepted flag is manufactured.
Observation/stdout possession is not the issuer action. The separate hash-bound
ROOT input is a caller trust premise, not a new approval schema or public
capability. No function here renews the original <=600-second deadline.

## 3. Real observer constructor handshake

```python
with caller.ObserverChild(
    deadline_ns=accepted_original_physical_run_deadline_ns,
    loader_sha256=accepted_checked_loader_sha256,
    source_pins=accepted_current_observer_source_pins,
) as observer_child:
    initialization = observer_child.ready()
    # Verify the original watcher/supervisor/generation/run-plan binding against
    # independently accepted caller inputs. Keep original external holds.
    observer_child.check_initialized()
    # Independent ROOT accepts/publishes the existing physical acceptance here,
    # after final policy/restore-config acceptance. This adapter cannot do it.
    # Check the original child again while performing that independent action.
    result = observer_child.finish()
# Only natural exit 0 plus required pipe/process disposal completes this scope.
```

Pass the **unchanged original** accepted physical RunPlan deadline, itself no later
than the original network end; never compute a fresh budget from the current
time. `source_pins` is exactly the installed observer `SOURCE_PINS` path set plus
`/usr/local/libexec/c3-test-fresh-physical-observe.py`, with independently reviewed
**current** values. No running-source measurement becomes acceptance. The
existing noatime/nofollow checked loader is itself separately pinned. The wrapper
compiles the actual source closure, injecting the same coordinated-restore module
before executing fresh-classic source, as the supported original entry does.

The finite owned child runs the real `Observation` constructor, emits
`observerInitialized` **only after it returns**, and retains that exact object
through its real `wait` and checked close. The unchanged fixed observer CLI has
no first-ready ACK and is not modified. Source reads/rechecks use checked bytes,
not its historical plain source reader. A signal timer bounds source loading,
constructor and observation by the original end, with separately bounded parent
pipe reads and original-child pidfd liveness checks. Popen scheduling or a file's
presence is not readiness. Early EOF/nonzero exit, constructor failure, expiry or
required disposal failure is unknown/refusal, never acceptance. This child never
signals/reaps the original watcher or supervisor; their existing owners retain
that responsibility. Only its own exact unreaped child is disposed.

## 4. Accepted-machine B original inventory

```python
freezer = caller.load_b_capture_api(
    loader_sha256=accepted_checked_loader_sha256,
    freezer_sha256=accepted_freezer_sha256,
)
unaccepted_original_inventory = caller.capture_b_originals(
    freezer, accepted_b_inventory_node,
)
# Independent ROOT review/publication is a separate action, before mutation.
```

This calls the actual `LinuxKernel`, read-only `SystemdRelaunchBarrier`,
`host_precheck(kernel, expected_machine_id=accepted_node['physical']['machineId'])`
and `capture(kernel)`. It does **not** invoke the historical standalone capture
CLI/default machine. A wrong accepted-machine binding fails at actual precheck,
before Docker inventory or any publication. Returned data is not `hostHold`
authority and contains no added `accepted:true`, capture/COMMIT receipt or
physical GO. The caller must load its node from the existing accepted inventory
validation, not from mutable public request data.
The same full B endpoint, including `username: "c3-test-runner"`, is required
before constructing `LinuxKernel`; no username stripping or alternate inventory
validator is used. The accepted physical machine ID still flows unchanged into
the actual `host_precheck(expected_machine_id=...)`.

## Local evidence and limits

Run only the disposable local regression:

```sh
python3 -B scripts/test-node-isolation/test_finite_test_caller.py -v
```

It exercises actual recovery roundtrip code, original finite creator, actual
Holder constructor/greeting/connect/receive, actual Lease and Controller.prepare,
real Popen/anonymous pipes/AF_UNIX/pidfds, actual observer constructor/wait with
real original watcher/supervisor processes, and actual freezer
precheck/capture/LinuxKernel over disposable proc/cgroup files. Independent ROOT
issuance/physical acceptance, SSH authentication/ancestry and reachability,
network namespaces/host arm/CAP_SYS_PTRACE, PID1/systemd and physical host/kernel
facts are **explicitly modeled**. Natural observer success is not physical or
full TEST lifecycle acceptance. These tests do not contact an installed target,
create operational lease/hold files, connect a database or start any real network
unit. They preserve failed attempts separately from passing evidence.

The inventory-shape repair preserves a three-case initial RED: validated P and B
nodes previously failed recovery before the known-host read, and validated B
failed capture before `LinuxKernel`. The repaired suite retains the original 19
test identities and adds four (two producer-to-recovery positives and two narrow
binding-refusal tests): **23 unique tests**, not the sum of repeated RED/GREEN
runs. The existing capture positive now also consumes the real validated full B
node. Wrong physical machine identity still reaches and fails the real precheck;
malformed machines and endpoint/username/ID substitutions fail before construction.
Lease/Holder/Observer IPC, original deadlines (<=600 seconds), no unknown retry,
and no automatic thaw/cleanup authority are unchanged. Additional observer source
bootstrap controls, if run, are separate controls, not additional caller tests.
