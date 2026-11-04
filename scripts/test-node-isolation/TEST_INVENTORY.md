# TEST physical inventory profiles

This parameterizes the existing finite TEST controller, capture, isolation,
originals and attestor consumers. It does **not** construct a new physical hold,
create a service/store, authorize PROD, or turn rootless containers into host
maintenance authority.

## Compatible historical profile

Existing `version: 1` physical/capture/isolation inputs select the
**historical-test-v1** profile. Its exact five IDs, endpoints, maintenance port
2222, runner/operator users, shared machine ID, dual-profile snapshots and host
freezer contract remain unchanged. No inventory file is consulted and existing
inputs do not silently move to a fresh profile. Historical endpoints must not
be used for fresh-lab testing.

## Independently accepted private profile

An operator independently accepts and installs the *same* JSON document at
`/etc/celerity/topology-test-inventory.json` on the application/coordinator and
each selected node. Its ancestors and file must be root-controlled, without
symlinks or group/other writes; the application's existing private reader also
requires no access for others. Do not generate authority from HTTP fields,
environment variables, mutable HyNode records, or a successful connection.

Exact schema (values below describe types, **not accepted pins**):

- `version: 1`, `profile: "accepted-test-v1"`;
- `executionContext: {target: "test", hostIdentity: "test.infograd.online"}`;
- `sharedNodeId`: the exact selected node sharing the coordinator/old-backend
  host; it is required, not an optional "no old writer" switch;
- `nodes`: an exact list of 1–5 records, each containing only:
  - `nodeId`: 24 lowercase hex characters;
  - `targetProfile`: `xray-main` or `xray-bridge`;
  - `endpoint: {ip, port: 2222, username: "c3-test-runner"}`; `ip` is an exact
    canonical RFC1918 IPv4 address, unique in the inventory;
  - `physical: {machineId, bootId, sshHostKeySha256}`: respectively 32 lowercase
    hex, lowercase UUID and SHA256 of the **raw** SSH public key; machine and key
    identities must each be unique;
  - `profiles`: exactly `[targetProfile]` or `["xray-main", "xray-bridge"]`.
    The shared node must target bridge and retain both profiles.

The five-node maximum preserves the existing bounded observation codec; it is
not a default allow-all cohort or a new unbounded capture protocol. Endpoint
aliases and multiple inventory rows for one physical machine remain refused.

Compute `inventorySha256` as SHA256 of UTF-8 JSON with recursively sorted object
keys, compact separators and unchanged array order. This is an independent
policy pin, not a self-acceptance operation.

Use `version: 2` plus this exact `inventorySha256` in:

1. `/etc/celerity/topology-test-physical.json` (all other existing physical pins,
   host hold/backend identity and original snapshot pins remain required);
2. every `/etc/c3-test-node-isolation.json` plan (including shared mode);
3. `/etc/c3-test-coordinated-capture.json` and its `ownerChallenge`.

The root factory reads the fixed inventory path, then validates exact inventory
membership, endpoints, profiles, machine/boot/key pins before opening channels.
The direct JS constructor's `inventory` argument is a trusted programmatic test
seam, never a request/environment input. Owner enrollment remains an explicit
root caller choice; ordinary runtime still requires already durable originals
and never falls back to capture.

The capture consumer loads the **pinned installed isolation bytes** to reuse the
same inventory validator; it does not add a Python module/service installation.
Its config and every node identity carry the same digest. The generated owner
challenge carries version/digest without changing the finite pipe wire version.
The coordinator's machine/boot must equal the accepted shared node. SSH argv and
known-hosts still use only fixed commands, pinned keys and accepted maintenance
endpoints. All-node counts/observations use exact accepted membership, never a
caller-selected subset. Node originals and ordinary attestation validate all
accepted profiles, including nonexecuted secondary originals, with the same
policy digest durably bound into original identity/bundle metadata and the plan
hash. Guard, flock, live old-writer, predecessor, CAS, and uncertainty retention
checks are not removed.

Reaccept source/config/helper hashes explicitly after installation; this change
does not silently repin any historical immutable source pack.

## Physical gate — still closed in the available rootless lab

The existing shared engine requires the actual Docker/systemd old backend:
`hysteria-backend`, updater and retained payloads; independent root host controls
`/system.slice/docker.service` and `containerd.service`; real cgroup freezer,
relaunch barrier and recovery/host-held channels. A namespace-local root user
or an in-memory "backend stopped" result is not equivalent.

The fresh cached endpoint probe used an actual rootless systemd container. It
found no `/usr/bin/docker`, no Docker socket and neither control cgroup. The
actual unchanged `panel-host-freezer.py` capture returned `FileNotFoundError`
for `/usr/bin/docker`; its host precheck also retained its historical machine
restriction. No fence was armed or fake successful observation returned.

Consequently do **not** run/adopt/enroll or seed a Mongo application receipt on
that lab under this contract. Inventory/schema positives and real local
files/fsync/flock tests are **modeled physical authority**, not acceptance of the
physical enrollment/HTTP/worker/executor/finalizer join.

Outside this slice, the existing freezer owner would need a narrowly reviewed
accepted-machine parameter on `host_precheck` (defaulting to historical identity)
for the new shared profile; the shared consumer would pass its already validated
machine. That source-only hunk cannot supply the missing Docker/systemd/cgroup
host primitive. Coordinated restoration/handback remains the historical profile;
no fresh restore/activation acceptance is claimed or authorized here. Do not
invent a rootless backend, use the outer host's daemon/socket, remove shared
checks, or call narrower green tests full-chain acceptance.
