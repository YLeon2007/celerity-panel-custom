# Wave 8 — partial runtime/data-plane acceptance

This is a **harness-only** successor to `scripts/anyorder-real-xray/`. It does not replay the unchanged eight-case subset.

## Native authority blocker

`authority-probe.cjs` invokes both existing public controller constructors. The fixed historical config is accepted for construction only; four fresh private nodes, five fresh private nodes, and historical IDs paired with private endpoints are refused with `TEST_PHYSICAL_AUTHORITY_UNKNOWN_RETAINED` **before any channel or observation**. It opens no SSH/DB and reads no real config/key/env file.

The blocker is `testPhysicalController.js:64–95`: exactly five fixed historical IDs, fixed IP/port/user/profile, and a specific shared machine are required. Both root runtime and owner-capture construction call that validator. `scripts/test-topology-owner.js:19–35` obtains its enrollment plan only through the held controller; it is not a caller-inventory API. Runtime `createTopologyOperationRuntime.js:245–269` needs that existing capability to supply the durable store to the default executor.

Do not relabel fresh resources as historical nodes, use historical endpoints, raw-insert owner/binding rows, invent a controller, relax the validator, or replace worker/executor methods to create a success. The native HTTP → durable jobs/Mongo → worker/finalizer → real SSH join stops at this missing fresh-inventory authority capability. General store acceptance of a private IP is not an operational controller for that IP.

## Independently available real data-plane extension

`run.cjs` runs one changed G3 output-first mixed case: reverse R→B1, forward R→B2 (explicit domain policy), reverse P→R. It uses real VLESS **REALITY + xtls-rprx-vision**, a private TLS 1.3/h2 destination, default B1 and domain-selected B2 nonce witnesses, and P/R direct-leak canaries. It deletes/recreates each edge with a new identity, fresh tunnel UUID and different port, checks removal of the old listeners/identities, and tests delete-all and a byte-no-op.

Real path: existing compiler/materializer/composer/executor → pinned NodeSSH → exact candidate runner → systemd/Xray/socket/config readbacks → private HTTP.

Synthetic boundary retained from wave 7: frozen descriptors, in-memory binding/maintenance reader, fixture bootstrap/units, initial single client. These are **not persisted native authority**, POST-created IDs, worker publication or operational physical authority. No worker method monkeypatches or injected terminal-success receipts are used. REALITY client/server configuration is private evidence; this is not a real subscriber/device or PPP test. Private explicit-domain policy is not public country egress.

## Execution

Only the designated private rootless wrapper and cached pinned images may run. No build/pull/npm, host root, privileged container, public port, remote SSH/PROD env, shared database or PPP. New maxima after a recorded capacity refusal: four 128 MiB endpoints plus one 256 MiB runner (768 MiB total); live MemAvailable must also reserve 1400 MiB integration-Mongo plus 2048 MiB asset-build headroom. Actual PID/start/cgroup/namespace/limits and cleanup are recorded; historical containers are read-only inspect/hash subjects, never exec targets.

```sh
NODE_PATH=/home/leon/celerity-l2tp-dev/node_modules node scripts/anyorder-runtime-xray/authority-probe.cjs /home/leon/c3-anyorder-execution-20261104/runtime-xray-wave8/authority-blocker.json
HERMES_HEAVY_MEMORY_HIGH=384M HERMES_HEAVY_MEMORY_MAX=512M HERMES_HEAVY_MEMORY_SWAP_MAX=0 HERMES_HEAVY_CPU_QUOTA=100% ~/.local/bin/hermes-heavy python3 scripts/anyorder-runtime-xray/launch.py --execute-local-fixture
python3 scripts/anyorder-runtime-xray/verify.py /home/leon/c3-anyorder-execution-20261104/runtime-xray-wave8/anyorder-<exact-run>
```

The launcher freezes source/harness hashes before launch and finally removes only exact owned resources, verifies PID/cgroup/network/container absence and unchanged historical identity/profile snapshots. Endpoint disposal may require force removal; that is distinct from the runner's natural exit. No Mongo is started while native authority is blocked, so there is no owned database/process to clean.
