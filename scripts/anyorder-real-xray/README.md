# Bounded any-order real-Xray fixture

Run only after explicit authorization of this **local rootless subset**:

```sh
python3 scripts/anyorder-real-xray/launch.py --execute-local-fixture
python3 scripts/anyorder-real-xray/verify.py /home/leon/c3-anyorder-execution-20261104/xray-wave7/<exact-run>
```

The launcher uses only the existing private `sandbox/podman.sh`, two checksum-pinned cached images (`--pull=never`), a fresh internal-only network, four fresh P/R/B1/B2 endpoints and a fresh runner. It refuses overlapping subnets and insufficient RAM reserve, snapshots historical container identities/profile hashes read-only, freezes the candidate with `git archive`, and mounts source/dependencies/harness read-only (only the candidate's runtime `logs/` leaf is writable). Synthetic keys, host-key pins, machine IDs, UUIDs and addresses are fresh. No existing endpoint is executed in or changed.

Each new container has a 256 MiB RAM limit, a 256 MiB configured swap limit, bounded CPU and PID counts. Interpret **actual cgroup readback**, not `--memory-swap` wording, when reporting swap availability. Maximum new RAM is 1.25 GiB; the launcher also reserves 1.4 GiB for the parallel Mongo worker and 1 GiB headroom. No build, package installation, Mongo, PPP, host device, privileged/host-namespace/socket access or published port is used.

## Evidence boundary

**Real:** compiler → descriptor materializer → composer → unchanged `TopologyOperationExecutor` → unchanged transport → candidate's pinned `NodeSSH` → exact candidate `runner.sh` → real systemd/Xray/ss/readback → a real loopback SOCKS/VLESS client and controlled HTTP targets.

**Synthetic, intentionally not native authority:** frozen before/after descriptors; in-memory operation/binding/maintenance records; an adapter that checks the preinstalled runner's exact digest while retaining private fixture units instead of the production managed unit. Those fixture units run as root **inside their unprivileged user namespace**, with `GOMAXPROCS=2`. This is not durable Mongo/worker settlement or physical enrollment/maintenance proof. With no binding reader, the real executor must refuse `TOPOLOGY_EXECUTION_BINDING_UNPROVEN` before dispatch; that refusal is checked separately. No security controller is introduced or installed.

The initial empty blocked profiles, one synthetic VLESS user and the SOCKS probe are fixture setup. All subsequent graph installation, no-op, deletion and recreation use real native executor/runner commands. There is no candidate rewrite to make a traffic test pass.

## Executed matrix

Eight bounded scenarios, **not all creation permutations**:

- G1 forward and reverse: P→B1.
- G2 all-forward, all-reverse and mixed: R→B1, then P→R.
- G3 all-forward, all-reverse and mixed: R→B1, R→B2, then P→R.

In every scenario: check each addition; replay a byte-identical plan; delete/recreate each edge; delete all; check default and domain-specific traffic after every operation. Recreation re-adds the same frozen link identity/credentials at the same port; new POST/link-ID allocation and another-port recreation are not covered. Default uses B1; the explicit `full:geo.anyorder.test` policy uses B2. Every node has a different loopback HTTP identity at the same port. P/R are positive direct-leak canaries. Responses bind a fresh nonce, bridge machine identity and observed loopback peer. Incomplete routes must fail HTTP, never return a P/R canary. Other profiles must remain byte-identical. No-op must retain config inode, hash, service PID/start timestamp and restart count.

A tiny synthetic `geoip.dat` supplies only private CIDRs needed by generated private-address guards. This plus a controlled domain rule is **not national geolocation data, public Internet or country-egress acceptance**. The client is VLESS/TCP/security-none, not REALITY.

## Outputs and teardown

Each unique run retains source/harness/image/lock pins, protected private candidate files, exact SSH exit/receipt JSONL, per-operation before/after service/config evidence, traffic/scenario JSONL, explicit result/exit status, dependency parity and exact-owned cleanup/readback. The verifier computes counts and rejects incomplete matrices. Failed attempts remain separate; do not sum them into a passing run.

Teardown stops/removes only recorded exact-owned container IDs and the exact fresh network ID, then checks their absence and unchanged historical identities/profile hashes. No global prune or historical evidence overwrite.

Not covered: HTTP POST/AutoDeploy/manual jobs/save-only queue semantics, Mongo transactions/worker publication, real accepted ownership bindings, background-writer compatibility, PPP/L2TP, REALITY, browser/assets, every permutation, other-port recreation, G4–G7, migration/rollback or PROD readiness.
