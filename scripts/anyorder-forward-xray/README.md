# Bounded legacy-forward MAIN Xray fixture

Test-only successor to `../anyorder-runtime-xray/`, fixed to two imported
legacy-forward nodes (portal and bridge). Product `src/` is immutable.

Each fresh `none` / `reality` run seeds a classic config through the actual
legacy generator, with independent MAIN VLESS clients and a nonempty, running,
separately credentialed SIDECAR on both nodes. Public
`TopologyConfigTransfer.initializeClassic/adopt` creates the imported owner
and immutable `profileTargetPin`; its callback uses actual pinned SSH
config/unit/service readback, but **external exclusion and query/transaction
persistence are explicitly synthetic**, copied from the accepted C fixture
seam. No hand-authored owner receipt/pin or product module override is used.

The unchanged materializer/composer and typed executor use the existing
synthetic binding/bootstrap adapter, real NodeSSH, unchanged runner, systemd,
actual Xray and identity/nonce-bound HTTP. Baseline/apply/no-op/delete/recreate
traffic tests preserve independently credentialed unrelated MAIN clients and
SIDECAR clients. The selected client is genuine REALITY+Vision; the tunnel
variant also uses actual generated REALITY when requested. Delete must block
only the selected route, not fall back to the portal's positive direct canary.
Recreation changes ID, port and UUID, removes the old listener/identity, and
restores selected traffic. No-op checks actual bytes/inode/PID/start/restarts.

Only the designated rootless private Podman wrapper is used, with exact
checksum-pinned cached image IDs and `--pull=never`. Two 192MiB endpoints plus
a 256MiB runner, bounded CPU/PIDs/Go threads, fresh exact-owned internal-only
network, no public ports/default route/host namespaces/sockets/devices. The
launcher pins source/harness and checks byte drift, exact cleanup and unchanged
historical fingerprints. It never starts a Mongo or native controller.

```sh
HERMES_HEAVY_MEMORY_HIGH=384M HERMES_HEAVY_MEMORY_MAX=512M \
HERMES_HEAVY_MEMORY_SWAP_MAX=0 HERMES_HEAVY_CPU_QUOTA=100% \
HERMES_HEAVY_TMP_ROOT=/home/leon/.hermes/cache/scratch/fwd-heavy \
~/.local/bin/hermes-heavy python3 scripts/anyorder-forward-xray/batch.py
python3 scripts/anyorder-forward-xray/verify.py <exact-none-run> <exact-reality-run>
```

Evidence is fresh-only under
`/home/leon/c3-anyorder-execution-20261104/forward-xray-wave31/`.
The verifier rejects partial, non-natural-success, missing, duplicate or
cleanup-incomplete observations. Private config/SSH material is never copied
into the public report. Failed attempts remain separate.

**Not proved:** native physical ownership/exclusion, public HTTP→Mongo→worker
physical join, full deployment, public create-ID allocation, Internet country
exit, background-writer compatibility, PPP or all-order permutations. Existing
physical-authority refusal is not reprobed or bypassed here. Do not combine
this independent real-data-plane subset with modeled or Mongo results into a
claim of full native deployment acceptance.
