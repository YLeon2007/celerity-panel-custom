# Installed reverse G2 — bounded real private Xray slice

Uses only the previously authorized cached rootless fixture via `/bin/sh /home/leon/c3-portal-bridge-delivery-20261103/sandbox/podman.sh`.

- Real classic P MAIN / R SIDECAR / B SIDECAR initialization, G/K suffix `[d]`, actual public initialize/adopt over SSH-observed bytes; no seeded owner receipts.
- Independent nonempty P SIDECAR / R MAIN / B MAIN, including **unchanged generated L2TP fragment** on R MAIN. Failure to run that exact profile under existing capabilities is a terminal stand limitation, not permission to remove it.
- Real generator/compiler/materializer/composer, typed executor, NodeSSH and unchanged runner; actual systemd/Xray services and identity/nonce-bound traffic.
- First scenario: baseline, apply unchanged d, new-execution byte-noop, delete d, new ID/port/credential d restores both routes. Second fresh scenario: delete u blocks portal but retains R→B group-SOCKS, fresh u restores portal.
- Client paths: credentialed VLESS portal P→R→B and an independent curl SOCKS client entering the actual existing loopback group listener on R SIDECAR. **Not L2TP/PPP ingress.** Six credentialed unrelated/independent profile traffic controls run at every stage.
- Synthetic seams: initial fixture/bootstrap units, owner query persistence/transaction shape, external hold, in-memory execution binding, protected installed PSK/users metadata, descriptor group-path publication and ID allocation. No native physical enrollment, Mongo/worker join or PPP readiness claims.
- No generated candidate patching, new capabilities, privileged/host namespace/device/socket/public ports, pull/build/install, old endpoint mutations or remote systems.

Run from a clean committed worktree in a finite `hermes-heavy-*` user scope (384MiB high / 512MiB max, swap0, CPU100%, TasksMax256):

```sh
python3 scripts/anyorder-installed-group-xray/batch.py
```

The launcher enforces its own cgroup separation, live memory reserve, pinned cached images/dependencies, source/harness freeze and exact-owned cleanup. Evidence goes only to `installed-group-xray-wave43`. Stops at first failed scenario; preserves failure and private raw logs. Never use a timeout/administrative kill as a natural successful runner exit.
