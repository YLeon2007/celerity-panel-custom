# Offline regression: retire a native reverse dialer

From the repository root, on the Linux host with the existing offline artifacts:

```bash
set -o pipefail
umask 077
scripts/retired-reverse-xray/run.sh \
  /home/leon/.hermes/cache/scratch/c3-reverse-signal-26119.kiMli6jL/xray \
  /home/leon/c3-main-62c4b74-xi7v5rrq/app/node_modules \
  |& tee ../retired-reverse-xray.log
```

The two arguments may point to equivalent local artifacts. The runner checks the
exact cached **Xray 26.11.9** binary by SHA-256. It needs unprivileged user/network
namespaces, bubblewrap (`--disable-userns` support), `ip`, Python 3.11+ at
`/usr/bin/python3`, and a local Node on `PATH`. The launcher uses the Debian-style
runtime library paths `/usr/lib` and `/usr/lib64`. It never installs or fetches
anything. Isolation failure is a failure, not a skip or a fallback to the host
network. The runner checks for a different network namespace, only `lo` up, and
no IPv4/IPv6 default route, before starting the fixture. Source, dependencies and
Xray are mounted read-only; raw diagnostics and profiles live only on disposable
private tmpfs. Normal output contains only checked facts, not UUIDs or raw logs.

## What the test proves

The real `composeRebuildProfiles` composes `portal → relay → bridge` and then
`portal → bridge`. Both edges in the original path use native VLESS reverse;
those arrows denote payload direction, not who dials. The replacement has a
fresh synthetic UUID but intentionally binds the **same IP:port** on the
surviving portal. TCP without TLS or VLESS encryption in this fixture isolates
UUID authentication from TLS/key mismatch. The same synthetic subscriber runs
throughout. All evidence is from real local Xray processes:

1. **Before:** the relay authenticates and a fresh nonce sent by the subscriber
   echoes back from the origin across both reverse hops.
2. **After / OLD:** the portal is reaped and started with the newly composed
   profile. The exact original relay process stays alive with its unchanged
   outbound and its old downstream exit, as a stale dialer might. The new Xray
   listener logs a VLESS invalid-user rejection matching the exact retired UUID
   (compared privately). With only OLD dialing the new listener, require zero
   authenticated reverse requests. All three subscriber probes must reach VLESS
   ingress, with zero new connections or payload at the origin and zero response
   bytes. An absent listener, startup failure, or generic EOF cannot pass.
3. **After / VALID:** start the surviving bridge using the new generated dialer.
   Require an authenticated reverse request and nonce echo through the same
   post-delete listener and subscriber, both before and after another real OLD
   rejection while the surviving dialer is active. All owned Xray children must
   be reaped before the final PASS.

The portal profiles change only their `log` section for observations. The relay
runs the complete original generated MAIN; each exit uses the exact generated
reverse outbound in a test-only wrapper restricted to the single loopback echo
origin (the stock exit policy denies private addresses). The test does not alter
product files, call DELETE/Apply, exercise a future graph planner, or claim
management-plane deployment, production egress, or coverage of other transports.
It is a **desired-graph composer + wire regression**, runnable on the baseline
and replayable after integration.
