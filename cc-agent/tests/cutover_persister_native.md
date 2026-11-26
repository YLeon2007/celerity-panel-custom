# Native MAIN cutover / cc-agent writer boundary

`TestNativeCutoverPersisterBoundary` is an opt-in characterization, not an Apply acceptance test. It runs the existing agent HTTP handler, `UserStore`, `ConfigPersister` and native atomic writer on synthetic data. Xray is an actual subprocess; the harness owns and joins its restarts (no systemd). No daemon, package, or deployed agent is changed.

The control starts from the desired MAIN. An agent `POST /users` reaches the real Xray HandlerService; a flush changes the bytes but not the canonical projection without the managed `settings.clients`.

The second case starts from exit A. The same agent request adds a user; the persister is paused at its existing `writeFile` seam **after** it has read and serialized MAIN. The harness writes exit B with that user and restarts Xray. It verifies the new PID, the boot projection, `ListRule`, a matching `TestRoute` context and the exact named user set. The old flush then does its original real atomic rename. The running process and users still check out, but the file again has exit A. A second flush does nothing because clients already agree with `UserStore`. The next Xray start selects A with the same user set. This is a stale whole-file publish, not an agent edit to the routing rules it read. The same publication race applies to a rollback target.

`ListRule` returns action and rule tags, not predicates. `TestRoute` proves the result of a supplied context, not the identity of all predicates. See the negative control in `scripts/native-portal-exit`. A stable observed projection and live user census cannot rule out an earlier writer still waiting to rename. This probe does not certify systemd, MongoDB, or production writer exclusion. Do not use it to remove the product guard.

The `/sync` control runs the real ordinary handler with one existing email. Both an unchanged UUID and a replacement UUID return the same exact zero-delta ACK while HandlerService still reports the original UUID and MAIN still has the original bytes and inode. Running the actual flush scheduled by `MarkDirty` preserves the inode only for the truly unchanged payload. The change under the same email replaces MAIN and leaves the live account stale. In particular, a zero-delta ACK followed by a readback is not evidence that it is safe to update an exact DIRECT pin.

## Reproduce offline

From the repository root, set `XRAY` to a local test binary: 26.3.27 (`8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`) or 26.11.9 (`e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d`). Use an existing Go toolchain and caches. Builds below cannot download anything. The test requires a sandbox without operational settings, resolver files, or sockets.

```sh
set -eu
out=$(mktemp -d "${TMPDIR:?}/c3-native-cutover.XXXXXXXX")
parent=$(readlink /proc/self/ns/net)
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOENV=off CGO_ENABLED=0 GOMAXPROCS=2 \
  unshare -Urn --fork --kill-child=SIGKILL go -C cc-agent test -c -mod=readonly -p 2 -o "$out/agent.test" .
unshare -Urn --fork --kill-child=SIGKILL /bin/sh -ec '
  ip link set lo up
  exec bwrap --unshare-pid --die-with-parent --new-session \
    --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin \
    --dev /dev --proc /proc --bind "$1" /work --ro-bind "$1/agent.test" /tools/agent.test \
    --ro-bind "$2" /tools/xray --clearenv --setenv PATH /usr/bin --setenv HOME /work \
    --setenv TMPDIR /work --setenv C3_CUTOVER_PARENT_NETNS "$3" --chdir /work -- \
    /tools/agent.test -test.run=^TestNativeCutoverPersisterBoundary$ -test.timeout=35s -test.v
' fixture "$out" "$XRAY" "$parent"
```
