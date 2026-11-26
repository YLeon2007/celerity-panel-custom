# Native Xray MAIN read-only proof

This one-shot child is for a **future trusted local host receiver**, not a
receiver, RPC proxy, or installer. It opens at most one TCP connection to
`127.0.0.1:61000` in its own network namespace, without DNS resolution, proxies,
network fallback or reconnect. No arguments or endpoint overrides. It invokes
only `HandlerService.GetInboundUsersCount`, `HandlerService.GetInboundUsers`,
and `RoutingService.TestRoute` with publication disabled.

## Private stdin / stdout v1

Pass one UTF-8 JSON object and close stdin. Example (synthetic):

```json
{
  "version": "native-xray-main-proof/v1",
  "namedInbounds": [
    {"tag":"vless-in","users":[
      {"email":"fixture@main.invalid","uuid":"00000000-0000-4000-8000-000000000001","flow":"xtls-rprx-vision","level":0}
    ]}
  ],
  "routes": [
    {"context":{"inboundTag":"vless-in","network":"tcp","targetPort":443,"targetDomain":"choice.example.invalid"},"outboundTag":"selected"},
    {"context":{"inboundTag":"vless-in","network":"tcp","targetPort":443,"targetDomain":"fallback.example.invalid"},"outboundTag":"default"}
  ]
}
```

- Supply all expected **named** rows per scoped VLESS inbound. An expected empty
  named census is `"users":[]`. Identity is exact email, canonical lower-case
  UUID, explicit flow (`""` or `"xtls-rprx-vision"`) and explicit `uint32` level.
  Order is irrelevant; duplicate case-folded emails and duplicate effective
  VLESS UUID keys are rejected per inbound. Tags use `[A-Za-z0-9_.:-]` (up to
  128 bytes); emails are 1–254 visible ASCII bytes.
- Route context is exactly a scoped inbound tag, `tcp` or `udp`, a nonzero
  destination port, and at least one of ASCII `targetDomain` (no trailing dot)
  or canonical literal `targetIP` (unmapped IPv4 or unzoned IPv6). Supplying both
  is meaningful: both are sent, without normalization, DNS lookup or dialing the
  target. The complete selected response must equal the context plus the
  expected outbound tag; a group tag or different/additional field fails.
  A route miss is **not** taken as the dispatcher's default outbound.
- Limits: 2 MiB stdin, 16 inbounds and 10,000 named users total, 32 distinct route
  contexts, 4 MiB per gRPC response, 4 s for all RPCs on one connection, 8 s for
  the whole child. Duplicate/unknown keys, `null`, and trailing values fail.
- Exit 0 produces one JSON receipt (below; census rows correspond to input
  order). Exit 2 rejects input; exit 1 means proof unavailable or mismatch;
  exit 124 is the hard deadline. Diagnostics contain only a fixed code and, if
  applicable, a zero-based inbound/route ordinal. Do not log stdin or native
  protobufs. Accept only a complete receipt with exit 0 on the original pipe.

```json
{"version":"native-xray-main-proof/v1","userScope":"named-vless-email-index","namedInbounds":[{"handlerCount":1,"enumeratedNamed":1}],"routesVerified":2}
```

## Evidence boundary

On both pinned Xray 26.3.27 and 26.11.9, count (read before and after the list)
and unfiltered enumeration see the **email index**. Adding a separate
anonymous UUID in the real fixtures changed neither. This evidence cannot
certify the absence or identity of anonymous clients, equality with the UUID
validator/authentication table, or successful authentication/traffic. Account
options other than UUID, flow, level and email are not part of the proof.
Counts do not make the reads an atomic snapshot.

The receiver must bind the invocation to the accepted MAIN PID/executable,
exclusive listener and active profile, independently check the VLESS tags
(including an empty census), and hold its generation/writer fence across the
observation. Plaintext loopback gRPC does not authenticate its peer. Require
`HandlerService` and `RoutingService` already available on that listener;
stock panel generation currently includes only `HandlerService` and
`StatsService`. This component does not enable services or weaken guards.
The receiver must allowlist its own finite plan and establish `AsIs` routing
with static outbound rules (no balancers) in the active router: the native
`TestRoute` runs `PickRoute` and other router profiles may resolve DNS or use
stateful balancing inside Xray. This is a check of the selected contexts, not
of every rule predicate, the full active config, or client egress.

## Offline build and tests

Run from the repository root with a prepared local Go/module cache. The Go
commands below are explicit-file builds against the unchanged `cc-agent`
module; enforce a read-only module cache and run with no network in the build
sandbox. `work` is an existing private directory under the approved scratch
root; `old` and `new` are the already-present immutable pinned executables.

```sh
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOENV=off
export GOMAXPROCS=2 CGO_ENABLED=0
proof=../scripts/native-xray-main-proof/proof.go
go -C cc-agent build -mod=readonly -p=2 -trimpath -o "$work/main-proof" "$proof"
go -C cc-agent test -mod=readonly -p=2 -v -timeout=30s "$proof" "${proof%.go}_test.go"

env -i PATH=/usr/bin:/usr/sbin HOME="$work" TMPDIR="$work" \
  C3_PROOF_PARENT_NETNS="$(readlink /proc/self/ns/net)" \
  unshare -Urn --fork --kill-child=SIGKILL /bin/sh -ec '
    ip link set lo up
    umask 077
    exec timeout -k 3 45 /usr/bin/python3 -I -B "$@"
  ' fixture scripts/native-xray-main-proof/test_native.py "$work/main-proof" "$old" "$new"
```

The native matrix checks SHA-256/version, PID ownership of the API listener,
positive and negative identity/route proofs, same tag/actions with a changed
route predicate, count/list behavior with an anonymous user, absent API and
missing RoutingService. All test outbounds blackhole; no traffic is sent to
the route targets. Each row prints its exact verified case roster and observed
Xray child exit statuses.
