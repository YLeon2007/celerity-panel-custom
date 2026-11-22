# Scoped native reverse observation (Xray 26.11.9)

The pinned Linux/amd64 core (build `676eaf6`, SHA-256 `e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d`) returned an online count of **zero** for a connected native reverse account even with `statsUserOnline` on that account's own configured level. The exact `GetStats` user downlink counter grew during the same idle authenticated carrier. Do not interpret registered online-map entries or a retained dynamic outbound tag as live sessions.

The bearer-protected agent handler takes two exact-name, non-resetting reads 11 seconds apart on the same local gRPC transport. It brackets the sample with the configured listener/account identity, exact email lookup in the runtime account tables, and the matching dynamic native egress. A flat interval or failure is not proof that a link is down. A positive means the authenticated account advanced downlink in the sample, not continuous socket presence, subscriber egress, or a latency measurement. Existing `/stats` resets can mask growth, not create it. The agent caps work at six requests with 13-second deadlines; the panel HTTP observer uses a **15-second** observation timeout. Neither anonymous traffic nor other connections to the same listener can advance the dedicated key. Old profiles do not get it until normal explicit Apply; old agents cannot answer this endpoint. Keep the result informational, separate from billing, subscriptions and lifecycle decisions.

The replay uses the Rebuild composer's receiver MAIN and its exact reverse dialer outbound (including the account name and the explicit `chrome` fingerprint on the pinned 26.11.9 dialer). A minimal dialer profile runs that outbound without the exit routing or GeoIP assets. REALITY uses a locally generated certificate and a loopback decoy. No generated wire fields are patched.

- **Connected → cut → recovered:** `createReverseObserver` uses the product panel HTTP client against the bearer-protected Go router, which queries the same real Xray receiver. The production models persist each result to a disposable `mongod`; `projectReverseHealth` reads it back as `online → deployed → online` without changing lifecycle status or the apply generation. Each HTTP request must take at least 11 seconds and complete within the 15-second observation budget. A positive projects as `deployed` once its proof expires.
- **Endpoint controls:** false before dial, on an actively connected pre-proof profile, for mismatched full ID/port/digest, under certificate-verified decoy traffic, under an unrecognized VLESS UUID, and while a separate anonymous reverse account advances aggregate downlink on the same connector. The cut retains the old dynamic egress; it is not itself proof. Stopping the receiver yields HTTP 503.

Only test binaries and fixture processes are started. The agent test registers the production router directly; it never starts the agent daemon. The panel helper does not start the panel or its jobs and suppresses file logging; HTTP, gRPC, Mongoose, and the projection are not mocked.

## Replay

Run from `cc-agent`. `W` is owned scratch with the approved `local-check` launcher (or a byte-identical copy). Set `XRAY` to the executable pinned above, `MONGOD` to a local MongoDB executable, and `GO`, `MOD`, `CACHE` to the local Go executable and prefilled caches. The launcher must provide Node and the panel's installed dependencies, `ip`, OpenSSL, Python 3.11+, and a fresh loopback-only namespace. No external Python helper, Xray assets, or running database are needed. The fixture checks isolation and removes its generated profiles, certificates, and database after reaping the children.

```sh
/bin/bash "$W/local-check" "$PWD" cwd /usr/bin/env \
  GOENV=off GOWORK=off GOTELEMETRY=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOVCS='*:off' \
  GOMODCACHE="$MOD" GOCACHE="$CACHE" GOMAXPROCS=2 \
  "$GO" test -p=2 -mod=readonly -c -o "$W/cc-agent.test" .
/bin/bash "$W/local-check" "$W" /usr/bin/env GOMAXPROCS=2 /usr/bin/python3 -IB \
  "$PWD/tests/reverse_evidence.py" "$(readlink /proc/self/ns/net)" "$W/cc-agent.test" "$XRAY" "$MONGOD"
```
