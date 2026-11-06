# Ordinary TEST strict serving witness

Ordinary environment-based TEST startup (no `C3_SETTINGS`) can expose the existing
`GET /classic-ready` handler with **both** trusted server-side settings:

```dotenv
PANEL_DOMAIN=test.infograd.online
C3_TEST_CLASSIC_READY=true
```

`PANEL_DOMAIN` is the existing configured identity, not a request Host header.
`C3_TEST_CLASSIC_READY` is a separate, exact-literal **endpoint exposure opt-in**;
it does not enable topology/L2TP execution or migrations. Missing/false/nonliteral
opt-in or a different configured domain leaves the ordinary route absent (404).
Selection happens once at route registration; requests cannot enable it. Existing
fresh `C3_SETTINGS` mode keeps its same handler without needing this opt-in.
Do not change ordinary startup to file-settings mode to obtain readiness.

A successful response is HTTP 200, `Cache-Control: no-store`, with exact bytes
`c3-classic-ready-v1\n`. It requires the existing complete-boot flag, no started
shutdown, Mongo readyState 1 and Redis status `ready`, then actual Mongo PING
(`timeoutMS: 1000`) and Redis PING, and a second shutdown check after both replies.
Failures return 503/no-store and `c3-classic-not-ready-v1\n`. The handler and
`/health` implementation are unchanged; `/health` is still dynamic and is not a
substitute for this witness. No request initializes models, indexes or services.

The boot flag was already shared by ordinary and fresh startup: it is set only
at the end of `startServer`, after the existing database/runtime/cache,
startup migrations, settings/homepage/expiry initialization, server setup and
background-schedule registration. This change does not move that flag or change
any bootstrap/index/migration/shutdown barrier, writer, timer or listen address.
Before those startup barriers, the actual app has no readiness HTTP listener;
an already-registered handler with an incomplete flag returns 503.

## Local verification

With lock-compatible installed dependencies, Node 20, a private scratch TMPDIR,
`C3_MONGOD`, `C3_REDIS_SERVER` (and its library path if needed), and an existing
private `C3_ORDINARY_READINESS_EVIDENCE` directory:

```sh
node --test --test-concurrency=1 tests/ordinaryReadiness.test.js tests/ordinaryReadiness.integration.test.js
node --test --test-concurrency=1 scripts/test-process-shutdown.js scripts/test-startup-failure-drain.js tests/classicRedisShutdown.integration.test.js
```

The new integration test starts one disposable loopback Mongo replica set and
Redis, with random empty application databases and seven execution switches
false. It execs the actual repository entry/routes in ordinary, fresh, disabled
and foreign-domain modes. A TCP guard rejects any non-loopback application
connection without replacing application dependencies. It checks real startup
refusal while Mongo boot work waits, exact success bytes, real Mongo/Redis PING
failures and recovery, unchanged health, and SIGTERM during a server-stalled
actual PING (503, then natural exit0). Every owned process must be reaped and its
disposable tree removed. Unit route-byte tests explicitly model dependency
states and both pending-PING/shutdown races; these are not physical-host proof.

## TEST-only rollout handoff — not performed here

1. Independently review/import the exact source commit/tree, then build and verify
   a **new immutable backend image**. A running old process/image does not acquire
   this route by changing environment or checking out source.
2. Add only `C3_TEST_CLASSIC_READY=true` to the ordinary TEST backend's trusted
   environment; retain the existing `PANEL_DOMAIN=test.infograd.online`, DB/cache
   endpoints, secrets, volumes, listen/proxy/network configuration, and all seven
   existing false execution switches: `L2TP_EXECUTION_ENABLED`,
   `L2TP_MIGRATIONS_ENABLED`, `TOPOLOGY_TEST_EXECUTION_ENABLED`,
   `TOPOLOGY_PRODUCTION_EXECUTION_ENABLED`, `L2TP_PRODUCTION_EXECUTION_ENABLED`,
   `CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED`,
   `CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED`.
3. Follow the separately approved backend-only stop/start and natural-exit gates.
   Verify exact source/image provenance and the strict endpoint on the actual
   serving path; retain `/health` checks separately. No PROD opt-in is implied.
4. Existing native bundles, sealed roots, launchers, network-constructor artifacts
   and their pins remain immutable and unchanged. This source change does **not**
   automatically refresh them. Any separately required rebuild/repin/requalification
   must be reviewed and executed as its own artifact task.

This witness proves local application serving/boot and current DB/cache replies,
not remote-writer quiescence, node/dataplane health, physical isolation, return
acceptance or physical GO. No deployment or remote operation is part of this
source candidate.
