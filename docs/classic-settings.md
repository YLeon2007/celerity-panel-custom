# Opt-in real classic application settings (source-only)

This closes application compatibility with the fresh launcher's two-key environment.
It does **not** provision or accept a root, namespace, ingress, supervisor, physical
host, owner bridge, restoration, or activation. All execution flags remain dormant.

## Contract

Absent `C3_SETTINGS`, ordinary dotenv/env configuration, logger paths, listener
selection, `/health` body and existing lifecycle remain unchanged. An empty or
invalid `C3_SETTINGS` is an explicit refusal, not ordinary-startup fallback.

When selected, `src/classicSettings.js` validates the bounded JSON file **before
application imports**. It neither sources a shell nor loads dotenv. Only then does
it project the exact file environment for existing env-only consumers (notably
Redis, HTTP/Caddy selection and the root lifecycle). Ambient variables are removed;
this includes ambient execution flags, updater secrets and alternate spool paths.
Validation errors expose only `CLASSIC_SETTINGS_REFUSED`, never file contents or
credential values. Node's interpreter environment must itself be controlled before
exec; this reader is not a defence against an earlier `NODE_OPTIONS` preload.

The launcher's fixed operational file is `/etc/classic.json`. The reader accepts
canonical absolute file/state paths so unprivileged local tests need no mount or
host `/etc` writes. **It does not independently attest those paths.** Operational
acceptance must pin the file bytes, `/state`, and the exact ingress described below.
The final file must be a regular single-link non-group/world-writable file, not a
symlink, at most 16 KiB. The accepted launcher already requires the entire read-only
root closure and excludes symlinks. Settings must not be edited in a serving root.

Exact top-level schema (no unknown keys):

- `version`: integer `1`.
- `context`: exactly `test.infograd.online`.
- `stateDirectory`: canonical absolute directory; operational value **`/state`**.
- `listenAddress`: concrete IPv4 address, not wildcard; operational value
  **`212.119.42.100`**. The local probe uses `127.0.0.1`. Binding an IPv6 or wildcard
  listener is incompatible with the launcher's exact IPv4 listener proof.
- `environment`: exact string-valued keys below, no ambient/default fallback:
  - `PANEL_DOMAIN`: exactly `test.infograd.online`.
  - `ACME_EMAIL`: email-shaped string.
  - `ENCRYPTION_KEY`, `SESSION_SECRET`: existing private values, at least 32 chars.
    Do not rotate or replace real encrypted-data/session keys using test fixtures.
  - `MONGO_URI`: explicit single-host `mongodb://` URI with a named database.
  - `REDIS_URL`: explicit single-host `redis://` URI, optional numeric database.
  - `USE_CADDY`: exactly `"true"` (HTTP behind separately accepted ingress).
  - `PORT`: canonical decimal port string; operational value **`"3000"`**.
  - `L2TP_EXECUTION_ENABLED`, `L2TP_MIGRATIONS_ENABLED`,
    `TOPOLOGY_TEST_EXECUTION_ENABLED`, `TOPOLOGY_PRODUCTION_EXECUTION_ENABLED`,
    `L2TP_PRODUCTION_EXECUTION_ENABLED`: all exactly **`"false"`**.

Other fields/options are deliberately not generalized here. This is not a migration
of the ordinary config API, a new sandbox, or an execution-authority capability.
Private Mongo/Redis credentials may be present in the pinned private file but must
not be copied into public manifests, test logs or issue reports.

Selected logging, panel log viewing/search, and log cleanup use
`<stateDirectory>/logs`; the access-log spool and temporary paths are also projected
beneath that state directory. Multer backup upload staging is
`<stateDirectory>/backup-uploads` in selected mode (ordinary startup keeps its
existing `/tmp/backup-uploads/`). This removes the eager import-time mkdir outside
private state; it does not accept backup/restore operations. Mongo seed lists,
including percent-encoded host separators, are refused before env publication.
No source
`/app/logs`, Greenlock directory, or dotenv write is needed for this startup. This
is still the real **classic** startup: its existing Mongo settings/index/backfill
work and background jobs have not been redesigned or disabled. It is not a
maintenance/read-only-database mode, and restored-data migrations are not accepted
by the empty disposable-database proof below. Other administrative features such
as backup/update/export are outside this focused startup compatibility claim.

## Deterministic witness and parent-owned hunk

Only selected mode adds `GET /classic-ready`. It returns HTTP 200 and exactly the
UTF-8 bytes `c3-classic-ready-v1\n` after boot preparation and current real Mongo
`ping` and Redis `PING` replies. Disconnected/not-started/shutting-down dependencies
or failed pings return 503. The body SHA-256 is:

```
437210538daa3691735d03ab798dbba7bef28404e621f17ea569a6b28c370da6
```

It is a serving/dependency witness, not topology readiness, traffic proof, physical
isolation, or ownership settlement. `/health` retains its dynamic uptime/cache
response, including in file mode; it must not be pinned as constant bytes.

The source bridge composition in `317bd903` applies this parent-owned launcher
handoff: both HTTP probes and ingress validation use `/classic-ready`, and the
body digest is fixed to the value above. `ENV` remains exactly
`{'C3_SETTINGS':'/etc/classic.json', 'NODE_ENV':'production'}` and the sealed-thaw
and physical eligibility predicates are unchanged. This is **not** authorization
to revise a live accepted policy. See `FRESH_OWNER_BRIDGE.md` for the distinct
composition and unperformed physical prerequisites.

## Evidence and focused verification

`tests/classicSettings.test.js` covers env projection, ambient exclusion, strict
identity/flags/types/URIs, redacted refusal, ordinary dotenv/env precedence and
state logging. `tests/classicApplication.integration.test.js` copies exact real
application source to a disposable mode-0444/0555 source tree and execs its actual
`index.js`, without module-loader replacements or application mocks. It uses
actual local MongoDB and Redis processes and unchanged installed dependencies.

The probe proves two serving generations on the same disposable DB, exact IPv4
binding, repeated pinned witness bytes, live `/health` and root HTTP, real settings
persistence, actual Mongo ping-failure refusal, SIGTERM then SIGINT finite clean
exit, listener closure, and invalid settings refusing before new Mongo/Redis
connections, state creation or HTTP serving. All test processes are locally owned;
no SSH, mounts, namespaces, services or TEST/PROD operation is performed. Read-only
Unix source permissions are real, but are **not** a mounted-root/physical proof.
The existing process shutdown/import-order/root lifecycle regressions are rerun.
No full suite or physical operational acceptance is claimed.

Run serially in the isolated `hermes-heavy` scope with scratch `TMPDIR`, pinned
`NODE_PATH` (local test only), `C3_MONGOD`, `C3_REDIS_SERVER`, any extracted Redis
`LD_LIBRARY_PATH`, and a private `C3_REAL_EVIDENCE` directory:

```
node --test --test-concurrency=1 tests/classicSettings.test.js \
  tests/classicApplication.integration.test.js
```

External RED/GREEN/failed-attempt logs, source snapshots, dependency/model pins,
exact commit/tree and required parent hunk are retained under
`/home/leon/celerity-prod-release-20261019/active-enable-20261021/real-classic/`.
