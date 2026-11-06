# Classic Redis shutdown: source candidate and OLD-to-candidate handoff

## Diagnosis and narrowly scoped change

On TEST132, wave75 stopped OLD before starting any candidate. OLD exited 1
without OOM. Its saved log shows SIGTERM → SSH-pool close → Redis write
ECONNRESET → `setXrayOnlineUsers: Connection is closed` → the ioredis close
stack. Redis itself was not stopped by that backend-only operation.

The deployed `index.js` and `cacheService.js` hashes equal the wave76 base
(`f82426071dd1d505f4293b036efa1659abbe586a`) and OLD
(`e9e51e0a43ca6b98aeadfd2158e78430d6a44148`):

- `index.js`: `f991dc50765eb96104cb666c79005d1c0e4a55c393ca12635826108c13918c4d`
- `src/services/cacheService.js`: `4e4cac1c229170001409a0693afc648a5d9cfa826231cd588d5b67c6e8e4f60b`

`setupCronJobs()` used to discard all scheduled task handles. Neither future
cron ticks nor callbacks already awaiting node I/O were stopped/joined by
`shutdown()`. Both the five-second online poll and thirty-second traffic poll
end in `cache.setXrayOnlineUsers()`. They could therefore write after QUIT had
been sent on the same ioredis client. `isConnected()` is not an operation drain;
it can remain true until the socket close event. Stopping node-cron schedules
alone would still abandon already-admitted callbacks.

The repair retains the existing root cron handles, closes callback admission,
stops every root cron schedule, cancels its delayed initial health/snapshot
check, and joins complete admitted callbacks before closing SSH/Redis/Mongo.
It uses the existing root all-settled drain and unchanged 30-minute deadline.
HTTP/worker/init drain order, Redis QUIT error propagation, worker uncertainty,
durable admissions/locks, and nonzero/exit0 gates are not relaxed. Cache command
implementations and their preexisting best-effort semantics are unchanged.

This is **not a panel-wide remote-writer-quiescence claim**. Independent expiry
timers, access-log processing/reconciliation, fire-and-forget service work,
external SSH/systemd descendants, other processes and remote effects are not
newly fenced by this root-cron repair. Existing uncertainty/ownership gates still
apply; a logged/caught preexisting task error is not a new durability proof.

## Focused verification

The real-process regression is
`tests/classicRedisShutdown.integration.test.js`. It runs the complete index.js,
real node-cron execute/stop, actual Sync online collection, CacheService,
ioredis 5.10.0, and disposable loopback Mongo/Redis. It controls only cron time
and the upstream node query/agent reply. A bounded 24,000-user reply plus a
150-ms real socket slow-reader window exposes the close race without injecting
an error or synthesizing a Redis response.

The exact base naturally exits 1 with a real write EPIPE and the same ioredis
`Connection is closed` stack; TEST's write errno was ECONNRESET. These are the
same post-QUIT lifecycle failure class, not a claim to reproduce TEST's exact
packet timing or identify which of the two polls was in flight there. The fixed
entry sends/acknowledges SETEX before QUIT, persists all 24,000 users, refuses a
late tick and exits 0. Mongo and Redis fixture processes also exit 0 by SIGTERM;
forced cleanup is a test failure, never acceptance.

Focused root tests additionally cover both telemetry callbacks, delayed-check
cancellation/in-flight join, repeated signals, failed task stop with sibling
drain, rejected/pending callbacks, unchanged hard deadline, independent QUIT
failure, admitted schema initialization, worker failures and retained ownership.
Run with lock-exact dependencies and Node 20, without a force-exit test option:

```sh
node --test --test-concurrency=1 scripts/test-process-shutdown.js scripts/test-startup-failure-drain.js
# Set C3_MONGOD, C3_REDIS_SERVER, TMPDIR and C3_REDIS_SHUTDOWN_EVIDENCE
# to disposable local fixture locations, not a shared/live database.
node --test --test-concurrency=1 tests/classicRedisShutdown.integration.test.js
```

## Deployment handoff — NOT authorization to execute

**A new image cannot repair the still-running OLD process.** Merely checking out
this source or changing the next Compose image does not change OLD's signal
handler. No in-place patch, remote stop/restart/redeploy, signal, Redis mutation,
native operation, flag change or cutover was performed for this repair.

OLD remains image
`sha256:4a14942de56cb63e5fa7ea8eb81b4988601390b937ef168d152164aa16fac012`,
container
`56b72d9df418a460f428cdaadf99b12978df3688f910e0b07611da3e6d41bfd2`.
The last read-only verification still found PID424115, running/no OOM. These are
historical pins to compare against a **fresh** future baseline, not permission
to act on stale PID/container identity.

A separately authorized backend-only rollout can use this source as follows:

1. Independently review/import the exact source commit/tree/diff from the frozen
   wave76 evidence. Build and seal a **new** backend image/archive from that
   source with the accepted dependency/runtime pins. Inspect actual image bytes
   and labels. The immutable wave74 image `sha256:7697f409508ce2c82fb1c35a3a3c938537e85a8e380c5cf5a5f17676b02e15aa`
   does **not** contain this fix and must not be relabeled or silently modified.
2. Before requesting any stop, obtain the maintenance approval, fresh baseline,
   idle updater/admission/retained-ownership checks, backend-only scope, private
   rollback bytes, same DB/volumes/env/flags and recovery access required by the
   existing rollout. Preserve all four other Compose services and leave native
   inactive. Store logs/receipts in a new evidence directory. This source-only
   task did not build or qualify a new deployment artifact.
3. The **first OLD stop remains an explicit premise**: wait for its natural
   completion and inspect that exact container's state. Only stopped + exit0 +
   no OOM + no forced kill/unknown outcome satisfies the existing stop gate.
   OLD may naturally exit0 when the race is not exercised; this is not guaranteed
   by the fix in the next image. A quiet cron interval or idle observation can
   reduce exposure but is not an execution-spanning drain proof or an exit0
   substitute. Do not retry stops automatically until one happens to pass.
4. On OLD exit1, timeout, OOM, forced termination or retained/unknown work:
   **do not start the candidate**. Preserve the failure and use only the
   separately approved/reconciled OLD restoration procedure; never clear locks,
   flush Redis, restore a shared DB or reinterpret the failure as exit0. If a
   guaranteed first-transition procedure is required, stop here for a separately
   reviewed/authorized migration contract. There is no existing demonstrated
   remote cron-drain API that makes this old binary clean-stop deterministically;
   another OLD-based bridge image would face the same first-stop premise.
5. Only after a genuinely accepted OLD stop may the new sealed image be started
   backend-only. Verify exact new source/image/dependency bytes, complete
   readiness, authenticated panel behavior and stable node/credential/config
   projections; keep the other containers and native state pinned. In a
   separately approved candidate stop/start smoke, require the same natural
   exit0 gate and capture that its admitted telemetry finishes before QUIT.
   A later rollback to OLD also restores the bug and the first-stop premise.

Thus wave76 delivers a causal **source repair**, not a claimed completed
OLD-to-candidate deployment. Unconditional first-stop success under the unchanged
exit0 gate remains unproven and cannot be manufactured by packaging the fix.
