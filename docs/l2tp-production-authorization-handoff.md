# Bounded L2TP execution authorization — integration handoff

## Implemented contract

- Server allowlist only: `test` / `test.infograd.online` or `production` / `lm1.infograd.online` (shared `domain/topologyExecutionContext.js`). Each consumer selects the canonical frozen object; its bound context and production authorization cannot be reassigned.
- `resolveL2tpExecutionAuthorization(env)` returns a frozen server-only options object. TEST retains the three literal `"true"` flags: `L2TP_EXECUTION_ENABLED`, `L2TP_MIGRATIONS_ENABLED`, `TOPOLOGY_TEST_EXECUTION_ENABLED`. PROD requires literal `"true"` for `L2TP_EXECUTION_ENABLED`, `L2TP_MIGRATIONS_ENABLED`, **`L2TP_PRODUCTION_EXECUTION_ENABLED`**. The TEST topology flag cannot authorize PROD. This does not turn on topology production execution (`TOPOLOGY_PRODUCTION_EXECUTION_ENABLED` is a separate topology gate).
- Options travel via `createL2tpExecutionRuntime.runtimeDependencies`, then `createL2tpRuntime`, service, worker, executor, preflight runner, node resolver and transport. Disabled/unbound active execution composition is dormant before injected factories or node lookup. Standalone service preflight/install reject before counted admission; worker rejects before recovery or claim.
- Install and newly context-wired user-edit/drift sync rows persist immutable `executionContext` outside `plan`. The schema rejects malformed or cross-paired contexts. Old rows remain readable, **not executable**: context-scoped transactional selection and CAS plus post-read validation reject unbound/foreign rows before claims or sync admission increments. No automatic context backfill is supplied.
- Identity is not added to HTTP operation inputs, remote desired/artifact JSON, fixed command payloads, or user/PSK resolver requests. Only internal resolver/claim calls carry the context.
- Shared PPP-readiness factories and the topology runtime now forward their already selected server context to the shared node resolver/transport. This prevents the new mandatory binding from breaking the existing TEST readiness path. Existing readiness/ownership/quiescence rules are unchanged.

## Exact outstanding host wiring

`src/modules/createL2tpPanelHost.js` is intentionally not modified (separately owned).
Against parent `cc0fd1099e8132d398f179b8d090cbc4610f5f82`, apply the following L2TP-specific wiring while reconciling that writer's topology changes:

```diff
 const { createL2tpWorkerLifecycle } = require('./relay-l2tp/runtime/createL2tpWorkerLifecycle');
+const { resolveL2tpExecutionAuthorization } = require('./relay-l2tp/domain/l2tpExecutionAuthorization');
@@
 } = {}) {
+    // Select once, before registerModels, runtime/service factories or any other injected callback.
+    const l2tpExecutionAuthorization = resolveL2tpExecutionAuthorization(env);
     const models = injectedModuleEntry.registerModels();
@@
-    const { isTopologyTestExecutionEnabled, isTestWorkerExecutionAllowed } = require(
+    const { isTopologyTestExecutionEnabled } = require(
         './relay-l2tp/runtime/createTopologyOperationRuntime'
     );
-    const testWorkerExecutionAllowed = isTestWorkerExecutionAllowed(env);
@@
             afterInstallSucceeded: deployTopologyAfterInstall,
-            enableUnsafeExecutionForTests: testWorkerExecutionAllowed,
-            enableInstallAdmission: testWorkerExecutionAllowed,
+            ...l2tpExecutionAuthorization,
```

Do not derive these options from a browser body, query, operation plan, or a later reread of mutable `env`. Existing `workerLifecycle.enabled` remains an independent lifecycle switch; unauthorized composition stays dormant even if that switch is true.

The internal runtime already injects context into `L2tpUserManagementRepository`. The topology runtime already injects its selected context into `L2tpPppDriftSyncRepository`; any additional direct producer construction must also receive the selected server context. No host-only producer is silently defaulted to TEST.

## Local verification and limits

- RED/GREEN observed for PROD rejection with TEST flags, absent/crossed bindings, standalone preflight gating, immutable propagation, mandatory resolver/transport authorization, durable schema/producer identity, active composition dormancy and environment opt-in selection.
- Positive local seams cover TEST and separately opted-in PROD; production install and sync execute through the real worker and typed executor against local fake transport, and production install persists its identity after counted preflight/exact lock release.
- Broad local run covers `l2tp*.test.js`, `remoteAdmission*.test.js`, `createL2tpRuntime`, `installPreflightAdmission`, `operationModels`, `topologyPppReadinessGate`, `topologyRuntimeComposition`, `topologyOperationRecoveryLifecycle`, `topologyOperationWorker`. Required import-time config is supplied with local fixture values; dependencies use `NODE_PATH=/home/leon/c3-int-verify/node_modules`.
- Final serial broad run: **758 passed, 0 failed/cancelled/skipped**, 46 files. Focused authorization/admission/assembled-install run without force-exit: **55/55 passed**. `node --check`: 35 changed/new JavaScript files passed; `git diff --check` passed. Broad runs use `--test-concurrency=1 --test-force-exit` for inherited import-time lifecycle timers, with stdout written directly to a file to avoid force-exit pipe truncation.
- The old host activation test `explicit complete activation wires execution factories lazily and starts only on request` currently fails because the unchanged host omits the mandatory context and therefore gets a dormant runtime. This is an explicit integration blocker, not a working deployed host claim. The host owner must apply wiring and update/re-run host tests before release.
- No remote SSH, Agent, database, deployment or production flag change was performed. This slice does not establish remote completion/quiescence or migrate legacy counted operations. Legacy queued/unbound operations/admissions must be explicitly reviewed before rollout; they are intentionally retained/fenced rather than relabelled on read.
