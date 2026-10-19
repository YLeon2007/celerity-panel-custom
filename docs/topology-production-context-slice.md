# Bounded topology production execution-context slice

This is local execution-context plumbing, **not release readiness or permission to run on PROD**.
No deployment configuration, secrets, database records, or remote hosts are changed by this slice.

## Server policy

The immutable allowlist contains only these exact pairs:

- `test` / `test.infograd.online`
- `production` / `lm1.infograd.online`

The runtime selects a pair from the server's exact `PANEL_DOMAIN`; it does not
accept a target or identity from the browser. Missing, unknown, coerced, or
cross-paired identities fail closed. No suffix, case, or whitespace normalization
is performed.

TEST retains the three exact string opt-ins `L2TP_EXECUTION_ENABLED=true`,
`L2TP_MIGRATIONS_ENABLED=true`, and `TOPOLOGY_TEST_EXECUTION_ENABLED=true`.
Production requires the first two shared gates and the separate
`TOPOLOGY_PRODUCTION_EXECUTION_ENABLED=true`; the TEST flag cannot authorize
production. Production does not inherit the TEST-only unproven-execution bypass,
PPP drift queue, or read-only resume probe.

The selected context is immutable and passed to the executor factory, coordinator,
plan materialization, and both node resolvers. Changing the source environment
or constructor input after selection cannot retarget an assembled component.
Idempotency keys use the selected target, including scoped/attach keys. Queue
requests still accept only their existing revision/scope contract.

For compatibility, direct legacy server-side coordinator callers that omit the
new constructor option retain their fixed TEST context. An explicitly supplied
incomplete/cross-paired context is rejected; the runtime never uses that default.
The executor now requires both target and host identity, even for TEST.

## Verification boundaries and remaining gates

- Positive and negative local tests cover production selection, independent
  opt-in, exact pairs, zero-adapter rejection, immutable snapshots, request-field
  rejection, real plan composition, runtime/coordinator/resolver assembly, and
  executor lifecycle through an injected bootstrapper/transport seam.
- The real runner bootstrapper is deliberately unchanged and still TEST-only.
  A production prepare through it fails with
  `TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE` before any upload/command. This is an
  integration prerequisite owned by a separate writer, not an enabled PROD path.
- The production worker still stops with
  `TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN` before claiming work. This slice does
  not weaken lock, admission, ownership, or remote-quiescence requirements.
- Panel-host recovery/startup and durable intent consumption remain TEST-gated;
  the legacy intent coordinator remains TEST-only. Context persistence,
  restart/recovery fencing, and host lifecycle integration require separate work.
- L2TP execution/ownership and proof/evidence gates are unchanged and are not
  certified for production by these tests.
- No live SSH, MongoDB, deployment, or client connectivity validation was done.
  Test persistence and transports are local seams. Any future remote checks or
  mutations require separate authorization and the remaining gates above.
