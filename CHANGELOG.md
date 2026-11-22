# Changelog

## Unreleased

- Xray setup fails if the final authenticated agent probe confirms the runtime API is down after a requested restart. No cascade redeploy or wizard completion follows that failure. Setup without a restart can still complete while Xray is offline.
- Missing or unusable Xray health proof is reported as `unknown`, not as an outage. Setup reports an explicit warning; the node does not show as online, its online-user count is cleared, and no `node.offline` webhook is emitted for an unsupported or invalid probe.

## CC Agent 1.5.1

- Preserve Xray users when `users.json` is missing, invalid, or conflicts with the managed clients at startup. Recovery requires a successful full panel `/sync`; `users.json` saves are atomic.
- Preserve fresh reverse-link activity evidence when `/stats` resets billing counters mid-sample. Draining an old balance alone does not establish activity.
- The agent build uses `cc-agent-v1.5.1`, separate from panel `v1.4.0`, and produces Actions artifacts only.

## CC Agent 1.5.0

- **CC Agent 1.5.0** adds authenticated `GET /xray-health`. It checks the local Xray runtime API without resetting traffic counters. `GET /health` still reports agent liveness only.

See the [local Xray status rollout note](docs/xray-runtime-status-rollout.md) for release sequencing.
