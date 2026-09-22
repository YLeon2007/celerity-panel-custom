# Test-only L2TP E2E evidence harness

This harness aggregates evidence for the later `test.infograd.online` L2TP contour. It is deliberately read-only:

- it does not run probes, open network connections, install software, invoke rollback, or mutate a node;
- it accepts only `--target test` and `--host-identity test.infograd.online`;
- it reads four externally produced JSON result files and prints a derived JSON report;
- it never accepts or reproduces raw command output, command text, credentials, or other free-form fields;
- absent, malformed, inconsistent, failed, or unknown evidence keeps `passed` equal to `false` and exits nonzero.

No real probe evidence or successful E2E report is bundled here. A later authorized run must collect the evidence externally.

## Run

```sh
node scripts/l2tp-e2e-evidence.js \
  --target test \
  --host-identity test.infograd.online \
  --preflight-result /path/to/preflight.json \
  --install-result /path/to/install.json \
  --health-result /path/to/health.json \
  --traffic-result /path/to/traffic.json \
  > /path/to/report.json
```

Exit status is `0` only when both setup checks and all seven E2E gates are explicitly `pass`. Every other outcome exits `1`; the JSON report is still emitted for inspection.

## Input contract

Each input must validate against [`evidence.schema.json`](./evidence.schema.json). All four files must use the same `runId`, and every file must pin:

- `schemaVersion: 1`
- `target: "test"`
- `hostIdentity: "test.infograd.online"`
- the evidence type matching its CLI flag
- a canonical UTC `observedAt` timestamp

Each result has exactly these fields:

- `gate`: the check or gate identifier;
- `status`: exactly `pass`, `fail`, or `unknown`;
- `exitCode`: `0` for `pass`, `1..255` for `fail`, and `null` for `unknown`;
- `commandOutputSha256`: lowercase `sha256:` plus 64 hexadecimal characters.

The digest is computed by the external collector over the exact captured command-output artifact bytes. Only the digest belongs in these JSON files. Raw output and credentials are rejected by the closed schema.

## Required contour

| Evidence file | Required result identifiers | Passing meaning |
|---|---|---|
| `preflight` | `preflight` | The externally executed preflight completed successfully. |
| `install` | `install` | The externally executed test installation completed successfully. |
| `health` | `l2tp_ipsec_established`, `rollback_recovery` | L2TP/IPsec was established, and rollback restored the expected health. |
| `traffic` | `tcp`, `udp`, `dns`, `quic`, `direct_ppp_egress_fail_closed` | Each traffic protocol passed; direct PPP egress remained blocked when the downstream path was unavailable. |

The report contains only normalized statuses, exit codes, command-output digests, per-input file digests, and safe validation errors. It does not infer a missing status and does not turn partial evidence into success.

## Tests

```sh
npm run test:l2tp-e2e-evidence
```
