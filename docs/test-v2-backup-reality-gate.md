# C³ TEST v2 — backup, rollback and REALITY/egress gate

**Not a deployment script.** The included CLI operates on local, already-created snapshot directories or redacted evidence JSON. It does not SSH, invoke Docker, restart services, change routing, or test a real client. Never run against production; stop on any mismatched host/domain, missing node, stale state or unexpected secret disclosure. The previously staged `/home/leon/.cache/c3-test-v2-predeploy-{backup.sh,nodes.js}` are *unexecuted examples*, not approved/runbook automation: in particular their live host/commit/date assumptions may drift, the node collector emits remote stderr, and `mongorestore --dryRun` must be checked against the exact intended archive before change. Do not execute them from this document.

## Offline rehearsal (safe on an isolated local fixture)

```sh
python3 -m unittest discover -s scripts/tests -p 'test_test_v2_testgate.py' -v
python3 scripts/test-v2-testgate.py --help
```

The tests create private throwaway panel/node snapshots and a local Git bundle, perform a disposable extraction with independent file hashing, validate gzip, and reject hostile tar paths/links, changed files, wrong host, wrong panel domain, loose permissions, unlisted files and false egress correlation. No fixture contains an actual subscription, private key, UUID or usable credential. A success here **does not** mean a live Mongo restore, node restore or REALITY path works.

## Before an authorized TEST-only change (operator checklist, not executed here)

1. Obtain separate change approval and maintenance/rollback window. Re-read TEST hostname (`VM-976045` is historical, verify live), domain `test.infograd.online`, panel git commit/tree and clean/expected worktree, Compose service and container IDs/restart counts. Resolve the **five** designated TEST node identities from the approved topology; do not infer by IP or replay hard-coded IDs. Confirm no production node is selected. Abort on drift.
2. Record root-only snapshots under a unique dated private directory on **each** machine; `umask 077`, `chmod 700` directory and `600` files. Capture panel `.env`, Compose variants, Caddyfile, source Git bundle (`git bundle create ... --all`), source archive from the deployed commit (`git archive`), Mongo archive with authenticated `mongodump --archive --gzip`, image ID/tag and container baseline. Capture each TEST node's Xray/bridge config and services, cc-agent, L2TP/IPsec/PPP and nft/iptables configuration where present, plus IP addresses/routes/rules and service state. Avoid dumping credential values to stdout or chat. Missing optional paths must be inventoried as absent; note symlinks explicitly rather than dereferencing them silently. Keep baseline image and old deployment intact until verification.
3. Normalize the panel source archive filename to `source.tar.gz` **without altering its bytes**; stage the panel snapshot as top-level `source.bundle`, `source.tar.gz`, `mongo.archive.gz`, `.env`, `docker-compose.yml`, `docker-compose.local.yml`, `Caddyfile` and any additional non-empty private top-level regular files. Stage each node's `node-config.tar.gz`, `hostname.txt` and optional top-level private regular files. If backups contain symlinks/special files, this harness refuses them: prepare a separately reviewed safe archive rather than weakening the check. No live snapshot was created by this work.
4. On an isolated trusted machine or the authorized TEST host, run the CLI against **each** sealed snapshot. This writes only the manifest in the given snapshot directory; don't run `seal` twice. Pin each printed SHA-256 in a *separate* operator record, not in the same writable snapshot. Treat `--host` as the verified exact machine hostname (panel historical example below). Keep the snapshot off git and access limited to operators.

```sh
python3 scripts/test-v2-testgate.py seal --role panel --host VM-976045 --backup-dir /PRIVATE/TEST-PANEL-SNAPSHOT
python3 scripts/test-v2-testgate.py verify --role panel --host VM-976045 --backup-dir /PRIVATE/TEST-PANEL-SNAPSHOT --manifest-sha256 PINNED_64_HEX
python3 scripts/test-v2-testgate.py seal --role node --host test-node-hostname --backup-dir /PRIVATE/TEST-NODE-SNAPSHOT
python3 scripts/test-v2-testgate.py verify --role node --host test-node-hostname --backup-dir /PRIVATE/TEST-NODE-SNAPSHOT --manifest-sha256 PINNED_64_HEX
```

5. The CLI verifies private top-level files, complete file set/checksums, exact TEST identity and panel domain, Git bundle (`git bundle verify`), gzip integrity and safe extraction/hash of source/node archives into throwaway directories. **It does not understand Mongo BSON or guarantee a restorable database.** On the authorized TEST Mongo only, run `mongorestore --archive --gzip --dryRun` on the *pinned* archive with credentials passed via the container's environment, no password on argv, and check exit status. Check Git bundle can be cloned in an isolated directory and that the source commit/tree agrees with recorded baseline. Check node tar inventories against live absent/present list, ownership/mode and independent backups of symlinks; rehearse restore into a throwaway directory and diff checksums, never over live `/etc` or `/usr/local/etc` during preflight. Re-run pinned verification immediately before change. Every node and panel must pass; no partial go-ahead.

## Rollback decision and controlled procedure (requires separate authorization)

Trigger rollback if default/geo egress, REALITY login, user restore, L2TP path, source provenance, untouched service identity or health regresses after the TEST change. **Do not roll back merely because a preflight fails before a deploy:** stop with live state untouched. Freeze further topology/sync operations, capture redacted failure evidence and read back the committed revision. Identify exact last-known-good snapshot by separately pinned manifest digest; verify *all six* snapshots again and confirm host identity, parent commit/tree and snapshot timestamp versus operation. Stop if any check fails. The pre-existing `scripts/staging/rollback.sh` is a separate staging protocol with different manifest/schema and is **not compatible** with these snapshots.

Under operator supervision only: restore source/config and Mongo from the pinned panel snapshot using explicit scoped TEST commands, preserve a second copy of current failed state, restore any changed node configs/firewall rules from *their own* pinned snapshots, test generated Xray/Compose configs before restarting affected TEST services, and avoid touching services/nodes that did not change. Never apply a node tar wholesale to `/`. Re-read installed file hashes, Mongo collection counts/indexes (without customer records), Git commit/tree, active rules/services/container IDs and restart counts; repeat all probes below. Do not report rollback successful without read-back and healthy end-to-end results. Escalate rather than improvise if restore/dry-run, topology ownership or identities differ.

## Controlled REALITY and bridge-egress gate (only after approved TEST rollout)

Use a disposable **loopback-bound SOCKS** Xray client derived from the exact TEST subscription's portal address, serverName, public key, shortId, fingerprint, flow and disposable user's UUID; hold this config in a private `0700` directory with `0600` files and delete it afterwards. Never commit, log, screenshot or print subscription URLs, UUID, private keys or full configs. First compare the subscription user UUID to the advertised portal inbound's client list *in memory*, and inspect portal listener ownership across all Xray processes. A TLS handshake/online topology is not proof of authorized VLESS ingress.

For both default and geo routes, select one deterministic TEST destination each, resolve via SOCKS remotely (`curl --socks5-hostname 127.0.0.1:LOCALPORT --fail --silent --show-error --max-time 15 https://<approved-ip-echo-endpoint>`), and record only HTTP status + public IPv4 (no raw response/log). Have an operator independently confirm the expected bridge's outward IP before probe; compare the observed exit, portal request timestamp/tag, and corresponding bridge request timestamp/tag in synchronized narrow log windows. A `200` alone is insufficient: the request must traverse the **intended** bridge. Test IPv4, UDP/DNS, meaningful transfer and IPv6 fallback separately; a successful server-side SOCKS probe still does not prove phone traffic. Do not put REALITY/UUID data into the JSON evidence.

A non-secret evidence file (example uses documentation IPs and is **not real evidence**) can be checked offline:

```json
{
  "schema": 1,
  "target": "TEST",
  "client": "disposable-loopback",
  "routes": [
    {"route":"default","expected_bridge":"test-bridge-a","observed_bridge":"test-bridge-a","expected_egress_ip":"198.51.100.10","observed_egress_ip":"198.51.100.10","http_status":200,"portal_request_seen":true,"bridge_request_seen":true},
    {"route":"geo","expected_bridge":"test-bridge-b","observed_bridge":"test-bridge-b","expected_egress_ip":"203.0.113.20","observed_egress_ip":"203.0.113.20","http_status":200,"portal_request_seen":true,"bridge_request_seen":true}
  ]
}
```

```sh
python3 scripts/test-v2-testgate.py egress --evidence /PRIVATE/redacted-test-egress.json
```

This validates the **shape and internal consistency of operator-provided observations**, not their truth or freshness. The operator must cross-check raw TEST log windows locally without exporting secret contents. Finally import the exact intended subscription in **phone Happ** on cellular and Wi-Fi, exercise default/geo web traffic, Telegram, DNS/UDP and IPv6 fallback, correlate the phone attempt with portal/bridge packet/log evidence, then remove disposable users/configs. If any leg fails, do not call the change verified; execute the approved rollback gate above or stop and investigate.
