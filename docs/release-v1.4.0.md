# v1.4.0 — operator release notes

[Русский](release-v1.4.0.ru.md) · [Changelog](../CHANGELOG.md)

## Upgrade from 1.3.3.12

1. Wait for MAIN to publish the release and verify that `v1.4.0` points to MAIN's announced commit. Do not upgrade from a moving branch or `latest`. Before the maintenance window, record the current commit and rollback image. Keep a verified MongoDB backup and private copies of `.env`, the Compose files and `mongo-keyfile`. Keep the **existing `ENCRYPTION_KEY`**; it is needed to read stored secrets.
2. For an existing source installation, check that the working tree is clean and that the Compose project, Mongo volume and environment file are the original ones. The stock 1.3.3.12 Compose file already uses replica set `rs0`. Shared accounts and database-backed relay admission need transactions and an elected PRIMARY. If Mongo is standalone, stop before enabling these features: replica-set conversion is a separate operation, not a volume replacement.
3. Check out the verified release commit. Set the flags you need in the existing `.env` (below). For stock source Compose, build and recreate only the panel during the window: `docker compose -f docker-compose.yml up -d --no-deps --build backend`. Do not rerun the installer or delete volumes. For a custom deployment, use its own deployment mechanism with the same pinned release.
4. Check `/health`, then sign in and compare the node list, map, subscription and L2TP page with their pre-upgrade state. The upgrade does not require Apply or Install. Inspect Preview before changing links. Neither `/health` nor `deployed` proves PPP forwarding; verify both intended exits from a client. Stop before making changes if anything differs unexpectedly. Rolling back the app image and environment does not roll back database writes.

## Flags and first use

| Backend variable | When to set it |
| --- | --- |
| `C3_REBUILD_ENABLED=true` | Enables Rebuild. Unset or `false` leaves it off. Leave conflicting strict/classic flags disabled and `C3_SETTINGS` and `TOPOLOGY_TEST_STARTUP_MODE` unset. See the [conflict list](rebuild-mode.md). |
| `C3_REBUILD_L2TP_INSTALL_ENABLED=true` | Required alongside Rebuild for relay admission and Install/Remove. Setting it does not install anything. |
| `C3_REBUILD_L2TP_RELAYS_JSON` | **Optional.** Leave it unset when granting admission in the panel. It is a separate operator-managed list; its entries are read-only in the UI and a database grant cannot override a conflicting ENV entry. |

- **Allow L2TP.** On the L2TP page choose “Verify for L2TP”. Compare the SSH host key fingerprint and machine ID with the relay's trusted enrollment record, then choose “Confirm L2TP admission”. Install is a separate action. On supported Debian 13 amd64 relays with a database-backed grant, Install can prepare strongSwan, xl2tpd, PPP and nftables. With ENV-only admission, packages must already be installed. Package changes are not rolled back; if the outcome is unknown, do not repeat Install or clear its lock.
- **Shared accounts.** Creating, disabling or deleting an account affects all installed L2TP relays. The password is shared; each relay allocates an address from its own pool. Remove uninstalls L2TP from one relay but keeps the shared directory. To retire the node itself, open the separate deletion preview: disconnecting active clients requires explicit confirmation, and removing an unreachable relay from the panel does not clean up its host.

## cc-agent 1.5.1: release candidate limitation

`nodeSetup` expects `cc-agent-linux-amd64`, `cc-agent-linux-arm64` and `SHA256SUMS`. The build produces those names, but the online installer reads `releases/latest/download`, not a pinned release. In rc1, `release-agent.yml` runs manually for `cc-agent-v1.5.1` and uploads an **Actions artifact**, not GitHub Release assets. The panel tag `v1.4.0` alone does not deliver the agent. Do not rely on that tag for an online install of 1.5.1. For an already accepted local kit, see the [nodeSetup kit checks](development/node-setup-offline-agent.md).
