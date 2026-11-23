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

## L2TP on a relay

- **Install on a clean relay.** On the L2TP page, verify the SSH host key fingerprint and machine ID against a trusted record, then confirm admission. On supported Debian 13 amd64 relays admitted this way, Install installs the missing strongSwan, xl2tpd, PPP and nftables packages. ENV-only admission still requires preinstalled packages. Install uses its own APT sources and cache; rolling back L2TP does not undo package changes.
- **If Install is interrupted,** choose “Check and continue” when offered. The panel checks what happened and can finish cleanup; it does not rerun Install. Start a new Install only when the panel says you can. If the outcome is unknown, leave the lock in place.
- **After a reboot or service restart,** the panel automatically checks that it is still managing the same installation before showing PPP/IPsec counts or allowing changes. An unknown count is not zero. Install records all eight required kernel modules in `modules-load.d`, including those already loaded. With Xray 26.11, the panel checks the local SOCKS handoff even when Xray opens a UDP port only on demand.

## Remove L2TP or delete the relay?

**Remove L2TP** uninstalls L2TP on this relay only. Active sessions block removal. Accounts are shared: creating, disabling or deleting one affects all installed relays. Removing L2TP leaves those accounts intact; each relay assigns addresses from its own pool.

**Delete relay** removes the node, its links and its copies of the accounts, not the shared directory. For an **online** relay, preview shows the active clients; disconnecting them needs explicit confirmation. Routine health and traffic updates no longer invalidate the preview. If the relay is unreachable, **abandon** removes its records from the panel without cleaning up the unreachable host. If a neighbor refuses a change, the panel names the neighbor and gives the reason instead of a generic 503. A `PARTIAL` result means deletion did not finish.

## cc-agent 1.5.1

If `users.json` is damaged, the agent leaves existing Xray users in place and waits for a successful full `/sync` from the panel. Upgrading the panel does not upgrade agents. `nodeSetup` uses `releases/latest/download`; the panel tag alone does not deliver 1.5.1. The manual agent workflow produces an Actions artifact, not GitHub Release assets. See the [verified local kit](development/node-setup-offline-agent.md).

## Limitations

- An old Classic L2TP record left after uninstall does not reserve its former pool or prevent installation on another relay. No database cleanup is needed. If a Classic operation is still in progress, wait for it to finish.
- After a reboot, the panel cannot recognize a pre-v1.4.0 L2TP installation that lacks its last applied configuration record (`currentApply`). Reinstall L2TP during a maintenance window; do not clear locks or bypass verification.
- The systemd package pin for Debian 13.0 (`257.8`) has not been tested on a live relay. The live test used `257.13`.
