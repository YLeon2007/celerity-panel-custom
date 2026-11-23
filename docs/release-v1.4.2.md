# v1.4.2 — operator release notes

[Русский](release-v1.4.2.ru.md) · [Changelog](../CHANGELOG.md)

## Rebuild and L2TP

### Add a second bridge exit without reinstalling L2TP

The second-exit fix targets the exact empty Xray bridge configuration that Rebuild writes as a placeholder. This covers both new L2TP installations and relays already installed under v1.4.1. Use the usual Rebuild Preview and Apply (Deploy); do not Remove or reinstall L2TP for this case. The on-disk placeholder must match byte for byte, with the expected ownership and permissions, and the `xray-bridge.service` unit must be absent. If the panel cannot establish that it is the canonical placeholder, stop. Do not edit, delete, or overwrite an unknown config to get past the check.

### Before a new Install

First apply the relay-to-bridge link in Rebuild. Install requires **both** a record of the applied link and a match between the running relay's MAIN Xray profile on disk and the fingerprint recorded by that Apply. The read-only preflight checks both before reserving the installation or touching APT. An older link can be applied but lack the required proof. If so, review Preview and use the normal Apply to record it before starting Install. Saving the link as a draft is not enough.

Install progress reflects actual stages: preflight, reservation, package preparation when needed, config preparation, installation, service restart, and verification. When APT reports unpacking or package setup, the panel uses those milestones. The percentage is not a timer, an ETA, or confirmation that Install succeeded.

### If a panel action has no confirmed outcome

The panel shows an acknowledgement for confirmed actions and refreshes the view with read-only requests. If it cannot confirm an outcome, it checks read-only for about five minutes. If the outcome is still unknown, affected controls stay locked. **Do not retry the action or clear the lock.** Use read-only checks and follow the recovery action the panel offers, if any.

### Verify relay identity before granting L2TP admission

Copy the read-only command from the admission dialog and run it in the provider's console, not through panel SSH. Compare the **actual SSH host public key blob type** and the **hex SHA-256 digest of the decoded blob** with the same-type line in the console output. Approve the key only if both match. At the next step, compare the panel's machine ID with `/etc/machine-id` from that console before confirming. If anything differs or cannot be verified, do not grant admission. The check uses public keys and the machine ID only; never paste or share private keys, passwords, PSKs, or tokens. Admission is separate from Install.

## API and MCP

- Xray setup through `POST /api/nodes/:id/setup` and MCP `manage_node` with `action: setup` follows the same role-specific path as the panel. Non-bridge Xray nodes use setup with `cc-agent`. A bridge is exit-only: setup installs Xray without starting or restarting the runtime or installing the agent. Apply the cascade separately to configure the bridge.
- The MCP JSON request limit remains **100 KiB (102,400 bytes)**. Oversized JSON sent to `POST /api/mcp` gets HTTP `413` with a localized JSON-RPC error asking for a smaller request. Reduce the request body rather than resending it unchanged.

`cc-agent` stays at **1.5.1**. Updating the panel does not update node agents.
