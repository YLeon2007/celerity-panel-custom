# v1.5.0 — operator release notes

[Русский](release-v1.5.0.ru.md) · [Changelog](../CHANGELOG.md)

## Reality Guard

Reality Guard is off globally and on every node by default. Enable it under **Settings → Security**, then choose **Notify only** on eligible nodes. It checks public REALITY targets on client inbounds of active, panel-managed Xray `standalone` and `portal` nodes, not relays or bridges. It skips busy nodes, transit and L2TP relay profiles, custom configurations, duplicate Xray cards on the same IP, and non-public targets or targets hosted on the node itself. It reports confirmed failures without changing targets or applying configuration; automatic replacement is unavailable.

## VLESS Encryption

VLESS Encryption is opt-in per main or extra client inbound; existing subscriptions stay unchanged when it is off. The server authentication options are X25519 and, where supported, ML-KEM-768. Use compatible clients. In Rebuild, configure and sync the inbound on a `standalone` Xray node with no active links before making it a portal. Node Save blocks encryption changes on protected Rebuild client inbounds, and Link Apply preserves their existing settings.

## mKCP links in Rebuild

mKCP uses UDP and requires Xray **26.6.1 or newer on both endpoints**. Choose `none` or TLS for tunnel security; REALITY is not supported with mKCP. Save the draft, review Preview, then explicitly confirm Apply. **Applied — runtime unverified** means the configuration was applied, not that UDP traffic was verified. `cc-agent` **1.5.1** cannot verify mKCP at runtime; test client traffic through the intended route separately.

## Modern Rebuild map

Switch between **Chains**, **Graph**, and the geographic **Map**. Compact edge badges summarize links; the tooltip and inspector show details such as protocol, transport, security, port, and status. Runtime **unverified** is distinct from both **error** and **online**.

**Add Link** uses the session CSRF token and saves a draft before Preview. Canceling Preview leaves the saved draft in place. Opening the map, switching views, and saving a draft do not apply topology changes; Apply requires explicit confirmation. To edit an existing link, use `/panel/nodes?map=classic`.

## Firefox CSRF compatibility

`Referrer-Policy: same-origin` keeps the `Referer` header off external requests. For protected requests, Firefox’s opaque `Origin: null` passes the origin check only with `Sec-Fetch-Site: same-origin`. Protected writes still require a valid session CSRF token.

Affected routes include:

- Rebuild map: session requests to save, edit, apply or remove links (`/api/cascade/links`), plus `/api/cascade/rebuild/preview`, `/api/cascade/chain/deploy` and `/api/cascade/topology/positions`.
- Rebuild L2TP: `install`, `remove`, `remove/cancel` and `admission/{probe,verify,confirm,revoke}` under `/panel/rebuild/relays/:id/l2tp/`; account actions under `/panel/rebuild/relays/l2tp/accounts/`.
- Reality Guard: `/panel/settings/reality-guard`, `/panel/nodes/:id/reality-guard`, and the create/edit node forms when they submit Reality Guard fields.
