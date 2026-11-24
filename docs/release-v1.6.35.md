# C³ CELERITY v1.6.35

On the new map, hover over a client count in Chains, Graph or the node inspector to see the IPs recently observed by Xray. The list is available only in a panel administrator session, never by API key or MCP. Connection samples live only in panel memory, for at most 60 seconds. No client IPs are written to logs, audit, Redis or MongoDB by this feature.

## Rollout order

1. Upgrade the panel to 1.6.35. Until the agent is upgraded, an online portal on 1.5.1 shows the hint to install 1.6.0; a node whose status is `unknown` shows data as unavailable.
2. Upgrade cc-agent to 1.6.0 on portals and on any standalone Xray nodes that need this feature.
3. For Rebuild links, open the normal Preview. To enable online stats, the portal diff should only replace `policy`, with no `protectedChanged`. Confirm Apply after reviewing the plan. Apply writes `policy.levels."0".statsUserOnline: true` to MAIN and **restarts Xray on each affected portal**. Relay and bridge profiles and client subscriptions are unchanged by this feature.

For a standalone Xray node **with no links and no topology-managed config**, use the ordinary per-node Sync (`POST /api/nodes/:id/sync`) after upgrading the agent, instead of Apply. SSH access is required to update MAIN, and Sync also restarts Xray when it writes the profile. The Sync response acknowledges that it has started; wait for it to finish and verify `statsUserOnline` in MAIN.

The dashboard counts users from a valid `/online-ips` snapshot; otherwise it keeps the 1.6.34 fallback. On the tested Xray versions (26.3.27 and 26.11.9), the list counts only open connections and excludes connections from `127.0.0.1`. An empty census alone does not prove that `statsUserOnline` is enabled.

Place the optional DB-IP Lite city and ASN MMDBs at `/app/data/geoip/city.mmdb` and `/app/data/geoip/asn.mmdb`, or set `GEOIP_CITY_DB` and `GEOIP_ASN_DB` to their paths inside the panel container. Replace the files atomically to update them without a restart. Without either file, that part of the geolocation stays blank. The provider field is the ASN organization when that is all the database provides. No database is included in the image.

[IP Geolocation by DB-IP](https://db-ip.com/) · DB-IP Lite data licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).
