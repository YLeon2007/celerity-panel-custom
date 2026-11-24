# C³ CELERITY v1.6.35

On the new map, hover over a client count in Chains, Graph or the node inspector to see the IPs recently observed by Xray. The list is available only in a panel administrator session, never by API key or MCP. Connection samples live only in panel memory, for at most 60 seconds. No client IPs are written to logs, audit, Redis or MongoDB by this feature.

Use cc-agent 1.6.0 on Xray portals and standalone nodes. For an existing Rebuild portal, review the `policy` replacement in the normal Preview before confirming Apply. Relay and bridge profiles and client subscriptions do not change. The dashboard counts users from a valid `/online-ips` snapshot; otherwise it keeps the 1.6.34 fallback. Xray reports recently observed source IPs, not an inventory of idle transport connections. An empty census alone does not prove that the core has `statsUserOnline` enabled.

Place the optional DB-IP Lite city and ASN MMDBs at `/app/data/geoip/city.mmdb` and `/app/data/geoip/asn.mmdb`, or set `GEOIP_CITY_DB` and `GEOIP_ASN_DB` to their paths inside the panel container. Replace the files atomically to update them without a restart. Without either file, that part of the geolocation stays blank. The provider field is the ASN organization when that is all the database provides. No database is included in the image.

[IP Geolocation by DB-IP](https://db-ip.com/) · DB-IP Lite data licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).
