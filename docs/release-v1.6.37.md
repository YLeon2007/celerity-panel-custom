# C³ CELERITY 1.6.37 — Long-lived Xray connections

- Open connections remain in the list and count as long as Xray reports them in fresh snapshots. A snapshot expires 60 seconds after its update timestamp. “Last connection” shows when the connection was opened, not when it last carried traffic.
- cc-agent 1.6.1 uses internal Rebuild connections only to confirm tracking support; their names and IPs are not returned. A confirmed empty list shows “No active connections.” If a fresh reply from agent 1.6.1 or newer does not confirm tracking, the map shows “No connections or connection tracking is disabled on this node.” Request failures still show “Connection data is unavailable.” IPs remain restricted to admin sessions.
- Rollout order: panel 1.6.37 → cc-agent 1.6.1 on portals. No Xray configuration changes or Apply are needed.
