# C³ CELERITY 1.6.38 — Per-portal exits

- In the modern map, edit a portal-to-relay link and choose an exit node. Saving creates a draft. Review it in Preview and confirm Apply. Choose the relay’s shared default to keep the existing routing.
- The selector stores a node, not a link. When several active links reach the same exit, the lowest numeric priority wins. Removing the preferred link through Preview → Apply switches to a surviving link; Preview shows that change. Removing or deactivating the last active link is blocked while a portal’s draft or applied selector names that exit (`409 REBUILD_EXIT_IN_USE`). Choose and apply a different exit or the shared default first.
- Leave the geo checkbox enabled to use the relay’s geo rules. To send all traffic arriving from that portal to a geo exit, select that exit node and turn off the geo checkbox.
- Rebuild only, with one relay. There is no automatic health-based failover. Classic, subscriptions, cc-agent, and shared PPP/L2TP routing are unchanged. A separate L2TP exit is not included.
