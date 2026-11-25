# Rebuild portal exits: local Xray checks

Run `verify-portal-exits.sh --xray PATH --cover PATH --mode reverse|mixed` in a disposable local workspace. The runner creates a private network namespace with only `lo`; it does not mount the host resolver, credentials or service sockets. `--xray` runs the portals and subscriber. `--relay-xray PATH` pins gateway/tail/island, and `--bridge-xray PATH` pins the bridge nodes; either pin defaults independently to `--xray` when omitted. API calls use the same binary as the process that owns the loopback API socket.

To exercise the operator version split, set `XRAY_OLD` to the local 26.3.27 binary, `XRAY_NEW` to the local 26.11.9 binary, and `COVER` to the local cover binary, then run:

```sh
for mode in reverse mixed; do
    ./scripts/native-portal-exit/verify-portal-exits.sh \
        --xray "$XRAY_OLD" --relay-xray "$XRAY_NEW" --bridge-xray "$XRAY_NEW" \
        --cover "$COVER" --mode "$mode" --scoped-matrix || exit $?
done
```

Logs and synthetic profiles remain in the unique evidence directory under `TMPDIR`. In `result.json`, `config_test_actors` and `live_actors` identify the role, version and executable for each config or process; `wire_endpoints` records both ends of each tunnel, and `api_calls` identifies the API owner and CLI. Successful HTTP rows include the origin marker and fresh access-log lines with exact route tags.

- `--chain-probe`: the original two-relay transport experiment, with hand-authored policy rules.
- `--scoped-proof`: authenticated TCP round trips in separate miniature Xray processes using the generated scoped listener/dialer. This checks protocol viability, not the readiness of any deployed MAIN.
- `--scoped-matrix`: the unmodified composer selects paths and routing rules for three portals, two chained relays, two bridge exits, and a disconnected relay. Separate origin markers and fresh access-log entries at each hop distinguish the shared and scoped channels. The runner removes and restores one synthetic listener via the real loopback Xray API, checking that the affected portal blocks and the other portal and shared PPP policy still route. For reverse, listener removal alone does not close established workers; the fixture drops their exact local TCP tuple inside its own network namespace before checking the cut.
- `--staged-matrix`: also exercises a synthetic staged MAIN with two dedicated loopback probes and a fixture-only RoutingService. It observes old portal routes and proves the new channels before replacing the ingress selectors in the same running Xray. It then restores the prior rules from their preimage. A separate fixture writer fsyncs an intent, performs one real Xray update and exits without acknowledging the caller; the observer checks live tags and traffic without replay. This is a loss-of-reply drill, not the product's durable cross-host recovery protocol.

The scoped and staged matrices generate their own `assets/geoip.dat` with just `PRIVATE` (`127.0.0.0/8`) and a synthetic `RU` (`198.51.100.43/32`). P1 with relay Geo enabled gets marker A for the RU address through the tail's Geo edge, but marker B for the numeric non-RU address. P2 with relay Geo off gets marker A for both via the tail's ordinary edge, not its Geo edge; the two A paths have different tags. The domain, HTTP sniffing and shared PPP cases still run. A scoped run checks 17 configs and 19 HTTP marker/block cases; a staged run adds nine HTTP checks.

The matrix checks Xray syntax of the generated TPROXY configuration. For traffic, it substitutes a loopback SOCKS ingress with the exact TPROXY tag and port; the actual generated ACL, local SOCKS handoff and shared Xray routing still run. It does **not** test kernel PPP/IPsec/TPROXY, the panel's Apply/recovery, public geodata, or deployment. Bridge egress is limited to the two local fixture origins. No mode contacts TEST B or PROD.
