# Fixed B132 physical placement (source candidate only)

The existing version1 TEST network plan now supports exactly two physical
placements. No new plan field, protocol, controller or configurable host list is
introduced:

| Physical machine ID | Required host IPv4 placement |
| --- | --- |
| `7fa266f995fe4aa69e96cf7d01359e34` (legacy) | `eth0`, `212.119.42.100/24` |
| `03ab697936cc4040aa9357936e136744` (B132) | `eth0`, `132.243.230.19/24` |

B132's interface and prefix were read through a strictly pinned, read-only SSH
connection, not inferred from its endpoint. The observed boot was
`fc0be45a-5b0b-42b3-b882-f9cee14be8b4`; host/self network namespace identities
were both `[4, 4026531840]`. Those values are test observations, **not source
constants or acceptance authority**. Every run still requires an independently
accepted plan with the exact current live boot and namespace identities, daemon,
peer, executable and other pins. Existing ownership, lease, resource exclusion,
namespace and source-drift checks are unchanged.

`PUBLIC` still means the **internal** fresh ingress `212.119.42.100`: fresh
namespace loopback `/32`, Caddy's exact TCP3000 route/rule and upstream, root
settings and actual same-netns launcher/readiness probe all retain that address.
The physical B132 address is used only in its host preflight prerequisite.
There is no host-address assignment/repair, alias, NAT or host route addition.

Run the narrowly scoped regression file from the repository root:

```sh
python3 -I -B scripts/test-node-isolation/test_fresh_network_b132.py -v
```

The suite executes real `validate_plan`, `Linux.check_host`, `check`,
`check_targets` and full `preflight` control flow through explicitly modeled
OS/daemon/peer/config/RPF seams. Address rows project the actual host observation;
route/rule/peer/Docker facts are synthetic and cannot establish physical
eligibility. Tool hashing and owned local descriptors/files are real; no target
constructor, setns or privileged network action runs. Wrong live identity,
boot/namespaces, interface/address/prefix/duplicates, cross-paired placement and
changed-source refusals are tested. New internal212 assertions exercise
constructor command serialization without dispatching it.

Only the immediate holder's constructor `SOURCE_PINS` entry follows the new
network bytes. Both historical fixed entry scripts and all immutable install
pack producers/profiles remain unchanged and **must refuse this candidate**.
The old `test_fresh_network` current-entry equality assertion, the analogous
client-entry equality assertion and entry-backed client lifecycle positives are
historical compatibility tests, not current source-candidate acceptance. Do not
repin those frozen products or rebind their acceptance globals to turn the new
source into an installable artifact. The new regression verifies their actual
loader drift refusal separately. Historical acceptance can still be replayed
against the byte-exact old constructor/client objects.

This is a frozen source candidate only. No integration/deploy, daemon/unit or
live service changes, network construction, physical acceptance or operational
GO is delivered.
