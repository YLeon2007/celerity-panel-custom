# B132 existing network entry: source candidate only

This closes the existing four-helper pin DAG for the independently accepted
B132 constructor. It does **not** install, publish to a host, integrate, construct
a namespace, activate a unit, or authorize execution/physical GO.

## Exact source tuple

All destinations below retain the existing **root:root, 0750 installed intent**.
Git blobs remain non-executable `100644`; frozen evidence copies are `0444`.
Source-copy modes are not installed acceptance.

| Repository source in `scripts/test-node-isolation/` | Existing installed destination | SHA256 |
| --- | --- | --- |
| `fresh_network.py` (unchanged accepted constructor) | `/usr/local/libexec/c3-test-fresh-network.py` | `8c9872795186be81dae235935b106de6fb156b8098b108b63506be145675e0d3` |
| `fresh_network_exec.py` | `/usr/local/libexec/c3-test-fresh-network-exec.py` | `347d207649a81adfafdcb26a1abf10978b03c733547be7193a414f9942a7d7e2` |
| `fresh_network_client.py` | `/usr/local/libexec/c3-test-fresh-network-client.py` | `7b2a5fc9ba0cc3747465319c230776898b5b5e4f91ccdcd6bba1086cdfaf3ab0` |
| `fresh_network_client_exec.py` | `/usr/local/libexec/c3-test-fresh-network-client-exec.py` | `89a133b0a7c2b1ef655f24cfd9c88abcc328237485b95e0cc25d4e75653c7068` |

The unchanged control prerequisite remains
`/usr/local/libexec/c3-test-fresh-network-control.py`, SHA256
`ced8d6264424f65f5f9d6f5c9b1f9de731953d196026e513ed6e3f13a0cd88ac`,
with the same root:root0750 intent. The unchanged service bytes hash to
`c137ec5e3b156276cf4953bb866a03c8cd565cd5c913e3fc6426e9eebc3b9a1a`.
Its invocation stays exactly
`/usr/bin/python3 -I -B /usr/local/libexec/c3-test-fresh-network-exec.py`.

The only production changes relative to `a7d2001db161098d186676fae9c8591a362e36f4`
are four literal pin values: the server's constructor pin, the holder's resulting
server-entry pin, and the client's constructor/final-holder pins. Constructor,
control, paths, boot/netns/ownership grammar, loader validation, self-source
injection, protocol and all lifecycle behavior remain unchanged.

## Actual fixed-loader proof

Run with the system interpreter and no bytecode writes:

```sh
/usr/bin/python3 -I -B scripts/test-node-isolation/test_fresh_network_entry.py -v
```

The new test file uses real existing descriptor-walk loaders, hashes and compiles
the actual source bytes, and consumes the client loader's real self-source digest
in `Holder`. No `PINS` or `SOURCE_PINS` value is patched. The fixed server's actual
`main/load` reaches the real `control.run`; its Linux/kernel effects are modeled.
The client uses its actual fixed `main/load/run` in a distinct PID.

B132-plan lifecycle replays cover observe → cutover → return → explicit abandon,
finite partial operator lines, idle heartbeat without deadline renewal, invalid
verbs and EOF (including EOF after cutover) with no invented cleanup. They reuse
unchanged existing assertion bodies; they are additional assembled-loader
executions, not new unique protocol coverage. Wrong/missing/changed constructor,
control, server-entry and holder files refuse before the modeled host boundary
or socket. Entry argument/root guards and all formerly entry-dependent cases
also run in the complete current network/client/B132 suite.

Root ownership/installed-root paths, host identity and privileged OS/Docker facts
are modeled. Files, descriptor IO, hashing/compilation, proc start, pidfds, AF_UNIX
credentials/protocol and owned finite subprocesses are real. This is local
source/lifecycle evidence, not acceptance of a deployed absolute command or
physical B132 eligibility.

## Historical proof is separate

The B132 historical-refusal test now explicitly loads SHA-bound original entry
Git blobs from `f82426071dd1d505f4293b036efa1659abbe586a`; it no longer mistakes
current entries for frozen historical ones. Original loaders still accept their
old tuple and reject the current constructor. Historical pack fixture proof is
run only on a disposable historical-input copy; original pack producers,
profiles, tests and acceptance pin maps remain unchanged.

Current source remains refused by the legacy producer (`NETWORK_SOURCE_DRIFT`)
and the 9e/b7/v2-v1/v2-v2 fixed producers (`FIXED_SOURCE_REQUIRED`). The new
regression exercises those actual predicates. Tiny historical fixture packs
are not a current source export or a rebuilt full application artifact.

## Minimal later publication inputs — still unauthorized

A separate independent review/publication decision must bind the exact four
source buffers above, their existing destination names and root:root0750 intent,
plus the unchanged control and service prerequisites. The frozen source-candidate
manifest records these values and the exact commit/tree provenance. No historical
producer/profile exports this tuple and none may be silently repinned.

Later publication additionally needs a fresh exact destination/ancestor inventory
(bytes, inode/metadata/modes, including existing versus absent targets), an
explicit scoped non-invocation/writer-exclusion window and reviewed publication
and exact readback. No such host observation, absence/replaceability claim or
publication permission is supplied here. No full application/dependency rebuild,
new profile/controller, unit invocation or namespace change is required merely
by this source predicate.

Independent plan/lease/resource authority, current host identity, retained
writer/cleanup exclusion and separately reviewed physical execution prerequisites
remain unchanged. Even a later source publication is not runtime GO.
