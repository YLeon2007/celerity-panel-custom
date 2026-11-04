# Bounded classic applied-profile import and compatible handback

**Status: executable adoption/baseline prerequisite plus precise local classic-to-any-order candidate conversion, not completed operational migration. No database, physical transport or service was used in these slices.** The composer now removes matched classic artifacts and preserves surviving original tunnel identities. The selected coordinator's installed-path forwarding and the selected reader's post-settlement profile readbacks still need separately owned integration; see [the conversion handoff](cascade-anyorder-conversion.md). Do not perform real adoption before closing those prerequisites.

## Source contract

The existing internal `TopologyConfigTransfer.adopt` accepts one additional optional server-side argument:

```js
await transfer.adopt({
    node, profile, generation: classic.generation, proofRef,
    legacyTopology: acceptedObservedComponent, // {nodes, links, groups}
});
```

This is not an HTTP/MCP input, a new owner store, a `verified` flag or dispatch permission. `acceptedObservedComponent` contains complete configuration descriptors, original IDs/UUIDs/keys/transports/policies and each role profile's **exact UTF-8 readback bytes** as `node.profileConfig` (string). Supply an independently accepted inventory, not a query of current desired rows. No bytes are generated onto a node by import.

- Adoption retains its existing canonical context, physical node, classic generation, maintenance challenge, old-dispatch exclusion, receipt, transaction and majority-confirmation protocol. The input is copied before the first asynchronous read.
- The existing `proof.readback.configSha256` must equal the exact local `profileConfig` byte digest. The existing generator must reproduce its owned listener/dialer, reverse entries and ordered route rules. Portal client listener/key metadata is checked independently of its runtime client list. Missing/duplicate/foreign cascade fragments refuse.
- Ownership matching uses `applyReversePortal`, `generateRelayConfig`, `generateCombinedBridgeConfig` and the older `generateBridgeConfig` variant; it does not infer ownership from a link's online/deployed status. Unrelated configuration and installed client entries remain in the original private profile string unchanged.
- The observed component is stored in the existing owner record as private `legacyAppliedTopology` in the **same adoption CAS** as the original snapshot/receipt. There is no default and no fabricated `TopologyOperation`, settlement pointer, close receipt or client proof.
- `TopologyDeploymentRepository.readSelected` explicitly projects this private field. It validates every component member against that member's own original/adoption evidence and requires identical complete imported descriptors on all affected owners. A partial transfer cannot become an applied component. It discovers old endpoints from imported evidence as well as settled operations, preserving the cleanup union after an endpoint edit.
- The existing selector overlays only the requested desired link. Saved neighbor edits, pending and inactive neighbors do not enter the imported baseline. Once a real selected operation settles, ordinary settled-operation provenance takes precedence; the adoption snapshot is historical evidence, not mutable current desired state.
- Imported data is bounded to one connected reverse classic component: at most 32 nodes, 64 links, 1 MiB per profile, 4 MiB total. Portals have one outgoing link; relays one upstream; shared bridges and old single/combined bridge layouts are recognized. `none` and REALITY tunnel/client security are supported. Forward layouts, TLS and imported route groups/installed-path ownership are **not supported by this V1 seam**. Classic forward listeners may belong to MAIN on a non-portal, TLS generation can consult certificate files, and an installed group cannot acquire applied authority from mutable desired policy. These cases refuse explicitly; they are not claimed as migrated.

`verifyLegacyAppliedProfile(topology, {node, profile, originalSnapshot})` rechecks the stored evidence. `legacyProfileArtifacts(topology, nodeId)` exposes the exact recognized legacy-generator ownership fragments for the existing composer owner; it reads no desired metadata or transport. It is a source composition helper, not a new authority or runner.

## Classic-generator conversion

The former `TOPOLOGY_PROFILE_BASELINE_MISMATCH` conversion prerequisite is now a positive actual-materializer assertion, not a successful-refusal migration claim. `composeDescriptorTransition` reuses `legacyProfileArtifacts` to validate/remove the actual observed classic before-artifacts. It merges only checked portal base-client ownership plus exactly matched base members, preserves runtime clients/unrelated sections, and normalizes an absent empty bridge `inbounds` array only in its private composition copy. Surviving classic reverse domains retain their original link-ID suffix, UUID and REALITY keys on both ends, including subsequent transitions with current checked readbacks. Failed classic matches cannot become unchecked dialer-side modern fallbacks.

`cascadeAnyOrderLegacyConversion.test.js` exercises public adoption/read → materializer → actual local fake-root runner apply/delete/recreate for combined, older single, relay and shared-bridge layouts under none/REALITY. Repeat candidates are byte-identical and do not restart the modeled service. The existing ownership/transfer/worker protocols are unchanged; local command/binding/physical observations remain explicitly modeled. See [the conversion handoff](cascade-anyorder-conversion.md) for the exact remaining selected coordinator/reader integration dependencies. Forward profile placement, TLS and installed-group import remain explicitly unsupported by V1.

## Manual deployment prerequisites and bounded sequence

These are prerequisites for a later separately authorized deployment, not commands executed here:

1. First close the composer conversion above on an isolated application copy, including add/delete/recreate, original link keys/domains, arbitrary fragments/client preservation and shared profiles. Validate the actual source, not a proposed module-loader patch.
2. Obtain a fresh read-only inventory of the selected existing component, all its shared role profiles, the other profile on each physical node, exact config/unit bytes and active/enabled service states. Separately accept node identity and inventory. Keep application/startup configuration, a compatible database snapshot and original node bytes/service states. Hashes in an owner row are not backups. Never include unrelated inaccessible nodes without a shared-resource reason.
3. Reconcile any old uncertain operation through its existing owner/result protocol. Do not remove locks, operations, reservations, admissions or history. Confirm the existing external held-maintenance authority excludes all competing writers for the selected physical resources; a database owner read or a flag switch cannot drain an old dispatcher.
4. Use the existing exact node/profile unique index and same-connection owner model. For absent owner slots use public `initializeClassic`; for existing classic owners use the actual current generation. Adopt each profile with the same accepted observed component under the existing held-maintenance protocol. A failure/unknown commit retains exclusion and any committed records; do not retry a guessed generation. This is per-profile transfer, not a new multi-node transaction or automatic rollback controller.
5. Require the actual selected reader to accept the entire component before normal admission. An already topology-owned nonempty profile without an imported snapshot cannot be blessed by updating a field: retain/refuse it, or restore/hand back via the existing protocol and make a fresh explicit adoption under the same external exclusion. No direct DB seeding.
6. Only after all source/runtime and physical prerequisites are satisfied enable the ordinary existing execution path for those owners. No native-to-classic fallback. Import itself establishes neither tunnel health, complete routing nor Internet/PPP/REALITY client readiness.

## Compatible return to the previous owner

Use unchanged public `handback({node, profile, generation: adopted.generation, proofRef})`.

- First resolve ongoing new operations through the ordinary existing protocol and retain their history. No stale-lock clearing or blind old-image start.
- Under the existing held external exclusion, restore the original **exact config bytes, unit bytes, active state and enabled state**. Each must match the original adoption snapshot; a restored flag or a byte-identical config alone is insufficient.
- `handback` compares the real readback, adoption receipt and exact generation, then records the classic generation/handback receipt. The imported snapshot is retained privately as historical evidence. It does not authorize topology after handback.
- The unchanged classic ownership reader accepts that receipt chain. Other existing operation-history vetoes still apply after real topology work and must be reconciled through their own existing protocol; handback does not delete or waive them. A subsequent adoption without a new import discards the prior adoption's imported snapshot rather than reusing it as current evidence.
- Start the compatible old backend only after the whole chosen shared-profile area has actually returned to classic and all independent old/new writer fences have been resolved. Partial/unknown handback is not an invitation to switch flags or restart the previous writer.

## Initial prerequisite-slice evidence (before composer conversion)

The following counts describe predecessor `066f4d5`, not the current conversion tests; current evidence and residual caller dependencies are in [the conversion handoff](cascade-anyorder-conversion.md).

`cascadeAnyOrderLegacyImport.test.js` exercises public `initializeClassic → adopt(legacyTopology) → readSelected → handback` for TEST and production canonical identities, using **only dummy data, modeled read-only node config/unit/service observations, and query-aware transaction-shaped persistence**. It uses actual classic generators, selector, materializer, strict Mongoose/BSON model and classic ownership reader. Its 25 tests include G2, single/combined/shared bridge layouts, REALITY/link keys and installed runtime clients, exact neighbor descriptors, endpoint cleanup union, pending/inactive exclusion, artifact mismatch, partial import, modeled unknown commit, restoration mismatch and the explicit unresolved conversion refusal. The local query fixture honors private-field selection; ordinary handback returns omit the imported descriptors while the stored historical evidence remains intact. No physical transport, database atomicity or operational deployment is claimed.

Final focused runs (natural process exit 0):

- legacy import: 25 passed;
- existing selected delete: 334 passed;
- existing classic ownership: 102 passed;
- existing selected apply: 17 passed;
- existing transfer: 2 passed, 80 existing Mongo tests skipped because `C3_MONGOD` was not enabled (database execution is outside this worker's scope).

Logs: `$TMPDIR/c3-legacy-import-checks/*.tap` and `$TMPDIR/c3-legacy-import-final/*.tap`. Read-only borrowed dependencies: `NODE_PATH=/home/leon/celerity-test-cascade-v2/node_modules`; no install/build or lock-exact bundle claim. The earlier changed-area run exposed six old fixture `.select()` omissions in normal transfer. The source was narrowed to project private descriptors only for an explicit import, preserving the old transfer projection; all 102 ownership tests and the subsequent independent selected-delete and transfer regressions passed. These source regressions are not a substitute for legacy conversion or physical testing.
