# Restricted preinstalled topology runner transport

This is a source-level **TEST-only transport capability**, not physical authority,
node provisioning, a PROD activation switch, or proof of deployed connectivity.
PROD composition still omits the binding reader/capability and the real worker
still refuses before claim. Root lifecycle, owner transfer and forced-command
grammar are unchanged.

## Trusted operational adapter contract

The existing server dependency `topologyExecutionAuthority` may explicitly declare
`runnerTransport: 'preinstalled-attested-v1'`. Runtime snapshots this declaration
and passes its **same** `TopologyExecutionAuthorityLifecycle` to the default
executor and binding store. An unknown declaration refuses composition. An absent
declaration preserves the existing authorized bootstrap mode; it does not detect
or silently adopt an installed runner. No environment, request or HyNode field can
select preinstalled mode.

In this mode the capability supplied by the controller's existing
`withHeldAuthority(TEST, work)` must provide, in addition to `assertHeld` and
`withVerifiedAuthority`:

```text
withVerifiedPreinstalledRunner(challenge, work) -> awaited work result
work(proof, assertCurrent) -> Promise
assertCurrent() -> Promise<void>, reject on any loss/unknown/revocation
```

This method must invoke `work` exactly once, await it, and sustain the actual
physical/endpoint/bootstrap-writer exclusion throughout the callback and awaited
cleanup. It must cooperate with nested binding-store physical authority checks
without reacquiring an incompatible non-reentrant maintenance lock. Readiness and
checks must have operationally bounded deadlines. Returning early, missing proof,
missing checker, revocation or failure poisons the current application scope;
escaped callback/check functions cannot authorize later dispatch. There is no
unfreeze, unmask, old-writer restart or shell/SFTP fallback on failure.

`challenge` is deeply frozen and has exactly `{ binding, connection, role }`:

* `binding`: the executor's complete accepted immutable durable V2 record,
  including exact operation/node/profile, revision, claim/lock generation,
  command IDs, boot and maintenance IDs. It is not a request-supplied record.
* `connection`: the separately verified immutable connection authority,
  `{ expectedEndpoint: { ip, port, username }, expectedHostKeySha256 }`.
  This slice accepts only port `2222` and username `c3-test-runner` on TEST.
  The host-key digest is lowercase 64-hex SHA-256 of the **raw SSH public-key wire
  blob**, not PEM/base64 text. Resolver/NodeSSH pin verification before auth is
  unchanged. Supply the dedicated runner private key via the already selected
  server credential source; an operator/root key is not an alternative.
* `role`: `portal`, `relay`, or `bridge`, from the validated frozen node plan.

The proof has exactly the following shape (all values are strict, not coerced):

```js
{
  authority: 'server-preinstalled-topology-runner-v1',
  binding,                         // exactly the accepted durable record
  bootId: binding.bootId,
  maintenanceId: binding.maintenanceId,
  connection,                      // exact separately enrolled endpoint + raw key
  runner: {
    path: '/usr/local/bin/celerity-topology-node-runner',
    sha256: TOPOLOGY_RUNNER_SHA256,  // sha256:<digest of shipped runner.sh bytes>
    mode: '0750', owner: 'root', regularFile: true,
    symlink: false, writableByRunner: false
  },
  profile: {
    targetProfile: binding.targetProfile,
    configDirectoryReady: true,
    bridgeUnitSha256: null,         // portal only; relay/bridge require below hash
    bridgeUnitDropIns: null         // portal only; relay/bridge require 'absent'
  },
  writers: 'excluded'
}
```

`configDirectoryReady` attests that the role's actual root-owned, non-symlinked
config directory is already safely usable (the legacy bootstrap's fixed
`install -d -m 0755 -o root -g root` prerequisite). For relay/bridge,
`bridgeUnitSha256` must be `sha256:<SHA-256 of BRIDGE_UNIT_SOURCE>` defined in
`topologyRunnerBootstrapper.js`: the exact root-owned non-symlinked
`/etc/systemd/system/xray-bridge.service`, selected as the active fragment with no
vendor override, mask or drop-ins. The application does not install/reload it.
Portal does not gain permission to inspect/change an unrelated bridge unit.

**The adapter is not implemented by this slice.** It must independently fix and
observe the enrolled physical machine, endpoint/user/raw key, boot, maintenance
identity, installed runner bytes/metadata, profile prerequisites, excluded aliases
and endpoint reassignment, old process trees and bootstrap/classic writers under
the real maintained guard. Copying the challenge, an old JSON receipt, mutable
HyNode data or the shipped digest into a proof is not physical evidence. The
binding-store's physical attestation remains separately required. Tests below
explicitly simulate this independent external boundary and do not install a
production attestor in source.

## Dispatch behavior

The default executor validates installation evidence **before credential
resolution** and freshly for every prepare/commit/verify/rollback/close/status
dispatch. Each command stays inside the attestor callback and same outer held
lifecycle; exact persisted binding/connection checks and the live runner checker
are rechecked immediately before dispatch. Proof shape/values are also rechecked
after awaited checks and dispatch. This transport exposes only `exec` to the
existing typed factory, not upload/SFTP. It never invokes `ensureRunner`, shell
inspection, mkdir, systemctl inspection, install or cleanup commands.

Terminal recovery also holds the attestor callback around the exact persisted
close-ID status query. It retains the existing read-only binding reader and does
not provision, bootstrap, claim, mint command IDs, or write Mongo rows.

## Local acceptance

`topologyTestHostBinding.test.js` assembles the actual panel host/default runtime,
real connected binding store, worker and finalizer against disposable loopback
Mongo and the actual fake-root runner entry point. The local SSH boundary sends
**every** argv through the real toolkit `isolation.parse_runner` before invoking
the runner; it has no fabricated successful inspection replies. A reviewed toolkit
checkout is an explicit test dependency, not runtime code or a copied grammar:

```sh
export C3_MONGOD=/path/to/reviewed/mongod
export C3_RESTRICTED_RUNNER_HELPER=/path/to/reviewed/scripts/test-node-isolation/isolation.py
# Set normal synthetic panel test configuration and NODE_PATH if using shared deps.
node --test --test-concurrency=1 \
  src/modules/relay-l2tp/tests/topologyTestHostBinding.test.js \
  src/modules/relay-l2tp/tests/topologyRunnerBootstrapper.test.js \
  src/modules/relay-l2tp/tests/topologyOperationExecutor.test.js \
  src/modules/relay-l2tp/tests/topologyExecutionAuthorityLifecycle.test.js
```

The assembled fixture proves two serial generations, successor, close/status,
actual stale-generation replay refusal, hash/endpoint/key/boot/profile/malformed
proof refusals before credentials, missing capability/authority/enrollment,
guard loss at resolution/after commit/after close, retained ownership, read-only
recovery, and unchanged PROD preclaim refusal. Profile unit tests separately cover
portal/relay/bridge exact unit/directory/file metadata and drop-in drift. Existing
legacy bootstrap/executor tests still exercise their authorized installation mode.
User RPC remains an explicit empty-user local seam in this fixture: these tests
are not nonempty user/PPP/client traffic or full TEST/PROD operational acceptance.
