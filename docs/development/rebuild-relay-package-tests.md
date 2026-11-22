# Relay Install package tests

The package guard, DIRECT adapter, and settlement tests are `test_rebuild_relay_packages.py`, `rebuildRelayDirectPackageHost.py` (include explicitly; its name is not discoverable by `test_*.py`), and `test_rebuild_relay_package_settlement.py` under `src/services/tests/`. Run the full files in a private offline sandbox. Package and service-manager commands are modeled. The tests exercise real file, link, and lock operations on disposable paths; the runner tests exercise real process settlement only with synthetic Python children.

The `joined package Install with packed guard:` cases in `rebuildRelayInstallPersistence.test.js` use the real Install service and packed DIRECT source. They use modeled persistence, in-memory SSH, and one disposable Debian-shaped root shared by package preparation and the subsequent stock Install. The positive checks the reservation, one modeled package write, idle service readback and actual boot-link cleanup in the disposable root, then normal Install settlement. The four controls cover lost reservation acknowledgement, an active IKE unit, foreign unit ownership, and missing authorization. The lost-acknowledgement case permits a read-only modeled package plan, not a package write.

## DIRECT package command budget

In the offline sandbox, the dedicated adapter cases are:

```sh
python3 -B src/services/tests/rebuildRelayDirectPackageHost.py -v \
  Adapter.test_real_guard_historical_clean_plan_fits_runner_budget \
  Adapter.test_real_guard_max_plan_fits_exact_runner_budget \
  Adapter.test_real_guard_exhausted_budget_retains_pending
```

These cases join the actual fresh `preflight` and `prepare-packages` wire actions, package guard, and `PackageRunner` counters. Host identity/ownership and child results are modeled; locking, intents, receipts, and containment artifacts use a disposable root. No package or service-manager binary runs, not even for simulations.

| Model | Preflight runner | Prepare runner | Result |
| --- | ---: | ---: | --- |
| Historical 12-package solver rows | 46 | 258 | Ready, owned masks and policy removed, new boot links disabled |
| 48-package plan with all four admitted SysV scripts | 86 | 391 | Ready at the exact cap |
| Same 48-package plan with a test cap of 390 | 86 | 390 | Last readback refused; no ready ACK, pending intent and policy retained |

With populated indexes the cap covers three complete observations in the prepare runner, one pinned simulation, and all containment and readback calls. With empty indexes the largest model takes 378 commands; preflight is still a separate read-only runner. Only `prepare-packages` has a 210-second host deadline (measured from startup), 220-second shell timeout and 240-second SSH timeout. The update and install commands each have a 78-second ceiling within that single host budget. These are bounds, not timings measured on a live relay.

## Empty lists on Debian 13 amd64

No manual `apt update` or `nodeSetup` change is required by this path. With no committed indexes, preflight binds the root-owned source files, Debian archive keyring, package state and idle services; it does not contact a mirror. Only after Install reserves the operation and the host records its intent may it request a single `apt-get --error-on=any update`, restricted to `main` from the already configured, allowlisted Debian repositories. The sealed invocation config disables default snippets, redirects and untrusted repositories; it is not written to `/etc/apt`. APT verifies `InRelease`; the guard matches the resulting native `Packages` files to signed sizes and SHA-256 before deriving and rechecking the normal pinned plan. The existing package-install autostart fences and inactive/disabled readback still apply. A failed or unconfirmed update never authorizes install or an automatic replay.

The `joined package Install with packed guard:` tests use synthetic APT/dpkg/systemd command results. They cover an empty cache, signature and acquisition failure, missing or altered index bytes, foreign sources, and the original service/admission controls. They do not run maintainer scripts or establish live SSH, PPP traffic or Remove acceptance. Those checks belong to MAIN on its separately authorized disposable relay.
