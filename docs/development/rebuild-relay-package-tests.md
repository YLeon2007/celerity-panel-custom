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

The cap covers three complete observations in the prepare runner, one pinned simulation, and all containment and readback calls. Preflight uses a separate runner. This is a count bound, not a wall-time claim; the 115-second host deadline and 78-second APT ceiling are unchanged. The historical solver rows are reused as model input, not as an authenticated APT replay. These tests do not validate host APT configuration isolation or `/proc` FD resolution by APT, package signatures or maintainer scripts, systemd mask or generator behavior, live SSH, or a working relay data plane.
