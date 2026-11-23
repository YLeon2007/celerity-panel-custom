# Relay Install package tests

The package guard, DIRECT adapter, and settlement tests are `test_rebuild_relay_packages.py`, `rebuildRelayDirectPackageHost.py` (include explicitly; its name is not discoverable by `test_*.py`), and `test_rebuild_relay_package_settlement.py` under `src/services/tests/`. Run the full files in a private offline sandbox with `umask 022` for stock directory modes. Package and service-manager commands are modeled. The tests exercise real file, link, and lock operations on disposable paths; the runner tests exercise real process settlement only with synthetic Python children.

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

## Package sources and archives on Debian 13 amd64

The guard ignores system APT sources, including provider mirrors, backports and third-party entries. Its sealed configuration uses exactly these binary `main` sources, each with `signed-by=/usr/share/keyrings/debian-archive-keyring.gpg`:

| Repository | Suite |
| --- | --- |
| `http://deb.debian.org/debian` | `trixie` |
| `http://deb.debian.org/debian` | `trixie-updates` |
| `http://security.debian.org/debian-security` | `trixie-security` |

The guard does not rewrite `/etc/apt`. It points the install command's `Dir::Cache::archives` at a private archive directory; existing downloads and partial files in `/var/cache/apt/archives` are neither used nor cleaned up. Ignoring system sources and archives does not waive keyring, index, package-state or service checks.

No manual `apt update` or `nodeSetup` change is required for clean, empty lists. Preflight binds the keyring, package state and idle services without contacting a mirror. Non-empty lists without any of the fixed repositories' `InRelease` files are not treated as an empty cache. Only after Install reserves the operation and the host records its intent may it request a single `apt-get --error-on=any update`. APT verifies `InRelease`; the guard matches the resulting native `Packages` files to signed sizes and SHA-256 before deriving and rechecking the pinned plan. The package-install autostart fences and inactive/disabled readback still apply. A failed or unconfirmed update never authorizes install or an automatic replay.

The `joined empty-index Install with packed guard:` cases in `rebuildRelayInstallPersistence.test.js` accept foreign sources and a non-empty shared archive cache without changing them. Separate controls refuse an unsafe keyring before reservation, and retain the reservation without installing after signature or acquisition failure, or missing or altered index bytes. These joined tests use synthetic APT/dpkg/systemd results; they do not run maintainer scripts or establish live SSH, PPP traffic or Remove acceptance.
