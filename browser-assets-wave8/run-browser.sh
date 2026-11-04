#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd -- "$root"
if [[ "${1:-}" != --in-scope ]]; then
  out=${1:?Usage: bash browser-assets-wave8/run-browser.sh browser-assets-wave8/FRESH-RUN}
  exec env HERMES_HEAVY_MEMORY_HIGH=1536M HERMES_HEAVY_MEMORY_MAX=2G \
    HERMES_HEAVY_MEMORY_SWAP_MAX=512M HERMES_HEAVY_CPU_QUOTA=100% \
    HERMES_HEAVY_TMP_ROOT=/home/leon/.hermes/cache/scratch/browser-wave8-heavy \
    /home/leon/.local/bin/hermes-heavy bash "$0" --in-scope "$out"
fi
shift
out=${1:?Missing fresh evidence path}
[[ "$out" == browser-assets-wave8/* ]] && [[ "$out" != *..* ]] && [[ ! -e "$out" ]]
# Only synthetic fixture configuration survives; no dotenv/index.js/cron startup.
exec timeout 300 env -i PATH="$PATH" HOME=/home/leon TMPDIR="$TMPDIR" \
  NODE_ENV=test PANEL_DOMAIN=panel.test.invalid ACME_EMAIL=admin@test.invalid \
  ENCRYPTION_KEY=test-encryption-key-32-characters-long SESSION_SECRET=test-session-secret \
  node browser-assets-wave8/acceptance.cjs "$out"
