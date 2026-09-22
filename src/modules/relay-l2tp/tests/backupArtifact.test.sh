#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/backup.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

run_backup() {
    unshare --user --map-root-user "$ARTIFACT" "$@"
}

expect_error() {
    local expected_code="$1"
    local label="$2"
    shift 2
    local output="$TMP_DIR/$label.out"
    local status=0
    set +e
    run_backup "$@" >"$output" 2>&1
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || fail "$label unexpectedly succeeded"
    grep -Fqx -- "{\"status\":\"error\",\"code\":\"$expected_code\"}" "$output" \
        || fail "$label returned the wrong structured error"
}

command -v unshare >/dev/null 2>&1 || fail 'unshare is required for root-owned backup fixtures'
[[ -x "$ARTIFACT" ]] || fail 'backup artifact is missing or not executable'

root="$TMP_DIR/root"
operation="$TMP_DIR/operation"
mkdir -p "$root/etc/ipsec.d" "$root/etc/ppp" "$root/etc/local" "$operation"
printf '%s\n' 'managed ipsec' >"$root/etc/ipsec.d/celerity-l2tp.conf"
printf '%s\n' 'local chap' >"$root/etc/ppp/chap-secrets"
printf '%s\n' 'never back this up' >"$root/etc/local/unmanaged.conf"
chmod 0640 "$root/etc/ipsec.d/celerity-l2tp.conf"
chmod 0644 "$root/etc/ppp/chap-secrets"

output="$TMP_DIR/backup.out"
run_backup "$operation" "$root" >"$output"
grep -Fqx -- '{"status":"ok","backedUp":2,"absent":5}' "$output" \
    || fail 'backup returned the wrong structured result'
[[ -f "$operation/backup.json" && ! -L "$operation/backup.json" ]] \
    || fail 'backup manifest was not created as a regular operation-local file'
[[ "$(unshare --user --map-root-user stat --format='%u:%g:%a' -- "$operation/backup.json")" == '0:0:600' ]] \
    || fail 'backup manifest is not root-owned mode 0600'

node - "$operation/backup.json" <<'NODE'
const fs = require('node:fs');
const assert = require('node:assert/strict');
const manifest = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
assert.deepEqual(manifest.files, [
    {
        path: 'etc/ipsec.d/celerity-l2tp.conf',
        mode: 0o640,
        content: 'managed ipsec\n',
    },
    {
        path: 'etc/ppp/chap-secrets',
        mode: 0o644,
        content: 'local chap\n',
    },
]);
assert.deepEqual(manifest.absent, [
    'etc/ipsec.secrets',
    'etc/xl2tpd/xl2tpd.conf',
    'etc/ppp/options.xl2tpd',
    'etc/nftables.d/celerity-l2tp.nft',
    'usr/local/etc/xray/config.json',
]);
assert.equal(JSON.stringify(manifest).includes('unmanaged'), false);
NODE

run_backup "$operation" "$root" >"$output"
grep -Fqx -- '{"status":"ok","backedUp":2,"absent":5}' "$output" \
    || fail 'idempotent backup returned the wrong result'

symlink_root="$TMP_DIR/symlink-root"
symlink_operation="$TMP_DIR/symlink-operation"
outside="$TMP_DIR/outside-secret"
mkdir -p "$symlink_root/etc" "$symlink_operation"
printf '%s\n' 'outside secret must not be read' >"$outside"
ln -s "$outside" "$symlink_root/etc/ipsec.secrets"
expect_error 'MANAGED_PATH_SYMLINK' 'symlinked-managed-file' "$symlink_operation" "$symlink_root"
[[ ! -e "$symlink_operation/backup.json" ]] || fail 'rejected backup created a manifest'

manifest_target="$TMP_DIR/manifest-target"
printf '%s\n' '{}' >"$manifest_target"
manifest_operation="$TMP_DIR/manifest-operation"
mkdir -p "$manifest_operation"
ln -s "$manifest_target" "$manifest_operation/backup.json"
expect_error 'BACKUP_MANIFEST_SYMLINK' 'symlinked-manifest' "$manifest_operation" "$root"
[[ "$(<"$manifest_target")" == '{}' ]] || fail 'backup followed the manifest symlink'

expect_error 'INVALID_ARGUMENTS' 'arbitrary-extra-input' "$operation" "$root" "$outside"

printf 'backup artifact fixture tests passed\n'
