#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/apply.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

run_apply() {
    unshare --user --map-root-user "$ARTIFACT" "$@"
}

expect_apply_error() {
    local expected_code="$1"
    local label="$2"
    local manifest_path="$3"
    local target_root="$4"
    local error_output="$TMP_DIR/error.out"
    local status

    set +e
    run_apply "$manifest_path" "$target_root" >"$error_output" 2>&1
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || fail "$label was accepted"
    grep -Fqx -- "{\"status\":\"error\",\"code\":\"$expected_code\"}" "$error_output" \
        || fail "$label returned the wrong error"
}

command -v unshare >/dev/null 2>&1 || fail 'unshare is required for the root-owned manifest fixture'
[[ -x "$ARTIFACT" ]] || fail 'apply artifact is missing or not executable'

contract_root="$TMP_DIR/contract-root"
contract_manifest="$TMP_DIR/contract-manifest.json"
mkdir -p "$contract_root/etc"
printf '%s\n' 'operator-owned global IPsec config' >"$contract_root/etc/ipsec.conf"
ROOT_DIR="$ROOT_DIR" node >"$contract_manifest" <<'NODE'
const { buildL2tpArtifacts } = require(
    `${process.env.ROOT_DIR}/src/modules/relay-l2tp/services/l2tpConfigService`,
);

process.stdout.write(JSON.stringify(buildL2tpArtifacts({
    clientCidr: '10.77.0.0/24',
    localAddress: '10.77.0.1',
    poolStart: '10.77.0.10',
    poolEnd: '10.77.0.200',
    dnsServers: ['1.1.1.1', '9.9.9.9'],
    tproxyPort: 12345,
    fwmark: 77,
    routeTable: 177,
    psk: 'artifact-contract-secret',
})));
NODE
contract_output="$TMP_DIR/contract-apply.out"
run_apply "$contract_manifest" "$contract_root" >"$contract_output"
grep -Fqx -- '{"status":"ok","changed":5,"unchanged":0}' "$contract_output" \
    || fail 'generated artifact manifest is incompatible with apply'
[[ -f "$contract_root/etc/ipsec.d/celerity-l2tp.conf" ]] \
    || fail 'generated IPsec drop-in was not applied'
[[ "$(<"$contract_root/etc/ipsec.conf")" == 'operator-owned global IPsec config' ]] \
    || fail 'generated artifact manifest replaced the global IPsec config'

root="$TMP_DIR/root"
manifest="$TMP_DIR/manifest.json"
mkdir -p "$root/etc/ipsec.d" "$root/etc/ppp"
printf '%s\n' 'old ipsec' >"$root/etc/ipsec.d/celerity-l2tp.conf"
printf '%s\n' 'operator-owned global IPsec config' >"$root/etc/ipsec.conf"
printf '%s\n' 'leave unmanaged bytes alone' >"$root/etc/local.conf"
printf '%s\n' 'local chap entry must survive' >"$root/etc/ppp/chap-secrets"
printf '%s\n' '{"files":[{"path":"etc/ipsec.d/celerity-l2tp.conf","mode":420,"content":"managed ipsec\n"},{"path":"etc/ipsec.secrets","mode":384,"content":"secret material\n"},{"path":"etc/xl2tpd/xl2tpd.conf","mode":420,"content":"managed xl2tpd\n"}]}' >"$manifest"

old_inode="$(/usr/bin/stat --format='%i' -- "$root/etc/ipsec.d/celerity-l2tp.conf")"
output="$TMP_DIR/apply.out"
run_apply "$manifest" "$root" >"$output"

grep -Fqx -- '{"status":"ok","changed":3,"unchanged":0}' "$output" \
    || fail 'successful apply did not report changed files'
[[ "$(<"$root/etc/ipsec.d/celerity-l2tp.conf")" == 'managed ipsec' ]] || fail 'managed config was not applied'
[[ "$(<"$root/etc/ipsec.secrets")" == 'secret material' ]] || fail 'managed secret was not applied'
[[ "$(<"$root/etc/xl2tpd/xl2tpd.conf")" == 'managed xl2tpd' ]] || fail 'nested managed config was not applied'
[[ "$(<"$root/etc/ipsec.conf")" == 'operator-owned global IPsec config' ]] \
    || fail 'global IPsec config changed'
[[ "$(<"$root/etc/local.conf")" == 'leave unmanaged bytes alone' ]] || fail 'unmanaged file changed'
[[ "$(<"$root/etc/ppp/chap-secrets")" == 'local chap entry must survive' ]] \
    || fail 'unmanaged chap-secrets data changed'
[[ "$(/usr/bin/stat --format='%a' -- "$root/etc/ipsec.d/celerity-l2tp.conf")" == '644' ]] || fail 'config mode is not 0644'
[[ "$(/usr/bin/stat --format='%a' -- "$root/etc/ipsec.secrets")" == '600' ]] || fail 'secret mode is not 0600'
[[ "$(/usr/bin/stat --format='%i' -- "$root/etc/ipsec.d/celerity-l2tp.conf")" != "$old_inode" ]] \
    || fail 'managed config was not installed by atomic rename'

stable_inode="$(/usr/bin/stat --format='%i' -- "$root/etc/ipsec.d/celerity-l2tp.conf")"
run_apply "$manifest" "$root" >"$output"
grep -Fqx -- '{"status":"ok","changed":0,"unchanged":3}' "$output" \
    || fail 'idempotent apply did not report unchanged files'
[[ "$(/usr/bin/stat --format='%i' -- "$root/etc/ipsec.d/celerity-l2tp.conf")" == "$stable_inode" ]] \
    || fail 'idempotent apply replaced an unchanged file'

absolute_target="$TMP_DIR/absolute-target.conf"
printf '{"files":[{"path":"%s","mode":420,"content":"escaped root\\n"}]}\n' \
    "$absolute_target" >"$manifest"
expect_apply_error 'ABSOLUTE_PATH_NOT_ALLOWED' 'absolute manifest path' "$manifest" "$root"
[[ ! -e "$absolute_target" ]] || fail 'absolute manifest path escaped the supplied root'

reject_root="$TMP_DIR/reject-root"
mkdir -p "$reject_root/etc/ipsec.d"
printf '%s\n' 'managed sentinel' >"$reject_root/etc/ipsec.d/celerity-l2tp.conf"
printf '%s\n' 'unmanaged global sentinel' >"$reject_root/etc/ipsec.conf"
printf '%s\n' 'unmanaged sentinel' >"$reject_root/etc/local.conf"

printf '%s\n' '{"files":[{"path":"etc/../ipsec.conf","mode":420,"content":"traversed\n"}]}' >"$manifest"
expect_apply_error 'PATH_TRAVERSAL_NOT_ALLOWED' 'traversal path' "$manifest" "$reject_root"

printf '%s\n' '{"files":[{"path":"etc/local.conf","mode":420,"content":"unexpected\n"}]}' >"$manifest"
expect_apply_error 'UNEXPECTED_PATH' 'unexpected path' "$manifest" "$reject_root"

printf '%s\n' '{"files":[{"path":"etc/ipsec.conf","mode":420,"content":"replace global\n"}]}' >"$manifest"
expect_apply_error 'UNEXPECTED_PATH' 'global IPsec config path' "$manifest" "$reject_root"

printf '%s\n' '{"files":[{"path":"etc/ipsec.d/celerity-l2tp.conf","mode":384,"content":"wrong mode\n"}]}' >"$manifest"
expect_apply_error 'UNEXPECTED_MODE' 'unexpected mode' "$manifest" "$reject_root"

printf '%s\n' '{"files":[{"path":"etc/ipsec.d/celerity-l2tp.conf","mode":420,"content":"first\n"},{"path":"etc/ipsec.d/celerity-l2tp.conf","mode":420,"content":"second\n"}]}' >"$manifest"
expect_apply_error 'DUPLICATE_PATH' 'duplicate path' "$manifest" "$reject_root"

printf '%s\n' '{"files":[{"path":"etc/ipsec.d/celerity-l2tp.conf","mode":420,"content":"would change\n"},{"path":"etc/ipsec.secrets","mode":420,"content":"bad mode\n"}]}' >"$manifest"
expect_apply_error 'UNEXPECTED_MODE' 'partially invalid manifest' "$manifest" "$reject_root"
[[ "$(<"$reject_root/etc/ipsec.d/celerity-l2tp.conf")" == 'managed sentinel' ]] \
    || fail 'invalid manifest partially changed a managed file'
[[ "$(<"$reject_root/etc/local.conf")" == 'unmanaged sentinel' ]] \
    || fail 'rejected manifests changed unmanaged data'
[[ "$(<"$reject_root/etc/ipsec.conf")" == 'unmanaged global sentinel' ]] \
    || fail 'rejected manifest changed the global IPsec config'

nonroot_manifest="$TMP_DIR/nonroot-manifest.json"
printf '%s\n' '{"files":[{"path":"etc/ipsec.d/celerity-l2tp.conf","mode":420,"content":"root only\n"}]}' >"$nonroot_manifest"
if [[ "$(id -u)" == '0' ]]; then
    chown 65534:65534 "$nonroot_manifest"
fi
set +e
"$ARTIFACT" "$nonroot_manifest" "$reject_root" >"$output" 2>&1
status=$?
set -e
[[ "$status" -ne 0 ]] || fail 'non-root-owned manifest was accepted'
grep -Fqx -- '{"status":"error","code":"MANIFEST_NOT_ROOT_OWNED"}' "$output" \
    || fail 'non-root-owned manifest returned the wrong error'

manifest_target="$TMP_DIR/manifest-target.json"
printf '%s\n' '{"files":[]}' >"$manifest_target"
manifest_link="$TMP_DIR/manifest-link.json"
ln -s "$manifest_target" "$manifest_link"
expect_apply_error 'INVALID_MANIFEST_FILE' 'symlinked manifest' "$manifest_link" "$reject_root"

symlink_root="$TMP_DIR/symlink-root"
outside_dir="$TMP_DIR/outside-dir"
mkdir -p "$symlink_root" "$outside_dir"
ln -s "$outside_dir" "$symlink_root/etc"
printf '%s\n' '{"files":[{"path":"etc/ipsec.d/celerity-l2tp.conf","mode":420,"content":"escaped symlink\n"}]}' >"$manifest"
expect_apply_error 'INVALID_TARGET' 'symlinked parent directory' "$manifest" "$symlink_root"
[[ ! -e "$outside_dir/ipsec.d/celerity-l2tp.conf" ]] \
    || fail 'symlinked parent escaped the supplied root'

atomic_root="$TMP_DIR/atomic-root"
mkdir -p "$atomic_root/etc/ipsec.d"
printf '%s\n' 'keep first file' >"$atomic_root/etc/ipsec.d/celerity-l2tp.conf"
printf '%s\n' 'keep outside target' >"$outside_dir/ipsec.secrets"
ln -s "$outside_dir/ipsec.secrets" "$atomic_root/etc/ipsec.secrets"
printf '%s\n' '{"files":[{"path":"etc/ipsec.d/celerity-l2tp.conf","mode":420,"content":"new first file\n"},{"path":"etc/ipsec.secrets","mode":384,"content":"new secret\n"}]}' >"$manifest"
expect_apply_error 'INVALID_TARGET' 'symlinked target' "$manifest" "$atomic_root"
[[ "$(<"$atomic_root/etc/ipsec.d/celerity-l2tp.conf")" == 'keep first file' ]] \
    || fail 'target validation failure partially changed an earlier file'
[[ "$(<"$outside_dir/ipsec.secrets")" == 'keep outside target' ]] \
    || fail 'symlinked target changed data outside the supplied root'

if compgen -G "$root/etc/.celerity-l2tp-apply.*" >/dev/null; then
    fail 'successful apply left staged files behind'
fi

printf 'apply artifact fixture tests passed\n'
