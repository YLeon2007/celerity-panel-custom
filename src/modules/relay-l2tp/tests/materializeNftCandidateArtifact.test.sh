#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/materialize-nft-candidate.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_materializer() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    set +e
    unshare --user --map-root-user "$ARTIFACT" "$@" >"$output" 2>&1
    status=$?
    set -e
}

expect_error() {
    local label="$1"
    shift
    invoke_materializer "$label" "$@"
    [[ "$status" -ne 0 ]] || fail "$label was accepted"
    [[ "$(<"$output")" == '{"status":"error","code":"NFT_ARTIFACT_INVALID"}' ]] \
        || fail "$label returned the wrong structured error"
}

write_manifest() {
    printf '%s\n' "$1" >"$TMP_DIR/operation/artifacts.json"
    chmod 0600 "$TMP_DIR/operation/artifacts.json"
}

[[ -x "$ARTIFACT" ]] || fail 'nft candidate materializer is missing or not executable'
mkdir -p "$TMP_DIR/operation/candidate"
chmod 0700 "$TMP_DIR/operation" "$TMP_DIR/operation/candidate"
source_content='table inet celerity_l2tp {
    chain prerouting { type filter hook prerouting priority mangle; policy accept; }
}'
SOURCE_CONTENT="$source_content" node >"$TMP_DIR/operation/artifacts.json" <<'NODE'
const manifest = {
    files: [
        { path: 'etc/ipsec.secrets', mode: 0o600, content: 'unrelated secret\n' },
        {
            path: 'etc/nftables.d/celerity-l2tp.nft',
            mode: 0o644,
            content: process.env.SOURCE_CONTENT,
        },
    ],
    metadata: { namespace: 'celerity_l2tp' },
};
process.stdout.write(`${JSON.stringify(manifest)}\n`);
NODE
chmod 0600 "$TMP_DIR/operation/artifacts.json"
manifest_hash="$(sha256sum "$TMP_DIR/operation/artifacts.json")"

invoke_materializer valid "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'valid nft artifact was not materialized'
[[ "$(<"$output")" == '{"status":"ok","candidate":"candidate/celerity-l2tp.nft"}' ]] \
    || fail 'nft candidate materializer returned the wrong structured result'
[[ -f "$TMP_DIR/operation/candidate/celerity-l2tp.nft" \
    && ! -L "$TMP_DIR/operation/candidate/celerity-l2tp.nft" ]] \
    || fail 'nft candidate was not created at the fixed operation path'
[[ "$(<"$TMP_DIR/operation/candidate/celerity-l2tp.nft")" == "$source_content" ]] \
    || fail 'nft candidate content differs from its typed artifact source'
[[ "$(unshare --user --map-root-user stat --format='%u:%g:%a' -- "$TMP_DIR/operation/candidate/celerity-l2tp.nft")" == '0:0:600' ]] \
    || fail 'nft candidate is not root-owned mode 0600'
[[ "$(sha256sum "$TMP_DIR/operation/artifacts.json")" == "$manifest_hash" ]] \
    || fail 'nft candidate materialization changed its source manifest'

candidate_hash="$(sha256sum "$TMP_DIR/operation/candidate/celerity-l2tp.nft")"
reject_manifest() {
    local label="$1"
    local manifest="$2"
    rm -f "$TMP_DIR/operation/artifacts.json"
    write_manifest "$manifest"
    expect_error "$label" "$TMP_DIR/operation"
    [[ "$(sha256sum "$TMP_DIR/operation/candidate/celerity-l2tp.nft")" == "$candidate_hash" ]] \
        || fail "$label changed the existing nft candidate"
}

reject_manifest traversal-entry \
    '{"files":[{"path":"../escape.nft","mode":420,"content":"escaped"},{"path":"etc/nftables.d/celerity-l2tp.nft","mode":420,"content":"table inet replacement {}"}]}'
[[ ! -e "$TMP_DIR/escape.nft" ]] || fail 'unsafe manifest path escaped the operation directory'
reject_manifest malformed-json '{not-json'
reject_manifest malformed-files '{"files":{}}'
reject_manifest missing-artifact '{"files":[]}'
reject_manifest wrong-mode \
    '{"files":[{"path":"etc/nftables.d/celerity-l2tp.nft","mode":384,"content":"table inet wrong_mode {}"}]}'
reject_manifest missing-content \
    '{"files":[{"path":"etc/nftables.d/celerity-l2tp.nft","mode":420}]}'
reject_manifest empty-content \
    '{"files":[{"path":"etc/nftables.d/celerity-l2tp.nft","mode":420,"content":""}]}'
reject_manifest duplicate-artifact \
    '{"files":[{"path":"etc/nftables.d/celerity-l2tp.nft","mode":420,"content":"first"},{"path":"etc/nftables.d/celerity-l2tp.nft","mode":420,"content":"second"}]}'
reject_manifest malformed-sibling \
    '{"files":[{"path":"etc/ipsec.secrets","mode":"0600","content":"invalid sibling"},{"path":"etc/nftables.d/celerity-l2tp.nft","mode":420,"content":"table inet replacement {}"}]}'
reject_manifest duplicate-json-key \
    '{"files":[],"files":[{"path":"etc/nftables.d/celerity-l2tp.nft","mode":420,"content":"table inet hidden {}"}]}'

rm -f "$TMP_DIR/operation/artifacts.json"
expect_error missing-manifest "$TMP_DIR/operation"
[[ "$(sha256sum "$TMP_DIR/operation/candidate/celerity-l2tp.nft")" == "$candidate_hash" ]] \
    || fail 'missing manifest changed the existing nft candidate'

printf '%s\n' '{"files":[{"path":"etc/nftables.d/celerity-l2tp.nft","mode":420,"content":"table inet symlinked {}"}]}' \
    >"$TMP_DIR/outside-artifacts.json"
ln -s "$TMP_DIR/outside-artifacts.json" "$TMP_DIR/operation/artifacts.json"
expect_error symlinked-manifest "$TMP_DIR/operation"
[[ "$(sha256sum "$TMP_DIR/operation/candidate/celerity-l2tp.nft")" == "$candidate_hash" ]] \
    || fail 'symlinked manifest changed the existing nft candidate'

rm -f "$TMP_DIR/operation/artifacts.json"
write_manifest '{"files":[{"path":"etc/nftables.d/celerity-l2tp.nft","mode":420,"content":"table inet candidate_symlink {}"}]}'
printf '%s\n' 'outside candidate sentinel' >"$TMP_DIR/outside-candidate.nft"
rm -f "$TMP_DIR/operation/candidate/celerity-l2tp.nft"
ln -s "$TMP_DIR/outside-candidate.nft" "$TMP_DIR/operation/candidate/celerity-l2tp.nft"
expect_error symlinked-candidate "$TMP_DIR/operation"
[[ "$(<"$TMP_DIR/outside-candidate.nft")" == 'outside candidate sentinel' ]] \
    || fail 'symlinked candidate changed an outside file'

rm -f "$TMP_DIR/operation/candidate/celerity-l2tp.nft"
rmdir "$TMP_DIR/operation/candidate"
mkdir "$TMP_DIR/outside-candidate-directory"
ln -s "$TMP_DIR/outside-candidate-directory" "$TMP_DIR/operation/candidate"
expect_error symlinked-candidate-directory "$TMP_DIR/operation"
[[ -z "$(find "$TMP_DIR/outside-candidate-directory" -mindepth 1 -print -quit)" ]] \
    || fail 'symlinked candidate directory received a candidate'

rm -f "$TMP_DIR/operation/candidate"
write_manifest '{"files":[{"path":"etc/nftables.d/celerity-l2tp.nft","mode":420,"content":"table inet recreated {}"}]}'
invoke_materializer recreated-directory "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'materializer did not create the fixed candidate directory'
[[ "$(<"$TMP_DIR/operation/candidate/celerity-l2tp.nft")" == 'table inet recreated {}' ]] \
    || fail 'candidate created in a missing fixed directory differs from source'

recreated_hash="$(sha256sum "$TMP_DIR/operation/candidate/celerity-l2tp.nft")"
invoke_materializer extra-argument "$TMP_DIR/operation" "$TMP_DIR/outside-candidate.nft"
[[ "$status" -ne 0 ]] || fail 'materializer accepted arbitrary candidate content arguments'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'extra candidate argument returned the wrong error'
[[ "$(sha256sum "$TMP_DIR/operation/candidate/celerity-l2tp.nft")" == "$recreated_hash" ]] \
    || fail 'extra candidate argument changed the fixed candidate'

ln -s "$TMP_DIR/operation" "$TMP_DIR/linked-operation"
expect_error symlinked-operation "$TMP_DIR/linked-operation"
[[ "$(sha256sum "$TMP_DIR/operation/candidate/celerity-l2tp.nft")" == "$recreated_hash" ]] \
    || fail 'symlinked operation changed the fixed candidate'

printf 'nft candidate materializer fixture tests passed\n'
