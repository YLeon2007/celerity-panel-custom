#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

target=''
repo_root=''
output=''
expected_source_commit=''
expected_source_tree=''

while (($#)); do
    (($# >= 2)) || fail "argument requires a value: $1"
    case "$1" in
        --target) target=$2 ;;
        --repo-root) repo_root=$2 ;;
        --output) output=$2 ;;
        --expected-source-commit) expected_source_commit=$2 ;;
        --expected-source-tree) expected_source_tree=$2 ;;
        *) fail "unknown argument: $1" ;;
    esac
    shift 2
done

require_test_target "$target"
require_git_oid 'expected source commit' "$expected_source_commit"
require_git_oid 'expected source tree' "$expected_source_tree"
[[ -n "$repo_root" && -d "$repo_root" && ! -L "$repo_root" ]] \
    || fail 'repo root must be a local directory'
[[ -n "$output" && ! -e "$output" && ! -L "$output" ]] \
    || fail 'output must be a new local file'

repo_root=$(cd -- "$repo_root" && pwd -P)
git_root=$(git -C "$repo_root" rev-parse --show-toplevel 2>/dev/null) \
    || fail 'repo root must be a Git worktree'
git_root=$(cd -- "$git_root" && pwd -P)
[[ "$repo_root" == "$git_root" ]] || fail 'repo root must be the Git worktree root'

output_parent=$(dirname -- "$output")
[[ -d "$output_parent" && ! -L "$output_parent" ]] || fail 'output parent must be a local directory'
output_parent=$(cd -- "$output_parent" && pwd -P)
output="$output_parent/$(basename -- "$output")"
case "$output" in
    "$repo_root"/*) fail 'output must be outside the source worktree' ;;
esac

actual_commit=$(git -C "$repo_root" rev-parse HEAD)
actual_tree=$(git -C "$repo_root" rev-parse 'HEAD^{tree}')
[[ "$actual_commit" == "$expected_source_commit" ]] || fail 'source commit does not match'
[[ "$actual_tree" == "$expected_source_tree" ]] || fail 'source tree does not match'
[[ -z $(git -C "$repo_root" status --porcelain --untracked-files=all) ]] \
    || fail 'source worktree must be clean'

stage_root=$(mktemp -d)
output_tmp=''
cleanup() {
    rm -rf -- "$stage_root"
    [[ -z "$output_tmp" ]] || rm -f -- "$output_tmp"
}
trap cleanup EXIT
mkdir -p -- "$stage_root/source"
git -C "$repo_root" archive --format=tar HEAD | tar -xf - -C "$stage_root/source"
printf '%s\n' \
    'schema_version=1' \
    "source_commit=$expected_source_commit" \
    "source_tree=$expected_source_tree" \
    'worktree_clean=true' \
    'archive_root=source' \
    "compose_file=$CELERITY_COMPOSE_FILE" \
    "app_service=$CELERITY_APP_SERVICE" \
    > "$stage_root/manifest.env"

[[ "$(git -C "$repo_root" rev-parse HEAD)" == "$expected_source_commit" ]] \
    || fail 'source commit changed during bundle creation'
[[ "$(git -C "$repo_root" rev-parse 'HEAD^{tree}')" == "$expected_source_tree" ]] \
    || fail 'source tree changed during bundle creation'
[[ -z $(git -C "$repo_root" status --porcelain --untracked-files=all) ]] \
    || fail 'source worktree changed during bundle creation'

output_tmp=$(mktemp "$output.tmp.XXXXXX")
tar \
    --sort=name \
    --format=ustar \
    --mtime=@0 \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --mode=u+rwX,go+rX,go-w \
    -C "$stage_root" \
    -cf - \
    manifest.env source \
    | gzip -n -9 > "$output_tmp"
chmod 0644 "$output_tmp"
mv -- "$output_tmp" "$output"
output_tmp=''
printf 'bundle_sha256=%s\n' "$(sha256_file "$output")"
