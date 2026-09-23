#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

target=''
host_identity=''
install_root=''
backup_root=''
source_bundle=''
source_bundle_sha256=''
expected_source_commit=''
expected_source_tree=''
module_artifact=''
module_artifact_sha256=''
config_env_file=''
declare -a config_file_refs=()

while (($#)); do
    (($# >= 2)) || fail "argument requires a value: $1"
    case "$1" in
        --target) target=$2 ;;
        --host-identity) host_identity=$2 ;;
        --install-root) install_root=$2 ;;
        --backup-root) backup_root=$2 ;;
        --source-bundle) source_bundle=$2 ;;
        --source-bundle-sha256) source_bundle_sha256=$2 ;;
        --expected-source-commit) expected_source_commit=$2 ;;
        --expected-source-tree) expected_source_tree=$2 ;;
        --module-artifact) module_artifact=$2 ;;
        --module-artifact-sha256) module_artifact_sha256=$2 ;;
        --config-env-file) config_env_file=$2 ;;
        --config-file-ref) config_file_refs+=("$2") ;;
        *) fail "unknown argument: $1" ;;
    esac
    shift 2
done

require_test_target "$target"
require_test_host_identity "$host_identity"
require_control_paths "$install_root" "$backup_root"
require_git_oid 'expected source commit' "$expected_source_commit"
require_git_oid 'expected source tree' "$expected_source_tree"
require_sha256 'source bundle checksum' "$source_bundle_sha256"
require_sha256 'module artifact checksum' "$module_artifact_sha256"
require_local_regular_file 'source bundle' "$source_bundle"
require_local_regular_file 'module artifact' "$module_artifact"
require_local_regular_file 'config env file' "$config_env_file"
require_file_checksum 'source bundle' "$source_bundle" "$source_bundle_sha256"
require_file_checksum 'module artifact' "$module_artifact" "$module_artifact_sha256"

declare -A seen_config_destinations=()
for config_ref in "${config_file_refs[@]}"; do
    [[ "$config_ref" == *=* ]] || fail 'config file refs must use config/test/PATH=LOCAL_FILE'
    destination=${config_ref%%=*}
    local_file=${config_ref#*=}
    [[ "$destination" =~ ^config/test/([A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$ ]] \
        || fail 'config file destinations must stay under config/test'
    [[ -z ${seen_config_destinations[$destination]+x} ]] \
        || fail 'config file destinations must be unique'
    seen_config_destinations[$destination]=1
    require_local_regular_file 'config file ref' "$local_file"
done

install_root_path=$(resolve_control_path "$install_root")
[[ -d "$install_root_path" && ! -L "$install_root_path" ]] \
    || fail "install root must already be the real $CELERITY_INSTALL_ROOT directory"
install_root_path=$(cd -- "$install_root_path" && pwd -P)
[[ -f "$install_root_path/.env" && ! -L "$install_root_path/.env" ]] \
    || fail 'installed .env must be a regular file'

validation_root=$(mktemp -d)
compose_env=''
cleanup() {
    secure_remove_file "$compose_env"
    rm -rf -- "$validation_root"
}
trap cleanup EXIT
extracted_source="$validation_root/source"
python3 "$SCRIPT_DIR/validate-staging-inputs.py" \
    --source-bundle "$source_bundle" \
    --module-artifact "$module_artifact" \
    --config-env-file "$config_env_file" \
    --expected-source-commit "$expected_source_commit" \
    --expected-source-tree "$expected_source_tree" \
    --extract-source "$extracted_source"
compose_env="$extracted_source/.env"
create_compose_env "$install_root_path/.env" "$config_env_file" "$compose_env"

compose_path="$extracted_source/$CELERITY_COMPOSE_FILE"
compose_base=(
    docker compose
    --project-directory "$extracted_source"
    --env-file "$compose_env"
    -f "$compose_path"
)
if ! "${compose_base[@]}" config --quiet >/dev/null 2>&1; then
    fail 'compose syntax preflight failed'
fi
if ! compose_services=$("${compose_base[@]}" config --services 2>/dev/null); then
    fail 'compose service layout preflight failed'
fi
actual_services=$(printf '%s\n' "$compose_services" | LC_ALL=C sort)
expected_services=$(printf '%s\n' backend caddy mongo redis updater | LC_ALL=C sort)
[[ "$actual_services" == "$expected_services" ]] \
    || fail 'compose services must be exactly backend, caddy, mongo, redis, updater'

printf 'precheck ok\n'
