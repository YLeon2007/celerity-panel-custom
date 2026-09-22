#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

target=''
host_identity=''
install_root=''
backup_root=''
backup_dir=''
backup_manifest_sha256=''
mongo_restore_hook=''
plan_only=''
execute=''

while (($#)); do
    (($# >= 2)) || fail "argument requires a value: $1"
    case "$1" in
        --target) target=$2 ;;
        --host-identity) host_identity=$2 ;;
        --install-root) install_root=$2 ;;
        --backup-root) backup_root=$2 ;;
        --backup-dir) backup_dir=$2 ;;
        --backup-manifest-sha256) backup_manifest_sha256=$2 ;;
        --mongo-restore-hook) mongo_restore_hook=$2 ;;
        --plan-only) plan_only=$2 ;;
        --execute) execute=$2 ;;
        *) fail "unknown argument: $1" ;;
    esac
    shift 2
done

require_test_target "$target"
require_test_host_identity "$host_identity"
require_control_paths "$install_root" "$backup_root"
require_sha256 'backup manifest checksum' "$backup_manifest_sha256"
[[ -x "$mongo_restore_hook" && -f "$mongo_restore_hook" && ! -L "$mongo_restore_hook" ]] \
    || fail 'Mongo restore hook must be a local executable regular file'
if [[ "$plan_only" == 'true' && -z "$execute" ]]; then
    mode='plan'
elif [[ "$execute" == 'true' && -z "$plan_only" ]]; then
    mode='execute'
else
    fail 'choose exactly one of --plan-only true or --execute true'
fi

backup_id=${backup_dir#"$backup_root"/}
[[ "$backup_dir" == "$backup_root/$backup_id" \
    && "$backup_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$ \
    && "$backup_id" != */* ]] \
    || fail 'backup directory must be one exact timestamped child of the test backup root'

backup_root_path=$(resolve_control_path "$backup_root")
[[ -d "$backup_root_path" && ! -L "$backup_root_path" ]] \
    || fail 'test backup root must be a real directory'
backup_root_path=$(cd -- "$backup_root_path" && pwd -P)
backup_dir_path=$(resolve_control_path "$backup_dir")
[[ -d "$backup_dir_path" && ! -L "$backup_dir_path" ]] \
    || fail 'requested test backup directory is missing or not a real directory'
backup_dir_path=$(cd -- "$backup_dir_path" && pwd -P)
[[ "$backup_dir_path" == "$backup_root_path/$backup_id" ]] \
    || fail 'backup directory escaped the test backup root'

state_file="$backup_dir_path/STATE"
[[ -f "$state_file" && ! -L "$state_file" && "$(<"$state_file")" == 'complete' ]] \
    || fail 'backup is missing an exact complete state marker'
manifest_file="$backup_dir_path/backup-manifest.env"
[[ -s "$manifest_file" && -f "$manifest_file" && ! -L "$manifest_file" ]] \
    || fail 'backup manifest must reference a non-empty regular file'
require_file_checksum 'backup manifest' "$manifest_file" "$backup_manifest_sha256"

declare -A manifest=()
while IFS= read -r manifest_line || [[ -n "$manifest_line" ]]; do
    [[ "$manifest_line" =~ ^([a-z][a-z0-9_]*)=(.*)$ ]] \
        || fail 'backup manifest has invalid syntax'
    manifest_key=${BASH_REMATCH[1]}
    manifest_value=${BASH_REMATCH[2]}
    [[ -z ${manifest[$manifest_key]+x} ]] \
        || fail 'backup manifest contains duplicate keys'
    manifest[$manifest_key]=$manifest_value
done < "$manifest_file"

expected_manifest_keys=(
    schema_version target host_identity install_root backup_root backup_id
    operation_id compose_file app_service deployed_source_commit
    deployed_source_tree config_test_present
)
[[ ${#manifest[@]} -eq ${#expected_manifest_keys[@]} ]] \
    || fail 'backup manifest has missing or unexpected keys'
for manifest_key in "${expected_manifest_keys[@]}"; do
    [[ -n ${manifest[$manifest_key]+x} ]] \
        || fail 'backup manifest has missing or unexpected keys'
done

[[ ${manifest[schema_version]} == '1' ]] || fail 'backup manifest schema does not match'
[[ ${manifest[target]} == "$target" ]] || fail 'backup manifest target does not match'
[[ ${manifest[host_identity]} == "$host_identity" ]] || fail 'backup manifest host identity does not match'
[[ ${manifest[install_root]} == "$install_root" ]] || fail 'backup manifest install root does not match'
[[ ${manifest[backup_root]} == "$backup_root" ]] || fail 'backup manifest backup root does not match'
[[ ${manifest[backup_id]} == "$backup_id" ]] || fail 'backup manifest backup id does not match'
[[ ${manifest[operation_id]} =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    || fail 'backup manifest operation id is invalid'
[[ ${manifest[compose_file]} == "$CELERITY_COMPOSE_FILE" ]] \
    || fail 'backup manifest Compose reference does not match'
[[ ${manifest[app_service]} == "$CELERITY_APP_SERVICE" ]] \
    || fail 'backup manifest service reference does not match'
require_git_oid 'backup manifest deployed source commit' "${manifest[deployed_source_commit]}"
require_git_oid 'backup manifest deployed source tree' "${manifest[deployed_source_tree]}"
[[ "$backup_id" == "${manifest[operation_id]}-${manifest[deployed_source_commit]:0:12}" ]] \
    || fail 'backup id does not match its operation and deployed source commit'
[[ ${manifest[config_test_present]} == 'true' || ${manifest[config_test_present]} == 'false' ]] \
    || fail 'backup manifest config/test marker is invalid'

source_archive="$backup_dir_path/source.tar.gz"
config_env="$backup_dir_path/config.env"
mongo_archive="$backup_dir_path/mongo.archive.gz"
checksums_file="$backup_dir_path/SHA256SUMS"
config_test_archive="$backup_dir_path/config-test.tar.gz"
[[ -s "$source_archive" && -f "$source_archive" && ! -L "$source_archive" ]] \
    || fail 'source backup must reference a non-empty regular file'
[[ -s "$config_env" && -f "$config_env" && ! -L "$config_env" ]] \
    || fail 'config backup must reference a non-empty regular file'
[[ -s "$mongo_archive" && -f "$mongo_archive" && ! -L "$mongo_archive" ]] \
    || fail 'Mongo backup must reference a non-empty regular file'
[[ -s "$checksums_file" && -f "$checksums_file" && ! -L "$checksums_file" ]] \
    || fail 'backup checksum manifest must be a non-empty regular file'

expected_checksum_names=(backup-manifest.env config.env mongo.archive.gz source.tar.gz)
if [[ ${manifest[config_test_present]} == 'true' ]]; then
    [[ -s "$config_test_archive" && -f "$config_test_archive" && ! -L "$config_test_archive" ]] \
        || fail 'config/test backup must reference a non-empty regular file'
    expected_checksum_names+=(config-test.tar.gz)
elif [[ -e "$config_test_archive" ]]; then
    fail 'unexpected config/test backup exists'
fi

declare -A backup_checksums=()
while IFS= read -r checksum_line || [[ -n "$checksum_line" ]]; do
    if [[ "$checksum_line" =~ ^([0-9a-f]{64})[[:space:]]\*([A-Za-z0-9._-]+)$ ]]; then
        checksum_value=${BASH_REMATCH[1]}
        checksum_name=${BASH_REMATCH[2]}
    else
        fail 'unsafe or invalid backup checksum reference'
    fi
    [[ -z ${backup_checksums[$checksum_name]+x} ]] \
        || fail 'backup checksum references must be unique'
    backup_checksums[$checksum_name]=$checksum_value
done < "$checksums_file"
[[ ${#backup_checksums[@]} -eq ${#expected_checksum_names[@]} ]] \
    || fail 'backup checksum references do not match required backups'
for checksum_name in "${expected_checksum_names[@]}"; do
    [[ -n ${backup_checksums[$checksum_name]+x} ]] \
        || fail 'backup checksum references do not match required backups'
done

require_file_checksum 'backup manifest' "$manifest_file" "${backup_checksums[backup-manifest.env]}"
require_file_checksum 'config backup' "$config_env" "${backup_checksums[config.env]}"
require_file_checksum 'Mongo backup' "$mongo_archive" "${backup_checksums[mongo.archive.gz]}"
require_file_checksum 'source backup' "$source_archive" "${backup_checksums[source.tar.gz]}"
if [[ ${manifest[config_test_present]} == 'true' ]]; then
    require_file_checksum 'config/test backup' "$config_test_archive" "${backup_checksums[config-test.tar.gz]}"
fi

runtime_root=$(mktemp -d)
lock_dir=''
cleanup() {
    rm -rf -- "$runtime_root"
    [[ -z "$lock_dir" ]] || rmdir -- "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT
staged_source="$runtime_root/source"
staged_config="$runtime_root/config"

untouched_services=(mongo redis caddy updater)
declare -A untouched_container_ids=()
declare -A untouched_restart_counts=()
current_untouched_container_id=''
current_untouched_restart_count=''

read_untouched_service_state() {
    local service=$1
    local container_ref
    local inspected_state
    local inspected_id
    local restart_count
    local unexpected

    if ! container_ref=$("${compose[@]}" ps --status running --quiet "$service" 2>/dev/null); then
        fail "untouched service $service is not running"
    fi
    [[ "$container_ref" =~ ^[0-9a-f]{12,64}$ ]] \
        || fail "untouched service $service must have exactly one running container"
    if ! inspected_state=$(docker inspect \
        --format '{{.Id}} {{.RestartCount}}' \
        "$container_ref" 2>/dev/null); then
        fail "untouched service $service container state is unavailable"
    fi
    [[ "$inspected_state" != *$'\n'* ]] \
        || fail "untouched service $service container state is invalid"
    read -r inspected_id restart_count unexpected <<< "$inspected_state"
    [[ "$inspected_id" =~ ^[0-9a-f]{64}$ \
        && "$restart_count" =~ ^[0-9]+$ \
        && -z "$unexpected" \
        && "$inspected_id" == "$container_ref"* ]] \
        || fail "untouched service $service container state is invalid"
    current_untouched_container_id=$inspected_id
    current_untouched_restart_count=$restart_count
}

capture_untouched_service_states() {
    local service
    for service in "${untouched_services[@]}"; do
        read_untouched_service_state "$service"
        untouched_container_ids[$service]=$current_untouched_container_id
        untouched_restart_counts[$service]=$current_untouched_restart_count
    done
}

verify_untouched_service_states() {
    local service
    for service in "${untouched_services[@]}"; do
        read_untouched_service_state "$service"
        [[ "$current_untouched_container_id" == "${untouched_container_ids[$service]}" ]] \
            || fail "untouched service $service container identity changed"
        [[ "$current_untouched_restart_count" == "${untouched_restart_counts[$service]}" ]] \
            || fail "untouched service $service restart count changed"
    done
}

validator_args=(
    --source-archive "$source_archive"
    --config-env-file "$config_env"
    --extract-source "$staged_source"
    --config-test-present "${manifest[config_test_present]}"
)
if [[ ${manifest[config_test_present]} == 'true' ]]; then
    validator_args+=(
        --config-test-archive "$config_test_archive"
        --extract-config-test "$staged_config"
    )
fi
python3 "$SCRIPT_DIR/validate-rollback-backup.py" "${validator_args[@]}"
install -m 0600 -- "$config_env" "$staged_source/.env"

while IFS= read -r -d '' javascript_file; do
    node --check "$javascript_file" >/dev/null \
        || fail 'restored JavaScript syntax preflight failed'
done < <(find "$staged_source" -type f -name '*.js' -print0 | sort -z)

print_plan() {
    printf '%s\n' \
        'rollback_plan_version=1' \
        "target=$target" \
        "host_identity=$host_identity" \
        "install_root=$install_root" \
        "backup_dir=$backup_dir" \
        "backup_manifest_sha256=$backup_manifest_sha256" \
        "deployed_source_commit=${manifest[deployed_source_commit]}" \
        "deployed_source_tree=${manifest[deployed_source_tree]}" \
        'restore_steps=source,config,mongo' \
        "container_build=$CELERITY_APP_SERVICE" \
        "container_restart=$CELERITY_APP_SERVICE --no-deps" \
        'untouched_services=mongo,redis,caddy,updater' \
        'untouched_verification=container-id,restart-count' \
        'node_mutation=none' \
        "health_template=docker compose --project-directory $install_root --env-file $install_root/.env -f $install_root/$CELERITY_COMPOSE_FILE ps $CELERITY_APP_SERVICE" \
        "health_template=curl --fail --silent --show-error --max-time 10 https://$CELERITY_TEST_HOST/health"
}

if [[ "$mode" == 'plan' ]]; then
    print_plan
    exit 0
fi

install_root_path=$(resolve_control_path "$install_root")
[[ -d "$install_root_path" && ! -L "$install_root_path" ]] \
    || fail "install root must already be the real $CELERITY_INSTALL_ROOT directory"
install_root_path=$(cd -- "$install_root_path" && pwd -P)
expected_install_root_path=$(resolve_control_path "$install_root")
expected_install_parent=$(cd -- "$(dirname -- "$expected_install_root_path")" && pwd -P)
[[ "$install_root_path" == "$expected_install_parent/$(basename -- "$install_root")" ]] \
    || fail 'install root resolved outside the guarded test path'
[[ -f "$install_root_path/$CELERITY_COMPOSE_FILE" && ! -L "$install_root_path/$CELERITY_COMPOSE_FILE" ]] \
    || fail 'installed Compose file must be a regular file'
[[ -f "$install_root_path/.env" && ! -L "$install_root_path/.env" ]] \
    || fail 'installed .env must be a regular file'
command -v rsync >/dev/null 2>&1 || fail 'rsync is required for exact source replacement'
command -v git >/dev/null 2>&1 || fail 'Git is required to validate rollback provenance'

validate_retained_baseline_identity() {
    local git_root
    local current_commit
    local current_tree

    require_safe_git_head_metadata "$install_root_path" 'install'
    if ! git_root=$(git -C "$install_root_path" rev-parse --show-toplevel 2>/dev/null); then
        fail 'install root must retain the recorded baseline Git worktree'
    fi
    [[ -d "$git_root" && ! -L "$git_root" ]] \
        || fail 'install Git root must be a real directory'
    git_root=$(cd -- "$git_root" && pwd -P)
    [[ "$git_root" == "$install_root_path" ]] \
        || fail 'install Git root must match the install root'
    if ! current_commit=$(git -C "$install_root_path" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) \
        || ! current_tree=$(git -C "$install_root_path" rev-parse --verify 'HEAD^{tree}' 2>/dev/null); then
        fail 'install Git identity is unavailable'
    fi
    [[ "$current_commit" == "${manifest[deployed_source_commit]}" \
        && "$current_tree" == "${manifest[deployed_source_tree]}" ]] \
        || fail 'install Git identity does not match the recorded baseline'
}

verify_restored_baseline_provenance() {
    local current_commit
    local current_tree
    local status_file="$runtime_root/restored-git-status"
    local status_entry
    local status_code
    local status_path

    if ! current_commit=$(git -C "$install_root_path" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) \
        || ! current_tree=$(git -C "$install_root_path" rev-parse --verify 'HEAD^{tree}' 2>/dev/null); then
        fail 'restored Git identity is unavailable'
    fi
    [[ "$current_commit" == "${manifest[deployed_source_commit]}" \
        && "$current_tree" == "${manifest[deployed_source_tree]}" ]] \
        || fail 'restored Git identity does not match the recorded baseline'
    if ! git -C "$install_root_path" status \
        --porcelain=v1 \
        -z \
        --untracked-files=all > "$status_file" 2>/dev/null; then
        fail 'restored Git status is unavailable'
    fi
    while IFS= read -r -d '' status_entry; do
        status_code=${status_entry:0:2}
        status_path=${status_entry:3}
        if [[ "$status_code" == '??' \
            && ( "$status_path" == '.env' \
                || "$status_path" == config/test/* \
                || "$status_path" == node_modules/* \
                || "$status_path" == data/* \
                || "$status_path" == logs/* \
                || "$status_path" == backups/* \
                || "$status_path" == greenlock.d/* ) ]]; then
            continue
        fi
        fail 'restored source does not exactly match the recorded baseline'
    done < "$status_file"
    rm -f -- "$status_file"
}

validate_retained_baseline_identity

compose=(
    docker compose
    --project-directory "$install_root_path"
    --env-file "$install_root_path/.env"
    -f "$install_root_path/$CELERITY_COMPOSE_FILE"
)

staged_compose=(
    docker compose
    --project-directory "$staged_source"
    --env-file "$config_env"
    -f "$staged_source/$CELERITY_COMPOSE_FILE"
)
"${staged_compose[@]}" config --quiet >/dev/null 2>&1 \
    || fail 'backup Compose preflight failed'

lock_dir="$backup_root_path/.deploy-lock"
mkdir -- "$lock_dir" 2>/dev/null || fail 'another staging control operation is active'
capture_untouched_service_states

rsync \
    --archive \
    --delete \
    --exclude='.git/' \
    --exclude='.env' \
    --exclude='config/test/' \
    --exclude='node_modules/' \
    --exclude='data/' \
    --exclude='logs/' \
    --exclude='backups/' \
    --exclude='greenlock.d/' \
    "$staged_source/" "$install_root_path/"
install -m 0600 -- "$config_env" "$install_root_path/.env"
rm -rf -- "$install_root_path/config/test"
if [[ ${manifest[config_test_present]} == 'true' ]]; then
    mkdir -p -m 0700 -- "$install_root_path/config/test"
    rsync --archive --delete "$staged_config/test/" "$install_root_path/config/test/"
fi
verify_restored_baseline_provenance

if ! BACKUP_DIR="$backup_dir_path" \
    MONGO_RESTORE_INPUT="$mongo_archive" \
    INSTALL_ROOT="$install_root_path" \
    COMPOSE_FILE="$CELERITY_COMPOSE_FILE" \
    APP_SERVICE="$CELERITY_APP_SERVICE" \
    "$mongo_restore_hook" >/dev/null 2>&1; then
    fail 'Mongo restore hook failed after source and config restore'
fi

"${compose[@]}" config --quiet >/dev/null 2>&1 \
    || fail 'restored Compose validation failed'
"${compose[@]}" build "$CELERITY_APP_SERVICE"
"${compose[@]}" up -d --no-deps "$CELERITY_APP_SERVICE"
running_services=$("${compose[@]}" ps --status running --services "$CELERITY_APP_SERVICE" 2>/dev/null) \
    || fail 'backend health validation failed'
[[ "$running_services" == "$CELERITY_APP_SERVICE" ]] \
    || fail 'backend is not reported running after rollback'
if ! wait_for_public_https_health; then
    fail 'public HTTPS health validation failed'
fi
verify_untouched_service_states

printf '%s\n' \
    'rollback ok' \
    "backup_dir=$backup_dir" \
    "backup_manifest_sha256=$backup_manifest_sha256"
