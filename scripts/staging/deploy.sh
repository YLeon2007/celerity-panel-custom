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
operation_id=''
mongo_dump_hook=''
plan_only=''
execute=''
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
        --operation-id) operation_id=$2 ;;
        --mongo-dump-hook) mongo_dump_hook=$2 ;;
        --plan-only) plan_only=$2 ;;
        --execute) execute=$2 ;;
        *) fail "unknown argument: $1" ;;
    esac
    shift 2
done

require_test_target "$target"
require_test_host_identity "$host_identity"
require_control_paths "$install_root" "$backup_root"
[[ "$operation_id" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    || fail 'operation id must use UTC YYYYMMDDTHHMMSSZ format'
[[ -x "$mongo_dump_hook" && -f "$mongo_dump_hook" && ! -L "$mongo_dump_hook" ]] \
    || fail 'Mongo dump hook must be a local executable regular file'
if [[ "$plan_only" == 'true' && -z "$execute" ]]; then
    mode='plan'
elif [[ "$execute" == 'true' && -z "$plan_only" ]]; then
    mode='execute'
else
    fail 'choose exactly one of --plan-only true or --execute true'
fi

precheck_args=(
    --target "$target"
    --host-identity "$host_identity"
    --install-root "$install_root"
    --backup-root "$backup_root"
    --source-bundle "$source_bundle"
    --source-bundle-sha256 "$source_bundle_sha256"
    --expected-source-commit "$expected_source_commit"
    --expected-source-tree "$expected_source_tree"
    --module-artifact "$module_artifact"
    --module-artifact-sha256 "$module_artifact_sha256"
    --config-env-file "$config_env_file"
)
for config_ref in "${config_file_refs[@]}"; do
    precheck_args+=(--config-file-ref "$config_ref")
done
"$SCRIPT_DIR/precheck.sh" "${precheck_args[@]}" >/dev/null

declare -a config_destinations=()
for config_ref in "${config_file_refs[@]}"; do
    config_destinations+=("${config_ref%%=*}")
done

print_plan() {
    local destinations='none'
    if ((${#config_destinations[@]})); then
        destinations=$(IFS=,; printf '%s' "${config_destinations[*]}")
    fi
    printf '%s\n' \
        'deploy_plan_version=1' \
        "target=$target" \
        "host_identity=$host_identity" \
        "install_root=$install_root" \
        "backup_dir=$backup_root/$operation_id-<predeploy-commit-prefix>" \
        'backup_id_source=predeploy-git-head' \
        "candidate_source_commit=$expected_source_commit" \
        "candidate_source_tree=$expected_source_tree" \
        "source_bundle_sha256=$source_bundle_sha256" \
        "module_artifact_sha256=$module_artifact_sha256" \
        'backup_steps=source,config,mongo' \
        'preflight_steps=bundle,module,config,compose,js-syntax' \
        'apply_steps=source,config' \
        "config_destinations=$destinations" \
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
backup_root_path=$(resolve_control_path "$backup_root")
command -v rsync >/dev/null 2>&1 || fail 'rsync is required for exact source replacement'
command -v git >/dev/null 2>&1 || fail 'Git is required to identify the predeploy source'

runtime_root=$(mktemp -d)
lock_dir=''
compose_env=''
cleanup() {
    secure_remove_file "$compose_env"
    rm -rf -- "$runtime_root"
    [[ -z "$lock_dir" ]] || rmdir -- "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT
staged_source="$runtime_root/source"

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

capture_predeploy_source_identity() {
    local git_root

    require_safe_git_head_metadata "$install_root_path" 'installed source'
    if ! git_root=$(git -C "$install_root_path" rev-parse --show-toplevel 2>/dev/null); then
        fail 'installed source must be a Git worktree'
    fi
    [[ -d "$git_root" && ! -L "$git_root" ]] \
        || fail 'installed source Git root must be a real directory'
    git_root=$(cd -- "$git_root" && pwd -P)
    [[ "$git_root" == "$install_root_path" ]] \
        || fail 'installed source Git root must match the install root'
    if ! deployed_source_commit=$(git -C "$install_root_path" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) \
        || ! deployed_source_tree=$(git -C "$install_root_path" rev-parse --verify 'HEAD^{tree}' 2>/dev/null); then
        fail 'installed source Git identity is unavailable'
    fi
    require_git_oid 'installed source commit' "$deployed_source_commit"
    require_git_oid 'installed source tree' "$deployed_source_tree"
    require_clean_predeploy_source 'installed source must be clean before backup'
}

require_clean_predeploy_source() {
    local refusal_message=$1
    local status_file="$runtime_root/predeploy-git-status"
    local status_entry
    local status_code
    local status_path

    if ! git -C "$install_root_path" status \
        --porcelain=v1 \
        -z \
        --untracked-files=all > "$status_file" 2>/dev/null; then
        fail 'installed source Git status is unavailable'
    fi
    while IFS= read -r -d '' status_entry; do
        status_code=${status_entry:0:2}
        status_path=${status_entry:3}
        if [[ "$status_code" == '??' \
            && ( "$status_path" == '.celerity-staging-source.env' \
                || "$status_path" == config/test/* ) ]]; then
            continue
        fi
        fail "$refusal_message"
    done < "$status_file"
    rm -f -- "$status_file"
}

verify_predeploy_source_identity() {
    local current_commit
    local current_tree

    if ! current_commit=$(git -C "$install_root_path" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) \
        || ! current_tree=$(git -C "$install_root_path" rev-parse --verify 'HEAD^{tree}' 2>/dev/null); then
        fail 'installed source Git identity changed during backup'
    fi
    [[ "$current_commit" == "$deployed_source_commit" \
        && "$current_tree" == "$deployed_source_tree" ]] \
        || fail 'installed source Git identity changed during backup'
    require_clean_predeploy_source 'installed source changed during backup'
}

python3 "$SCRIPT_DIR/validate-staging-inputs.py" \
    --source-bundle "$source_bundle" \
    --module-artifact "$module_artifact" \
    --config-env-file "$config_env_file" \
    --expected-source-commit "$expected_source_commit" \
    --expected-source-tree "$expected_source_tree" \
    --extract-source "$staged_source"
compose_env="$staged_source/.env"
create_compose_env "$install_root_path/.env" "$config_env_file" "$compose_env"

while IFS= read -r -d '' javascript_file; do
    node --check "$javascript_file" >/dev/null \
        || fail 'JavaScript syntax preflight failed'
done < <(find "$staged_source" -type f -name '*.js' -print0 | sort -z)

staged_compose=(
    docker compose
    --project-directory "$staged_source"
    --env-file "$compose_env"
    -f "$staged_source/$CELERITY_COMPOSE_FILE"
)
"${staged_compose[@]}" config --quiet >/dev/null 2>&1 \
    || fail 'staged Compose preflight failed'

mkdir -p -m 0700 -- "$backup_root_path"
[[ -d "$backup_root_path" && ! -L "$backup_root_path" ]] || fail 'backup root must not be a symlink'
backup_root_path=$(cd -- "$backup_root_path" && pwd -P)
lock_dir="$backup_root_path/.deploy-lock"
mkdir -- "$lock_dir" 2>/dev/null || fail 'another staging control operation is active'
capture_predeploy_source_identity
backup_id="$operation_id-${deployed_source_commit:0:12}"
backup_dir="$backup_root/$backup_id"
backup_dir_path="$backup_root_path/$backup_id"
[[ ! -e "$backup_dir_path" ]] || fail 'timestamped backup destination already exists'
mkdir -m 0700 -- "$backup_dir_path"
printf 'incomplete\n' > "$backup_dir_path/STATE"

source_archive="$backup_dir_path/source.tar.gz"
tar \
    --sort=name \
    --format=posix \
    --mtime=@0 \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --exclude='./.git' \
    --exclude='./.env' \
    --exclude='./config/test' \
    --exclude='./node_modules' \
    --exclude='./data' \
    --exclude='./logs' \
    --exclude='./backups' \
    --exclude='./greenlock.d' \
    -C "$install_root_path" \
    -czf "$source_archive" \
    .
install -m 0600 -- "$install_root_path/.env" "$backup_dir_path/config.env"
config_test_present='false'
if [[ -d "$install_root_path/config/test" && ! -L "$install_root_path/config/test" ]]; then
    config_test_present='true'
    tar \
        --sort=name \
        --format=posix \
        --mtime=@0 \
        --owner=0 \
        --group=0 \
        --numeric-owner \
        -C "$install_root_path/config" \
        -czf "$backup_dir_path/config-test.tar.gz" \
        test
elif [[ -e "$install_root_path/config/test" ]]; then
    fail 'installed config/test must be a real directory when present'
fi

mongo_dump_output="$backup_dir_path/mongo.archive.gz"
if ! BACKUP_DIR="$backup_dir_path" \
    MONGO_DUMP_OUTPUT="$mongo_dump_output" \
    INSTALL_ROOT="$install_root_path" \
    COMPOSE_FILE="$CELERITY_COMPOSE_FILE" \
    APP_SERVICE="$CELERITY_APP_SERVICE" \
    "$mongo_dump_hook" >/dev/null 2>&1; then
    fail 'Mongo dump hook failed before source replacement'
fi
[[ -s "$mongo_dump_output" && -f "$mongo_dump_output" && ! -L "$mongo_dump_output" ]] \
    || fail 'Mongo dump hook did not create a non-empty regular archive'
chmod 0600 "$mongo_dump_output"
verify_predeploy_source_identity

cat > "$backup_dir_path/backup-manifest.env" <<EOF
schema_version=1
target=$target
host_identity=$host_identity
install_root=$install_root
backup_root=$backup_root
backup_id=$backup_id
operation_id=$operation_id
compose_file=$CELERITY_COMPOSE_FILE
app_service=$CELERITY_APP_SERVICE
deployed_source_commit=$deployed_source_commit
deployed_source_tree=$deployed_source_tree
config_test_present=$config_test_present
EOF
(
    cd -- "$backup_dir_path"
    checksum_files=(backup-manifest.env config.env mongo.archive.gz source.tar.gz)
    [[ "$config_test_present" == 'false' ]] || checksum_files+=(config-test.tar.gz)
    sha256sum --binary -- "${checksum_files[@]}" > SHA256SUMS
)
printf 'complete\n' > "$backup_dir_path/STATE"

compose=(
    docker compose
    --project-directory "$install_root_path"
    --env-file "$compose_env"
    -f "$install_root_path/$CELERITY_COMPOSE_FILE"
)
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
install -m 0600 -- "$compose_env" "$install_root_path/.env"
rm -rf -- "$install_root_path/config/test"
if ((${#config_file_refs[@]})); then
    mkdir -p -m 0700 -- "$install_root_path/config/test"
fi
for config_ref in "${config_file_refs[@]}"; do
    destination=${config_ref%%=*}
    local_file=${config_ref#*=}
    destination_path="$install_root_path/$destination"
    mkdir -p -m 0700 -- "$(dirname -- "$destination_path")"
    install -m 0600 -- "$local_file" "$destination_path"
done
cat > "$install_root_path/.celerity-staging-source.env" <<EOF
candidate_source_commit=$expected_source_commit
candidate_source_tree=$expected_source_tree
candidate_source_bundle_sha256=$source_bundle_sha256
candidate_module_artifact_sha256=$module_artifact_sha256
target=test
host_identity=$CELERITY_TEST_HOST
EOF
chmod 0644 "$install_root_path/.celerity-staging-source.env"

"${compose[@]}" config --quiet >/dev/null 2>&1 \
    || fail 'installed Compose validation failed'
"${compose[@]}" build "$CELERITY_APP_SERVICE"
"${compose[@]}" up -d --no-deps "$CELERITY_APP_SERVICE"
running_services=$("${compose[@]}" ps --status running --services "$CELERITY_APP_SERVICE" 2>/dev/null) \
    || fail 'backend health validation failed'
[[ "$running_services" == "$CELERITY_APP_SERVICE" ]] \
    || fail 'backend is not reported running after deploy'
if ! wait_for_public_https_health; then
    fail 'public HTTPS health validation failed'
fi
verify_untouched_service_states

printf '%s\n' \
    'deploy ok' \
    "backup_dir=$backup_dir" \
    "backup_manifest_sha256=$(sha256_file "$backup_dir_path/backup-manifest.env")"
