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

backup_id="$operation_id-${expected_source_commit:0:12}"
backup_dir="$backup_root/$backup_id"
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
        "backup_dir=$backup_dir" \
        "source_commit=$expected_source_commit" \
        "source_tree=$expected_source_tree" \
        "source_bundle_sha256=$source_bundle_sha256" \
        "module_artifact_sha256=$module_artifact_sha256" \
        'backup_steps=source,config,mongo' \
        'preflight_steps=bundle,module,config,compose,js-syntax' \
        'apply_steps=source,config' \
        "config_destinations=$destinations" \
        "container_build=$CELERITY_APP_SERVICE" \
        "container_restart=$CELERITY_APP_SERVICE --no-deps" \
        'node_mutation=none' \
        "health_template=docker compose --project-directory $install_root --env-file $install_root/.env -f $install_root/$CELERITY_COMPOSE_FILE ps $CELERITY_APP_SERVICE" \
        "health_template=curl --fail --silent --show-error --max-time 10 https://$CELERITY_TEST_HOST/health"
}

if [[ "$mode" == 'plan' ]]; then
    print_plan
    exit 0
fi

[[ -d "$install_root" && ! -L "$install_root" ]] \
    || fail "install root must already be the real $CELERITY_INSTALL_ROOT directory"
[[ -f "$install_root/$CELERITY_COMPOSE_FILE" && ! -L "$install_root/$CELERITY_COMPOSE_FILE" ]] \
    || fail 'installed Compose file must be a regular file'
[[ -f "$install_root/.env" && ! -L "$install_root/.env" ]] \
    || fail 'installed .env must be a regular file'
command -v rsync >/dev/null 2>&1 || fail 'rsync is required for exact source replacement'

runtime_root=$(mktemp -d)
lock_dir=''
cleanup() {
    rm -rf -- "$runtime_root"
    [[ -z "$lock_dir" ]] || rmdir -- "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT
staged_source="$runtime_root/source"
python3 "$SCRIPT_DIR/validate-staging-inputs.py" \
    --source-bundle "$source_bundle" \
    --module-artifact "$module_artifact" \
    --config-env-file "$config_env_file" \
    --expected-source-commit "$expected_source_commit" \
    --expected-source-tree "$expected_source_tree" \
    --extract-source "$staged_source"

while IFS= read -r -d '' javascript_file; do
    node --check "$javascript_file" >/dev/null \
        || fail 'JavaScript syntax preflight failed'
done < <(find "$staged_source" -type f -name '*.js' -print0 | sort -z)

staged_compose=(
    docker compose
    --project-directory "$staged_source"
    --env-file "$config_env_file"
    -f "$staged_source/$CELERITY_COMPOSE_FILE"
)
"${staged_compose[@]}" config --quiet >/dev/null 2>&1 \
    || fail 'staged Compose preflight failed'

mkdir -p -m 0700 -- "$backup_root"
[[ -d "$backup_root" && ! -L "$backup_root" ]] || fail 'backup root must not be a symlink'
lock_dir="$backup_root/.deploy-lock"
mkdir -- "$lock_dir" 2>/dev/null || fail 'another staging control operation is active'
[[ ! -e "$backup_dir" ]] || fail 'timestamped backup destination already exists'
mkdir -m 0700 -- "$backup_dir"
printf 'incomplete\n' > "$backup_dir/STATE"

source_archive="$backup_dir/source.tar.gz"
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
    -C "$install_root" \
    -czf "$source_archive" \
    .
install -m 0600 -- "$install_root/.env" "$backup_dir/config.env"
config_test_present='false'
if [[ -d "$install_root/config/test" && ! -L "$install_root/config/test" ]]; then
    config_test_present='true'
    tar \
        --sort=name \
        --format=posix \
        --mtime=@0 \
        --owner=0 \
        --group=0 \
        --numeric-owner \
        -C "$install_root/config" \
        -czf "$backup_dir/config-test.tar.gz" \
        test
elif [[ -e "$install_root/config/test" ]]; then
    fail 'installed config/test must be a real directory when present'
fi

mongo_dump_output="$backup_dir/mongo.archive.gz"
if ! BACKUP_DIR="$backup_dir" \
    MONGO_DUMP_OUTPUT="$mongo_dump_output" \
    INSTALL_ROOT="$install_root" \
    COMPOSE_FILE="$CELERITY_COMPOSE_FILE" \
    APP_SERVICE="$CELERITY_APP_SERVICE" \
    "$mongo_dump_hook" >/dev/null 2>&1; then
    fail 'Mongo dump hook failed before source replacement'
fi
[[ -s "$mongo_dump_output" && -f "$mongo_dump_output" && ! -L "$mongo_dump_output" ]] \
    || fail 'Mongo dump hook did not create a non-empty regular archive'
chmod 0600 "$mongo_dump_output"

cat > "$backup_dir/backup-manifest.env" <<EOF
schema_version=1
target=$target
host_identity=$host_identity
install_root=$install_root
backup_root=$backup_root
backup_id=$backup_id
operation_id=$operation_id
compose_file=$CELERITY_COMPOSE_FILE
app_service=$CELERITY_APP_SERVICE
deployed_source_commit=$expected_source_commit
deployed_source_tree=$expected_source_tree
config_test_present=$config_test_present
EOF
(
    cd -- "$backup_dir"
    checksum_files=(backup-manifest.env config.env mongo.archive.gz source.tar.gz)
    [[ "$config_test_present" == 'false' ]] || checksum_files+=(config-test.tar.gz)
    sha256sum --binary -- "${checksum_files[@]}" > SHA256SUMS
)
printf 'complete\n' > "$backup_dir/STATE"

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
    "$staged_source/" "$install_root/"
install -m 0600 -- "$config_env_file" "$install_root/.env"
rm -rf -- "$install_root/config/test"
if ((${#config_file_refs[@]})); then
    mkdir -p -m 0700 -- "$install_root/config/test"
fi
for config_ref in "${config_file_refs[@]}"; do
    destination=${config_ref%%=*}
    local_file=${config_ref#*=}
    destination_path="$install_root/$destination"
    mkdir -p -m 0700 -- "$(dirname -- "$destination_path")"
    install -m 0600 -- "$local_file" "$destination_path"
done
cat > "$install_root/.celerity-staging-source.env" <<EOF
source_commit=$expected_source_commit
source_tree=$expected_source_tree
source_bundle_sha256=$source_bundle_sha256
module_artifact_sha256=$module_artifact_sha256
target=test
host_identity=$CELERITY_TEST_HOST
EOF
chmod 0644 "$install_root/.celerity-staging-source.env"

compose=(
    docker compose
    --project-directory "$install_root"
    --env-file "$install_root/.env"
    -f "$install_root/$CELERITY_COMPOSE_FILE"
)
"${compose[@]}" config --quiet >/dev/null 2>&1 \
    || fail 'installed Compose validation failed'
"${compose[@]}" build "$CELERITY_APP_SERVICE"
"${compose[@]}" up -d --no-deps "$CELERITY_APP_SERVICE"
running_services=$("${compose[@]}" ps --status running --services "$CELERITY_APP_SERVICE" 2>/dev/null) \
    || fail 'backend health validation failed'
[[ "$running_services" == "$CELERITY_APP_SERVICE" ]] \
    || fail 'backend is not reported running after deploy'

printf '%s\n' \
    'deploy ok' \
    "backup_dir=$backup_dir" \
    "backup_manifest_sha256=$(sha256_file "$backup_dir/backup-manifest.env")"
