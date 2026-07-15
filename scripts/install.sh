#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# C³ CELERITY custom one-command installer
# Default target: public repo YLeon2007/celerity-panel-custom.
#
# Production install:
#   curl -fsSL https://raw.githubusercontent.com/YLeon2007/celerity-panel-custom/main/scripts/install.sh | sudo -E bash
#
# Develop branch test:
#   export BRANCH=develop
#   curl -fsSL https://raw.githubusercontent.com/YLeon2007/celerity-panel-custom/develop/scripts/install.sh | sudo -E bash
#
# Optional non-interactive mode:
#   PANEL_DOMAIN=panel.example.com ACME_EMAIL=admin@example.com bash scripts/install.sh
#
# Private fork only: set GITHUB_TOKEN with read access before running.

REPO="${REPO:-YLeon2007/celerity-panel-custom}"
REPO_URL=""
BRANCH="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/hysteria-panel}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/hysteria-panel-install-backups}"
INSTALL_USER="${INSTALL_USER:-${SUDO_USER:-root}}"
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
ACME_EMAIL="${ACME_EMAIL:-}"
MONGO_USER="${MONGO_USER:-hysteria}"
LOG_LEVEL="${LOG_LEVEL:-info}"
SYNC_INTERVAL="${SYNC_INTERVAL:-2}"
PANEL_IP_WHITELIST="${PANEL_IP_WHITELIST:-}"
FORCE="${FORCE:-0}"
NO_START="${NO_START:-0}"
START_TIMEOUT="${START_TIMEOUT:-240}"
SKIP_HTTPS_CHECK="${SKIP_HTTPS_CHECK:-0}"
HEALTHCHECK_URL="${HEALTHCHECK_URL:-}"

log() { printf '\033[1;34m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fail "Run as root, e.g. curl ... | sudo -E bash"
  fi
}

random_hex() {
  local bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
  else
    # `head` closes the pipe early; temporarily disable pipefail so the normal
    # SIGPIPE from `tr` is not treated as a generation failure.
    set +o pipefail
    tr -dc 'a-f0-9' </dev/urandom | head -c "$((bytes * 2))"
    local rc=$?
    set -o pipefail
    return "$rc"
  fi
}

install_docker_if_needed() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    log "Docker and docker compose are already installed"
    return
  fi
  log "Installing Docker using get.docker.com"
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update
    apt-get install -y curl ca-certificates git openssl
  fi
  curl -fsSL https://get.docker.com | sh
  docker compose version >/dev/null 2>&1 || fail "docker compose is not available after Docker install"
}

install_base_tools() {
  local missing="" cmd
  for cmd in git curl openssl tar awk grep realpath; do
    command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
  done
  if [ -n "$missing" ]; then
    log "Installing base tools:$missing"
    apt-get update
    apt-get install -y git curl openssl tar gawk grep coreutils ca-certificates
  fi
}

prompt_for_missing_inputs() {
  # An existing installation owns its effective domain/email. Reuse them when
  # callers do not explicitly provide values; write_env_safely will preserve all
  # existing non-empty values even when FORCE=1.
  if [ -f "$INSTALL_DIR/.env" ]; then
    if [ -z "$PANEL_DOMAIN" ]; then
      PANEL_DOMAIN="$(awk -F= '/^PANEL_DOMAIN=/{v=substr($0,index($0,"=")+1)} END{print v}' "$INSTALL_DIR/.env")"
    fi
    if [ -z "$ACME_EMAIL" ]; then
      ACME_EMAIL="$(awk -F= '/^ACME_EMAIL=/{v=substr($0,index($0,"=")+1)} END{print v}' "$INSTALL_DIR/.env")"
    fi
  fi

  if [ -n "$PANEL_DOMAIN" ] && [ -n "$ACME_EMAIL" ]; then
    return
  fi

  if [ ! -r /dev/tty ]; then
    fail "Interactive input is unavailable. Set PANEL_DOMAIN and ACME_EMAIL environment variables."
  fi

  if [ -z "$PANEL_DOMAIN" ]; then
    printf '\nУкажите домен для панели / Enter panel domain: ' >/dev/tty
    IFS= read -r PANEL_DOMAIN </dev/tty
    PANEL_DOMAIN="${PANEL_DOMAIN#http://}"
    PANEL_DOMAIN="${PANEL_DOMAIN#https://}"
    PANEL_DOMAIN="${PANEL_DOMAIN%%/*}"
  fi

  if [ -z "$ACME_EMAIL" ]; then
    printf "Укажите email администратора домена для получения сертификата Let's Encrypt / Enter domain administrator email for Let's Encrypt certificate: " >/dev/tty
    IFS= read -r ACME_EMAIL </dev/tty
  fi
}

valid_hostname() {
  local name="$1" label
  [ "${#name}" -le 253 ] || return 1
  case "$name" in
    ''|.*|*.|*..*|*[!A-Za-z0-9.-]*) return 1 ;;
  esac
  local IFS='.'
  read -r -a labels <<<"$name"
  for label in "${labels[@]}"; do
    [ -n "$label" ] && [ "${#label}" -le 63 ] || return 1
    case "$label" in
      -*|*-|*[!A-Za-z0-9-]*) return 1 ;;
    esac
  done
}

validate_inputs() {
  prompt_for_missing_inputs

  [ -n "$PANEL_DOMAIN" ] || fail "PANEL_DOMAIN is required, e.g. PANEL_DOMAIN=panel.example.com"
  [ -n "$ACME_EMAIL" ] || fail "ACME_EMAIL is required, e.g. ACME_EMAIL=admin@example.com"
  valid_hostname "$PANEL_DOMAIN" || fail "PANEL_DOMAIN must be a valid hostname without scheme/path"
  printf '%s' "$ACME_EMAIL" | grep -Eq '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$' \
    || fail "ACME_EMAIL must look like an email address, e.g. admin@example.com"

  case "$INSTALL_DIR" in
    /*) ;;
    *) fail "INSTALL_DIR must be an absolute path" ;;
  esac
  case "$INSTALL_DIR" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
      fail "Refusing unsafe INSTALL_DIR: $INSTALL_DIR" ;;
    /tmp/*|/var/tmp/*|/run/*|/dev/shm/*)
      fail "Refusing INSTALL_DIR below a world-writable or runtime directory: $INSTALL_DIR" ;;
  esac
  [ ! -L "$INSTALL_DIR" ] || fail "INSTALL_DIR must not be a symlink: $INSTALL_DIR"
  [ "$(realpath -m -- "$INSTALL_DIR")" = "$INSTALL_DIR" ] \
    || fail "INSTALL_DIR must be normalized and must not traverse symlink parents"
  case "$BACKUP_ROOT" in
    /*) ;;
    *) fail "BACKUP_ROOT must be an absolute path" ;;
  esac
  case "$BACKUP_ROOT" in
    /|/tmp|/tmp/*|/var/tmp|/var/tmp/*|/run|/run/*|/dev/shm|/dev/shm/*)
      fail "Refusing unsafe BACKUP_ROOT: $BACKUP_ROOT" ;;
  esac
  [ ! -L "$BACKUP_ROOT" ] || fail "BACKUP_ROOT must not be a symlink: $BACKUP_ROOT"
  [ "$(realpath -m -- "$BACKUP_ROOT")" = "$BACKUP_ROOT" ] \
    || fail "BACKUP_ROOT must be normalized and must not traverse symlink parents"
  case "$COMPOSE_FILE" in
    ''|/*|*'..'*) fail "COMPOSE_FILE must be a relative filename inside INSTALL_DIR" ;;
  esac
  printf '%s' "$COMPOSE_FILE" | grep -Eq '^[A-Za-z0-9._/-]+$' || fail "Invalid COMPOSE_FILE"
  case "$FORCE:$NO_START:$SKIP_HTTPS_CHECK" in
    [01]:[01]:[01]) ;;
    *) fail "FORCE, NO_START and SKIP_HTTPS_CHECK must be 0 or 1" ;;
  esac
  case "$START_TIMEOUT" in
    ''|*[!0-9]*) fail "START_TIMEOUT must be an integer number of seconds" ;;
  esac
  [ "$START_TIMEOUT" -ge 30 ] || fail "START_TIMEOUT must be at least 30 seconds"
  printf '%s' "$MONGO_USER" | grep -Eq '^[A-Za-z0-9_.-]+$' || fail "Invalid MONGO_USER"
  printf '%s' "$LOG_LEVEL" | grep -Eq '^[A-Za-z]+$' || fail "Invalid LOG_LEVEL"
  printf '%s' "$SYNC_INTERVAL" | grep -Eq '^[0-9]+$' || fail "Invalid SYNC_INTERVAL"
  case "$PANEL_IP_WHITELIST" in *$'\n'*|*$'\r'*) fail "Invalid PANEL_IP_WHITELIST" ;; esac

  local secret_name secret_value min_len
  for secret_name in ENCRYPTION_KEY SESSION_SECRET MONGO_PASSWORD UPDATER_SECRET; do
    secret_value="${!secret_name:-}"
    [ -z "$secret_value" ] || case "$secret_value" in *$'\n'*|*$'\r'*) fail "$secret_name must be one line" ;; esac
    case "$secret_name" in
      MONGO_PASSWORD) min_len=16 ;;
      *) min_len=32 ;;
    esac
    [ -z "$secret_value" ] || [ "${#secret_value}" -ge "$min_len" ] \
      || fail "$secret_name must be at least $min_len characters when provided"
    [ -z "$secret_value" ] || printf '%s' "$secret_value" | grep -Eq '^[A-Za-z0-9._~%+/=-]+$' \
      || fail "$secret_name contains characters unsafe for an unquoted .env value"
  done

  printf '%s' "$REPO" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' || fail "Invalid REPO owner/name"
  git check-ref-format --branch "$BRANCH" >/dev/null 2>&1 || fail "Invalid BRANCH/ref"
  REPO_URL="https://github.com/$REPO.git"
  export REPO_URL
  case "${GITHUB_TOKEN:-}" in *[[:space:]]*) fail "GITHUB_TOKEN must not contain whitespace" ;; esac

  id "$INSTALL_USER" >/dev/null 2>&1 || fail "INSTALL_USER does not exist: $INSTALL_USER"
  INSTALL_GROUP="$(id -gn "$INSTALL_USER")"
  export INSTALL_GROUP
}

make_backup_if_existing() {
  if [ ! -e "$INSTALL_DIR" ]; then
    return
  fi

  install -d -m 700 "$BACKUP_ROOT"
  local ts backup
  ts="$(date +%Y%m%d-%H%M%S)"
  backup="$(mktemp "$BACKUP_ROOT/hysteria-panel-$ts.XXXXXX.tar.gz")"
  log "Existing $INSTALL_DIR found; creating backup: $backup"
  tar \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='logs/*.log' \
    --exclude='backups/*' \
    -czf "$backup" -C "$(dirname "$INSTALL_DIR")" "$(basename "$INSTALL_DIR")"
  chmod 600 "$backup"

  if [ -d "$INSTALL_DIR/.git" ]; then
    local sha
    sha="$(git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null || true)"
    [ -z "$sha" ] || printf '%s\n' "$sha" >"$backup.git-sha"
  fi

  if [ "$FORCE" != "1" ]; then
    fail "Backup created. Re-run with FORCE=1 only for an intentional repair/update. Backup: $backup"
  fi
}

clone_or_update_repo() {
  mkdir -p "$(dirname "$INSTALL_DIR")"

  if [ -d "$INSTALL_DIR/.git" ]; then
    log "Updating existing git checkout in $INSTALL_DIR"
    if [ -n "$(git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" status --porcelain=v1)" ]; then
      fail "Existing checkout has local changes. Backup was created; clean or commit them before FORCE=1."
    fi
    git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
    run_git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" fetch origin \
      "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH"
    if git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" show-ref --verify --quiet "refs/heads/$BRANCH"; then
      git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" checkout "$BRANCH"
      git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" merge --ff-only "refs/remotes/origin/$BRANCH"
    else
      git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" checkout --track -b "$BRANCH" "refs/remotes/origin/$BRANCH"
    fi
  else
    if [ -e "$INSTALL_DIR" ]; then
      rm -rf -- "$INSTALL_DIR"
    fi

    log "Cloning $REPO_URL ref $BRANCH into $INSTALL_DIR"
    run_git clone --branch "$BRANCH" --single-branch "$REPO_URL" "$INSTALL_DIR"
  fi

  # Never persist a token in the checkout remote URL.
  git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
  chown -R "$INSTALL_USER:$INSTALL_GROUP" "$INSTALL_DIR"
  unset GITHUB_TOKEN || true
}

run_git() {
  if [ -z "${GITHUB_TOKEN:-}" ]; then
    git "$@"
    return
  fi

  (
    local tmp_base tmp_home
    tmp_base="${TMPDIR:-/tmp}"
    if [ "$(id -u)" -eq 0 ] && [ -d /run ]; then
      tmp_base=/run
    fi
    tmp_home="$(mktemp -d "$tmp_base/celerity-installer-git.XXXXXX")"
    chmod 700 "$tmp_home"
    trap 'rm -rf -- "$tmp_home"' EXIT HUP INT TERM
    cat >"$tmp_home/.netrc" <<EOF_NETRC
machine github.com
  login x-access-token
  password $GITHUB_TOKEN
EOF_NETRC
    chmod 600 "$tmp_home/.netrc"
    env -u GITHUB_TOKEN HOME="$tmp_home" git "$@"
  )
}

env_value() {
  local key="$1"
  awk -v key="$key" 'index($0, key "=") == 1 { value=substr($0, length(key)+2) } END { print value }' .env
}

ensure_env_value() {
  local key="$1" value="$2" current tmp
  current="$(env_value "$key")"
  if [ -n "$current" ]; then
    return
  fi

  if grep -q "^${key}=" .env; then
    tmp="$(mktemp "$INSTALL_DIR/.env.tmp.XXXXXX")"
    awk -v key="$key" -v value="$value" '
      BEGIN { written=0 }
      index($0, key "=") == 1 {
        if (!written) { print key "=" value; written=1 }
        next
      }
      { print }
      END { if (!written) print key "=" value }
    ' .env >"$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" .env
  else
    printf '%s=%s\n' "$key" "$value" >>.env
  fi
}

write_env_safely() {
  cd "$INSTALL_DIR"
  local had_env=0
  if [ -f .env ]; then
    had_env=1
    local env_backup
    install -d -m 700 "$BACKUP_ROOT"
    env_backup="$(mktemp "$BACKUP_ROOT/.env-$(date +%Y%m%d-%H%M%S).XXXXXX.backup")"
    cp -a .env "$env_backup"
    chmod 600 "$env_backup"
    chown "$INSTALL_USER:$INSTALL_GROUP" "$env_backup"
    log "Preserving existing .env values; backup: $env_backup"
  else
    : >.env
  fi
  chmod 600 .env

  # Existing non-empty values always win, including on FORCE=1. Missing/empty
  # values are added or repaired without rotating encryption/database secrets.
  ensure_env_value PANEL_DOMAIN "$PANEL_DOMAIN"
  ensure_env_value DOKPLOY_PANEL_HOST "$PANEL_DOMAIN"
  ensure_env_value DOKPLOY_TRAEFIK_SERVICE_PORT 3000
  ensure_env_value ACME_EMAIL "$ACME_EMAIL"
  ensure_env_value ENCRYPTION_KEY "${ENCRYPTION_KEY:-$(random_hex 16)}"
  ensure_env_value SESSION_SECRET "${SESSION_SECRET:-$(random_hex 32)}"
  ensure_env_value MONGO_USER "$MONGO_USER"
  ensure_env_value MONGO_PASSWORD "${MONGO_PASSWORD:-$(random_hex 16)}"
  ensure_env_value UPDATER_SECRET "${UPDATER_SECRET:-$(random_hex 32)}"
  ensure_env_value USE_CADDY true
  ensure_env_value SESSION_COOKIE_SECURE true
  ensure_env_value PANEL_IP_WHITELIST "$PANEL_IP_WHITELIST"
  ensure_env_value SYNC_INTERVAL "$SYNC_INTERVAL"
  ensure_env_value LOG_LEVEL "$LOG_LEVEL"

  chmod 600 .env
  chown "$INSTALL_USER:$INSTALL_GROUP" .env
  PANEL_DOMAIN="$(env_value PANEL_DOMAIN)"
  ACME_EMAIL="$(env_value ACME_EMAIL)"
  MONGO_USER="$(env_value MONGO_USER)"
  export PANEL_DOMAIN ACME_EMAIL MONGO_USER
  validate_effective_env
  if [ "$had_env" = 1 ]; then
    log "Existing .env secrets were retained; only missing/empty keys were added"
  else
    log "Generated .env, including an HMAC UPDATER_SECRET"
  fi
}

validate_effective_env() {
  local value
  valid_hostname "$PANEL_DOMAIN" || fail "Effective PANEL_DOMAIN in .env is invalid"
  printf '%s' "$ACME_EMAIL" | grep -Eq '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$' \
    || fail "Effective ACME_EMAIL in .env is invalid"
  printf '%s' "$MONGO_USER" | grep -Eq '^[A-Za-z0-9_.-]+$' || fail "Effective MONGO_USER in .env is invalid"
  value="$(env_value ENCRYPTION_KEY)"; [ "${#value}" -ge 32 ] || fail "Effective ENCRYPTION_KEY is too short"
  value="$(env_value SESSION_SECRET)"; [ "${#value}" -ge 32 ] || fail "Effective SESSION_SECRET is too short"
  value="$(env_value MONGO_PASSWORD)"; [ "${#value}" -ge 16 ] || fail "Effective MONGO_PASSWORD is too short"
  value="$(env_value UPDATER_SECRET)"; [ "${#value}" -ge 32 ] || fail "Effective UPDATER_SECRET is too short"
}

prepare_dirs() {
  cd "$INSTALL_DIR"
  install -d -m 750 -o "$INSTALL_USER" -g "$INSTALL_GROUP" logs greenlock.d
  install -d -m 700 -o "$INSTALL_USER" -g "$INSTALL_GROUP" backups data
}

container_running() {
  [ "$(docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null || true)" = running ]
}

container_healthy() {
  [ "$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$1" 2>/dev/null || true)" = healthy ]
}

backend_health_ok() {
  docker exec hysteria-backend node -e \
    "fetch('http://127.0.0.1:3000/health').then(r=>{if(!r.ok)process.exit(1);return r.json()}).then(x=>{if(x.status!=='ok')process.exit(1)}).catch(()=>process.exit(1))" \
    >/dev/null 2>&1
}

https_health_ok() {
  if [ "$SKIP_HTTPS_CHECK" = 1 ]; then
    return 0
  fi
  local url="${HEALTHCHECK_URL:-https://$PANEL_DOMAIN/health}"
  curl -fsS --connect-timeout 10 --max-time 20 -- "$url" >/dev/null 2>&1
}

verify_updater_hmac() {
  docker exec -i hysteria-backend node <<'NODE'
const crypto = require('crypto');
const secret = process.env.UPDATER_SECRET || '';
if (secret.length < 32) process.exit(2);
const ts = String(Date.now());
const signature = crypto.createHmac('sha256', secret).update(`${ts}.`).digest('hex');
fetch('http://updater:8484/status', { headers: {
  'x-updater-ts': ts,
  'x-updater-signature': signature,
}}).then(async (r) => {
  if (!r.ok) process.exit(3);
  const body = await r.json();
  if (!body || !body.state) process.exit(4);
}).catch(() => process.exit(5));
NODE
}

verify_mount_isolation() {
  local backend_mounts updater_mounts
  backend_mounts="$(docker inspect -f '{{range .Mounts}}{{println .Type "|" .Source "|" .Destination "|" .RW}}{{end}}' hysteria-backend)"
  updater_mounts="$(docker inspect -f '{{range .Mounts}}{{println .Type "|" .Source "|" .Destination "|" .RW}}{{end}}' hysteria-updater)"
  ! printf '%s\n' "$backend_mounts" | grep -Fq '/var/run/docker.sock' \
    || fail "Security check failed: backend has Docker socket access"
  [ "$(printf '%s\n' "$updater_mounts" | sed '/^$/d' | wc -l)" -eq 2 ] \
    || fail "Updater has an unexpected number of mounts"
  printf '%s\n' "$updater_mounts" | grep -Fxq 'bind | /var/run/docker.sock | /var/run/docker.sock | true' \
    || fail "Updater Docker socket mount is missing"
  printf '%s\n' "$updater_mounts" | grep -Fxq "bind | $INSTALL_DIR | $INSTALL_DIR | true" \
    || fail "Updater project bind mount is missing or points to the wrong path"
}

start_stack() {
  cd "$INSTALL_DIR"
  [ -f "$COMPOSE_FILE" ] || fail "Compose file not found: $INSTALL_DIR/$COMPOSE_FILE"

  log "Validating Compose configuration"
  docker compose -f "$COMPOSE_FILE" config >/dev/null
  docker info >/dev/null 2>&1 || fail "Docker daemon is not running or not reachable"

  # Build before recreation: a build failure leaves the currently running stack
  # untouched during intentional FORCE=1 repair/update runs.
  log "Building backend and isolated updater sidecar"
  docker compose -f "$COMPOSE_FILE" build backend updater
  log "Starting stack"
  docker compose -f "$COMPOSE_FILE" up -d

  local deadline=$((SECONDS + START_TIMEOUT))
  log "Waiting up to ${START_TIMEOUT}s for containers and health checks"
  while [ "$SECONDS" -lt "$deadline" ]; do
    if container_running hysteria-backend \
      && container_running hysteria-updater \
      && container_running hysteria-caddy \
      && container_healthy hysteria-mongo \
      && container_healthy hysteria-redis \
      && backend_health_ok \
      && https_health_ok; then
      break
    fi
    sleep 3
  done

  if ! container_running hysteria-backend \
    || ! container_running hysteria-updater \
    || ! container_running hysteria-caddy \
    || ! container_healthy hysteria-mongo \
    || ! container_healthy hysteria-redis \
    || ! backend_health_ok \
    || ! https_health_ok; then
    warn "Installation health gate failed; current container state and bounded logs follow"
    docker compose -f "$COMPOSE_FILE" ps >&2 || true
    docker compose -f "$COMPOSE_FILE" logs --tail=120 backend updater caddy mongo redis >&2 || true
    fail "Stack did not become healthy within ${START_TIMEOUT}s"
  fi

  verify_updater_hmac || fail "Updater HMAC status check failed"
  verify_mount_isolation
  log "Container, HTTPS, updater HMAC and Docker socket isolation checks passed"
  docker compose -f "$COMPOSE_FILE" ps
}

main() {
  need_root
  install_base_tools
  validate_inputs
  install_docker_if_needed
  make_backup_if_existing
  clone_or_update_repo
  write_env_safely
  prepare_dirs

  if [ "$NO_START" = 1 ]; then
    log "NO_START=1 set; skipping docker compose build/up"
  else
    start_stack
  fi

  local effective_domain version
  effective_domain="$(env_value PANEL_DOMAIN)"
  version="$(awk -F'"' '/"version"/ { print $4; exit }' package.json 2>/dev/null || true)"
  cat <<EOF_DONE

Done.
Panel URL: https://$effective_domain/panel
Install dir: $INSTALL_DIR
Install owner: $INSTALL_USER:$INSTALL_GROUP
Repo: $REPO_URL (ref: $BRANCH)
Version: ${version:-unknown}

Useful commands:
  cd $INSTALL_DIR
  docker compose -f $COMPOSE_FILE ps
  docker compose -f $COMPOSE_FILE logs -f backend updater

For future production updates, use Settings -> Maintenance -> Panel update
(or follow docs/safe-update.md for the manual backup/rollback procedure).

EOF_DONE
}

if [ "${CELERITY_INSTALLER_LIBRARY:-0}" != 1 ]; then
  main "$@"
fi
