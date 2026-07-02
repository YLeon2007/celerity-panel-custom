#!/usr/bin/env bash
set -euo pipefail

# C³ CELERITY custom one-command installer
# Default target: private repo YLeon2007/celerity-panel-custom.
#
# Minimal usage for a public/SSH-accessible checkout:
#   PANEL_DOMAIN=panel.example.com ACME_EMAIL=admin@example.com bash scripts/install.sh
#
# For the private GitHub repo via HTTPS token:
#   export GITHUB_TOKEN=TOKEN_PLACEHOLDER
#   export PANEL_DOMAIN=panel.example.com
#   export ACME_EMAIL=admin@example.com
#   curl -fsSL -H "Authorization: Bearer TOKEN_PLACEHOLDER" \
#     https://raw.githubusercontent.com/YLeon2007/celerity-panel-custom/main/scripts/install.sh | sudo -E bash

REPO="${REPO:-YLeon2007/celerity-panel-custom}"
BRANCH="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/hysteria-panel}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/hysteria-panel-install-backups}"
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
ACME_EMAIL="${ACME_EMAIL:-}"
MONGO_USER="${MONGO_USER:-hysteria}"
LOG_LEVEL="${LOG_LEVEL:-info}"
SYNC_INTERVAL="${SYNC_INTERVAL:-2}"
PANEL_IP_WHITELIST="${PANEL_IP_WHITELIST:-}"
FORCE="${FORCE:-0}"
NO_START="${NO_START:-0}"

log() { printf '\033[1;34m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fail "Run as root, e.g. sudo -E bash scripts/install.sh"
  fi
}

random_hex() {
  bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
  else
    tr -dc 'a-f0-9' </dev/urandom | head -c "$((bytes * 2))"
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
  missing=""
  for cmd in git curl openssl tar; do
    command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
  done
  if [ -n "$missing" ]; then
    log "Installing base tools:$missing"
    apt-get update
    apt-get install -y git curl openssl tar ca-certificates
  fi
}

validate_inputs() {
  [ -n "$PANEL_DOMAIN" ] || fail "PANEL_DOMAIN is required, e.g. PANEL_DOMAIN=panel.example.com"
  [ -n "$ACME_EMAIL" ] || fail "ACME_EMAIL is required, e.g. ACME_EMAIL=admin@example.com"
  case "$PANEL_DOMAIN" in
    http://*|https://*|*/*) fail "PANEL_DOMAIN must be a hostname only, without scheme/path" ;;
  esac
}

make_backup_if_existing() {
  if [ ! -e "$INSTALL_DIR" ]; then
    return
  fi

  mkdir -p "$BACKUP_ROOT"
  ts="$(date +%Y%m%d-%H%M%S)"
  backup="$BACKUP_ROOT/hysteria-panel-$ts.tar.gz"
  log "Existing $INSTALL_DIR found; creating backup: $backup"
  tar \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='logs/*.log' \
    -czf "$backup" -C "$(dirname "$INSTALL_DIR")" "$(basename "$INSTALL_DIR")"

  if [ "$FORCE" != "1" ]; then
    fail "Backup created. Re-run with FORCE=1 to update existing $INSTALL_DIR. Backup: $backup"
  fi
}

clone_or_update_repo() {
  mkdir -p "$(dirname "$INSTALL_DIR")"

  if [ -d "$INSTALL_DIR/.git" ]; then
    log "Updating existing git checkout in $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch origin "$BRANCH"
    git -C "$INSTALL_DIR" checkout "$BRANCH"
    git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
    return
  fi

  if [ -e "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
  fi

  log "Cloning $REPO branch $BRANCH into $INSTALL_DIR"
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    tmp_home="$(mktemp -d)"
    cat >"$tmp_home/.netrc" <<EOF_NETRC
machine github.com
  login x-access-token
  password $GITHUB_TOKEN
EOF_NETRC
    chmod 600 "$tmp_home/.netrc"
    HOME="$tmp_home" git clone --branch "$BRANCH" "https://github.com/$REPO.git" "$INSTALL_DIR"
    rm -rf "$tmp_home"
  else
    git clone --branch "$BRANCH" "https://github.com/$REPO.git" "$INSTALL_DIR"
  fi

  # Ensure the token is not persisted in remote URLs.
  git -C "$INSTALL_DIR" remote set-url origin "https://github.com/$REPO.git"
}

write_env_if_needed() {
  cd "$INSTALL_DIR"
  if [ -f .env ] && [ "$FORCE" != "1" ]; then
    log ".env already exists; keeping it"
    return
  fi

  if [ -f .env ]; then
    cp -a .env ".env.backup-$(date +%Y%m%d-%H%M%S)"
  fi

  enc="${ENCRYPTION_KEY:-$(random_hex 16)}"
  sess="${SESSION_SECRET:-$(random_hex 32)}"
  mongo_pass="${MONGO_PASSWORD:-$(random_hex 16)}"

  log "Writing .env"
  cat > .env <<EOF_ENV
PANEL_DOMAIN=$PANEL_DOMAIN
DOKPLOY_PANEL_HOST=$PANEL_DOMAIN
DOKPLOY_TRAEFIK_SERVICE_PORT=3000
ACME_EMAIL=$ACME_EMAIL
ENCRYPTION_KEY=$enc
SESSION_SECRET=$sess
MONGO_USER=$MONGO_USER
MONGO_PASSWORD=$mongo_pass
USE_CADDY=true
SESSION_COOKIE_SECURE=true
PANEL_IP_WHITELIST=$PANEL_IP_WHITELIST
SYNC_INTERVAL=$SYNC_INTERVAL
LOG_LEVEL=$LOG_LEVEL
EOF_ENV
  chmod 600 .env
}

prepare_dirs() {
  cd "$INSTALL_DIR"
  mkdir -p logs backups greenlock.d
  chmod 700 backups || true
}

start_stack() {
  cd "$INSTALL_DIR"
  [ -f "$COMPOSE_FILE" ] || fail "Compose file not found: $INSTALL_DIR/$COMPOSE_FILE"

  log "Building and starting stack with $COMPOSE_FILE"
  docker compose -f "$COMPOSE_FILE" up -d --build

  log "Container status"
  docker compose -f "$COMPOSE_FILE" ps
}

main() {
  need_root
  validate_inputs
  install_base_tools
  install_docker_if_needed
  make_backup_if_existing
  clone_or_update_repo
  write_env_if_needed
  prepare_dirs

  if [ "$NO_START" = "1" ]; then
    log "NO_START=1 set; skipping docker compose up"
  else
    start_stack
  fi

  cat <<EOF_DONE

Done.
Panel URL: https://$PANEL_DOMAIN/panel
Install dir: $INSTALL_DIR
Repo: https://github.com/$REPO (branch: $BRANCH)

Useful commands:
  cd $INSTALL_DIR
  docker compose -f $COMPOSE_FILE ps
  docker compose -f $COMPOSE_FILE logs -f backend
  docker compose -f $COMPOSE_FILE pull && docker compose -f $COMPOSE_FILE up -d --build

EOF_DONE
}

main "$@"
