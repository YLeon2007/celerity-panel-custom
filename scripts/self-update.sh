#!/usr/bin/env bash
set -Eeuo pipefail

REPO_PATH="${SELF_UPDATE_REPO_PATH:-/opt/hysteria-panel-host}"
REMOTE="${SELF_UPDATE_REMOTE:-origin}"
BRANCH="${SELF_UPDATE_BRANCH:-main}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_ROOT="$REPO_PATH/backups/self-update"
BACKUP_DIR="$BACKUP_ROOT/$TIMESTAMP"
ROLLBACK_PATH="$BACKUP_DIR/ROLLBACK.sh"
MIN_FREE_KB="${SELF_UPDATE_MIN_FREE_KB:-1048576}"

log() { printf '[self-update] %s\n' "$*"; }
fail() { printf '[self-update] ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

need git
need docker
need tar
need df
need awk
need cp
need mkdir

[ -d "$REPO_PATH/.git" ] || fail "Git checkout not found at $REPO_PATH"
cd "$REPO_PATH"

FREE_KB="$(df -Pk "$REPO_PATH" | awk 'NR==2 {print $4}')"
[ -n "$FREE_KB" ] || fail "Cannot determine free disk space for $REPO_PATH"
if [ "$FREE_KB" -lt "$MIN_FREE_KB" ]; then
  fail "Not enough free disk space: ${FREE_KB}KB available, need at least ${MIN_FREE_KB}KB"
fi
log "Free disk space OK: ${FREE_KB}KB"

mkdir -p "$BACKUP_DIR"
log "BACKUP_DIR=$BACKUP_DIR"
log "ROLLBACK_PATH=$ROLLBACK_PATH"

CURRENT_SHA="$(git rev-parse HEAD)"
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
log "Current ref: $CURRENT_BRANCH $CURRENT_SHA"

if [ -f .env ]; then
  cp -a .env "$BACKUP_DIR/.env"
  log "Backed up .env"
fi

# Backup selected mutable/project files without copying huge runtime directories.
tar --exclude='./.git' \
    --exclude='./node_modules' \
    --exclude='./backups' \
    --exclude='./logs' \
    --exclude='./.env' \
    -czf "$BACKUP_DIR/files.tar.gz" .
log "Backed up project files"

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose -f docker-compose.yml)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose -f docker-compose.yml)
else
  fail "docker compose/docker-compose not found"
fi

read_env_value() {
  local key="$1"
  local file="${2:-.env}"
  [ -f "$file" ] || return 0
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); gsub(/^"|"$/, ""); gsub(/^'"'"'|'"'"'$/, ""); print; exit }' "$file"
}

MONGO_CID="$("${COMPOSE[@]}" ps -q mongo 2>/dev/null || true)"
if [ -n "$MONGO_CID" ]; then
  MONGO_USER="${MONGO_USER:-$(read_env_value MONGO_USER)}"
  MONGO_USER="${MONGO_USER:-hysteria}"
  MONGO_PASSWORD="${MONGO_PASSWORD:-$(read_env_value MONGO_PASSWORD)}"
  if [ -n "$MONGO_PASSWORD" ]; then
    log "Creating MongoDB dump"
    docker exec "$MONGO_CID" mongodump \
      --username "$MONGO_USER" \
      --password "$MONGO_PASSWORD" \
      --authenticationDatabase admin \
      --db hysteria \
      --archive=/tmp/self-update-mongo.archive.gz \
      --gzip
    docker cp "$MONGO_CID:/tmp/self-update-mongo.archive.gz" "$BACKUP_DIR/mongo.archive.gz"
    docker exec "$MONGO_CID" rm -f /tmp/self-update-mongo.archive.gz >/dev/null 2>&1 || true
    log "Backed up MongoDB"
  else
    log "Skipping MongoDB dump: MONGO_PASSWORD is empty"
  fi
else
  log "Skipping MongoDB dump: mongo container is not running"
fi

cat > "$ROLLBACK_PATH" <<EOF_ROLLBACK
#!/usr/bin/env bash
set -Eeuo pipefail
cd "$REPO_PATH"
echo "[rollback] Restoring git ref $CURRENT_SHA"
git reset --hard "$CURRENT_SHA"
if [ -f "$BACKUP_DIR/.env" ]; then
  cp -a "$BACKUP_DIR/.env" "$REPO_PATH/.env"
fi
if [ -f "$BACKUP_DIR/files.tar.gz" ]; then
  tar -xzf "$BACKUP_DIR/files.tar.gz" -C "$REPO_PATH"
fi
if docker compose version >/dev/null 2>&1; then
  docker compose -f docker-compose.yml up -d --build
elif command -v docker-compose >/dev/null 2>&1; then
  docker-compose -f docker-compose.yml up -d --build
else
  echo "[rollback] docker compose not found" >&2
  exit 1
fi
echo "[rollback] Done. MongoDB dump (if needed) is at: $BACKUP_DIR/mongo.archive.gz"
EOF_ROLLBACK
chmod +x "$ROLLBACK_PATH"
log "Created rollback script"

git fetch --prune "$REMOTE" "$BRANCH"
log "Fast-forwarding from $CURRENT_SHA to $REMOTE/$BRANCH"
git pull --ff-only "$REMOTE" "$BRANCH"

log "Rebuilding containers"
"${COMPOSE[@]}" up -d --build

log "Self-update completed"
log "BACKUP_DIR=$BACKUP_DIR"
log "ROLLBACK_PATH=$ROLLBACK_PATH"
