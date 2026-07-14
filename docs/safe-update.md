# Safe Production Updates

Step-by-step guide for updating C³ CELERITY on production servers with minimal downtime.

---

## 📋 Pre-Update Checklist

Before any update:

1. **Create a database backup**
   ```bash
   # Via panel UI: Dashboard → Backup → Download
   # Or manually via mongodump:
   docker exec hysteria-mongo mongodump --archive=/data/db/backup.archive --username=hysteria --password --authenticationDatabase=admin
   docker cp hysteria-mongo:/data/db/backup.archive ./backup-$(date +%Y%m%d-%H%M%S).archive
   ```

2. **Check current version**
   ```bash
   docker logs hysteria-backend --tail 50 | grep -i version
   ```

3. **Check available disk space**
   ```bash
   df -h
   # Minimum 2GB free space for the new image
   ```

4. **Backup your .env file**
   ```bash
   cp .env .env.backup-$(date +%Y%m%d)
   ```

---

## 🖱️ In-panel update (UI)

The panel can update and roll back itself from **Settings → Maintenance → Panel update**,
without SSH. It works for both Docker Hub and build-from-source deployments and is powered
by an isolated `updater` sidecar container.

### One-time setup

1. Generate a strong secret and add it to `.env` (min. 32 chars):
   ```bash
   echo "UPDATER_SECRET=$(openssl rand -hex 32)" >> .env
   ```

2. Recreate the stack so the `updater` service starts:
   ```bash
   # Docker Hub deployment
   docker compose -f docker-compose.hub.yml up -d
   # Build-from-source deployment
   docker compose up -d
   ```

Without `UPDATER_SECRET` the updater refuses all requests and the UI shows manual
instructions instead of the update button (fail-safe default).

### How it works

- The panel never has access to the Docker socket; only the `updater` sidecar does.
- The panel sends an HMAC-signed, single-purpose request ("move `backend` to version X").
- **Hub mode:** the updater rewrites `PANEL_TAG` in `.env`, pulls the image and recreates
  the backend.
- **Source mode:** the updater runs `git checkout --force vX.Y.Z`, rebuilds and recreates
  the backend. The forced checkout **discards local modifications to tracked files** —
  the deployment copy must not carry manual patches (untracked files such as `.env`,
  `data/`, `logs/` and `backups/` are never touched).
- A database backup is created before the update by default. `docker pull` / `docker build`
  run before the container is recreated, so a failed download/build leaves the running panel
  untouched.
- **Rollback** is the same operation targeting an older version. Note that a rollback does
  **not** revert database schema changes — recover data from a backup if needed.
- Rolling back to a release that predates the in-panel updater removes the update UI from
  the running panel (old code / old compose file without `UPDATER_URL`). Rolling forward
  again then requires one manual update using the steps below.

Dokploy and local (`docker-compose.local.yml`) deployments do not run the updater; use the
manual steps below.

---

## 🚀 Update (Docker Hub — recommended)

For production deployments using `docker-compose.hub.yml`:

### 1. Navigate to project directory

```bash
cd /path/to/hysteria-panel
```

### 2. Stop current containers (short downtime)

```bash
docker compose -f docker-compose.hub.yml down
```

> **Downtime:** ~10-30 seconds

### 3. Pull the new image

```bash
docker compose -f docker-compose.hub.yml pull
```

### 4. Start updated containers

```bash
docker compose -f docker-compose.hub.yml up -d
```

### 5. Check status

```bash
# All containers should be "running"
docker compose -f docker-compose.hub.yml ps

# Check logs for errors
docker logs hysteria-backend --tail 100 -f
```

### 6. Verify accessibility

```bash
curl -I https://your-domain/panel
```

---

## 🔧 Update (build from source)

For deployments using `docker-compose.yml` with local build:

### 1. Navigate to project directory

```bash
cd /path/to/hysteria-panel
```

### 2. Get latest changes

```bash
git fetch origin
git status  # check for uncommitted changes
git pull origin main
```

### 3. Stop current containers

```bash
docker compose down
```

### 4. Rebuild the image

```bash
docker compose build --no-cache backend
```

> **Time:** 2-5 minutes depending on server

### 5. Start containers

```bash
docker compose up -d
```

### 6. Check status

```bash
docker compose ps
docker logs hysteria-backend --tail 100 -f
```

---

## 🔄 Rollback to Previous Version

If problems occur after update:

### Option 1: Rollback to specific image version

1. Edit `docker-compose.hub.yml`:
   ```yaml
   backend:
     image: clickdevtech/hysteria-panel:v1.2.3  # specify desired version
   ```

2. Apply changes:
   ```bash
   docker compose -f docker-compose.hub.yml down
   docker compose -f docker-compose.hub.yml pull
   docker compose -f docker-compose.hub.yml up -d
   ```

### Option 2: Rollback to previous git commit

```bash
# Find the previous working commit
git log --oneline -10

# Checkout
git checkout <commit-hash>

# Rebuild
docker compose build --no-cache backend
docker compose up -d
```

### Option 3: Database restoration

```bash
# Restore from backup
docker cp ./backup.archive hysteria-mongo:/data/db/backup.archive
docker exec hysteria-mongo mongorestore --archive=/data/db/backup.archive --drop --username=hysteria --password --authenticationDatabase=admin
```

---

## ✅ After Update

1. **Check authentication** — login to the panel
2. **Check nodes** — all nodes should show `online` status
3. **Check subscriptions** — open subscription URL in browser
4. **Check API** — make a test request with API key
5. **Monitor logs** for 10-15 minutes:
   ```bash
   docker logs hysteria-backend -f --tail 50
   ```

---

## ⚠️ Common Issues

### Container won't start

```bash
# Check logs
docker logs hysteria-backend

# Common causes:
# - Error in .env file
# - MongoDB connection issue
# - Out of memory
```

### MongoDB connection fails

```bash
# Check MongoDB status
docker logs hysteria-mongo --tail 50

# Restart MongoDB
docker compose restart mongo
```

### SSL certificates not working

```bash
# Check greenlock.d contents
ls -la greenlock.d/

# Restart with cache clear
docker compose down
docker compose up -d
```

---

## 📅 Recommended Schedule

| Action | Frequency |
|--------|-----------|
| Database backup | Daily (auto) + before updates |
| Check for updates | Weekly |
| Security patches | Within 48 hours |
| Major updates | After staging testing |

---

## 🛡️ Best Practices

1. **Test on staging** — duplicate environment for update testing
2. **Update during low-traffic hours** — night/early morning in users' timezone
3. **Keep backups** — at least 3 recent database backups
4. **Document changes** — save records of versions and update dates
5. **Don't update everything at once** — panel first, then nodes if needed

---

## 📞 If Something Goes Wrong

1. Don't panic — data is safe in MongoDB
2. Check logs: `docker logs hysteria-backend --tail 200`
3. Rollback to previous version
4. Restore database from backup if needed
5. Create a GitHub issue with problem description and logs
