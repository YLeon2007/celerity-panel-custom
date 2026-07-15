# Custom deployment

This repository can deploy the custom C³ CELERITY panel from source with one installer script.

## One-command install from the public GitHub repository

The automatic prerequisite path supports Debian/Ubuntu (`apt-get`) on amd64 and
arm64. Other distributions must provide Git, curl, OpenSSL, Docker Engine and
Docker Compose v2 before running the script.

```bash
curl -fsSL \
  https://raw.githubusercontent.com/YLeon2007/celerity-panel-custom/main/scripts/install.sh \
  | sudo -E bash
```

The script prompts for missing values (`PANEL_DOMAIN`, `ACME_EMAIL`) in interactive mode. For automation, pass them as environment variables.

For `develop` testing:

```bash
export BRANCH='develop'

curl -fsSL \
  https://raw.githubusercontent.com/YLeon2007/celerity-panel-custom/develop/scripts/install.sh \
  | sudo -E bash
```

The installer defaults to:

```text
REPO=YLeon2007/celerity-panel-custom
BRANCH=main
INSTALL_DIR=/opt/hysteria-panel
COMPOSE_FILE=docker-compose.yml
```

Override if needed:

```bash
export BRANCH=develop
export INSTALL_DIR=/opt/hysteria-panel-dev
```

> If you deploy from a private fork instead of this public repository, set `GITHUB_TOKEN` with read access before running the installer.

## Existing installation safety

If `/opt/hysteria-panel` already exists, the installer creates a tar backup under:

```text
/opt/hysteria-panel-install-backups/
```

Then it stops and asks you to re-run with:

```bash
FORCE=1
```

This prevents accidental overwrites. `FORCE=1` is for intentional repair or
reinstallation, not the normal update path. Routine updates should use
**Settings → Maintenance → Panel update** or `docs/safe-update.md`.

## Generated secrets

If not provided, the installer generates:

```text
ENCRYPTION_KEY
SESSION_SECRET
MONGO_PASSWORD
UPDATER_SECRET
```

and writes them to:

```text
/opt/hysteria-panel/.env
```

`.env` is never committed.

On `FORCE=1`, existing non-empty `.env` values are retained. The installer only
adds missing/empty keys; it never rotates database or encryption secrets. It also
creates persistent `logs/`, `backups/`, `greenlock.d/`, and `data/` directories.

Unless `NO_START=1` is used, success is reported only after MongoDB/Redis health,
backend `/health`, public HTTPS, signed updater status, and Docker-socket isolation
have passed. Only the updater sidecar receives `/var/run/docker.sock`.

## Update existing custom checkout

```bash
cd /opt/hysteria-panel
git fetch origin main
git checkout main
git pull --ff-only origin main
docker compose -f docker-compose.yml build backend updater
docker compose -f docker-compose.yml up -d
```

## Notes

- Production deploy uses `docker-compose.yml`: backend is built from this repository and Caddy terminates HTTPS.
- In-panel updates are under **Settings → Maintenance → Panel update** and target immutable GitHub releases.
- Xray Access Logs remain disabled by default and are enabled separately per node.
- The installer uses `USE_CADDY=true` and expects DNS for `PANEL_DOMAIN` to point to the server.
- Keep tokens out of shell history where possible; revoke temporary GitHub tokens after deployment.
