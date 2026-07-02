# Custom deployment

This repository can deploy the custom C³ CELERITY panel from source with one installer script.

## One-command install from the public GitHub repository

```bash
export PANEL_DOMAIN='panel.example.com'
export ACME_EMAIL='admin@example.com'

curl -fsSL \
  https://raw.githubusercontent.com/YLeon2007/celerity-panel-custom/main/scripts/install.sh \
  | sudo -E bash
```

For `develop` testing:

```bash
export PANEL_DOMAIN='panel.example.com'
export ACME_EMAIL='admin@example.com'
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

This prevents accidental overwrites.

## Generated secrets

If not provided, the installer generates:

```text
ENCRYPTION_KEY
SESSION_SECRET
MONGO_PASSWORD
```

and writes them to:

```text
/opt/hysteria-panel/.env
```

`.env` is never committed.

## Update existing custom checkout

```bash
cd /opt/hysteria-panel
git fetch origin main
git checkout main
git pull --ff-only origin main
docker compose -f docker-compose.yml up -d --build
```

## Notes

- Production deploy uses `docker-compose.yml`: backend is built from this repository and Caddy terminates HTTPS.
- The installer uses `USE_CADDY=true` and expects DNS for `PANEL_DOMAIN` to point to the server.
- Keep tokens out of shell history where possible; revoke temporary GitHub tokens after deployment.
