#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT=$(mktemp -d "${PWD}/.installer-test.XXXXXX")
trap 'rm -rf -- "$ROOT"' EXIT
REPO_ROOT="$PWD"

# Backend builds must be lockfile-reproducible and must not contain Docker tooling;
# only the isolated updater image is allowed to control the Docker daemon.
grep -Fq 'RUN npm ci --omit=dev' Dockerfile
! grep -Eq '^RUN .*docker-cli' Dockerfile
grep -Eq '^RUN .*docker-cli.*docker-cli-compose' updater/Dockerfile

export CELERITY_INSTALLER_LIBRARY=1
export INSTALL_DIR="$ROOT/project"
export BACKUP_ROOT="$ROOT/backups"
export INSTALL_USER="$(id -un)"
export PANEL_DOMAIN=new.example.com
export ACME_EMAIL=new@example.com

mkdir -p "$INSTALL_DIR"
cat >"$INSTALL_DIR/.env" <<'EOF_ENV'
PANEL_DOMAIN=old.example.com
ACME_EMAIL=old@example.com
ENCRYPTION_KEY=0123456789abcdef0123456789abcdef
SESSION_SECRET=0123456789abcdef0123456789abcdef
MONGO_USER=hysteria
MONGO_PASSWORD=existing-mongo-password
UPDATER_SECRET=
CUSTOM_KEEP=unchanged
EOF_ENV
chmod 644 "$INSTALL_DIR/.env"

# shellcheck source=install.sh
source "$REPO_ROOT/scripts/install.sh"
INSTALL_GROUP="$(id -gn "$INSTALL_USER")"
export INSTALL_GROUP

write_env_safely
prepare_dirs

[ "$(env_value PANEL_DOMAIN)" = old.example.com ]
[ "$(env_value DOKPLOY_PANEL_HOST)" = old.example.com ]
[ "$(env_value ACME_EMAIL)" = old@example.com ]
[ "$(env_value ENCRYPTION_KEY)" = 0123456789abcdef0123456789abcdef ]
[ "$(env_value SESSION_SECRET)" = 0123456789abcdef0123456789abcdef ]
[ "$(env_value MONGO_PASSWORD)" = existing-mongo-password ]
[ "$(env_value CUSTOM_KEEP)" = unchanged ]
[ "$(env_value UPDATER_SECRET | wc -c)" -ge 33 ]
[ "$(stat -c %a "$INSTALL_DIR/.env")" = 600 ]
[ "$(stat -c %a "$INSTALL_DIR/data")" = 700 ]
[ "$(stat -c %a "$INSTALL_DIR/backups")" = 700 ]
[ "$(find "$BACKUP_ROOT" -maxdepth 1 -name '.env-*.backup' | wc -l)" = 1 ]

expect_failure() {
  local expected="$1"
  shift
  local output rc
  set +e
  output="$("$@" 2>&1)"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || {
    printf 'expected failure but command succeeded: %s\n' "$*" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -Fq "$expected" || {
    printf 'missing expected failure %q in output:\n%s\n' "$expected" "$output" >&2
    return 1
  }
}

expect_failure 'SESSION_SECRET must be at least 32 characters' \
  env CELERITY_INSTALLER_LIBRARY=1 INSTALL_DIR="$ROOT/short" BACKUP_ROOT="$ROOT/backups2" \
      INSTALL_USER="$(id -un)" PANEL_DOMAIN=x.example.com ACME_EMAIL=x@example.com \
      SESSION_SECRET=short REPO_ROOT="$REPO_ROOT" bash -c 'source "$REPO_ROOT/scripts/install.sh"; validate_inputs'

expect_failure 'SESSION_SECRET contains characters unsafe for an unquoted .env value' \
  env CELERITY_INSTALLER_LIBRARY=1 INSTALL_DIR="$ROOT/unsafe-secret" BACKUP_ROOT="$ROOT/backups-secret" \
      INSTALL_USER="$(id -un)" PANEL_DOMAIN=x.example.com ACME_EMAIL=x@example.com \
      SESSION_SECRET='0123456789abcdef0123456789abc#ef' REPO_ROOT="$REPO_ROOT" \
      bash -c 'source "$REPO_ROOT/scripts/install.sh"; validate_inputs'

expect_failure 'Refusing INSTALL_DIR below a world-writable or runtime directory' \
  env CELERITY_INSTALLER_LIBRARY=1 INSTALL_DIR=/tmp/celerity-unsafe BACKUP_ROOT="$ROOT/backups3" \
      INSTALL_USER="$(id -un)" PANEL_DOMAIN=x.example.com ACME_EMAIL=x@example.com \
      REPO_ROOT="$REPO_ROOT" bash -c 'source "$REPO_ROOT/scripts/install.sh"; validate_inputs'

# A failed private clone must not leave temporary HOME/.netrc credentials.
mkdir -p "$ROOT/tmp" "$ROOT/bin"
cat >"$ROOT/bin/git" <<'EOF_GIT'
#!/usr/bin/env bash
if [ "${1:-}" = clone ]; then exit 73; fi
exec /usr/bin/git "$@"
EOF_GIT
chmod 700 "$ROOT/bin/git"
set +e
env CELERITY_INSTALLER_LIBRARY=1 TMPDIR="$ROOT/tmp" PATH="$ROOT/bin:$PATH" INSTALL_DIR="$ROOT/clone" \
    BACKUP_ROOT="$ROOT/backups4" INSTALL_USER="$(id -un)" PANEL_DOMAIN=x.example.com \
    ACME_EMAIL=x@example.com GITHUB_TOKEN=dummy REPO=owner/repo BRANCH=main REPO_ROOT="$REPO_ROOT" \
    bash -c 'source "$REPO_ROOT/scripts/install.sh"; INSTALL_GROUP=$(id -gn "$INSTALL_USER"); REPO_URL="https://github.com/$REPO.git"; clone_or_update_repo' \
    >/dev/null 2>&1
rc=$?
set -e
[ "$rc" -ne 0 ]
[ -z "$(find "$ROOT/tmp" -mindepth 1 -maxdepth 1 -print -quit)" ]

# Updating an existing checkout to a previously unseen branch must create the
# remote-tracking ref explicitly and move only by fast-forward.
git init -q --bare "$ROOT/source.git"
git init -q -b main "$ROOT/source-work"
git -C "$ROOT/source-work" config user.email test@example.com
git -C "$ROOT/source-work" config user.name installer-test
printf 'main\n' >"$ROOT/source-work/version.txt"
git -C "$ROOT/source-work" add version.txt
git -C "$ROOT/source-work" commit -qm main
git -C "$ROOT/source-work" remote add origin "file://$ROOT/source.git"
git -C "$ROOT/source-work" push -q -u origin main
git -C "$ROOT/source-work" switch -qc feature/installer-test
printf 'feature\n' >"$ROOT/source-work/version.txt"
git -C "$ROOT/source-work" commit -qam feature
git -C "$ROOT/source-work" push -q -u origin feature/installer-test
git clone -q --branch main "file://$ROOT/source.git" "$ROOT/update"
(
  export CELERITY_INSTALLER_LIBRARY=1 INSTALL_DIR="$ROOT/update" BACKUP_ROOT="$ROOT/update-backups"
  export INSTALL_USER="$(id -un)" PANEL_DOMAIN=x.example.com ACME_EMAIL=x@example.com
  export BRANCH=feature/installer-test REPO=owner/repo
  source "$REPO_ROOT/scripts/install.sh"
  INSTALL_GROUP="$(id -gn "$INSTALL_USER")"
  REPO_URL="file://$ROOT/source.git"
  clone_or_update_repo
)
[ "$(git -C "$ROOT/update" branch --show-current)" = feature/installer-test ]
[ "$(cat "$ROOT/update/version.txt")" = feature ]
[ "$(git -C "$ROOT/update" rev-parse HEAD)" = "$(git -C "$ROOT/source-work" rev-parse feature/installer-test)" ]

printf 'installer regression tests passed\n'
