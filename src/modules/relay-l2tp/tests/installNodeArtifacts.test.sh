#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
PACKAGE_SOURCE="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

make_package_fixture() {
    local name="$1"
    local package="$TMP_DIR/$name"
    mkdir -p "$package"
    cp -a "$PACKAGE_SOURCE/." "$package/"
    printf '%s\n' "$package"
}

invoke_installer() {
    local label="$1"
    local package="$2"
    shift 2
    rm -rf "$TMP_DIR/bin" "$TMP_DIR/var-lib"
    mkdir -p "$TMP_DIR/bin" "$TMP_DIR/var-lib"
    output="$TMP_DIR/$label.out"
    status=0
    set +e
    /usr/bin/bwrap \
        --unshare-user --uid 0 --gid 0 \
        --unshare-pid \
        --ro-bind / / \
        --bind "$TMP_DIR/bin" /usr/local/bin \
        --bind "$TMP_DIR/var-lib" /var/lib \
        --dev /dev \
        --proc /proc \
        "$package/install.sh" "$@" >"$output" 2>&1
    status=$?
    set -e
}

inspect_installed_metadata() {
    /usr/bin/bwrap \
        --unshare-user --uid 0 --gid 0 \
        --unshare-pid \
        --ro-bind / / \
        --bind "$TMP_DIR/bin" /usr/local/bin \
        --bind "$TMP_DIR/var-lib" /var/lib \
        --dev /dev \
        --proc /proc \
        /usr/bin/stat -c '%u:%g:%a:%F' \
        /usr/local/bin/celerity-l2tp-artifact-receiver \
        /usr/local/bin/celerity-l2tp-artifact-runner \
        /var/lib/celerity/l2tp/operations
}

[[ -x "$PACKAGE_SOURCE/install.sh" ]] || fail 'node artifact installer is missing or not executable'
[[ -x "$PACKAGE_SOURCE/receive-artifact.py" ]] || fail 'receiver source is missing or not executable'

package="$(make_package_fixture valid-package)"
invoke_installer valid "$package"
[[ "$status" -eq 0 ]] || fail 'valid package installation failed'
[[ "$(<"$output")" == '{"status":"ok"}' ]] || fail 'installer returned unexpected output'
[[ -f "$TMP_DIR/bin/celerity-l2tp-artifact-receiver" ]] || fail 'receiver was not installed at the fixed target'
[[ ! -L "$TMP_DIR/bin/celerity-l2tp-artifact-receiver" ]] || fail 'receiver target must be a regular file'
[[ -f "$TMP_DIR/bin/celerity-l2tp-artifact-runner" ]] || fail 'runner was not installed at the fixed target'
[[ ! -L "$TMP_DIR/bin/celerity-l2tp-artifact-runner" ]] || fail 'runner target must be a regular file'
[[ "$(sha256sum "$package/receive-artifact.py" | cut -d ' ' -f 1)" == \
   "$(sha256sum "$TMP_DIR/bin/celerity-l2tp-artifact-receiver" | cut -d ' ' -f 1)" ]] \
    || fail 'installed receiver digest differs from the fixed package artifact'
[[ "$(sha256sum "$package/runner.sh" | cut -d ' ' -f 1)" == \
   "$(sha256sum "$TMP_DIR/bin/celerity-l2tp-artifact-runner" | cut -d ' ' -f 1)" ]] \
    || fail 'installed runner digest differs from the fixed package artifact'
mapfile -t metadata < <(inspect_installed_metadata)
[[ "${metadata[0]}" == '0:0:755:regular file' ]] || fail 'receiver is not an exact root-owned mode 0755 executable'
[[ "${metadata[1]}" == '0:0:755:regular file' ]] || fail 'runner is not an exact root-owned mode 0755 executable'
[[ "${metadata[2]}" == '0:0:700:directory' ]] || fail 'operations root is not an exact root-owned mode 0700 directory'

package="$(make_package_fixture tampered-package)"
printf '\n# tampered\n' >>"$package/receive-artifact.py"
invoke_installer tampered "$package"
[[ "$status" -ne 0 ]] || fail 'tampered receiver was accepted'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_PACKAGE"}' ]] \
    || fail 'tampered receiver returned an unsanitized error'
[[ ! -e "$TMP_DIR/bin/celerity-l2tp-artifact-receiver" ]] \
    || fail 'tampered receiver reached the fixed target'
[[ ! -e "$TMP_DIR/bin/celerity-l2tp-artifact-runner" ]] \
    || fail 'runner was published before receiver validation completed'

package="$(make_package_fixture insecure-package)"
chmod 0775 "$package/receive-artifact.py"
invoke_installer insecure "$package"
[[ "$status" -ne 0 ]] || fail 'insecure receiver permissions were accepted'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_PACKAGE"}' ]] \
    || fail 'insecure package returned an unsanitized error'
[[ ! -e "$TMP_DIR/bin/celerity-l2tp-artifact-receiver" ]] \
    || fail 'insecure receiver reached the fixed target'

package="$(make_package_fixture arguments-package)"
invoke_installer arguments "$package" --target "$TMP_DIR/arbitrary"
[[ "$status" -ne 0 ]] || fail 'arbitrary installer arguments were accepted'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'arbitrary installer arguments returned the wrong error'
[[ ! -e "$TMP_DIR/arbitrary" ]] || fail 'an arbitrary install target was created'
[[ ! -e "$TMP_DIR/bin/celerity-l2tp-artifact-receiver" ]] \
    || fail 'receiver was installed after invalid arguments'

printf 'node artifact installer fixture tests passed\n'
