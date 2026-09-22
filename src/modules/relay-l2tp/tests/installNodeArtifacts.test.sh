#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
PACKAGE_SOURCE="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp"
TMP_DIR="$(mktemp -d)"
LIB_DIR="$TMP_DIR/local/lib/celerity/relay-l2tp"
RUNNER_LINK="$TMP_DIR/local/bin/celerity-l2tp-artifact-runner"
RECEIVER_LINK="$TMP_DIR/local/bin/celerity-l2tp-artifact-receiver"
trap 'rm -rf "$TMP_DIR"' EXIT

readonly -a PAYLOADS=(
    runner.sh
    receive-artifact.py
    apply.sh
    preflight.sh
    backup.sh
    compose-xray-fragment.sh
    validate-xray.sh
    materialize-nft-candidate.sh
    validate-nft.sh
    activate-xray.sh
    apply-firewall-policy.sh
    start-l2tp.sh
    sync-users.sh
    verify-users.sh
    verify.sh
    commit.sh
    rollback.sh
    install-runtime.sh
)

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

make_package_fixture() {
    local name="$1"
    local package="$TMP_DIR/$name"
    mkdir -p "$package"
    cp -a "$PACKAGE_SOURCE/." "$package/"
    chmod 0755 "$package" "$package"/*.sh "$package/receive-artifact.py"
    printf '%s\n' "$package"
}

invoke_installer() {
    local label="$1"
    local package="$2"
    shift 2
    rm -rf "$TMP_DIR/local" "$TMP_DIR/var-lib"
    mkdir -p "$TMP_DIR/local/bin" "$TMP_DIR/local/lib" "$TMP_DIR/var-lib"
    chmod 0755 "$TMP_DIR/local" "$TMP_DIR/local/bin" "$TMP_DIR/local/lib" "$TMP_DIR/var-lib"
    output="$TMP_DIR/$label.out"
    status=0
    set +e
    /usr/bin/bwrap \
        --unshare-user --uid 0 --gid 0 \
        --unshare-pid \
        --ro-bind / / \
        --bind "$TMP_DIR/local" /usr/local \
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
        --bind "$TMP_DIR/local" /usr/local \
        --bind "$TMP_DIR/var-lib" /var/lib \
        --dev /dev \
        --proc /proc \
        /usr/bin/stat -c '%u:%g:%a:%F' \
        /usr/local/lib/celerity/relay-l2tp \
        /usr/local/lib/celerity/relay-l2tp/runner.sh \
        /usr/local/lib/celerity/relay-l2tp/receive-artifact.py \
        /usr/local/lib/celerity/relay-l2tp/verify-users.sh \
        /var/lib/celerity/l2tp/operations
}

assert_no_payload_was_copied() {
    local label="$1"
    [[ ! -e "$RECEIVER_LINK" && ! -L "$RECEIVER_LINK" ]] \
        || fail "$label published the receiver link"
    [[ ! -e "$RUNNER_LINK" && ! -L "$RUNNER_LINK" ]] \
        || fail "$label published the runner link"
    if [[ -d "$LIB_DIR" ]]; then
        [[ -z "$(find "$LIB_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
            || fail "$label copied a payload before package validation completed"
    fi
}

[[ -x "$PACKAGE_SOURCE/install.sh" ]] || fail 'node artifact installer is missing or not executable'
[[ -x "$PACKAGE_SOURCE/receive-artifact.py" ]] || fail 'receiver source is missing or not executable'

package="$(make_package_fixture valid-package)"
invoke_installer valid "$package"
[[ "$status" -eq 0 ]] || fail "valid package installation failed: $(<"$output")"
[[ "$(<"$output")" == '{"status":"ok"}' ]] || fail 'installer returned unexpected output'
[[ -L "$RECEIVER_LINK" ]] || fail 'receiver was not linked at the fixed target'
[[ "$(readlink "$RECEIVER_LINK")" == '../lib/celerity/relay-l2tp/receive-artifact.py' ]] \
    || fail 'receiver fixed link has the wrong target'
[[ -L "$RUNNER_LINK" ]] || fail 'runner was not linked at the fixed target'
[[ "$(readlink "$RUNNER_LINK")" == '../lib/celerity/relay-l2tp/runner.sh' ]] \
    || fail 'runner fixed link has the wrong target'
for payload in "${PAYLOADS[@]}"; do
    [[ -f "$LIB_DIR/$payload" && ! -L "$LIB_DIR/$payload" ]] \
        || fail "$payload was not installed in the module library"
    [[ "$(sha256sum "$package/$payload" | cut -d ' ' -f 1)" == \
       "$(sha256sum "$LIB_DIR/$payload" | cut -d ' ' -f 1)" ]] \
        || fail "installed $payload digest differs from the fixed package artifact"
done
mapfile -t metadata < <(inspect_installed_metadata)
[[ "${metadata[0]}" == '0:0:755:directory' ]] \
    || fail 'module library is not an exact root-owned mode 0755 directory'
[[ "${metadata[1]}" == '0:0:755:regular file' ]] \
    || fail 'runner is not an exact root-owned mode 0755 executable'
[[ "${metadata[2]}" == '0:0:755:regular file' ]] \
    || fail 'receiver is not an exact root-owned mode 0755 executable'
[[ "${metadata[3]}" == '0:0:755:regular file' ]] \
    || fail 'user verifier is not an exact root-owned mode 0755 executable'
[[ "${metadata[4]}" == '0:0:700:directory' ]] \
    || fail 'operations root is not an exact root-owned mode 0700 directory'

for payload in "${PAYLOADS[@]}"; do
    package="$(make_package_fixture "tampered-${payload//[^A-Za-z0-9]/-}")"
    printf '\n# tampered\n' >>"$package/$payload"
    invoke_installer "tampered-${payload//[^A-Za-z0-9]/-}" "$package"
    [[ "$status" -ne 0 ]] || fail "tampered $payload was accepted"
    [[ "$(<"$output")" == '{"status":"error","code":"INVALID_PACKAGE"}' ]] \
        || fail "tampered $payload returned an unsanitized error"
    assert_no_payload_was_copied "tampered $payload"
done

package="$(make_package_fixture insecure-package)"
chmod 0775 "$package/receive-artifact.py"
invoke_installer insecure "$package"
[[ "$status" -ne 0 ]] || fail 'insecure receiver permissions were accepted'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_PACKAGE"}' ]] \
    || fail 'insecure package returned an unsanitized error'
assert_no_payload_was_copied 'insecure receiver'

package="$(make_package_fixture arguments-package)"
invoke_installer arguments "$package" --target "$TMP_DIR/arbitrary"
[[ "$status" -ne 0 ]] || fail 'arbitrary installer arguments were accepted'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'arbitrary installer arguments returned the wrong error'
[[ ! -e "$TMP_DIR/arbitrary" ]] || fail 'an arbitrary install target was created'
assert_no_payload_was_copied 'invalid arguments'

printf 'node artifact installer fixture tests passed\n'
