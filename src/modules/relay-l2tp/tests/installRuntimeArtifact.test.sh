#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/install-runtime.sh"
ORIGINAL_PATH="$PATH"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_installer() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    set +e
    PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
        INSTALLED_PACKAGES_FILE="$TMP_DIR/installed-packages" \
        DPKG_CALL_LOG="$TMP_DIR/dpkg-calls.log" \
        APT_CALL_LOG="$TMP_DIR/apt-call.log" \
        "$ARTIFACT" "$@" >"$output" 2>&1
    status=$?
    set -e
}

[[ -x "$ARTIFACT" ]] || fail 'runtime installer artifact is missing or not executable'
mkdir -p "$TMP_DIR/bin"
printf '%s\n' ppp nftables >"$TMP_DIR/installed-packages"

cat >"$TMP_DIR/bin/dpkg-query" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$@" >>"$DPKG_CALL_LOG"
package="${*: -1}"
if grep -Fqx -- "$package" "$INSTALLED_PACKAGES_FILE"; then
    printf '%s' 'ii '
    exit 0
fi
exit 1
STUB
chmod +x "$TMP_DIR/bin/dpkg-query"

cat >"$TMP_DIR/bin/apt-get" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
{
    printf 'DEBIAN_FRONTEND=%s\n' "${DEBIAN_FRONTEND-}"
    printf '%s\n' "$@"
} >"$APT_CALL_LOG"
[[ "${DEBIAN_FRONTEND-}" == 'noninteractive' ]] || exit 91
[[ "$#" -eq 6 ]] || exit 92
[[ "$1" == '--yes' && "$2" == '--no-install-recommends' && "$3" == '--no-remove' && "$4" == 'install' ]] || exit 93
[[ "$5" == 'strongswan' && "$6" == 'xl2tpd' ]] || exit 94
printf '%s\n' strongswan xl2tpd >>"$INSTALLED_PACKAGES_FILE"
STUB
chmod +x "$TMP_DIR/bin/apt-get"

invoke_installer install
[[ "$status" -eq 0 ]] || fail 'runtime installation failed'
[[ "$(<"$output")" == '{"status":"ok","changed":2,"present":4}' ]] \
    || fail 'runtime installation returned the wrong structured result'
mapfile -t apt_call <"$TMP_DIR/apt-call.log"
[[ "${apt_call[0]}" == 'DEBIAN_FRONTEND=noninteractive' ]] \
    || fail 'apt was not noninteractive'
[[ "${apt_call[*]:1}" == '--yes --no-install-recommends --no-remove install strongswan xl2tpd' ]] \
    || fail 'apt received anything except the fixed necessary package set and options'

rm -f "$TMP_DIR/apt-call.log"
invoke_installer idempotent
[[ "$status" -eq 0 ]] || fail 'idempotent runtime check failed'
[[ "$(<"$output")" == '{"status":"ok","changed":0,"present":4}' ]] \
    || fail 'idempotent runtime check returned the wrong structured result'
[[ ! -e "$TMP_DIR/apt-call.log" ]] || fail 'idempotent runtime check invoked apt'

invoke_installer arbitrary-argument '--allow-unauthenticated'
[[ "$status" -ne 0 ]] || fail 'runtime installer accepted an arbitrary apt argument'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'arbitrary argument returned the wrong structured error'
[[ ! -e "$TMP_DIR/apt-call.log" ]] || fail 'rejected argument invoked apt'

printf 'runtime installer artifact fixture tests passed\n'
