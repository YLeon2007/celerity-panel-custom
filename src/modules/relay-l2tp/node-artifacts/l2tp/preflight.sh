#!/usr/bin/env bash
set -Eeuo pipefail

readonly OS_RELEASE_PATH="${CELERITY_PREFLIGHT_OS_RELEASE_PATH:-/etc/os-release}"
readonly XRAY_CONFIG_PATH="${CELERITY_PREFLIGHT_XRAY_CONFIG_PATH:-/usr/local/etc/xray/config.json}"
readonly XRAY_UNIT_NAME='xray.service'

json_escape() {
    local value="${1-}"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '%s' "$value"
}

emit_error() {
    local check="$1" code="$2"
    printf '{"check":"%s","status":"error","code":"%s"}\n' \
        "$(json_escape "$check")" "$(json_escape "$code")"
}

if [[ "$#" -ne 1 ]]; then
    emit_error 'input' 'INVALID_ARGUMENTS'
    exit 64
fi

readonly DESIRED_STATE_PATH="$1"
if [[ ! -f "$DESIRED_STATE_PATH" || ! -r "$DESIRED_STATE_PATH" ]]; then
    emit_error 'desired_state' 'INVALID_DESIRED_STATE_FILE'
    exit 66
fi
if [[ "$(stat --format='%u' -- "$DESIRED_STATE_PATH" 2>/dev/null || true)" != '0' ]]; then
    emit_error 'desired_state' 'DESIRED_STATE_NOT_ROOT_OWNED'
    exit 77
fi

os_release="$(cat -- "$OS_RELEASE_PATH" 2>/dev/null || true)"
os_id=''
os_version=''
while IFS='=' read -r key value; do
    case "$key" in
        ID) os_id="${value#\"}"; os_id="${os_id%\"}" ;;
        VERSION_ID) os_version="${value#\"}"; os_version="${os_version%\"}" ;;
    esac
done <<<"$os_release"
case "$os_id" in
    debian|ubuntu)
        printf '{"check":"os","status":"ok","id":"%s","version":"%s"}\n' \
            "$(json_escape "$os_id")" "$(json_escape "$os_version")"
        ;;
    *)
        printf '{"check":"os","status":"error","code":"UNSUPPORTED_OS","id":"%s","version":"%s"}\n' \
            "$(json_escape "$os_id")" "$(json_escape "$os_version")"
        exit 69
        ;;
esac

client_cidr="$(python3 - "$DESIRED_STATE_PATH" <<'PY'
import ipaddress
import json
import sys
try:
    data = json.load(open(sys.argv[1], encoding='utf-8'))
    value = data.get('clientCidr')
    network = ipaddress.IPv4Network(value, strict=True)
    if str(network) != value:
        raise ValueError('non-canonical')
    print(value)
except Exception:
    raise SystemExit(1)
PY
)" || {
    emit_error 'desired_state' 'INVALID_CLIENT_CIDR'
    exit 65
}
printf '{"check":"client_cidr","status":"ok","cidr":"%s"}\n' "$(json_escape "$client_cidr")"

xray_path="$(command -v xray || true)"
if [[ -z "$xray_path" ]]; then
    emit_error 'xray' 'XRAY_BINARY_MISSING'
    exit 70
fi
xray_version="$($xray_path version 2>/dev/null | sed -n '1p' || true)"
if [[ -z "$xray_version" ]]; then
    emit_error 'xray' 'XRAY_VERSION_UNAVAILABLE'
    exit 70
fi
printf '{"check":"xray","status":"ok","version":"%s"}\n' "$(json_escape "$xray_version")"

if [[ ! -f "$XRAY_CONFIG_PATH" || ! -r "$XRAY_CONFIG_PATH" ]]; then
    emit_error 'xray_config' 'XRAY_CONFIG_MISSING'
    exit 71
fi
if ! "$xray_path" run -test -config "$XRAY_CONFIG_PATH" >/dev/null 2>&1; then
    emit_error 'xray_config' 'XRAY_CONFIG_INVALID'
    exit 71
fi
printf '{"check":"xray_config","status":"ok","path":"%s"}\n' "$(json_escape "$XRAY_CONFIG_PATH")"

unit_state="$(systemctl show "$XRAY_UNIT_NAME" --property=LoadState --value 2>/dev/null || true)"
if [[ "$unit_state" != 'loaded' ]]; then
    emit_error 'xray_unit' 'XRAY_UNIT_MISSING'
    exit 72
fi
printf '{"check":"xray_unit","status":"ok","unit":"%s"}\n' "$XRAY_UNIT_NAME"
