#!/usr/bin/env bash
set -Eeuo pipefail

emit_error() {
    local code="$1"
    printf '{"status":"error","code":"%s"}\n' "$code" >&2
}

if [[ "$#" -ne 1 ]]; then
    emit_error 'INVALID_ARGUMENTS'
    exit 64
fi

readonly OPERATION_DIR="$1"
readonly ROOT_PATH="${CELERITY_L2TP_ROOT:-/}"
readonly XRAY_CONFIG_PATH="${ROOT_PATH%/}/usr/local/etc/xray/config.json"
readonly PRIORITY='10077'
readonly NFT_FAMILY='inet'
readonly NFT_TABLE='celerity_l2tp'

parsed="$(python3 - "$OPERATION_DIR" "$ROOT_PATH" <<'PY'
import json
import os
import stat
import sys

operation_path, root_path = sys.argv[1:]
dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
file_flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, 'O_NOFOLLOW'):
    dir_flags |= os.O_NOFOLLOW
    file_flags |= os.O_NOFOLLOW


def read_json(parent, name):
    descriptor = os.open(name, file_flags, dir_fd=parent)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_size > 1024 * 1024:
            raise RuntimeError('invalid input')
        with os.fdopen(descriptor, encoding='utf-8') as handle:
            descriptor = -1
            return json.load(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


operation = os.open(operation_path, dir_flags)
root = os.open(root_path, dir_flags)
try:
    if os.fstat(operation).st_uid != 0 or os.fstat(root).st_uid != 0:
        raise RuntimeError('ownership')
    desired = read_json(operation, 'desired.json')
    state = os.open('state', dir_flags, dir_fd=operation)
    try:
        if os.fstat(state).st_uid != 0:
            raise RuntimeError('state ownership')
        marker = read_json(state, 'firewall.applied.json')
    finally:
        os.close(state)
finally:
    os.close(root)
    os.close(operation)

fwmark = desired.get('fwmark')
route_table = desired.get('routeTable')
priority = marker.get('priority')
if any(type(value) is not int or not 1 <= value <= 2**31 - 1 for value in (fwmark, route_table, priority)):
    raise RuntimeError('routing values')
if marker.get('fwmark') != fwmark or marker.get('routeTable') != route_table or priority != 10077:
    raise RuntimeError('firewall ownership mismatch')
print(f'{fwmark} {route_table}')
PY
)" || {
    emit_error 'VERIFY_STATE_INVALID'
    exit 66
}
read -r fwmark route_table <<<"$parsed"

if [[ ! -f "$XRAY_CONFIG_PATH" || -L "$XRAY_CONFIG_PATH" ]]; then
    emit_error 'XRAY_CONFIG_INVALID'
    exit 66
fi

xray_path="$(command -v xray || true)"
systemctl_path="$(command -v systemctl || true)"
nft_path="$(command -v nft || true)"
ip_path="$(command -v ip || true)"
if [[ -z "$xray_path" || -z "$systemctl_path" || -z "$nft_path" || -z "$ip_path" ]]; then
    emit_error 'RUNTIME_COMMAND_MISSING'
    exit 69
fi

if ! "$xray_path" run -test -config "$XRAY_CONFIG_PATH" >/dev/null 2>&1; then
    emit_error 'XRAY_VERIFY_FAILED'
    exit 70
fi
for unit in xray.service strongswan-starter.service xl2tpd.service; do
    if ! "$systemctl_path" is-active --quiet "$unit" >/dev/null 2>&1; then
        emit_error 'SERVICE_VERIFY_FAILED'
        exit 70
    fi
done
if ! "$nft_path" list table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1; then
    emit_error 'NFT_VERIFY_FAILED'
    exit 70
fi
rule_state="$($ip_path -4 rule show priority "$PRIORITY" 2>/dev/null || true)"
if ! RULE_STATE="$rule_state" python3 - "$fwmark" "$route_table" "$PRIORITY" <<'PY'
import os
import re
import sys

fwmark, route_table, priority = (int(value) for value in sys.argv[1:])
for line in os.environ.get('RULE_STATE', '').splitlines():
    priority_match = re.match(r'^\s*(\d+):(?:\s|$)', line)
    mark_match = re.search(r'(?:^|\s)fwmark\s+(\S+)(?:\s|$)', line)
    table_match = re.search(r'(?:^|\s)(?:lookup|table)\s+(\d+)(?:\s|$)', line)
    if priority_match is None or mark_match is None or table_match is None:
        continue
    try:
        installed_mark = int(mark_match.group(1), 0)
    except ValueError:
        continue
    if int(priority_match.group(1)) == priority and installed_mark == fwmark and int(table_match.group(1)) == route_table:
        raise SystemExit(0)
raise SystemExit(1)
PY
then
    emit_error 'IP_RULE_VERIFY_FAILED'
    exit 70
fi
route_state="$($ip_path -4 route show table "$route_table" type local 2>/dev/null || true)"
if [[ -z "$route_state" || "$route_state" != *'local 0.0.0.0/0'* ]]; then
    emit_error 'IP_ROUTE_VERIFY_FAILED'
    exit 70
fi

if ! python3 - "$OPERATION_DIR" "$fwmark" "$route_table" "$PRIORITY" <<'PY'
import json
import os
import secrets
import sys

operation_path, fwmark, route_table, priority = sys.argv[1:]
dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
if hasattr(os, 'O_NOFOLLOW'):
    dir_flags |= os.O_NOFOLLOW
operation = os.open(operation_path, dir_flags)
try:
    state = os.open('state', dir_flags, dir_fd=operation)
    try:
        payload = json.dumps({
            'fwmark': int(fwmark),
            'routeTable': int(route_table),
            'priority': int(priority),
            'namespace': 'celerity_l2tp',
        }, separators=(',', ':')).encode('ascii')
        temporary = f'.verified.{secrets.token_hex(12)}'
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600, dir_fd=state)
        try:
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, 0, 0)
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary, 'verified.json', src_dir_fd=state, dst_dir_fd=state)
            os.fsync(state)
        finally:
            try:
                os.unlink(temporary, dir_fd=state)
            except FileNotFoundError:
                pass
    finally:
        os.close(state)
finally:
    os.close(operation)
PY
then
    emit_error 'VERIFY_STATE_RECORD_FAILED'
    exit 74
fi

printf '%s\n' '{"status":"ok","checks":7,"namespace":"celerity_l2tp"}'
