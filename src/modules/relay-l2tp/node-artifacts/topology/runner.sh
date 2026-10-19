#!/usr/bin/env bash
# Protocol v2: the Python supervisor is the only entry point. The shell payload
# below is read as data, never entered through an environment/CLI bypass.
# A timeout is NOT cancellation. No automatic lease expiry or journal recovery.
exec /usr/bin/python3 /dev/fd/3 "$0" "$@" 3<<'FENCE_PY'
import fcntl
import json
import os
import re
import stat
import subprocess
import sys

MAX_JOURNAL_BYTES = 4194304
MAX_GENERATIONS = 1024


def refuse(code, status=75):
    print(json.dumps(dict(ok=False, code=code, outcome='unknown', ownershipRetained=True),
                     separators=(',', ':')), file=sys.stderr)
    raise SystemExit(status)


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def durable(directory, value):
    serialized = json.dumps(value, separators=(',', ':'), sort_keys=True) + '\n'
    if len(serialized.encode()) > MAX_JOURNAL_BYTES:
        refuse('JOURNAL_CAPACITY_RETAINED')
    temporary = os.path.join(directory, 'journal.next')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(serialized)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, os.path.join(directory, 'journal.json'))
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def directory(path):
    try:
        os.mkdir(path, 0o700)
        parent = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        refuse('UNSAFE_FENCE_ROOT')


def sync_artifacts(state, binding, config):
    # Completion is never published before the candidate, rollback snapshot,
    # metadata and active config (including absent-directory entries) are synced.
    roots = [state + '/operations/' + binding['operationId'] + '/' + binding['targetProfile'],
             state + '/backups/' + binding['backupId'] + '/' + binding['targetProfile']]
    for root in roots:
        if not os.path.exists(root):
            continue
        for parent, directories, files in os.walk(root, followlinks=False):
            for name in files + directories:
                target = os.path.join(parent, name)
                fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        parent = root
        while parent != state:
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            parent = os.path.dirname(parent)
    for target in ([config] if os.path.lexists(config) else []) + [os.path.dirname(config), state]:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def main():
    script, *args = sys.argv[1:]
    names = ['command', 'operation-id', 'node-id', 'candidate-hash', 'backup-id', 'target-profile',
             'execution-context', 'attempt-id', 'generation', 'predecessor-generation', 'command-id']
    if len(args) not in (22, 24) or args[::2] != ['--' + n for n in names] + (['--checks'] if len(args) == 24 else []):
        refuse('FENCE_REQUIRED', 64)
    request = dict(zip(names + ['checks'], args[1::2]))
    command = request['command']
    if command not in ('prepare', 'commit', 'verify', 'rollback', 'close', 'status'):
        refuse('UNSUPPORTED_FENCED_COMMAND', 64)
    safe = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
    for key in ('operation-id', 'node-id', 'backup-id', 'attempt-id', 'generation', 'predecessor-generation', 'command-id'):
        if not safe.fullmatch(request[key]) or request[key] in ('.', '..'):
            refuse('INVALID_IDENTITY', 65)
    if request['generation'] == 'none' or not re.fullmatch(r'sha256:[a-f0-9]{64}', request['candidate-hash']):
        refuse('INVALID_IDENTITY', 65)
    if request['target-profile'] not in ('xray-main', 'xray-bridge') or request['execution-context'] not in ('test.infograd.online', 'lm1.infograd.online'):
        refuse('INVALID_EXECUTION_CONTEXT', 65)
    if ('checks' in request) != (command == 'verify'):
        refuse('INVALID_ARGUMENTS', 64)
    root = os.environ.get('CELERITY_TOPOLOGY_ROOT', '')
    if root and (not root.startswith('/') or root == '/' or any(p in ('.', '..', '') for p in root.split('/')[1:])):
        refuse('INVALID_ROOT', 73)
    # Production ancestors are trusted root-owned provisioning paths. Fake-root
    # tests use the same no-symlink rule, including all ancestors of that root.
    path = ''
    for part in (root + '/var/lib').split('/')[1:]:
        path += '/' + part
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            refuse('UNSAFE_FENCE_ROOT')
    state = root + '/var/lib/celerity/topology'
    for path in (root + '/var/lib/celerity', state, state + '/fences', state + '/fences/' + request['target-profile']):
        directory(path)
    fence = path
    try:
        lock = os.open(fence + '/lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        fresh_lock = True
    except FileExistsError:
        lock = os.open(fence + '/lock', os.O_RDWR | os.O_NOFOLLOW)
        fresh_lock = False
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        refuse('COMMAND_IN_FLIGHT')
    # Keep the lock fd inherited by every shell child; killing only this local
    # supervisor cannot release the mutex while an inherited child still runs.
    boot_path = root + '/proc/sys/kernel/random/boot_id'
    with open(boot_path) as handle:
        boot = handle.read().strip()
    if not safe.fullmatch(boot):
        refuse('BOOT_ID_UNAVAILABLE')
    keys = dict(zip(names[1:6] + names[6:10],
                    ['operationId', 'nodeId', 'candidateHash', 'backupId', 'targetProfile',
                     'executionContext', 'attemptId', 'generation', 'predecessorGeneration']))
    binding = {value: request[key] for key, value in keys.items()}
    journal_path = fence + '/journal.json'
    if os.path.lexists(fence + '/journal.next'):
        refuse('JOURNAL_UNCERTAIN')
    if os.path.lexists(journal_path):
        fd = os.open(journal_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as handle:
            if os.fstat(handle.fileno()).st_size > MAX_JOURNAL_BYTES:
                refuse('JOURNAL_CAPACITY_RETAINED')
            journal = json.load(handle, object_pairs_hook=unique)
        if set(journal) != {'version', 'bootId', 'nodeId', 'executionContext', 'head', 'generations'} or journal['version'] != 2:
            refuse('JOURNAL_UNCERTAIN')
        if journal['bootId'] != boot:
            refuse('BOOT_CHANGED_UNCERTAIN')
        if journal['nodeId'] != binding['nodeId'] or journal['executionContext'] != binding['executionContext']:
            refuse('FENCE_BINDING_MISMATCH')
    else:
        if not fresh_lock:
            refuse('JOURNAL_UNCERTAIN')
        # Never silently adopt pre-v2 receipts as proof of remote quiescence.
        for legacy in ('operations', 'backups'):
            legacy_root = state + '/' + legacy
            if os.path.lexists(legacy_root):
                if not stat.S_ISDIR(os.lstat(legacy_root).st_mode):
                    refuse('LEGACY_STATE_UNPROVEN')
                for entry in os.scandir(legacy_root):
                    if entry.is_symlink() or os.path.lexists(entry.path + '/' + binding['targetProfile']):
                        refuse('LEGACY_STATE_UNPROVEN')
        journal = dict(version=2, bootId=boot, nodeId=binding['nodeId'],
                       executionContext=binding['executionContext'], head=None, generations={})
        durable(fence, journal)  # Fresh fence must leave a recoverable journal before any result.
    generations = journal['generations']
    generation = binding['generation']
    current = generations.get(generation)
    command_id = request['command-id']
    if current is not None and current['binding'] != binding:
        refuse('FENCE_BINDING_MISMATCH')
    if command == 'status':
        if current is None:
            refuse('UNKNOWN_COMMAND_OUTCOME')
        record = current['commands'].get(command_id)
        if record is None or record['state'] != 'completed':
            refuse('UNKNOWN_COMMAND_OUTCOME')
        print(json.dumps(dict(record['receipt'], command='status'), separators=(',', ':')))
        return
    if current is not None and current['phase'] == 'closed':
        refuse('GENERATION_CLOSED')
    if any(command_id in record['commands'] for record in generations.values()):
        refuse('COMMAND_REUSE')
    if current is None:
        if len(generations) >= MAX_GENERATIONS:
            refuse('JOURNAL_CAPACITY_RETAINED')
        if command not in ('prepare', 'close'):
            refuse('GENERATION_NOT_PREPARED')
        head = journal['head']
        if head is not None and generations[head]['phase'] != 'closed':
            refuse('OWNERSHIP_RETAINED')
        if binding['predecessorGeneration'] != (head or 'none'):
            refuse('STALE_PREDECESSOR')
        current = dict(binding=binding, phase='new', commands={})
        generations[generation] = current
        journal['head'] = generation
    if journal['head'] != generation:
        refuse('STALE_GENERATION')
    if any(r['state'] != 'completed' for r in current['commands'].values()):
        refuse('UNKNOWN_COMMAND_OUTCOME')
    allowed = dict(prepare=('new',), commit=('prepared',), verify=('committed',),
                   rollback=('prepared', 'committed', 'verified'),
                   close=('new', 'prepared', 'verified', 'rolledback'))
    if current['phase'] not in allowed[command]:
        refuse('INVALID_PHASE')
    previous_phase = current['phase']
    current['phase'] = command + '-running'
    current['commands'][command_id] = dict(state='running', command=command)
    durable(fence, journal)  # Write-ahead: any crash now permanently retains it.
    with open(script) as handle:
        payload = handle.read().split('# BEGIN_FENCED_SHELL_PAYLOAD\n', 1)[1]
    legacy_args = args[:12]
    if command == 'verify':
        legacy_args += ['--checks', request['checks']]
    expected = dict(ok=True, command=command, **{k: binding[k] for k in
                    ('operationId', 'nodeId', 'candidateHash', 'backupId', 'targetProfile')})
    if command != 'close':
        result = subprocess.run(['/bin/bash', '-c', payload, script, *legacy_args],
                                stdin=sys.stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                pass_fds=(lock,))
        if (result.returncode != 0 or result.stderr or
                result.stdout != (json.dumps(expected, separators=(',', ':')) + '\n').encode()):
            refuse('COMMAND_OUTCOME_UNKNOWN')
    # Blocking systemctl alone is not the proof: also observe no outstanding
    # unit job and the exact resulting state under the same exclusive fence.
    job, service_state = 'not-applicable', 'not-applicable'
    service = 'xray.service' if binding['targetProfile'] == 'xray-main' else 'xray-bridge.service'
    config = root + '/usr/local/etc/' + ('xray' if binding['targetProfile'] == 'xray-main' else 'xray-bridge') + '/config.json'
    if command in ('commit', 'verify', 'rollback') or (command == 'close' and previous_phase in ('verified', 'rolledback')):
        observation = subprocess.run([root + '/usr/bin/systemctl', 'show', '--property=Job',
                                      '--property=ActiveState', '--property=SubState', '--', service],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(lock,))
        stopped = command == 'rollback' and not os.path.exists(config)
        if command == 'close':
            stopped = current['serviceState'] == 'inactive:dead'
        expected_state = ('inactive', 'dead') if stopped else ('active', 'running')
        lines = observation.stdout.decode().splitlines()
        if (observation.returncode != 0 or observation.stderr or len(lines) != 3 or
                set(lines) != {'Job=', 'ActiveState=' + expected_state[0], 'SubState=' + expected_state[1]}):
            refuse('SYSTEMD_COMPLETION_UNPROVEN')
        job, service_state = 'completed', ':'.join(expected_state)
    if command != 'close':
        sync_artifacts(state, binding, config)
    current['phase'] = dict(prepare='prepared', commit='committed', verify='verified',
                            rollback='rolledback', close='closed')[command]
    receipt = dict(expected, **{k: binding[k] for k in
                   ('executionContext', 'attemptId', 'generation', 'predecessorGeneration')},
                   commandId=command_id, protocolVersion=2, completion='completed',
                   phase=current['phase'], terminal=command == 'close', ownershipRetained=True,
                   terminalOutcome=(previous_phase if previous_phase in ('verified', 'rolledback') else 'cancelled') if command == 'close' else 'not-terminal',
                   bootId=boot, systemdJob=job, serviceState=service_state,
                   completedCommand=command)
    current['serviceState'] = service_state
    current['commands'][command_id] = dict(state='completed', command=command, receipt=receipt)
    durable(fence, journal)
    print(json.dumps(receipt, separators=(',', ':')))


try:
    main()
except SystemExit:
    raise
except BaseException:
    refuse('JOURNAL_UNCERTAIN')
FENCE_PY
# BEGIN_FENCED_SHELL_PAYLOAD
set -Eeuo pipefail
umask 077

readonly STATE_RELATIVE_ROOT='var/lib/celerity/topology'
readonly MAX_CANDIDATE_BYTES=4194304
TEMPORARY_FILE=''

emit_error() {
    local code="$1"
    printf '{"ok":false,"code":"%s"}\n' "$code" >&2
}

fail() {
    local code="$1"
    local status="$2"
    emit_error "$code"
    exit "$status"
}

cleanup() {
    if [[ -n "$TEMPORARY_FILE" ]]; then
        /usr/bin/rm -f -- "$TEMPORARY_FILE" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if [[ ( "$#" -ne 12 && "$#" -ne 14 ) \
    || "$1" != '--command' \
    || "$3" != '--operation-id' \
    || "$5" != '--node-id' \
    || "$7" != '--candidate-hash' \
    || "$9" != '--backup-id' \
    || "${11}" != '--target-profile' ]]; then
    fail 'INVALID_ARGUMENTS' 64
fi

readonly COMMAND="$2"
readonly OPERATION_ID="$4"
readonly NODE_ID="$6"
readonly CANDIDATE_HASH="$8"
readonly BACKUP_ID="${10}"
readonly TARGET_PROFILE="${12}"
readonly CHECKS_TOKEN="${14-}"
readonly SAFE_ID_PATTERN='^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
readonly HASH_PATTERN='^sha256:[a-f0-9]{64}$'

[[ "$COMMAND" =~ ^(prepare|commit|verify|rollback)$ ]] \
    || fail 'UNKNOWN_COMMAND' 64
if [[ "$COMMAND" == 'verify' ]]; then
    [[ "$#" -eq 14 && "${13}" == '--checks' ]] \
        || fail 'INVALID_ARGUMENTS' 64
else
    [[ "$#" -eq 12 ]] || fail 'INVALID_ARGUMENTS' 64
fi
[[ "$OPERATION_ID" =~ $SAFE_ID_PATTERN \
    && "$NODE_ID" =~ $SAFE_ID_PATTERN \
    && "$BACKUP_ID" =~ $SAFE_ID_PATTERN ]] \
    || fail 'INVALID_IDENTITY' 65
[[ "$CANDIDATE_HASH" =~ $HASH_PATTERN ]] \
    || fail 'INVALID_CANDIDATE_HASH' 65

ROOT_PREFIX="${CELERITY_TOPOLOGY_ROOT:-}"
if [[ -n "$ROOT_PREFIX" ]]; then
    [[ "$ROOT_PREFIX" == /* \
        && "$ROOT_PREFIX" != '/' \
        && "$ROOT_PREFIX" != *'/../'* \
        && "$ROOT_PREFIX" != */.. \
        && "$ROOT_PREFIX" != *'/./'* \
        && "$ROOT_PREFIX" != */. ]] \
        || fail 'INVALID_ROOT' 73
    ROOT_PREFIX="${ROOT_PREFIX%/}"
fi
readonly ROOT_PREFIX

case "$TARGET_PROFILE" in
    xray-main)
        readonly CONFIG_PATH="$ROOT_PREFIX/usr/local/etc/xray/config.json"
        readonly SERVICE_NAME='xray.service'
        ;;
    xray-bridge)
        readonly CONFIG_PATH="$ROOT_PREFIX/usr/local/etc/xray-bridge/config.json"
        readonly SERVICE_NAME='xray-bridge.service'
        ;;
    *)
        fail 'UNKNOWN_TARGET_PROFILE' 65
        ;;
esac

readonly STATE_ROOT="$ROOT_PREFIX/$STATE_RELATIVE_ROOT"
readonly OPERATION_DIR="$STATE_ROOT/operations/$OPERATION_ID/$TARGET_PROFILE"
readonly BACKUP_DIR="$STATE_ROOT/backups/$BACKUP_ID/$TARGET_PROFILE"
readonly CANDIDATE_PATH="$OPERATION_DIR/candidate.json"
readonly OPERATION_METADATA="$OPERATION_DIR/receipt.fields"
readonly BACKUP_METADATA="$BACKUP_DIR/receipt.fields"
readonly BACKUP_CONFIG="$BACKUP_DIR/config.json"
readonly BACKUP_ABSENT="$BACKUP_DIR/config.absent"
readonly XRAY_PATH="$ROOT_PREFIX/usr/local/bin/xray"
readonly XRAY_ASSET_DIR="$ROOT_PREFIX/usr/local/share/xray"
readonly SYSTEMCTL_PATH="$ROOT_PREFIX/usr/bin/systemctl"
readonly SS_PATH="$ROOT_PREFIX/usr/bin/ss"

emit_receipt() {
    printf '{"ok":true,"command":"%s","operationId":"%s","nodeId":"%s","candidateHash":"%s","backupId":"%s","targetProfile":"%s"}\n' \
        "$COMMAND" \
        "$OPERATION_ID" \
        "$NODE_ID" \
        "$CANDIDATE_HASH" \
        "$BACKUP_ID" \
        "$TARGET_PROFILE"
}

write_metadata() {
    local target="$1"
    {
        printf 'operationId=%s\n' "$OPERATION_ID"
        printf 'nodeId=%s\n' "$NODE_ID"
        printf 'candidateHash=%s\n' "$CANDIDATE_HASH"
        printf 'backupId=%s\n' "$BACKUP_ID"
        printf 'targetProfile=%s\n' "$TARGET_PROFILE"
    } >"$target" || fail 'STATE_WRITE_FAILED' 70
    /usr/bin/chmod 0600 -- "$target" >/dev/null 2>&1 \
        || fail 'STATE_WRITE_FAILED' 70
}

metadata_matches() {
    local target="$1"
    local -a fields=()
    [[ -f "$target" && ! -L "$target" ]] || return 1
    mapfile -t fields <"$target" || return 1
    [[ "${#fields[@]}" -eq 5 \
        && "${fields[0]}" == "operationId=$OPERATION_ID" \
        && "${fields[1]}" == "nodeId=$NODE_ID" \
        && "${fields[2]}" == "candidateHash=$CANDIDATE_HASH" \
        && "${fields[3]}" == "backupId=$BACKUP_ID" \
        && "${fields[4]}" == "targetProfile=$TARGET_PROFILE" ]]
}

file_hash_matches() {
    local target="$1"
    local digest_line digest
    [[ -f "$target" && ! -L "$target" ]] || return 1
    digest_line="$(/usr/bin/sha256sum -- "$target" 2>/dev/null)" || return 1
    digest="${digest_line%% *}"
    [[ "sha256:$digest" == "$CANDIDATE_HASH" ]]
}

candidate_structure_valid() {
    local target="$1"
    /usr/bin/python3 - "$target" >/dev/null 2>&1 <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, 'rb') as handle:
    raw = handle.read()
document = json.loads(raw.decode('utf-8'))
if not isinstance(document, dict):
    raise SystemExit(1)
if not isinstance(document.get('inbounds'), list):
    raise SystemExit(1)
if not isinstance(document.get('outbounds'), list):
    raise SystemExit(1)
canonical = json.dumps(
    document,
    ensure_ascii=False,
    separators=(',', ':'),
).encode('utf-8') + b'\n'
if raw != canonical:
    raise SystemExit(1)
PY
}

parse_checks() {
    /usr/bin/python3 - "$CHECKS_TOKEN" "$SERVICE_NAME" <<'PY'
import base64
import json
import re
import sys


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate key')
        value[key] = item
    return value


def reject_constant(_value):
    raise ValueError('invalid number')


token, service_name = sys.argv[1:]
if re.fullmatch(r'[A-Za-z0-9_-]+', token) is None:
    raise SystemExit(1)
try:
    raw = base64.b64decode(
        token + ('=' * (-len(token) % 4)),
        altchars=b'-_',
        validate=True,
    )
    if base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=') != token:
        raise ValueError('non-canonical base64url')
    checks = json.loads(
        raw.decode('utf-8'),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
if type(checks) is not list:
    raise SystemExit(1)
for check in checks:
    if type(check) is not dict or type(check.get('type')) is not str:
        raise SystemExit(1)
    if check['type'] == 'service':
        if (set(check) != {'type', 'serviceUnit', 'expectedState'}
                or check.get('serviceUnit') != service_name
                or check.get('expectedState') != 'active'):
            raise SystemExit(1)
        continue
    if check['type'] == 'port':
        port = check.get('port')
        if (set(check) != {'type', 'protocol', 'port', 'expectedState'}
                or check.get('protocol') != 'tcp'
                or type(port) is not int
                or not 1 <= port <= 65535
                or check.get('expectedState') != 'listening'):
            raise SystemExit(1)
        print(port)
        continue
    raise SystemExit(1)
PY
}

REQUIRED_TCP_PORTS=()
if [[ "$COMMAND" == 'verify' ]]; then
    checks_ports=''
    checks_ports="$(parse_checks)" || fail 'INVALID_CHECKS' 65
    if [[ -n "$checks_ports" ]]; then
        mapfile -t REQUIRED_TCP_PORTS <<<"$checks_ports"
    fi
fi
readonly -a REQUIRED_TCP_PORTS

ensure_fixed_state_roots() {
    local directory
    for directory in \
        "$ROOT_PREFIX/var/lib/celerity" \
        "$STATE_ROOT" \
        "$STATE_ROOT/operations" \
        "$STATE_ROOT/backups"; do
        if [[ -e "$directory" || -L "$directory" ]]; then
            [[ -d "$directory" && ! -L "$directory" ]] || fail 'INVALID_STATE_ROOT' 73
        else
            /usr/bin/mkdir -m 0700 -- "$directory" >/dev/null 2>&1 \
                || fail 'STATE_WRITE_FAILED' 70
        fi
    done
}

prepare_candidate() {
    local size digest_line digest config_parent
    ensure_fixed_state_roots
    [[ ! -e "$OPERATION_DIR" && ! -L "$OPERATION_DIR" \
        && ! -e "$BACKUP_DIR" && ! -L "$BACKUP_DIR" ]] \
        || fail 'STATE_ALREADY_EXISTS' 65

    /usr/bin/mkdir -p -m 0700 -- "$OPERATION_DIR" "$BACKUP_DIR" >/dev/null 2>&1 \
        || fail 'STATE_WRITE_FAILED' 70
    TEMPORARY_FILE="$(/usr/bin/mktemp --tmpdir="$OPERATION_DIR" '.candidate.XXXXXX')" \
        || fail 'STATE_WRITE_FAILED' 70
    /usr/bin/cat >"$TEMPORARY_FILE" || fail 'CANDIDATE_READ_FAILED' 65
    size="$(/usr/bin/stat -c '%s' -- "$TEMPORARY_FILE" 2>/dev/null)" \
        || fail 'CANDIDATE_READ_FAILED' 65
    [[ "$size" -gt 0 && "$size" -le "$MAX_CANDIDATE_BYTES" ]] \
        || fail 'INVALID_CANDIDATE' 65
    digest_line="$(/usr/bin/sha256sum -- "$TEMPORARY_FILE" 2>/dev/null)" \
        || fail 'INVALID_CANDIDATE' 65
    digest="${digest_line%% *}"
    [[ "sha256:$digest" == "$CANDIDATE_HASH" ]] \
        || fail 'CANDIDATE_HASH_MISMATCH' 65
    candidate_structure_valid "$TEMPORARY_FILE" \
        || fail 'INVALID_CANDIDATE' 65
    /usr/bin/chmod 0600 -- "$TEMPORARY_FILE" >/dev/null 2>&1 \
        || fail 'STATE_WRITE_FAILED' 70
    /usr/bin/mv -fT -- "$TEMPORARY_FILE" "$CANDIDATE_PATH" >/dev/null 2>&1 \
        || fail 'STATE_WRITE_FAILED' 70
    TEMPORARY_FILE=''
    [[ -x "$XRAY_PATH" ]] || fail 'XRAY_UNAVAILABLE' 69
    [[ -d "$XRAY_ASSET_DIR" && ! -L "$XRAY_ASSET_DIR" \
        && -r "$XRAY_ASSET_DIR" && -x "$XRAY_ASSET_DIR" ]] \
        || fail 'XRAY_ASSETS_UNAVAILABLE' 69
    XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" \
        "$XRAY_PATH" run -test -config "$CANDIDATE_PATH" >/dev/null 2>&1 \
        || fail 'CANDIDATE_INVALID' 65

    config_parent="${CONFIG_PATH%/*}"
    [[ -d "$config_parent" && ! -L "$config_parent" ]] \
        || fail 'INVALID_TARGET' 73
    if [[ -e "$CONFIG_PATH" || -L "$CONFIG_PATH" ]]; then
        [[ -f "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] \
            || fail 'INVALID_TARGET' 73
        /usr/bin/install -m 0600 -- "$CONFIG_PATH" "$BACKUP_CONFIG" >/dev/null 2>&1 \
            || fail 'BACKUP_FAILED' 70
    else
        : >"$BACKUP_ABSENT" || fail 'BACKUP_FAILED' 70
        /usr/bin/chmod 0600 -- "$BACKUP_ABSENT" >/dev/null 2>&1 \
            || fail 'BACKUP_FAILED' 70
    fi

    write_metadata "$OPERATION_METADATA"
    write_metadata "$BACKUP_METADATA"
    emit_receipt
}

assert_bound_state() {
    metadata_matches "$OPERATION_METADATA" \
        && metadata_matches "$BACKUP_METADATA" \
        || fail 'RECEIPT_BINDING_MISMATCH' 65
}

commit_candidate() {
    local target_parent temporary
    assert_bound_state
    # Refuse activation when the prepared rollback snapshot is contradictory,
    # absent, or a symlink; a later rollback must have one unambiguous source.
    if [[ -f "$BACKUP_CONFIG" && ! -L "$BACKUP_CONFIG" ]]; then
        [[ ! -e "$BACKUP_ABSENT" && ! -L "$BACKUP_ABSENT" ]] \
            || fail 'BACKUP_INVALID' 65
    elif [[ -f "$BACKUP_ABSENT" && ! -L "$BACKUP_ABSENT" ]]; then
        [[ ! -e "$BACKUP_CONFIG" && ! -L "$BACKUP_CONFIG" ]] \
            || fail 'BACKUP_INVALID' 65
    else
        fail 'BACKUP_INVALID' 65
    fi
    file_hash_matches "$CANDIDATE_PATH" || fail 'CANDIDATE_HASH_MISMATCH' 65
    target_parent="${CONFIG_PATH%/*}"
    [[ -d "$target_parent" && ! -L "$target_parent" ]] || fail 'INVALID_TARGET' 73
    if [[ -e "$CONFIG_PATH" || -L "$CONFIG_PATH" ]]; then
        [[ -f "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] || fail 'INVALID_TARGET' 73
    fi
    temporary="$(/usr/bin/mktemp --tmpdir="$target_parent" '.celerity-topology.XXXXXX')" \
        || fail 'ACTIVATION_FAILED' 70
    TEMPORARY_FILE="$temporary"
    /usr/bin/install -m 0644 -- "$CANDIDATE_PATH" "$temporary" >/dev/null 2>&1 \
        || fail 'ACTIVATION_FAILED' 70
    /usr/bin/mv -fT -- "$temporary" "$CONFIG_PATH" >/dev/null 2>&1 \
        || fail 'ACTIVATION_FAILED' 70
    TEMPORARY_FILE=''
    [[ -x "$SYSTEMCTL_PATH" ]] || fail 'SYSTEMCTL_UNAVAILABLE' 69
    "$SYSTEMCTL_PATH" restart "$SERVICE_NAME" >/dev/null 2>&1 \
        || fail 'ACTIVATION_FAILED' 70
    emit_receipt
}

verify_candidate() {
    local port listeners
    assert_bound_state
    file_hash_matches "$CONFIG_PATH" || fail 'VERIFICATION_FAILED' 65
    [[ -x "$XRAY_PATH" && -x "$SYSTEMCTL_PATH" ]] \
        || fail 'VERIFICATION_UNAVAILABLE' 69
    [[ -d "$XRAY_ASSET_DIR" && ! -L "$XRAY_ASSET_DIR" \
        && -r "$XRAY_ASSET_DIR" && -x "$XRAY_ASSET_DIR" ]] \
        || fail 'XRAY_ASSETS_UNAVAILABLE' 69
    XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" \
        "$XRAY_PATH" run -test -config "$CONFIG_PATH" >/dev/null 2>&1 \
        || fail 'VERIFICATION_FAILED' 65
    "$SYSTEMCTL_PATH" is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1 \
        || fail 'VERIFICATION_FAILED' 65
    if [[ "${#REQUIRED_TCP_PORTS[@]}" -gt 0 ]]; then
        [[ -x "$SS_PATH" ]] || fail 'VERIFICATION_UNAVAILABLE' 69
        for port in "${REQUIRED_TCP_PORTS[@]}"; do
            listeners="$("$SS_PATH" -H -ltn "sport = :$port" 2>/dev/null)" \
                || fail 'VERIFICATION_UNAVAILABLE' 69
            [[ -n "$listeners" ]] || fail 'VERIFICATION_FAILED' 65
        done
    fi
    emit_receipt
}

rollback_candidate() {
    local target_parent temporary
    assert_bound_state
    target_parent="${CONFIG_PATH%/*}"
    [[ -d "$target_parent" && ! -L "$target_parent" ]] || fail 'INVALID_TARGET' 73
    if [[ -f "$BACKUP_CONFIG" && ! -L "$BACKUP_CONFIG" && ! -e "$BACKUP_ABSENT" ]]; then
        if [[ -e "$CONFIG_PATH" || -L "$CONFIG_PATH" ]]; then
            [[ -f "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] || fail 'INVALID_TARGET' 73
        fi
        temporary="$(/usr/bin/mktemp --tmpdir="$target_parent" '.celerity-topology.XXXXXX')" \
            || fail 'ROLLBACK_FAILED' 70
        TEMPORARY_FILE="$temporary"
        /usr/bin/install -m 0644 -- "$BACKUP_CONFIG" "$temporary" >/dev/null 2>&1 \
            || fail 'ROLLBACK_FAILED' 70
        /usr/bin/mv -fT -- "$temporary" "$CONFIG_PATH" >/dev/null 2>&1 \
            || fail 'ROLLBACK_FAILED' 70
        TEMPORARY_FILE=''
        [[ -x "$SYSTEMCTL_PATH" ]] || fail 'SYSTEMCTL_UNAVAILABLE' 69
        "$SYSTEMCTL_PATH" restart "$SERVICE_NAME" >/dev/null 2>&1 \
            || fail 'ROLLBACK_FAILED' 70
    elif [[ -f "$BACKUP_ABSENT" && ! -L "$BACKUP_ABSENT" && ! -e "$BACKUP_CONFIG" ]]; then
        if [[ -e "$CONFIG_PATH" || -L "$CONFIG_PATH" ]]; then
            [[ -f "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] || fail 'INVALID_TARGET' 73
            /usr/bin/rm -f -- "$CONFIG_PATH" >/dev/null 2>&1 \
                || fail 'ROLLBACK_FAILED' 70
        fi
        [[ -x "$SYSTEMCTL_PATH" ]] || fail 'SYSTEMCTL_UNAVAILABLE' 69
        "$SYSTEMCTL_PATH" stop "$SERVICE_NAME" >/dev/null 2>&1 \
            || fail 'ROLLBACK_FAILED' 70
    else
        fail 'BACKUP_INVALID' 65
    fi
    emit_receipt
}

case "$COMMAND" in
    prepare) prepare_candidate ;;
    commit) commit_candidate ;;
    verify) verify_candidate ;;
    rollback) rollback_candidate ;;
esac
