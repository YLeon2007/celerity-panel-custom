#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ROLLBACK_SOURCE="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/rollback.sh"
ORIGINAL_PATH="$PATH"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

make_forbidden_command() {
    local name="$1"
    cat >"$TMP_DIR/bin/$name" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "${0##*/}" >>"$MUTATION_LOG"
exit 99
STUB
    chmod +x "$TMP_DIR/bin/$name"
}

invoke_rollback() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    rm -f "$TMP_DIR/apply-call.log"
    set +e
    PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
        APPLY_CALL_LOG="$TMP_DIR/apply-call.log" \
        MUTATION_LOG="$TMP_DIR/mutations.log" \
        "$TMP_DIR/lib/rollback.sh" "$@" >"$output" 2>&1
    status=$?
    set -e
}

[[ -x "$ROLLBACK_SOURCE" ]] || fail 'rollback artifact is missing or not executable'
mkdir -p "$TMP_DIR/bin" "$TMP_DIR/lib" "$TMP_DIR/operation"
cp "$ROLLBACK_SOURCE" "$TMP_DIR/lib/rollback.sh"
chmod +x "$TMP_DIR/lib/rollback.sh"
cat >"$TMP_DIR/lib/apply.sh" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "${0##*/}" "$@" >"$APPLY_CALL_LOG"
printf '%s\n' '{"status":"ok","changed":2,"unchanged":0}'
STUB
chmod +x "$TMP_DIR/lib/apply.sh"
printf '%s\n' '{"files":[]}' >"$TMP_DIR/operation/backup.json"
: >"$TMP_DIR/mutations.log"
for forbidden in apply.sh cp mv install systemctl nft xray; do
    make_forbidden_command "$forbidden"
done

invoke_rollback valid "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'rollback dispatch failed'
[[ "$(<"$output")" == '{"status":"ok","changed":2,"unchanged":0}' ]] \
    || fail 'rollback did not return the fixed apply result'
mapfile -t call <"$TMP_DIR/apply-call.log"
[[ "${#call[@]}" -eq 3 ]] || fail 'rollback passed an unexpected argument count to apply'
[[ "${call[0]}" == 'apply.sh' ]] || fail 'rollback did not execute the fixed sibling apply artifact'
[[ "${call[1]}" == "$TMP_DIR/operation/backup.json" ]] \
    || fail 'rollback did not use the operation backup manifest'
[[ "${call[2]}" == '/' ]] || fail 'rollback did not restore to the fixed filesystem root'

outside="$TMP_DIR/outside-backup.json"
printf '%s\n' '{"files":[]}' >"$outside"
invoke_rollback extra-argument "$TMP_DIR/operation" "$outside"
[[ "$status" -ne 0 ]] || fail 'rollback accepted an arbitrary manifest argument'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'rollback returned the wrong structured argument error'
[[ ! -e "$TMP_DIR/apply-call.log" ]] || fail 'rejected rollback invoked apply'
[[ ! -s "$TMP_DIR/mutations.log" ]] || fail 'rollback invoked a PATH mutation command'

printf 'rollback artifact fixture tests passed\n'
