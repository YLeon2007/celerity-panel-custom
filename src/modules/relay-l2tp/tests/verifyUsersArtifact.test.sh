#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/verify-users.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_verify() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    set +e
    CELERITY_L2TP_ROOT="$TMP_DIR/root" \
        unshare --user --map-root-user "$ARTIFACT" "$TMP_DIR/operation" "$@" >"$output" 2>&1
    status=$?
    set -e
    result="$(<"$output")"
    [[ "$result" != *"$SECRET_CANARY"* ]] || fail "$label leaked the secret canary"
    [[ "$result" != *'alpha'* && "$result" != *'disabled-user'* && "$result" != *'foreign-user'* ]] \
        || fail "$label leaked a user identity"
    OUTPUT="$result" node - <<'NODE' || fail "$label did not emit one strict verifier JSON object"
const lines = process.env.OUTPUT.split('\n');
if (lines.length !== 1) process.exit(1);
const value = JSON.parse(lines[0]);
const keys = Object.keys(value);
if (JSON.stringify(keys) !== JSON.stringify([
    'ok', 'credentialRevision', 'enabledUserCount', 'managedUserCount', 'code',
])) process.exit(1);
NODE
}

write_chap() {
    printf '%s' "$1" >"$TMP_DIR/root/etc/ppp/chap-secrets"
    chmod 0600 "$TMP_DIR/root/etc/ppp/chap-secrets"
}

expect_failure() {
    local label="$1"
    local expected_code="$2"
    local expected_managed="$3"
    invoke_verify "$label"
    [[ "$status" -ne 0 ]] || fail "$label mismatch was accepted"
    [[ "$result" == "{\"ok\":false,\"credentialRevision\":42,\"enabledUserCount\":2,\"managedUserCount\":$expected_managed,\"code\":\"$expected_code\"}" ]] \
        || fail "$label returned the wrong strict failure result: $result"
}

SECRET_CANARY='verify-users-secret-canary-7b6d'
mkdir -p "$TMP_DIR/operation" "$TMP_DIR/root/etc/ppp"
chmod 0700 "$TMP_DIR/operation"
printf '%s\n' "$(node -e '
const secret = process.argv[1];
process.stdout.write(JSON.stringify({
  credentialRevision: 42,
  users: [
    { login: "alpha", password: secret, ipAddress: "10.77.0.10", enabled: true },
    { login: "beta", password: "beta-secret", ipAddress: "10.77.0.11", enabled: true },
    { login: "disabled-user", password: "disabled-secret", ipAddress: "10.77.0.12", enabled: false },
  ],
}));
' "$SECRET_CANARY")" >"$TMP_DIR/operation/desired.json"
chmod 0600 "$TMP_DIR/operation/desired.json"

expected_block="# local unmanaged line
# BEGIN CELERITY MANAGED L2TP USERS
\"alpha\" l2tpd \"$SECRET_CANARY\" 10.77.0.10
\"beta\" l2tpd \"beta-secret\" 10.77.0.11
# END CELERITY MANAGED L2TP USERS
# local unmanaged tail
"
write_chap "$expected_block"

[[ -x "$ARTIFACT" ]] || fail 'verify-users artifact is missing or not executable'
invoke_verify success
[[ "$status" -eq 0 ]] || fail 'matching managed users failed verification'
[[ "$result" == '{"ok":true,"credentialRevision":42,"enabledUserCount":2,"managedUserCount":2,"code":"USERS_VERIFIED"}' ]] \
    || fail "success returned the wrong strict result: $result"

write_chap "# BEGIN CELERITY MANAGED L2TP USERS
\"alpha\" l2tpd \"$SECRET_CANARY\" 10.77.0.10
# END CELERITY MANAGED L2TP USERS
"
expect_failure missing MANAGED_USERS_MISSING 1

write_chap "# BEGIN CELERITY MANAGED L2TP USERS
\"alpha\" l2tpd \"$SECRET_CANARY\" 10.77.0.10
\"beta\" l2tpd \"beta-secret\" 10.77.0.11
\"foreign-user\" l2tpd \"foreign-secret\" 10.77.0.99
# END CELERITY MANAGED L2TP USERS
"
expect_failure extra MANAGED_USERS_EXTRA 3

write_chap "# BEGIN CELERITY MANAGED L2TP USERS
\"alpha\" l2tpd \"$SECRET_CANARY\" 10.77.0.10
\"alpha\" l2tpd \"$SECRET_CANARY\" 10.77.0.10
\"beta\" l2tpd \"beta-secret\" 10.77.0.11
# END CELERITY MANAGED L2TP USERS
"
expect_failure duplicate MANAGED_USERS_DUPLICATE 3

write_chap "# BEGIN CELERITY MANAGED L2TP USERS
\"alpha\" l2tpd \"altered-$SECRET_CANARY\" 10.77.0.10
\"beta\" l2tpd \"beta-secret\" 10.77.0.11
# END CELERITY MANAGED L2TP USERS
"
expect_failure altered MANAGED_USERS_ALTERED 2

write_chap "# BEGIN CELERITY MANAGED L2TP USERS
\"alpha\" l2tpd \"$SECRET_CANARY\" 10.77.0.10
\"beta\" l2tpd \"beta-secret\" 10.77.0.11
\"disabled-user\" l2tpd \"disabled-secret\" 10.77.0.12
# END CELERITY MANAGED L2TP USERS
"
expect_failure disabled DISABLED_USERS_PRESENT 3

write_chap "$expected_block"
invoke_verify extra-argument "$TMP_DIR/outside"
[[ "$status" -ne 0 ]] || fail 'verify-users accepted an arbitrary path'
[[ "$result" == '{"ok":false,"credentialRevision":null,"enabledUserCount":0,"managedUserCount":0,"code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'invalid arguments returned the wrong strict error'

printf 'verify users artifact fixture tests passed\n'
