#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ARTIFACT="$ROOT_DIR/src/modules/relay-l2tp/node-artifacts/l2tp/sync-users.sh"
ORIGINAL_PATH="$PATH"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

invoke_sync() {
    local label="$1"
    shift
    output="$TMP_DIR/$label.out"
    status=0
    set +e
    PATH="$TMP_DIR/bin:$ORIGINAL_PATH" \
        CELERITY_L2TP_ROOT="$TMP_DIR/root" \
        MUTATION_LOG="$TMP_DIR/mutation.log" \
        unshare --user --map-root-user "$ARTIFACT" "$@" >"$output" 2>&1
    status=$?
    set -e
}

[[ -x "$ARTIFACT" ]] || fail 'sync users artifact is missing or not executable'
mkdir -p "$TMP_DIR/bin" "$TMP_DIR/operation" "$TMP_DIR/root/etc/ppp"
printf '%s\n' 'local line must survive' >"$TMP_DIR/root/etc/ppp/chap-secrets"
printf '%s\n' 'outside sentinel' >"$TMP_DIR/outside"
printf '%s\n' '{"files":[{"path":"etc/ppp/chap-secrets","mode":384,"content":"local line must survive\n"}],"absent":["etc/ipsec.d/celerity-l2tp.conf","etc/ipsec.secrets","etc/xl2tpd/xl2tpd.conf","etc/ppp/options.xl2tpd","etc/nftables.d/celerity-l2tp.nft","usr/local/etc/xray/config.json"]}' \
    >"$TMP_DIR/operation/backup.json"
printf '%s\n' '{"users":[{"login":"zeta","password":"zeta-secret","ipAddress":"10.77.0.11","enabled":false},{"login":"alpha","password":"alpha-secret","ipAddress":"10.77.0.10","enabled":true}],"chapSecretsPath":"'"$TMP_DIR"'/outside"}' \
    >"$TMP_DIR/operation/desired.json"
for command in systemctl service iptables nft; do
    cat >"$TMP_DIR/bin/$command" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "${0##*/}" >>"$MUTATION_LOG"
exit 99
STUB
    chmod +x "$TMP_DIR/bin/$command"
done

invoke_sync valid "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'fixed user sync failed'
[[ "$(<"$output")" == '{"status":"ok","changed":1,"managedUsers":1,"disabledUsers":1}' ]] \
    || fail 'user sync returned the wrong structured result'
expected='local line must survive
# BEGIN CELERITY MANAGED L2TP USERS
"alpha" l2tpd "alpha-secret" 10.77.0.10
# END CELERITY MANAGED L2TP USERS'
[[ "$(<"$TMP_DIR/root/etc/ppp/chap-secrets")" == "$expected" ]] \
    || fail 'user sync did not preserve unmanaged content and replace only its block'
[[ "$(unshare --user --map-root-user stat --format='%u:%g:%a' -- "$TMP_DIR/root/etc/ppp/chap-secrets")" == '0:0:600' ]] \
    || fail 'chap-secrets metadata is not root-owned mode 0600'
[[ "$(<"$TMP_DIR/outside")" == 'outside sentinel' ]] || fail 'desired JSON selected an arbitrary output path'
[[ ! -s "$TMP_DIR/mutation.log" ]] || fail 'user sync invoked a service or firewall command'
! grep -Fq -- 'alpha-secret' "$output" || fail 'user sync output leaked a password'

invoke_sync idempotent "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'idempotent user sync failed'
[[ "$(<"$output")" == '{"status":"ok","changed":0,"managedUsers":1,"disabledUsers":1}' ]] \
    || fail 'idempotent user sync returned the wrong result'

ROOT_DIR="$ROOT_DIR" node >"$TMP_DIR/operation/desired.json" <<'NODE'
const { INSTALL_STEP_TYPES } = require(
    `${process.env.ROOT_DIR}/src/modules/relay-l2tp/services/l2tpProvisionPlanService`,
);
const { materializeInstallOperation } = require(
    `${process.env.ROOT_DIR}/src/modules/relay-l2tp/services/l2tpOperationMaterializer`,
);
const desired = {
    clientCidr: '10.77.0.0/24',
    localAddress: '10.77.0.1',
    poolStart: '10.77.0.10',
    poolEnd: '10.77.0.200',
    dnsServers: ['1.1.1.1'],
    tproxyPort: 12345,
    fwmark: 77,
    routeTable: 177,
};
const result = materializeInstallOperation({
    plan: {
        ok: true,
        operationId: 'materialized-without-user-credentials',
        desired,
        steps: INSTALL_STEP_TYPES.map(type => ({ type })),
    },
    secrets: { psk: 'transient-psk-not-for-desired' },
});
const remoteDesired = result.remoteArtifacts.find(artifact => artifact.type === 'desired');
process.stdout.write(remoteDesired.content);
NODE
node -e '
const fs = require("node:fs");
const desired = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (!Array.isArray(desired.users) || desired.users.length !== 0) process.exit(1);
if (JSON.stringify(desired).match(/password|psk|secret/i)) process.exit(1);
' "$TMP_DIR/operation/desired.json" \
    || fail 'materialized desired did not contain an explicit credential-free users array'
invoke_sync materialized-without-credentials "$TMP_DIR/operation"
[[ "$status" -eq 0 ]] || fail 'sync users rejected materialized desired without user credentials'
[[ "$(<"$output")" == '{"status":"ok","changed":1,"managedUsers":0,"disabledUsers":0}' ]] \
    || fail 'credential-free materialized desired returned the wrong result'
expected_without_users='local line must survive
# BEGIN CELERITY MANAGED L2TP USERS
# END CELERITY MANAGED L2TP USERS'
[[ "$(<"$TMP_DIR/root/etc/ppp/chap-secrets")" == "$expected_without_users" ]] \
    || fail 'credential-free materialized desired did not clear only managed users'

before="$(<"$TMP_DIR/root/etc/ppp/chap-secrets")"
printf '%s\n' '{"users":[{"login":"alice","password":"first-secret","ipAddress":"10.77.0.10","enabled":true},{"login":"alice","password":"second-secret","ipAddress":"10.77.0.11","enabled":true}]}' \
    >"$TMP_DIR/operation/desired.json"
invoke_sync duplicate "$TMP_DIR/operation"
[[ "$status" -ne 0 ]] || fail 'duplicate desired users were accepted'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_DESIRED_USERS"}' ]] \
    || fail 'invalid users returned the wrong structured error'
[[ "$(<"$TMP_DIR/root/etc/ppp/chap-secrets")" == "$before" ]] \
    || fail 'invalid users changed chap-secrets'
! grep -Eq -- 'first-secret|second-secret' "$output" || fail 'invalid user error leaked a password'

rm -f "$TMP_DIR/operation/backup.json"
invoke_sync missing-backup "$TMP_DIR/operation"
[[ "$status" -ne 0 ]] || fail 'user sync ran without an operation backup'
[[ "$(<"$output")" == '{"status":"error","code":"BACKUP_REQUIRED"}' ]] \
    || fail 'missing backup returned the wrong error'
[[ "$(<"$TMP_DIR/root/etc/ppp/chap-secrets")" == "$before" ]] \
    || fail 'missing backup changed chap-secrets'

invoke_sync extra "$TMP_DIR/operation" "$TMP_DIR/outside"
[[ "$status" -ne 0 ]] || fail 'user sync accepted an arbitrary path'
[[ "$(<"$output")" == '{"status":"error","code":"INVALID_ARGUMENTS"}' ]] \
    || fail 'extra argument returned the wrong error'

printf 'sync users artifact fixture tests passed\n'
