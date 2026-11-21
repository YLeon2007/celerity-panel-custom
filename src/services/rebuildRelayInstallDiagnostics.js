'use strict';

// DIRECT wire suffix -> public check. List only fixed helper emissions here.
// An alias is an explicit entry, not a prefix/pattern match. New entries
// must have RU/EN copy for the public check. This table grants no write proof.
const hostChecks = new Map([
    ['XRAY_DROPIN_UNSUPPORTED', 'XRAY_DROPIN_UNSUPPORTED'],
    ['PPP_MODULES_REQUIRED', 'PPP_MODULES_REQUIRED', 'shared-prerequisite'],
    ['PPP_MODULES_PERSISTENCE_CONFLICT', 'PPP_MODULES_PERSISTENCE_CONFLICT', 'shared-prerequisite'],
    ['PPP_MODULES_LOAD_FAILED', 'PPP_MODULES_LOAD_FAILED', 'shared-prerequisite'],
    ['NETWORK_OBSERVATION_REQUIRED', 'NETWORK_OBSERVATION_REQUIRED', 'shared-prerequisite'],
    ['IKE_ACTIVE_RULE_220', 'IKE_ACTIVE_RULE_220', 'pre-write-only'],
    ['RULE_220_CONFLICT', 'RULE_220_CONFLICT', 'pre-write-only'],
    ['IKE_ACTIVE_UNMANAGED', 'IKE_ACTIVE_UNMANAGED', 'pre-write-only'],
    ['XL2TPD_CONFIG_MISSING', 'XL2TPD_CONFIG_MISSING'],
    ['XRAY_CONFIG_WRITABLE', 'XRAY_CONFIG_WRITABLE'],
    ['XL2TPD_NATIVE_UNIT_REQUIRED', 'XL2TPD_NATIVE_UNIT_REQUIRED'],
    ['RUNTIME_PACKAGE_AUTOSTART_UNSAFE', 'RUNTIME_PACKAGE_AUTOSTART_UNSAFE', 'fresh-pre-write'],
    ['RUNTIME_NATIVE_UNIT_REQUIRED', 'RUNTIME_NATIVE_UNIT_REQUIRED', 'fresh-pre-write'],
    ['XL2TPD_NATIVE_UNIT_CONFLICT', 'XL2TPD_NATIVE_UNIT_CONFLICT'],
].map(([suffix, check, scope]) => [suffix, { check, scope }]));
const stages = new Map([
    ['preflight', 'HOST_PREFLIGHT'],
    ['prepare', 'HOST_BASELINE'],
    ['check', 'HOST_CANDIDATE'],
    ['install', 'HOST_INSTALL'],
]);
const checks = new Set([...Array.from(hostChecks.values(), ({ check }) => check), ...stages.values(),
    'VPN_UNITS_MASKED', 'VPN_UNITS_NOT_LOADED']);
const installCheckIds = Object.freeze([...checks]);
const isInstallCheck = check => checks.has(check);
const isInstallStage = action => stages.has(action);
function specificHostRefusal(action, suffix, noWrite) {
    const match = hostChecks.get(suffix);
    if (!isInstallStage(action) || !match) return undefined;
    if (match.scope && match.scope !== 'fresh-pre-write' && action === 'preflight') return undefined;
    if (['pre-write-only', 'fresh-pre-write'].includes(match.scope) && action === 'install' && !noWrite) return undefined;
    return { check: match.check, prerequisitePartial: match.scope === 'shared-prerequisite'
        && action === 'install' && !noWrite };
}
const prerequisiteCheck = action => stages.get(action);

function requireInstallHostReady(host, canPreparePpp = host?.pppPreparation === true) {
    if (host?.masked === false && host.unitsLoaded === true
        && (host.ppp === true || (host.ppp === false && canPreparePpp === true))) return;
    const code = 'REBUILD_L2TP_HOST_NOT_READY';
    const check = host?.masked === true ? 'VPN_UNITS_MASKED' : host?.unitsLoaded === false ? 'VPN_UNITS_NOT_LOADED'
        : host?.ppp === false ? 'PPP_MODULES_REQUIRED' : 'HOST_PREFLIGHT';
    throw withInstallCheck(Object.assign(new Error(code), { code }), check);
}

const failed = 'REBUILD_L2TP_INSTALL_FAILED';
// Defaults for fixed, already-public service codes. A valid install refusal
// can have a different outcome depending on rollback and reservation cleanup.
const codeOutcomes = new Map([
    ['REBUILD_INVALID_REQUEST', 'refused'],
    ['REBUILD_BUSY', 'busy'],
    ['REBUILD_LOCK_LOST', 'unknown'],
    ['REBUILD_LOCK_RELEASE_UNCONFIRMED', 'unknown'],
    ['REBUILD_TRANSPORT_CLEANUP_FAILED', 'unknown'],
    ...['INSTALL_DISABLED', 'INSTALL_IDENTITY_MISMATCH', 'INSTALL_INPUT_INVALID', 'INSTALL_PLAN_INVALID',
        'NOT_FRESH_RELAY', 'BINDING_MISMATCH', 'SSH_PIN_INVALID', 'SSH_ENDPOINT_INVALID', 'SSH_CONNECT_FAILED',
        'HOST_NOT_READY', 'TOPOLOGY_NOT_APPLIED', 'CREDENTIAL_KEY_INVALID', 'ADDRESS_INVENTORY_INVALID',
        'ADDRESS_SPACE_EXHAUSTED', 'ACCOUNT_INVENTORY_INVALID', 'ACCOUNT_POOL_EXHAUSTED',
        'ACCOUNT_SOURCE_NOT_ENROLLED', 'ACCOUNT_SOURCE_CONFLICT', 'ACCOUNT_SOURCE_PREFLIGHT_REFUSED',
        'PROFILE_PRECONDITION', 'XRAY_BASELINE_UNSUPPORTED', 'STOCK_INSTALL_OUT_OF_SCOPE', 'STOCK_ARTIFACT_MISMATCH',
        'DIRECT_IDENTITY', 'DIRECT_PREREQUISITE', 'DIRECT_BASELINE_CHANGED', 'DIRECT_NETWORK_CONFLICT',
        'DIRECT_PROFILE_USERS', 'DIRECT_RUNTIME_UNPROVED', 'DIRECT_CANDIDATE_INVALID', 'DIRECT_COMMAND_FAILED',
    ].map(code => [`REBUILD_L2TP_${code}`, 'refused']),
    ...['ACCOUNT_SOURCE_BUSY', 'ACCOUNTS_BLOCKED'].map(code => [`REBUILD_L2TP_${code}`, 'busy']),
    ...['DIRECT_OUTCOME_UNKNOWN', 'DIRECT_ROLLBACK_DRIFT', 'RESERVATION_FAILED', 'RESERVATION_CLEANUP_FAILED',
        'INSTALL_OUTCOME_UNKNOWN', 'ROLLBACK_OUTCOME_UNKNOWN', 'ROLLBACK_CLEANUP_FAILED',
        'FINISH_OUTCOME_UNKNOWN', 'INSTALL_FAILED', 'VERIFY_FAILED', 'ACCOUNTS_PERSISTENCE_UNAVAILABLE',
    ].map(code => [`REBUILD_L2TP_${code}`, 'unknown']),
    ['REBUILD_L2TP_INSTALLED_CLEANUP_FAILED', 'installed'],
]);
const outcomes = new Set([...codeOutcomes.values(), 'rolled_back']);

const checkedIds = new WeakMap();
function withInstallCheck(error, check) {
    if (isInstallCheck(check)) {
        checkedIds.set(error, check);
        error.check = check;
    }
    return error;
}
const checkedInstallId = error => checkedIds.get(error);

const failures = new WeakSet();
function installFailure(code, outcome, check, { retryAllowed } = {}) {
    if (!codeOutcomes.has(code) || !outcomes.has(outcome)) {
        code = failed;
        outcome = 'unknown';
        check = undefined;
    }
    const error = withInstallCheck(Object.assign(new Error(code), { code, outcome,
        ...(outcome === 'unknown' && retryAllowed === false && { retryAllowed: false }) }), check);
    failures.add(error);
    return Object.freeze(error);
}

function classifyInstallFailure(error) {
    if (failures.has(error)) return error;
    const code = error?.code;
    const outcome = codeOutcomes.get(code);
    return outcome ? installFailure(code, outcome, checkedInstallId(error)) : installFailure(failed, 'unknown');
}

function publicInstallFailure(error) {
    const { code, outcome, check, retryAllowed } = classifyInstallFailure(error);
    return { code, outcome, ...(check !== undefined && { check }), ...(retryAllowed === false && { retryAllowed }) };
}

module.exports = { installCheckIds, isInstallStage, specificHostRefusal, prerequisiteCheck, requireInstallHostReady,
    withInstallCheck, checkedInstallId, installFailure, classifyInstallFailure, publicInstallFailure };
