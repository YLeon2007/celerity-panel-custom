'use strict';

// DIRECT wire suffix -> public check. List only fixed helper emissions here.
// An alias is an explicit entry, not a prefix/pattern match. New entries
// must have RU/EN/zh-CN copy for the public check. This table grants no write proof.
const hostChecks = new Map([
    ['XRAY_DROPIN_UNSUPPORTED', 'XRAY_DROPIN_UNSUPPORTED'],
    ['PPP_MODULES_REQUIRED', 'PPP_MODULES_REQUIRED', 'shared-prerequisite'],
    ['PPP_MODULES_PERSISTENCE_CONFLICT', 'PPP_MODULES_PERSISTENCE_CONFLICT', 'shared-prerequisite'],
    ['PPP_MODULES_LOAD_FAILED', 'PPP_MODULES_LOAD_FAILED', 'shared-prerequisite'],
    ['KERNEL_MODULE_BLACKLISTED', 'KERNEL_MODULE_BLACKLISTED', 'shared-prerequisite'],
    ['NETWORK_OBSERVATION_REQUIRED', 'NETWORK_OBSERVATION_REQUIRED', 'shared-prerequisite'],
    ['IKE_ACTIVE_RULE_220', 'IKE_ACTIVE_RULE_220', 'fresh-pre-write'],
    ['RULE_220_CONFLICT', 'RULE_220_CONFLICT', 'fresh-pre-write'],
    ['IKE_ACTIVE_UNMANAGED', 'IKE_ACTIVE_UNMANAGED', 'fresh-pre-write'],
    ['XL2TPD_CONFIG_MISSING', 'XL2TPD_CONFIG_MISSING'],
    ['XRAY_CONFIG_WRITABLE', 'XRAY_CONFIG_WRITABLE'],
    ['XRAY_PROFILE_OWNER_UNSUPPORTED', 'XRAY_PROFILE_OWNER_UNSUPPORTED', 'prepare-only'],
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
// These exact codes reach classification before reservation. On the write
// path, the coordinator instead returns a rollback or uncertain outcome.
const profileChecks = new Map([
    ['REBUILD_L2TP_TOPOLOGY_NOT_APPLIED', 'REBUILD_LINKS_NOT_APPLIED'],
    ['REBUILD_L2TP_KCP_LISTENER_UNSUPPORTED', 'KCP_LISTENER_UNSUPPORTED'],
    ['REBUILD_L2TP_XRAY_BASELINE_UNSUPPORTED', 'XRAY_BASELINE_UNSUPPORTED'],
    ['REBUILD_L2TP_DIRECT_PROFILE_USERS', 'XRAY_PROFILE_USERS_UNPROVED'],
    ['REBUILD_L2TP_DIRECT_RUNTIME_UNPROVED', 'XRAY_RUNTIME_UNPROVED'],
]);
const packageChecks = new Set([
    'PACKAGE_SOURCES_UNSUPPORTED', 'PACKAGE_INDEXES_UNVERIFIED', 'PACKAGE_SERVICES_UNSAFE', 'PACKAGE_APT_PLAN',
]);
const packageRefusals = new Map([...packageChecks, 'RUNTIME_PACKAGE_AUTOSTART_UNSAFE', 'KERNEL_MODULE_BLACKLISTED']
    .map(id => [`DIRECT_${id}\n`, id]));
const packageUncertain = new Map([...packageChecks].map(id => [`DIRECT_UNCERTAIN_${id}\n`, id]));
// Only called for prepare-packages. Neither form certifies settlement of a write.
function packageWriteCheck(result) {
    if (result?.stdout !== '') return undefined;
    if (result.code === 70) return packageRefusals.get(result.stderr);
    if (result.code === 75) return packageUncertain.get(result.stderr);
}
// Only these keys may cross the authenticated DIRECT and public Install boundaries.
// Canonical wire order; mirror FOREIGN_REASONS in rebuildRelayDirectHost.py.
const foreignKeys = ['SWAN_PROFILE_PRESENT', 'IKE_PROFILE_PRESENT', 'OPTIONS_PRESENT', 'STARTER_NOT_STOCK',
    'SECRETS_NOT_EMPTY', 'CHAP_NOT_EMPTY', 'LNS_NOT_STOCK', 'XRAY_UNIT_0666', 'XRAY_BRIDGE_UNIT_0666',
    'UNIT_WRITABLE', 'NFT_DIR_PRESENT', 'DROPIN_PRESENT', 'MODULES_LOAD_FOREIGN',
    'NETWORK_UNIT_ORPHANED', 'LEGACY_NFT_PRESENT', 'IPSEC_D_FOREIGN_CONF', 'SWAN_TREE_NOT_STOCK',
    'CONFFILE_UNKNOWN', 'INCLUDE_FOREIGN'];
const foreignCheck = 'L2TP_FOREIGN_CONFIG';
const foreignChanged = 'L2TP_FOREIGN_CONFIG_CHANGED';
const maxConflictFrame = `DIRECT_NO_WRITE_${foreignChanged} ${foreignKeys.join(',')} ${'0'.repeat(64)} ${foreignKeys.join(',')}\n`.length;
const freshConflicts = new Set([foreignCheck, foreignChanged, 'L2TP_DAEMON_ACTIVE', 'L2TP_UDP_BOUND', 'L2TP_PPP_ACTIVE']);
const conflictCodes = new Set([...freshConflicts].map(check => `REBUILD_${check}`));
const conflictCode = proof => `REBUILD_${proof.kind ?? proof.check}`;
const cleanupChallenges = new WeakMap();
const cleanupChallenge = error => cleanupChallenges.get(error);
const setCleanupChallenge = (error, challenge) => { cleanupChallenges.set(error, Object.freeze(challenge)); return error; };
const conflicts = new WeakMap();
function freshConflictFromFrame(action, result) {
    if (!isInstallStage(action) || result?.code !== 70 || result.stdout !== '' || typeof result.stderr !== 'string'
        || result.stderr.length > maxConflictFrame) return undefined;
    const prefix = action === 'install' ? 'DIRECT_NO_WRITE_' : 'DIRECT_';
    if (!result.stderr.startsWith(prefix) || !result.stderr.endsWith('\n')) return undefined;
    const [kind, items, digest, permitted, ...extra] = result.stderr.slice(prefix.length, -1).split(' ');
    if (!freshConflicts.has(kind) || extra.length) return undefined;
    if (kind !== foreignCheck && kind !== foreignChanged) return items === undefined ? { check: kind } : undefined;
    if (items === undefined) return kind === foreignChanged ? { check: foreignCheck, kind } : undefined;
    const keys = items.split(',');
    if (!items || foreignKeys.filter(key => keys.includes(key)).join(',') !== items) return undefined;
    if (digest === undefined) return kind === foreignCheck ? { check: foreignCheck, keys: Object.freeze(keys) } : undefined;
    if (!permitted || !/^[a-f0-9]{64}(?![\s\S])/.test(digest)) return undefined;
    const cleanable = permitted === '-' ? [] : permitted.split(',');
    if (permitted !== '-' && keys.filter(key => cleanable.includes(key)).join(',') !== permitted) return undefined;
    const manual = keys.filter(key => !cleanable.includes(key));
    return Object.freeze({ kind, check: foreignCheck, keys: Object.freeze(keys), digest,
        cleanable: Object.freeze(cleanable), manual: Object.freeze(manual) });
}
function withFreshConflict(error, proof) {
    conflicts.set(error, proof);
    return withInstallCheck(error, proof.check);
}
const freshConflict = error => conflicts.get(error);
const preflightModuleChecks = new Set(['PPP_MODULES_REQUIRED', 'PPP_MODULES_PERSISTENCE_CONFLICT',
    'KERNEL_MODULE_BLACKLISTED', 'NETWORK_OBSERVATION_REQUIRED']);
const checks = new Set([...freshConflicts].filter(check => check !== foreignChanged).concat([...packageChecks, ...Array.from(hostChecks.values(), ({ check }) => check), ...stages.values(),
    ...profileChecks.values(), 'VPN_UNITS_MASKED', 'VPN_UNITS_NOT_LOADED', 'FOREIGN_CONFIG_RESTORED', 'CLEANUP_CONSENT_REQUIRED',
    'CLEANUP_CONSENT_UNAVAILABLE', 'CLEANUP_CONSENT_XRAY_OPT_IN_REQUIRED']));
// The view uses the same localized map for the headline and list items.
// List item IDs are not valid top-level checks.
const installCheckIds = Object.freeze([...checks, ...foreignKeys]);
const isInstallCheck = check => checks.has(check);
const isInstallStage = action => stages.has(action);
function specificHostRefusal(action, suffix, noWrite) {
    if (action === 'preflight' && !noWrite && (packageChecks.has(suffix) || preflightModuleChecks.has(suffix))) {
        return { check: suffix, prerequisitePartial: false };
    }
    const match = hostChecks.get(suffix);
    if (action === 'prove-applied-main' && !noWrite
        && ['XRAY_DROPIN_UNSUPPORTED', 'XRAY_CONFIG_WRITABLE', 'XRAY_PROFILE_OWNER_UNSUPPORTED'].includes(suffix)) {
        return { check: match.check, prerequisitePartial: false };
    }
    if (!isInstallStage(action) || !match) return undefined;
    if (match.scope === 'prepare-only' && action !== 'prepare') return undefined;
    if (match.scope && match.scope !== 'fresh-pre-write' && action === 'preflight') return undefined;
    if (['pre-write-only', 'fresh-pre-write'].includes(match.scope) && action === 'install' && !noWrite) return undefined;
    return { check: match.check, prerequisitePartial: match.scope === 'shared-prerequisite'
        && action === 'install' && !noWrite };
}
const prerequisiteCheck = action => stages.get(action);

const nativePreparationKeys = ['machineId', 'ppp', 'masked', 'unitsLoaded', 'pppPreparation', 'nativePreparation'];
function hasPackagePreparation(host) {
    return host && Object.keys(host).length === 2 && Object.hasOwn(host, 'machineId') && Object.hasOwn(host, 'packagePreparation')
        && typeof host.machineId === 'string' && /^[a-f0-9]{32}(?![\s\S])/.test(host.machineId)
        && typeof host.packagePreparation === 'string' && /^[a-f0-9]{64}(?![\s\S])/.test(host.packagePreparation);
}

function hasNativePreparation(host) {
    return host?.nativePreparation === true && host.pppPreparation === true && host.unitsLoaded === false
        && host.masked === false && typeof host.ppp === 'boolean'
        && Object.keys(host).length === nativePreparationKeys.length
        && nativePreparationKeys.every(key => Object.hasOwn(host, key));
}

function requireInstallHostReady(host, preflight = host) {
    if (host?.masked === false && host.unitsLoaded === preflight?.unitsLoaded
        && (hasNativePreparation(preflight) || (host.unitsLoaded === true && !Object.hasOwn(preflight, 'nativePreparation')))
        && (host.ppp === true || (host.ppp === false && preflight.pppPreparation === true))) return;
    const code = 'REBUILD_L2TP_HOST_NOT_READY';
    const check = hasPackagePreparation(host) ? 'RUNTIME_PACKAGE_AUTOSTART_UNSAFE'
        : host?.masked === true ? 'VPN_UNITS_MASKED' : host?.unitsLoaded === false ? 'VPN_UNITS_NOT_LOADED'
        : host?.unitsLoaded !== preflight?.unitsLoaded ? 'HOST_BASELINE'
        : host?.ppp === false ? 'PPP_MODULES_REQUIRED' : 'HOST_PREFLIGHT';
    throw withInstallCheck(Object.assign(new Error(code), { code }), check);
}

const failed = 'REBUILD_L2TP_INSTALL_FAILED';
// Defaults for fixed, already-public service codes. A valid install refusal
// can have a different outcome depending on rollback and reservation cleanup.
const codeOutcomes = new Map([
    ['REBUILD_INVALID_REQUEST', 'refused'],
    ...Array.from(conflictCodes, code => [code, 'refused']),
    ['REBUILD_BUSY', 'busy'],
    ['REBUILD_LOCK_LOST', 'unknown'],
    ['REBUILD_LOCK_RELEASE_UNCONFIRMED', 'unknown'],
    ['REBUILD_TRANSPORT_CLEANUP_FAILED', 'unknown'],
    ...['INSTALL_DISABLED', 'INSTALL_IDENTITY_MISMATCH', 'IDENTITY_CHANGED', 'INSTALL_INPUT_INVALID', 'INSTALL_PLAN_INVALID',
        'GRANT_CONFLICT', 'GRANT_INVALID', 'GRANT_ENV_INVALID', 'GRANT_REGISTRY_INVALID', 'GRANT_PERSISTENCE_UNAVAILABLE',
        'NOT_FRESH_RELAY', 'BINDING_MISMATCH', 'SSH_PIN_INVALID', 'SSH_ENDPOINT_INVALID', 'SSH_CONNECT_FAILED',
        'HOST_NOT_READY', 'TOPOLOGY_NOT_APPLIED', 'KCP_LISTENER_UNSUPPORTED', 'CREDENTIAL_KEY_INVALID', 'ADDRESS_INVENTORY_INVALID',
        'ADDRESS_SPACE_EXHAUSTED', 'ACCOUNT_INVENTORY_INVALID', 'ACCOUNT_POOL_EXHAUSTED',
        'ACCOUNT_SOURCE_NOT_ENROLLED', 'ACCOUNT_SOURCE_CONFLICT', 'ACCOUNT_SOURCE_PREFLIGHT_REFUSED',
        'PROFILE_PRECONDITION', 'XRAY_BASELINE_UNSUPPORTED', 'STOCK_INSTALL_OUT_OF_SCOPE', 'STOCK_ARTIFACT_MISMATCH',
        'DIRECT_IDENTITY', 'DIRECT_PREREQUISITE', 'DIRECT_BASELINE_CHANGED', 'DIRECT_NETWORK_CONFLICT',
        'DIRECT_PROFILE_USERS', 'DIRECT_RUNTIME_UNPROVED', 'DIRECT_CANDIDATE_INVALID', 'DIRECT_COMMAND_FAILED',
        'CLEANUP_CONSENT_REQUIRED', 'CLEANUP_CONSENT_INVALID', 'CLEANUP_CONSENT_UNAVAILABLE', 'CLEANUP_CONSENT_XRAY_OPT_IN_REQUIRED',
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
function installFailure(code, outcome, check, { retryAllowed, conflict } = {}) {
    if (!codeOutcomes.has(code) || !outcomes.has(outcome)) {
        code = failed;
        outcome = 'unknown';
        check = undefined;
    }
    const error = withInstallCheck(Object.assign(new Error(code), { code, outcome,
        ...(retryAllowed === false && { retryAllowed: false }) }), check);
    if (outcome === 'refused' && conflict?.check === check) conflicts.set(error, conflict);
    failures.add(error);
    return Object.freeze(error);
}

function classifyInstallFailure(error) {
    if (failures.has(error)) return error;
    const code = error?.code;
    const conflict = freshConflict(error);
    const outcome = (conflict || !conflictCodes.has(code)) ? codeOutcomes.get(code) : undefined;
    const retryAllowed = error?.retryAllowed === false ? false : undefined;
    const check = conflict?.check ?? checkedInstallId(error) ?? profileChecks.get(code);
    return installFailure(outcome ? code : failed,
        error?.outcome === 'unknown' ? 'unknown' : outcome ?? 'unknown', check, { retryAllowed, conflict });
}

function publicInstallFailure(error) {
    const classified = classifyInstallFailure(error);
    const { code, outcome, check, retryAllowed } = classified;
    const keys = freshConflict(classified)?.keys;
    const challenge = outcome === 'refused' && cleanupChallenge(classified);
    return { code, outcome, ...(check !== undefined && { check }), ...(keys && { keys }), ...(challenge || {}),
        ...(retryAllowed === false && { retryAllowed }) };
}

module.exports = { installCheckIds, isInstallStage, specificHostRefusal, packageWriteCheck, prerequisiteCheck, hasNativePreparation, hasPackagePreparation, requireInstallHostReady,
    withInstallCheck, checkedInstallId, freshConflictFromFrame, freshConflict, withFreshConflict,
    installFailure, classifyInstallFailure, publicInstallFailure, conflictCode, setCleanupChallenge };
