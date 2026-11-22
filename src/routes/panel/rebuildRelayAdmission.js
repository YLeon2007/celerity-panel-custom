'use strict';

const { requireAuth } = require('./helpers');

// Match the raw URL; don't let Express decode an alternate spelling of a node ID.
const admissionPath = /^\/rebuild\/relays\/[^/]+\/l2tp\/admission\/[^/]+$/;
const nodeIdPattern = /^[a-f0-9]{24}(?![\s\S])/;
const pinPattern = /^[a-f0-9]{64}(?![\s\S])/;
const machinePattern = /^[a-f0-9]{32}(?![\s\S])/;
const challengeJson = /^\s*\{\s*"challenge"\s*:\s*"[a-f0-9]{64}"\s*\}\s*$/;
const emptyJson = /^\s*\{\s*\}\s*$/;
const actions = new Set(['probe', 'verify', 'confirm', 'revoke']);
const needsChallenge = action => action === 'verify' || action === 'confirm';
const invalid = 'REBUILD_L2TP_ADMISSION_INVALID_REQUEST';
const unavailable = 'REBUILD_L2TP_ADMISSION_UNAVAILABLE';
const identityChanged = 'REBUILD_L2TP_IDENTITY_CHANGED';
const grantConflict = 'REBUILD_L2TP_GRANT_CONFLICT';
const grantUnavailable = 'REBUILD_L2TP_GRANT_UNAVAILABLE';
const unavailableGrantCodes = new Set([grantUnavailable, 'REBUILD_L2TP_GRANT_PERSISTENCE_UNAVAILABLE',
    'REBUILD_L2TP_GRANT_ENV_INVALID', 'REBUILD_L2TP_GRANT_REGISTRY_INVALID', 'REBUILD_L2TP_GRANT_INVALID']);
const grantEffectStatus = code => code === identityChanged || code === grantConflict || code === 'REBUILD_L2TP_GRANT_CHANGED' ? 409
    : unavailableGrantCodes.has(code) ? 503 : undefined;
const errorStatuses = new Map([
    [invalid, 400],
    ['REBUILD_L2TP_ADMISSION_CHALLENGE_INVALID', 409],
    ['REBUILD_L2TP_GRANT_LEGACY_SINGLETON_IN_USE', 409],
    ['REBUILD_L2TP_INSTALL_DISABLED', 409], ['REBUILD_L2TP_GRANT_OUTCOME_UNKNOWN', 503],
    ['REBUILD_LOCK_RELEASE_UNCONFIRMED', 503], ['REBUILD_L2TP_IDENTITY_UNAVAILABLE', 503],
    ['REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE', 503],
    ['REBUILD_L2TP_ACCOUNTS_BLOCKED', 409], ['REBUILD_BUSY', 409], ['REBUILD_LOCK_LOST', 409],
]);
const refreshCodes = new Set(['REBUILD_L2TP_GRANT_OUTCOME_UNKNOWN', 'REBUILD_LOCK_RELEASE_UNCONFIRMED']);
const conflictFields = new Set(['nodeId', 'machineId', 'sshHostKeySha256', 'endpoint', 'host', 'port', 'username']);
const validNodeId = value => typeof value === 'string' && nodeIdPattern.test(value);
const matches = (pattern, value) => typeof value === 'string' && pattern.test(value);
const validHost = value => matches(/^[A-Za-z0-9.:[\]_-]{1,253}(?![\s\S])/, value);
const validUsername = value => matches(/^[^\s\x00-\x1f\x7f]{1,128}(?![\s\S])/, value);
const validActor = value => matches(/^[^\x00-\x1f\x7f]{1,256}(?![\s\S])/, value) && value === value.trim();
const actionFrom = path => path.slice(path.lastIndexOf('/') + 1);
const errorResponse = (res, status, code) => res.status(status).json({ error: { code } });
const reject = res => errorResponse(res, 400, invalid);

function validAdmissionJson(path, bytes) {
    return (needsChallenge(actionFrom(path)) ? challengeJson : emptyJson).test(bytes.toString('utf8'));
}

function publicReceipt(action, nodeId, value) {
    if (value?.nodeId !== nodeId) return null;
    if (action === 'revoke') return { nodeId };
    const { host, port, username, sshHostKeySha256, machineId, challenge } = value;
    if (!validHost(host) || !Number.isInteger(port) || port < 1 || port > 65535 || !validUsername(username)
        || !matches(pinPattern, sshHostKeySha256)) return null;
    const result = { nodeId, host, port, username, sshHostKeySha256 };
    if (action !== 'probe') {
        if (!matches(machinePattern, machineId)) return null;
        result.machineId = machineId;
    }
    if (action === 'probe' || action === 'verify') {
        if (!matches(pinPattern, challenge)) return null;
        result.challenge = challenge;
    }
    return result;
}

function publicConflict(error) {
    // Admission projects the service's categorical detail; registry conflicts
    // may also carry a field and two source labels. Never copy values.
    const field = error.detail ?? error.field;
    const sources = error.sources;
    const pair = Array.isArray(sources) && sources.length === 2
        && (sources[0] === 'env' || sources[0] === 'db') && (sources[1] === 'env' || sources[1] === 'db');
    const detail = { ...(conflictFields.has(field) && { field }),
        ...(pair ? { sources: [sources[0], sources[1]] } : field === 'env-read-only' ? { sources: ['env'] } : {}) };
    return Object.keys(detail).length ? detail : undefined;
}

function mountAdmission(router, service, { requireSessionId, checkCsrf, requireCompletedOnboarding }, limiter) {
    const getService = () => service ??= require('../../services/rebuildRelayAdmission').createRebuildRelayAdmission();
    router.post(admissionPath, requireAuth, requireSessionId, (req, res, next) => {
        if (!validActor(req.session.adminUsername)) return errorResponse(res, 403, 'REBUILD_L2TP_SESSION_REQUIRED');
        next();
    }, checkCsrf, (req, res, next) => {
        const [,,, nodeId] = req.path.split('/');
        const action = actionFrom(req.path), body = req.body;
        if (!validNodeId(nodeId) || !actions.has(action) || req.url.includes('?')
            || !req.is('application/json') || req.get('content-length') === '0'
            || !body || Object.getPrototypeOf(body) !== Object.prototype) return reject(res);
        const keys = Object.keys(body);
        if (needsChallenge(action) ? keys.length !== 1 || keys[0] !== 'challenge' || !matches(pinPattern, body.challenge)
            : keys.length !== 0) return reject(res);
        next();
    }, limiter, requireCompletedOnboarding(res => errorResponse(res, 503, unavailable)), async (req, res) => {
        const [,,, nodeId] = req.path.split('/');
        const action = actionFrom(req.path);
        try {
            const result = publicReceipt(action, nodeId, await getService().perform({ action, nodeId,
                actor: req.session.adminUsername, sessionId: req.sessionID, challenge: req.body.challenge }));
            if (!result) return errorResponse(res, 503, unavailable);
            // Do not derive an ETag from the one-use challenge.
            return res.type('application/json').end(JSON.stringify(result));
        } catch (error) {
            const code = error?.code;
            const status = grantEffectStatus(code) ?? errorStatuses.get(code);
            if (!status) return errorResponse(res, 503, unavailable);
            const conflict = code === grantConflict ? publicConflict(error) : undefined;
            return res.status(status).json({ error: { code, ...(conflict && { conflict }),
                ...(refreshCodes.has(code) && { retryAllowed: false }) } });
        }
    });
    router.all(admissionPath, (_req, res) => errorResponse(res.set('Allow', 'POST'), 405, 'METHOD_NOT_ALLOWED'));
    router.all(admissionPath, (_err, _req, res, _next) => errorResponse(res, 503, unavailable));
}

module.exports = { mountAdmission, admissionPath, validAdmissionJson, reject, validNodeId,
    identityChanged, grantConflict, grantUnavailable, grantEffectStatus };
