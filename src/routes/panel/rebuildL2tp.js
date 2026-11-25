'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const { requireAuth, render } = require('./helpers');
const { requirePanelCsrf } = require('./csrf');
const { isRebuildEnabled } = require('../../services/rebuildMode');
const { installCheckIds } = require('../../services/rebuildRelayInstallDiagnostics');
const { isInspectionReason } = require('../../services/rebuildRelayInspection');
const { runtimeForeignChange, networkObservationRequired, networkNotReadyDetails } = require('../../services/rebuildRelayRuntimeRefusal');
const { mountAdmission, admissionPath, validAdmissionJson, reject: rejectAdmission,
    validNodeId, validActor, grantEffectStatus, identityChanged } = require('./rebuildRelayAdmission');
const { retirePath, validRetireJson, rejectRetire, mountRetire } = require('./rebuildRelayRetire');
const { observe, readObservation, header, rebuildL2tpScriptVersion } = require('./rebuildL2tpObservation');

const pagePath = /^\/l2tp$/;
const accountPath = /^\/rebuild\/relays\/l2tp\/accounts\/reveal$/;
const reconcilePath = /^\/rebuild\/relays\/l2tp\/accounts\/reconcile$/;
// No Express parameter capture: validate the raw segment, without URL decoding.
const pskPath = /^\/rebuild\/relays\/[^/]+\/l2tp\/psk\/reveal$/;
const installRecoveryPath = /^\/rebuild\/relays\/[^/]+\/l2tp\/install\/recover$/;
const effectPath = /^\/rebuild\/relays\/(?:[^/]+\/l2tp\/(?:install|remove(?:\/cancel)?)|l2tp\/accounts\/(?:create|disable|delete))\/?$/i;
const loginPattern = /^[A-Za-z0-9._@-]{1,64}(?![\s\S])/;
const idPattern = /^[a-f0-9]{24}(?![\s\S])/;
const jsonString = String.raw`"(?:[^"\\]|\\.)*"`;
const accountJson = new RegExp(String.raw`^\s*\{\s*${jsonString}\s*:\s*${jsonString}\s*\}\s*$`);
const emptyJson = /^\s*\{\s*\}\s*$/;
const reconcileInvalid = 'REBUILD_L2TP_RECONCILE_INVALID_REQUEST';
const reconcileUnavailable = res => revealError(res, 503, 'REBUILD_L2TP_RECONCILE_UNAVAILABLE');
const reconcileBlocked = 'REBUILD_L2TP_ACCOUNTS_MANUAL_BLOCK';
const reconcileUnknown = 'REBUILD_L2TP_ACCOUNTS_OUTCOME_UNKNOWN';
const invalidRecovery = res => revealError(res, 400, 'REBUILD_INVALID_REQUEST');
const unconfirmedRecovery = (res, status = 503) => res.status(status).json({
    error: { code: 'REBUILD_L2TP_INSTALL_RECOVERY_UNCONFIRMED', retryAllowed: false },
});

function noStore(_req, res, next) {
    res.set('Cache-Control', 'no-store');
    next();
}

function revealError(res, status, code) {
    return res.status(status).json({ error: { code } });
}

function unavailable(res) {
    return revealError(res, 503, 'REBUILD_L2TP_REVEAL_UNAVAILABLE');
}

function invalidRequest(res) {
    return revealError(res, 400, 'REBUILD_L2TP_REVEAL_INVALID_REQUEST');
}

// Mount at app level before CORS and the general parsers. The panel router
// cannot mark or sanitize requests that those earlier middlewares terminate.
const parseScopedJson = express.json({
    limit: '1kb',
    inflate: false,
    verify(req, _res, bytes) {
        // Verify the wire shape before JSON.parse can discard duplicate keys.
        const path = req.path.slice('/panel'.length);
        const valid = admissionPath.test(path) ? validAdmissionJson(path, bytes)
            : retirePath.test(path) ? validRetireJson(path, bytes)
                : (accountPath.test(path) ? accountJson : emptyJson).test(bytes.toString('utf8'));
        if (!valid) throw new Error('Invalid rebuild L2TP request');
    },
});

function rebuildL2tpIngress(req, res, next) {
    if (!/^\/panel\//i.test(req.path)) return next();
    const path = req.path.slice('/panel'.length);
    if (req.method === 'GET' && pagePath.test(path)) return noStore(req, res, next);
    if (effectPath.test(path)) return noStore(req, res, next);
    const reconcile = reconcilePath.test(path);
    const admission = admissionPath.test(path);
    const retire = retirePath.test(path);
    const installRecovery = installRecoveryPath.test(path);
    if (!admission && !retire && !reconcile && !installRecovery && !accountPath.test(path) && !pskPath.test(path)) return next();
    res.set('Cache-Control', 'no-store');
    if (req.method !== 'POST') return next();
    const reject = () => admission ? rejectAdmission(res)
        : retire ? rejectRetire(res) : installRecovery ? invalidRecovery(res)
            : reconcile ? revealError(res, 400, reconcileInvalid) : invalidRequest(res);
    if (req.url.includes('?') || !req.is('application/json') || req.get('content-length') === '0') return reject();
    if ((admission || retire || installRecovery) && !req.get('content-length') && !req.get('transfer-encoding')) return reject();
    return parseScopedJson(req, res, err => err ? reject() : next());
}

function renderPage(res, model) {
    const t = res.locals.t;
    const title = t?.('rebuildL2tp.title');
    const installChecks = Object.fromEntries(installCheckIds.map(check => [check, t?.(`rebuildL2tp.installChecks.${check}`)]));
    return render(res, 'rebuild-l2tp', { title: title && title !== 'rebuildL2tp.title' ? title : 'L2TP', page: 'l2tp',
        ...model, installChecks, rebuildL2tpScriptVersion: rebuildL2tpScriptVersion() });
}

function sendLoadError(res) {
    res.status(503);
    try {
        return renderPage(res, { loadError: true, relays: [], accounts: [], canManageAccounts: false });
    } catch {
        return res.type('text/plain').send(res.locals.t?.('dashboard.loadError') || 'Loading error');
    }
}

// The shared legacy onboarding middleware allows requests through on a failed
// Settings read. Neither this page nor secret access can use that fallback.
function requireCompletedOnboarding(onUnavailable) {
    return async (_req, res, next) => {
        let settings;
        try {
            const Settings = require('../../models/settingsModel');
            settings = await Settings.findById('settings').select('deployment.completed').lean();
        } catch {
            return onUnavailable(res);
        }
        if (settings?.deployment?.completed !== true) return res.redirect('/panel/wizard');
        next();
    };
}

const hasSessionId = req => req.session?.authenticated === true && typeof req.sessionID === 'string' && !!req.sessionID;

function requireSessionId(req, res, next) {
    if (!hasSessionId(req)) {
        return revealError(res, 403, 'REBUILD_L2TP_SESSION_REQUIRED');
    }
    next();
}

function checkCsrf(req, res, next) {
    // This API only accepts the header. Reject non-ASCII before the shared
    // comparison, which expects string length and byte length to agree.
    const token = req.get('x-csrf-token');
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}(?![\s\S])/.test(token)) {
        return res.status(403).json({ error: 'CSRF validation failed', code: 'CSRF_TOKEN_INVALID' });
    }
    return requirePanelCsrf(req, res, next);
}

function revealInput(isAccount) {
    return (req, res, next) => {
        const body = req.body;
        const identifier = isAccount ? body?.login : req.path.split('/')[3];
        const keys = body && Object.getPrototypeOf(body) === Object.prototype ? Object.keys(body) : null;
        if (req.url.includes('?') || !req.is('application/json') || req.get('content-length') === '0' || !keys
            || (isAccount ? keys.length !== 1 || keys[0] !== 'login' || typeof identifier !== 'string' || !loginPattern.test(identifier)
                : keys.length !== 0 || !idPattern.test(identifier))) {
            return invalidRequest(res);
        }
        res.locals.rebuildL2tpIdentifier = identifier;
        next();
    };
}

function mountNoStore(router) {
    router.all([accountPath, pskPath, reconcilePath, admissionPath, effectPath, retirePath, installRecoveryPath], noStore);
    router.get(pagePath, (req, res, next) => req.method === 'GET' ? noStore(req, res, next) : next());
}

function mountOverview(router, getOverview, exposePanelCsrfToken) {
    router.get(pagePath, (req, _res, next) => req.method === 'GET' ? next() : next('route'),
        requireAuth, exposePanelCsrfToken, requireCompletedOnboarding(sendLoadError), async (req, res) => {
            try {
                const removalNotice = req.query.view === 'remove-unconfirmed' ? 'uncertain'
                    : req.query.view === 'remove-cleanup' ? 'removeCleanupFailed'
                        : req.query.view === 'remove-foreign-change' ? 'runtimeForeignChange'
                            : req.query.view === 'remove-network-not-ready' ? 'runtimeNetworkNotReady' : null;
                if (removalNotice) return renderPage(res, { removalNotice, relays: [], accounts: [], canManageAccounts: false });
                const changedRelayId = validNodeId(req.query.identityChanged) ? req.query.identityChanged : null;
                // Read the request-bound witness before loading the overview. A
                // completion during the GET cannot vouch for an earlier snapshot.
                const outcome = req.url === '/l2tp' && readObservation(req);
                const model = await getOverview().overview();
                if (outcome) res.set(header, `${req.headers[header]}:${outcome}`);
                return renderPage(res, { ...model, changedRelayId,
                    canRequestInstallRecovery: hasSessionId(req) && validActor(req.session.adminUsername) && req.query.view !== 'only',
                    reconcileViewOnly: req.query.view === 'only' || changedRelayId !== null });
            } catch {
                return sendLoadError(res);
            }
        });
}

function mountReveals(router, getOverview) {
    const revealLimiter = rateLimit({
        windowMs: 60 * 1000,
        max: 10,
        keyGenerator: req => req.sessionID,
        standardHeaders: true,
        legacyHeaders: false,
        handler: (_req, res) => revealError(res, 429, 'REBUILD_L2TP_REVEAL_RATE_LIMITED'),
    });
    const onboarded = requireCompletedOnboarding(unavailable);
    for (const [path, method, isAccount] of [[accountPath, 'revealPassword', true], [pskPath, 'revealPsk', false]]) {
        router.post(path, requireAuth, requireSessionId, checkCsrf, revealInput(isAccount), revealLimiter, onboarded,
            async (_req, res) => {
                let secret;
                try {
                    secret = await getOverview()[method](res.locals.rebuildL2tpIdentifier);
                } catch {
                    return unavailable(res);
                }
                if (secret === null) return revealError(res, 404, 'REBUILD_L2TP_SECRET_NOT_FOUND');
                if (typeof secret !== 'string' || !secret) return unavailable(res);
                // Avoid generating an ETag from a secret response.
                return res.type('application/json').end(JSON.stringify({ secret }));
            });
        router.all(path, (_req, res) => revealError(res.set('Allow', 'POST'), 405, 'METHOD_NOT_ALLOWED'));
        router.all(path, (_err, _req, res, _next) => unavailable(res));
    }
}

function mountReconcile(router, getOverview, reconcile, limiter) {
    router.post(reconcilePath, requireAuth, requireSessionId, checkCsrf, (req, res, next) => {
        const body = req.body;
        if (req.url.includes('?') || !req.is('application/json') || req.get('content-length') === '0'
            || !body || Object.getPrototypeOf(body) !== Object.prototype || Object.keys(body).length !== 0) {
            return revealError(res, 400, reconcileInvalid);
        }
        if (!isRebuildEnabled()) {
            return revealError(res, 409, 'REBUILD_L2TP_RECONCILE_DISABLED');
        }
        next();
    }, requireCompletedOnboarding(reconcileUnavailable), limiter, async (req, res) => {
        const acknowledge = observe(req);
        const receipt = (status, count) => res.json({ executionMode: 'rebuild', status,
            ...(count !== undefined && { sessionsTerminated: count, sessionsTerminatedScope: 'request' }) });
        const manualBlock = () => res.status(409).json({ error: { code: reconcileBlocked, retryAllowed: false } });
        try {
            const { hasPendingAccounts, overview } = getOverview();
            // This is a scoped recovery request, not a request to mutate a
            // specific account or host. The writer rechecks under its lock.
            if (!await hasPendingAccounts()) return receipt('settled');
            // Let the current merged overview attest to multi-relay recovery.
            // The service independently rechecks authority under the writer lock.
            const authority = await overview();
            if (authority.grantProblem === identityChanged) {
                return await hasPendingAccounts() ? manualBlock() : receipt('settled');
            }
            if (authority.grantProblem) {
                const status = grantEffectStatus(authority.grantProblem);
                return status ? revealError(res, status, authority.grantProblem) : reconcileUnavailable(res);
            }
            if (authority.canReconcileAccounts !== true) {
                return await hasPendingAccounts() ? revealError(res, 409, 'REBUILD_L2TP_RECONCILE_DISABLED') : receipt('settled');
            }
            let result, failed = false, reason, failureCode, identityBlocked = false, foreignChange = false,
                networkNotReady = false, outcomeUnknown = false;
            try { result = await reconcile(); } catch (error) {
                failed = true;
                const diagnostic = error?.retryAllowed === false && error.inspectionReason;
                if (isInspectionReason(diagnostic)) reason = diagnostic;
                failureCode = error?.code;
                identityBlocked = error?.identityBlocked === true;
                foreignChange = failureCode === 'REBUILD_L2TP_ACCOUNTS_BLOCKED' && error.runtimeForeignChange === true
                    && error.retryAllowed === false && error.outcome === undefined;
                networkNotReady = failureCode === 'REBUILD_L2TP_ACCOUNTS_BLOCKED' && error.check === networkObservationRequired
                    && error.retryAllowed === false && error.outcome === undefined;
                outcomeUnknown = failureCode === reconcileUnknown && error.outcome === 'unknown' && error.retryAllowed === false;
            }
            // A host refusal is diagnostic only while the pending fence still
            // exists. Busy, lost replies and unclassified outcomes stay pending.
            if (await hasPendingAccounts()) {
                if (outcomeUnknown) return res.status(409).json({ error: { code: reconcileUnknown, outcome: 'unknown', retryAllowed: false } });
                if (identityBlocked || failureCode === reconcileBlocked || failureCode === identityChanged) return manualBlock();
                if (foreignChange) return res.status(409).json({ error: { code: runtimeForeignChange, retryAllowed: false } });
                if (networkNotReady) return res.status(409).json({ error: networkNotReadyDetails });
                const grantStatus = grantEffectStatus(failureCode);
                if (grantStatus) return revealError(res, grantStatus, failureCode);
                if (reason) return res.json({ executionMode: 'rebuild', status: 'inspection-unproved', reason, retryAllowed: false });
                return receipt('pending');
            }
            if (failed) return reconcileUnavailable(res);
            // Publish only acknowledged closures from this settled revocation, never its account or relay metadata.
            const count = result?.sessionsTerminated;
            const proved = result?.executionMode === 'rebuild' && result.recovered === true
                && (result.status === 'disabled' || result.status === 'deleted') && Number.isSafeInteger(count) && count >= 0;
            if (result?.executionMode === 'rebuild' && result.recovered === true
                && ['created', 'disabled', 'deleted', 'canceled'].includes(result.status)) acknowledge('settled');
            return receipt('settled', proved ? count : undefined);
        } catch {
            return reconcileUnavailable(res);
        }
    });
    router.all(reconcilePath, (_req, res) => revealError(res.set('Allow', 'POST'), 405, 'METHOD_NOT_ALLOWED'));
}

function mountInstallRecovery(router, limiter) {
    router.post(installRecoveryPath, requireAuth, requireSessionId, (req, res, next) => {
        if (!validActor(req.session.adminUsername)) return revealError(res, 403, 'REBUILD_L2TP_SESSION_REQUIRED');
        next();
    }, checkCsrf, (req, res, next) => {
        const body = req.body;
        if (!validNodeId(req.path.split('/')[3]) || req.url.includes('?') || !req.is('application/json')
            || !body || Object.getPrototypeOf(body) !== Object.prototype || Object.keys(body).length !== 0) {
            return invalidRecovery(res);
        }
        next();
    }, limiter, requireCompletedOnboarding(unconfirmedRecovery), async (req, res) => {
        const nodeId = req.path.split('/')[3];
        const acknowledge = observe(req);
        try {
            const service = require('../../services/rebuildService').createRebuildService();
            const result = await service.recoverRelayInstall(nodeId, { actor: req.session.adminUsername });
            if (result?.status !== 'can_install_again' || (result.nodeId !== undefined && result.nodeId !== nodeId)
                || result.error !== undefined || result.retryAllowed === false || result.outcome === 'unknown') {
                return unconfirmedRecovery(res);
            }
            acknowledge('can_install_again');
            return res.json({ executionMode: 'rebuild', status: 'can_install_again', nodeId });
        } catch (error) {
            if (error?.retryAllowed === false && error.outcome === undefined && !error.remoteOutcomeUncertain) {
                if (error.code === 'REBUILD_L2TP_INSTALL_RECOVERY_NO_STATE') {
                    return res.status(409).json({ error: { code: error.code, retryAllowed: false } });
                }
                if (error.code === 'REBUILD_L2TP_INSTALL_RECOVERY_RECHECK') {
                    return res.status(503).json({ error: { code: error.code, retryAllowed: false }, nodeId });
                }
            }
            const status = error?.code === 'REBUILD_L2TP_INSTALL_DISABLED' ? 409 : grantEffectStatus(error?.code);
            return unconfirmedRecovery(res, status);
        }
    });
    router.all(installRecoveryPath, (_req, res) => revealError(res.set('Allow', 'POST'), 405, 'METHOD_NOT_ALLOWED'));
}

function createRoutes(service, admission) {
    // No service construction or query at startup or on a refused request.
    const getOverview = () => service ??= require('../../services/rebuildL2tpOverview').createRebuildL2tpOverview();
    const reconcile = () => require('../../services/rebuildService').createRebuildService().reconcileRelayAccounts();
    return {
        mountNoStore,
        mountOverview: (router, exposePanelCsrfToken) => mountOverview(router, getOverview, exposePanelCsrfToken),
        mountReconcile: (router, limiter) => mountReconcile(router, getOverview, reconcile, limiter),
        mountReveals: router => mountReveals(router, getOverview),
        mountInstallRecovery,
        mountAdmission: (router, limiter) => mountAdmission(router, admission,
            { requireSessionId, checkCsrf, requireCompletedOnboarding }, limiter),
        mountRetire: (router, limiter) => mountRetire(router,
            { requireSessionId, checkCsrf, requireCompletedOnboarding }, limiter),
    };
}

module.exports = { createRoutes, rebuildL2tpIngress };
