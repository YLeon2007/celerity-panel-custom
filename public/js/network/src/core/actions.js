import { createRebuildClient, isObjectId, isPreviewId, linkIdOf, RebuildRequestError, SessionChanged } from './api.js';
import { t } from './i18n.js';
import { toast } from '../ui/dom.js';

const kcpRefusals = new Set([
    'REBUILD_KCP_XRAY_VERSION_UNSUPPORTED', 'REBUILD_KCP_UDP_PORT_CONFLICT', 'REBUILD_L2TP_KCP_LISTENER_UNSUPPORTED',
]);
const stale = new Set(['REBUILD_PREVIEW_CHANGED', 'REBUILD_LINK_CHANGED', 'REBUILD_PREVIEW_REQUIRED']);
const statuses = new Set(['pending', 'staged', 'deployed', 'online', 'offline', 'error']);
const changes = new Set(['create', 'replace', 'unchanged']);
const sections = new Set(['inbounds', 'outbounds', 'routing', 'reverse', 'log', 'api', 'stats', 'policy', 'dns', 'observatory']);

function validReport(report) {
    // The coordinator reads exactly one MAIN and one bridge profile per node.
    if (typeof report?.allowed !== 'boolean' || !isPreviewId(report.previewId)
        || !Array.isArray(report.nodes) || !report.nodes.length || Object.hasOwn(report, 'error')) return false;
    const seen = new Set();
    for (const node of report.nodes) {
        if (!isObjectId(node?.nodeId) || seen.has(node.nodeId) || !Array.isArray(node.profiles) || node.profiles.length !== 2) return false;
        seen.add(node.nodeId);
        const profiles = new Set(node.profiles.map(p => p?.profile));
        if (!profiles.has('main') || !profiles.has('bridge')) return false;
        if (!node.profiles.every(p => changes.has(p.change) && typeof p.protectedChanged === 'boolean'
            && Array.isArray(p.sections) && p.sections.every(s => sections.has(s)))) return false;
    }
    return true;
}

function allowsApply(report) {
    const clear = obj => !Object.hasOwn(obj, 'protectedChanged') || obj.protectedChanged === false;
    return report.allowed === true && clear(report)
        && report.nodes.every(node => clear(node) && node.profiles.every(p => p.protectedChanged === false));
}

function refusalInfo(err) {
    const error = err instanceof RebuildRequestError ? err.body?.error : null;
    const code = error?.code;
    if (err instanceof SessionChanged || err instanceof RebuildRequestError && err.status === 403) {
        return { message: t('map.rebuild.sessionChanged'), notSaved: err instanceof SessionChanged || err.csrfRejected };
    }
    if (err instanceof RebuildRequestError && err.status === 409 && kcpRefusals.has(code)) {
        // This route publishes localized plain text for typed mKCP refusals.
        // Never display a generic transport / exception message.
        const issueMessages = Array.isArray(error.issues) ? error.issues.map(issue => issue?.message).filter(publicText) : [];
        return { message: publicText(error.message) ? error.message : issueMessages.join(' ') || t('map.rebuild.kcpRefused'), notSaved: true };
    }
    if (err instanceof RebuildRequestError && err.status === 400 && code === 'INVALID_KCP_LINK_SETTINGS') {
        return { message: t('map.rebuild.kcpRefused'), notSaved: true };
    }
    if (stale.has(code)) return { message: t('map.rebuild.previewChanged') };
    return { notSaved: err instanceof RebuildRequestError && err.status === 400 && code === 'REBUILD_INVALID_REQUEST' };
}

function publicText(value) {
    return typeof value === 'string' && value.trim().length > 0 && !/[\p{Cc}\p{Bidi_Control}]/u.test(value);
}

async function showRefusal(message) {
    const dialog = window.C3RebuildPreview;
    if (typeof dialog?.showRefusal === 'function') {
        try { await dialog.showRefusal(message); return; } catch (_) { /* Fall back to the map toast. */ }
    }
    toast(message, 'error');
}

const draftResult = (status, linkId = null) => ({ status, desiredSaved: linkId !== null, linkId });

/** Rebuild-only controller. Callers own the buttons and form; construction is idle. */
export function createActions(store) {
    let busy = false;

    async function run(task, onBusy) {
        if (busy) return onBusy;
        busy = true;
        let needsRefresh = false;
        const refresh = () => {
            if (!needsRefresh) return;
            needsRefresh = false;
            return store.refreshAfterWrite();
        };
        // Start readback even if the operator leaves the refusal dialog open.
        const refuse = message => Promise.all([refresh(), showRefusal(message)]);
        try {
            return await task(() => { needsRefresh = true; }, refuse);
        } finally {
            try {
                await refresh();
            } finally {
                busy = false;
            }
        }
    }

    function selectedLinkId(edgeId) {
        return store.index.links.has(edgeId) ? linkIdOf(edgeId) : null;
    }

    function lookupNode(nodeId) {
        const node = store.index.nodes.get(nodeId);
        return node ? { label: node.label, role: store.model.roleOf(node) } : null;
    }

    async function previewAndWrite(client, linkId, operation, markWrite, refuse) {
        const dialog = window.C3RebuildPreview;
        if (typeof dialog?.confirmReport !== 'function') {
            await refuse(t('map.rebuild.previewUnavailable'));
            return false;
        }
        const removing = operation === 'remove';
        let report;
        try {
            report = await client.preview(linkId, removing);
            client.assertSession();
        } catch (err) {
            await refuse(refusalInfo(err).message || t('map.rebuild.previewUnavailable'));
            return false;
        }
        if (!validReport(report)) {
            await refuse(t('map.rebuild.previewUnavailable'));
            return false;
        }
        // The UI can only approve this exact server-issued token. A denied
        // report may still be rendered, but never supplies write authority.
        const token = report.previewId;
        const allowed = allowsApply(report);
        let approved;
        try {
            approved = await dialog.confirmReport({ report: allowed ? report : { ...report, allowed: false }, removing, lookupNode });
        } catch (_) {
            await refuse(t('map.rebuild.previewUnavailable'));
            return false;
        }
        if (!allowed || approved === null) return false;
        if (approved !== token) {
            await refuse(t('map.rebuild.previewUnavailable'));
            return false;
        }
        try {
            client.assertSession();
            markWrite();
            const reply = await client[operation](linkId, token);
            if (reply?.executionMode !== 'rebuild' || reply.allowed !== true || reply.previewId !== token
                || Object.hasOwn(reply, 'error') || (removing ? reply.deleted !== linkId : reply.status !== 'succeeded')) {
                throw new Error('Unconfirmed Rebuild write');
            }
        } catch (err) {
            await refuse(refusalInfo(err).message || t('map.rebuild.writeUnconfirmed'));
            return false;
        }
        toast(removing ? t('map.rebuild.removed') : t('map.rebuild.applied'));
        return true;
    }

    async function applySelection(edgeId, operation) {
        const linkId = selectedLinkId(edgeId);
        if (!linkId) return false;
        return run(async (markWrite, refuse) => {
            let client;
            try { client = createRebuildClient(); } catch (err) {
                await refuse(refusalInfo(err).message || t('map.rebuild.previewUnavailable'));
                return false;
            }
            return previewAndWrite(client, linkId, operation, markWrite, refuse);
        }, false);
    }

    async function createAndDeploy(body) {
        return run(async (markWrite, refuse) => {
            if (typeof window.C3RebuildPreview?.confirmReport !== 'function') {
                await refuse(t('map.rebuild.previewUnavailable'));
                return draftResult('not_saved');
            }
            let client, reply;
            try {
                client = createRebuildClient();
                markWrite();
                reply = await client.saveDraft(body);
                if (reply?.executionMode !== 'rebuild' || reply.status !== 'saved' || Object.hasOwn(reply, 'error')
                    || reply.desiredSaved !== true || !isObjectId(reply.linkId)) throw new Error('Unconfirmed draft save');
            } catch (err) {
                // The route latches an acknowledged draft even if lock cleanup
                // subsequently fails. That reply cannot authorize preview/apply.
                const partial = err instanceof RebuildRequestError && [400, 404, 409, 428].includes(err.status)
                    && typeof err.body?.error?.code === 'string' ? err.body : null;
                const linkId = partial?.desiredSaved === true && isObjectId(partial.linkId) ? partial.linkId : null;
                const info = refusalInfo(err);
                await refuse(info.message || t('map.rebuild.saveUnconfirmed'));
                if (linkId) toast(t('map.rebuild.draftSaved'), 'warning');
                return linkId ? draftResult('saved', linkId) : draftResult(info.notSaved ? 'not_saved' : 'unknown');
            }
            const { linkId } = reply;
            if (await previewAndWrite(client, linkId, 'deploy', markWrite, refuse)) return draftResult('applied', linkId);
            toast(t('map.rebuild.draftSaved'), 'warning');
            return draftResult('saved', linkId);
        }, draftResult('busy'));
    }

    async function checkHealth(edgeId) {
        const linkId = selectedLinkId(edgeId);
        if (!linkId) return false;
        return run(async markWrite => {
            try {
                const client = createRebuildClient();
                // The GET can record an observation. Never infer a status from
                // the legacy `healthy` field or update the edge optimistically.
                markWrite();
                const { status } = await client.checkHealth(linkId);
                if (!statuses.has(status)) throw new Error('Invalid health status');
                const label = status === 'staged' ? t('map.rebuild.healthStaged') : t(`map.status.${status}`);
                toast(t('map.rebuild.healthStatus', { status: label }), status === 'online' ? 'success' : 'warning');
                return true;
            } catch (_) {
                toast(t('map.rebuild.healthUnavailable'), 'error');
                return false;
            }
        }, false);
    }

    return {
        isBusy: () => busy,
        deploy: edgeId => applySelection(edgeId, 'deploy'),
        deployChain: edgeId => applySelection(edgeId, 'deployChain'),
        remove: edgeId => applySelection(edgeId, 'remove'),
        checkHealth,
        createAndDeploy,
    };
}
