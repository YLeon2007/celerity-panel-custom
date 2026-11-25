import { createRebuildClient, isObjectId, isPreviewId, linkIdOf, RebuildRequestError, SessionChanged } from './api.js';
import { editPatch, InvalidEditFields } from './edit-fields.js';
import { t } from './i18n.js';
import { toast } from '../ui/dom.js';

const kcpRefusals = new Set([
    'REBUILD_KCP_XRAY_VERSION_UNSUPPORTED', 'REBUILD_KCP_UDP_PORT_CONFLICT', 'REBUILD_L2TP_KCP_LISTENER_UNSUPPORTED',
]);
const stale = new Set(['REBUILD_PREVIEW_CHANGED', 'REBUILD_LINK_CHANGED', 'REBUILD_PREVIEW_REQUIRED']);
const editUnavailable = new Set(['REBUILD_LINK_NOT_FOUND', 'REBUILD_DELETION_PENDING', 'REBUILD_INVALID_EDGE_ROLE', 'REBUILD_REPLACE_WITH_DELETE_CREATE']);
const tlsRefusals = new Set(['REBUILD_TLS_SERVER_NAME_REQUIRED', 'REBUILD_TLS_NAME_MISMATCH', 'REBUILD_TLS_TRUST_UNVERIFIED', 'REBUILD_TLS_CERT_UNREADABLE']);
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

function refusalInfo(err, editing = false) {
    const error = err instanceof RebuildRequestError ? err.body?.error : null;
    const code = error?.code;
    if (err instanceof SessionChanged || err instanceof RebuildRequestError && err.status === 403) {
        return { message: t('map.rebuild.sessionChanged'), notSaved: err instanceof SessionChanged || err.csrfRejected };
    }
    if (err instanceof RebuildRequestError && err.status === 409 && kcpRefusals.has(code)) {
        // This route publishes localized plain text for typed mKCP refusals.
        // Never display a generic transport / exception message.
        const issues = Array.isArray(error.issues) ? error.issues.map(issue => issue?.message).filter(publicText).join(' ') : '';
        const summary = publicText(error.message) ? error.message : '';
        return { message: [summary, issues && !summary.includes(issues) ? issues : ''].filter(Boolean).join(' ')
            || t('map.rebuild.kcpRefused'), notSaved: true };
    }
    if (err instanceof RebuildRequestError && err.status === 400 && code === 'INVALID_KCP_LINK_SETTINGS') {
        return { message: t('map.rebuild.kcpRefused'), notSaved: true };
    }
    if (err instanceof RebuildRequestError && [400, 409].includes(err.status)) {
        if (code === 'REBUILD_PORTAL_EXIT_INVALID' || code === 'REBUILD_INVALID_EXIT') {
            return { message: t('map.portalExit.badExit'), notSaved: true };
        }
        if (code === 'REBUILD_PORTAL_EXIT_AMBIGUOUS') return { message: t('map.portalExit.ambiguous'), notSaved: true };
        if (code === 'REBUILD_PORTAL_EXIT_UNSUPPORTED') return { message: t('map.portalExit.unsupported'), notSaved: true };
        if (code === 'REBUILD_EXIT_IN_USE') {
            const names = portalNames(error, err.body.details);
            return { message: names ? t('map.portalExit.inUseNamed', { names }) : t('map.portalExit.inUse'), notSaved: true };
        }
    }
    if (editing && err instanceof RebuildRequestError) {
        if ((err.status === 404 || err.status === 409) && editUnavailable.has(code)) {
            return { message: t('map.edit.unavailable'), notSaved: true, reloadEdit: true };
        }
        if (err.status === 409 && tlsRefusals.has(code)) return { message: t('map.edit.tlsRefused'), notSaved: true };
        if (err.status === 400 && code === 'REBUILD_INVALID_REQUEST') return { message: t('map.create.badSettings'), notSaved: true };
    }
    if (stale.has(code)) return { message: t('map.rebuild.previewChanged') };
    return { notSaved: err instanceof RebuildRequestError && err.status === 400 && code === 'REBUILD_INVALID_REQUEST' };
}

function publicText(value) {
    return typeof value === 'string' && value.trim().length > 0 && !/[\p{Cc}\p{Bidi_Control}]/u.test(value);
}

function portalNames(error, details) {
    const lists = [error.portals, error.portalNames, error.details?.portals, error.details?.portalNames,
        error.details, details?.portals, details?.portalNames, details];
    const names = lists.filter(Array.isArray).flatMap(rows => rows.slice(0, 100)).map(row => {
        const name = typeof row === 'string' ? row : row?.name;
        return publicText(name) && !/[<>\u2028\u2029]/u.test(name) && !isObjectId(name.trim()) ? name.trim().slice(0, 120) : '';
    }).filter(Boolean);
    return [...new Set(names)].slice(0, 10).join(', ');
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
    // At most one open edit. Keep the read's client and baseline private;
    // neither caller-supplied fields nor a new token can rebind a save.
    let openedEdit = null;

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

    function editableEdge(edgeId, edit) {
        const edge = store.index.links.get(edgeId);
        const id = linkIdOf(edgeId)?.toLowerCase();
        if (!id || edge?.canEdit !== true || !isObjectId(edge.source) || !isObjectId(edge.target)
            || edge.source.toLowerCase() === edge.target.toLowerCase()) return false;
        if (edge.linkId != null && (!isObjectId(edge.linkId) || edge.linkId.toLowerCase() !== id)) return false;
        return !edit || (edit._id === id && edit.portalNode === edge.source.toLowerCase()
            && edit.bridgeNode === edge.target.toLowerCase());
    }

    async function loadEdit(edgeId) {
        return run(async (_, refuse) => {
            openedEdit = null;
            try {
                if (!editableEdge(edgeId)) throw new Error('Selected link is not editable');
                const client = createRebuildClient();
                const edit = await client.getEditLink(linkIdOf(edgeId).toLowerCase());
                if (!editableEdge(edgeId, edit)) throw new Error('Selected link changed');
                openedEdit = { edgeId, client, edit };
                return edit;
            } catch (err) {
                await refuse(err instanceof InvalidEditFields && err.key === 'badExit' ? t('map.portalExit.badExit')
                    : refusalInfo(err).message || t('map.edit.unavailable'));
                return null;
            }
        }, null);
    }

    function lookupNode(nodeId) {
        const node = store.index.nodes.get(nodeId);
        return node ? { label: node.label, role: store.model.roleOf(node) } : null;
    }

    async function previewAndWrite(client, linkId, operation, markWrite, refuse, stillEditable) {
        const dialog = window.C3RebuildPreview;
        if (typeof dialog?.confirmReport !== 'function') {
            await refuse(t('map.rebuild.previewUnavailable'));
            return false;
        }
        if (stillEditable && !stillEditable()) {
            await refuse(t('map.edit.unavailable'));
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
        if (stillEditable && !stillEditable()) {
            await refuse(t('map.edit.unavailable'));
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

    async function saveAndDeploy(body, markWrite, refuse, binding = null) {
        if (typeof window.C3RebuildPreview?.confirmReport !== 'function') {
            await refuse(t('map.rebuild.previewUnavailable'));
            return draftResult('not_saved');
        }
        const expectedId = binding?.edit._id;
        const matchingId = id => isObjectId(id) && (!binding || id.toLowerCase() === expectedId);
        const stillEditable = binding && (() => editableEdge(binding.edgeId, binding.edit));
        let client, reply;
        try {
            client = binding ? binding.client : createRebuildClient();
            client.assertSession();
            // Consume before a possible save. Only a definite, correctable
            // pre-write refusal can leave this same baseline open for retry.
            openedEdit = null;
            markWrite();
            reply = binding ? await client.updateDraft(expectedId, body) : await client.saveDraft(body);
            if (reply?.executionMode !== 'rebuild' || reply.status !== 'saved' || Object.hasOwn(reply, 'error')
                || reply.desiredSaved !== true || !matchingId(reply.linkId)) throw new Error('Unconfirmed draft save');
        } catch (err) {
            // An acknowledged draft can survive failed cleanup. Such a
            // partial reply must match the target and cannot authorize Apply.
            const partial = err instanceof RebuildRequestError && [400, 404, 409, 428].includes(err.status)
                && typeof err.body?.error?.code === 'string' ? err.body : null;
            const claimed = err instanceof RebuildRequestError && err.body
                && (Object.hasOwn(err.body, 'desiredSaved') || Object.hasOwn(err.body, 'linkId'));
            const linkId = partial?.desiredSaved === true && matchingId(partial.linkId) ? expectedId ?? partial.linkId : null;
            const info = binding && claimed && !linkId ? {} : refusalInfo(err, !!binding);
            if (binding && info.notSaved && !linkId && !info.reloadEdit && !(err instanceof SessionChanged) && !err.csrfRejected) {
                try {
                    client.assertSession();
                    if (stillEditable()) openedEdit = binding;
                } catch (_) { /* A changed session always needs a fresh load. */ }
            } else if (binding) openedEdit = null;
            await refuse(info.message || t('map.rebuild.saveUnconfirmed'));
            if (linkId) toast(t('map.rebuild.draftSaved'), 'warning');
            return linkId ? draftResult('saved', linkId) : draftResult(info.notSaved ? 'not_saved' : 'unknown');
        }
        const linkId = expectedId ?? reply.linkId;
        if (await previewAndWrite(client, linkId, 'deploy', markWrite, refuse, stillEditable)) return draftResult('applied', linkId);
        toast(t('map.rebuild.draftSaved'), 'warning');
        return draftResult('saved', linkId);
    }

    function createAndDeploy(body) {
        return run((markWrite, refuse) => saveAndDeploy(body, markWrite, refuse), draftResult('busy'));
    }

    async function editAndDeploy(edgeId, changes) {
        return run(async (markWrite, refuse) => {
            const binding = openedEdit;
            if (!binding || binding.edgeId !== edgeId || !editableEdge(edgeId, binding.edit)) {
                openedEdit = null;
                await refuse(t('map.edit.unavailable'));
                return draftResult('not_saved');
            }
            let patch;
            try {
                binding.client.assertSession();
                patch = editPatch(binding.edit, changes);
            } catch (err) {
                if (err instanceof SessionChanged) openedEdit = null;
                await refuse(err instanceof InvalidEditFields ? t(err.key === 'badExit' ? 'map.portalExit.badExit' : `map.create.${err.key}`)
                    : refusalInfo(err).message || t('map.edit.unavailable'));
                return draftResult('not_saved');
            }
            if (!Object.keys(patch).length) return draftResult('unchanged');
            return saveAndDeploy(patch, markWrite, refuse, binding);
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
        loadEdit,
        editAndDeploy,
    };
}
