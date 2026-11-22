'use strict';

(() => {
    const dialog = document.getElementById('relay-retire-dialog');
    if (!dialog?.dataset.csrf || typeof dialog.showModal !== 'function') return;
    const copy = JSON.parse(dialog.dataset.messages);
    const csrf = dialog.dataset.csrf;
    const target = dialog.querySelector('[data-retire-target]');
    const message = dialog.querySelector('[data-retire-message]');
    const status = dialog.querySelector('[data-retire-status]');
    const approve = dialog.querySelector('[data-retire-confirm]');
    const close = dialog.querySelector('[data-retire-close]');
    const buttons = [...document.querySelectorAll('[data-retire-node]')];
    const validCount = n => Number.isSafeInteger(n) && n >= 0;
    const put = (key, name, value) => copy[key].replace(`{${name}}`, () => value);
    let selected = null, approval = null, submitting = false;

    function hideApproval() {
        approval = null;
        approve.hidden = true;
        approve.disabled = true;
        approve.textContent = '';
    }

    function applyPreview(context, preview) {
        if (preview?.nodeId !== context.id || !['online', 'abandon'].includes(preview.mode)) return false;
        if (preview.allowed === false) {
            showError(preview.code === 'REBUILD_NEIGHBOR_UNAVAILABLE' ? 'neighborUnavailable' : 'protectedChange');
            return true;
        }
        if (preview.allowed !== true || typeof preview.ticket !== 'string' || !/^[a-f0-9]{64}(?![\s\S])/.test(preview.ticket)) return false;
        let decision, label;
        if (preview.mode === 'online') {
            if (!validCount(preview.activeClients)) return false;
            if (preview.activeClients === 0) {
                message.textContent = copy.onlineZero;
                label = copy.confirmDelete;
                decision = 'delete';
            } else {
                message.textContent = put('onlineForce', 'count', preview.activeClients);
                label = put('confirmForce', 'count', preview.activeClients);
                decision = 'force';
            }
        } else {
            if (preview.activeClients !== null) return false;
            const iso = preview.unavailableSince;
            const time = typeof iso === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z(?![\s\S])/.test(iso) ? Date.parse(iso) : NaN;
            const since = Number.isFinite(time) ? put('offlineSince', 'time', `${new Intl.DateTimeFormat(dialog.dataset.locale, {
                dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC',
            }).format(time)} (UTC)`) : copy.offlineSinceUnknown;
            const accounts = validCount(preview.accountCount) ? put('accountCount', 'count', preview.accountCount) : copy.accountCountUnknown;
            message.textContent = `${since}\n${accounts}`;
            label = copy.confirmAbandon;
            decision = 'abandon';
        }
        approval = { context, ticket: preview.ticket, decision };
        approve.textContent = label;
        approve.disabled = false;
        approve.hidden = false;
        return true;
    }

    async function post(context, action, body) {
        const response = await fetch(`/panel/rebuild/relays/${context.id}/retire/${action}`, {
            method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'x-csrf-token': csrf },
            body: JSON.stringify(body),
        });
        return { response, data: await response.json() };
    }

    function showError(key) {
        message.textContent = '';
        status.textContent = copy[key];
    }

    function refusal(code) {
        if (code === 'REBUILD_NEIGHBOR_UNAVAILABLE') return 'neighborUnavailable';
        if (code === 'REBUILD_RETIRE_PROTECTED_CHANGE') return 'protectedChange';
        if (code === 'REBUILD_RETIRE_CONFIRMATION_REQUIRED' || code === 'REBUILD_RETIRE_DECISION_REQUIRED') return 'newPreviewRequired';
        if (code === 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE') return 'previewUnavailable';
        return null;
    }

    function lockTarget(id) {
        for (const button of buttons) if (button.dataset.retireNode === id) button.disabled = true;
    }

    for (const button of buttons) {
        if (!/^[a-f0-9]{24}(?![\s\S])/.test(button.dataset.retireNode)) continue;
        button.addEventListener('click', async () => {
            if (selected || submitting) return;
            const context = Object.freeze({ id: button.dataset.retireNode });
            selected = context;
            hideApproval();
            target.textContent = `${button.dataset.retireName} (${context.id})`;
            message.textContent = '';
            status.textContent = copy.loading;
            dialog.showModal();
            try {
                const { response, data } = await post(context, 'preview', {});
                if (selected !== context) return;
                status.textContent = '';
                if (!response.ok || !applyPreview(context, data?.preview)) {
                    showError(refusal(data?.error?.code) ?? 'previewUnavailable');
                }
            } catch {
                if (selected === context) showError('previewUnavailable');
            }
        });
        button.disabled = false;
    }

    approve.addEventListener('click', async event => {
        if (!approval || approval.context !== selected || submitting || !dialog.open || event.detail > 1) return;
        const { context, ticket, decision } = approval;
        submitting = true;
        close.disabled = true;
        hideApproval();
        message.textContent = '';
        status.textContent = copy.deleting;
        try {
            const { response, data } = await post(context, 'confirm', { ticket, decision });
            if (response.ok && data?.nodeId === context.id && data.status === 'deleted') {
                lockTarget(context.id);
                location.reload();
                return;
            }
            const code = data?.error?.code;
            if (response.status === 409 && code === 'PREVIEW_CHANGED') {
                if (decision === 'abandon') { showError('newPreviewRequired'); return; }
                status.textContent = copy.changed;
                if (!applyPreview(context, data.preview)) showError('previewUnavailable');
                return;
            }
            if (response.status === 409 && code === 'REBUILD_RETIRE_DECISION_REQUIRED' && validCount(data.error.activeClients)
                && data.error.activeClients > 0) {
                status.textContent = put('forceRequired', 'count', data.error.activeClients);
                return;
            }
            const known = refusal(code);
            if (!response.ok && known) { showError(known); return; }
        } catch { /* A lost acknowledgement is not a clean refusal. */ }
        finally {
            submitting = false;
            close.disabled = false;
            close.focus();
        }
        lockTarget(context.id);
        showError('outcomeUnconfirmed');
    });

    close.addEventListener('click', () => { if (!submitting) dialog.close(); });
    dialog.addEventListener('cancel', event => { if (submitting) event.preventDefault(); });
    dialog.addEventListener('close', () => {
        if (dialog.open) return;
        selected = null;
        hideApproval();
    });
})();
