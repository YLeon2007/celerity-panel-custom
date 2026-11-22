(() => {
    'use strict';

    const page = document.getElementById('rebuild-l2tp');
    if (!page) return;
    const words = JSON.parse(page.dataset.messages);
    const installChecks = JSON.parse(page.dataset.installChecks || '{}');
    const admissionWords = JSON.parse(page.dataset.admissionMessages || '{}');

    async function post(url, body, signal) {
        const response = await fetch(url, {
            method: 'POST', mode: 'same-origin', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
            headers: { 'Content-Type': 'application/json', 'x-csrf-token': page.dataset.csrf },
            body: JSON.stringify(body),
        });
        const data = await response.json().catch(() => null);
        return { response, data };
    }

    function bindSecret(widget) {
        const value = widget.querySelector('[data-secret-value]');
        const eye = widget.querySelector('[data-show-secret]');
        const copy = widget.querySelector('[data-copy-secret]');
        const status = widget.querySelector('[role="status"]');
        const icon = eye.querySelector('i');
        let pending = null;

        function update() {
            const expanded = !value.hidden;
            const label = expanded || pending ? eye.dataset.hideLabel : eye.dataset.showLabel;
            eye.setAttribute('aria-label', label);
            eye.setAttribute('aria-expanded', String(expanded));
            eye.title = label;
            icon.className = expanded || pending ? 'ti ti-eye-off' : 'ti ti-eye';
            copy.disabled = Boolean(pending);
        }

        function hide() {
            const request = pending;
            pending = null;
            request?.abort();
            value.hidden = true;
            value.textContent = '';
            status.textContent = '';
            update();
        }

        async function reveal(request) {
            const { login, secretUrl } = widget.dataset;
            const { response, data } = await post(secretUrl, login === undefined ? {} : { login }, request.signal);
            // Abort is best-effort. Never publish a response from a request that has been hidden or superseded.
            if (request !== pending || !response.ok || typeof data?.secret !== 'string' || !data.secret) throw new Error();
            return data.secret;
        }

        async function useSecret(show) {
            if (requireRefresh || flow) return;
            const clipboard = navigator.clipboard;
            const visible = !value.hidden;
            if (!show && (visible ? typeof clipboard?.writeText !== 'function'
                : typeof clipboard?.write !== 'function' || typeof window.ClipboardItem !== 'function')) {
                status.textContent = words.copyFailed;
                return;
            }
            const request = new AbortController();
            pending = request;
            status.textContent = words.working;
            update();
            let errorKey = show ? 'revealFailed' : 'copyFailed';
            try {
                if (show) {
                    const secret = await reveal(request);
                    if (request !== pending) return;
                    value.textContent = secret;
                    value.hidden = false;
                } else if (visible) {
                    await clipboard.writeText(value.textContent);
                } else {
                    // Start the clipboard write during the click (before fetch resolves) for browsers
                    // that require transient user activation. The secret never enters the DOM.
                    const blob = reveal(request).then(secret => {
                        if (request !== pending) throw new Error();
                        return new Blob([secret], { type: 'text/plain' });
                    }).catch(error => {
                        errorKey = 'revealFailed';
                        throw error;
                    });
                    const writing = (async () => clipboard.write([new window.ClipboardItem({ 'text/plain': blob })]))();
                    await Promise.all([blob, writing]);
                }
                if (request === pending) status.textContent = show ? '' : words.copied;
            } catch {
                if (request === pending) status.textContent = words[errorKey];
            } finally {
                if (request === pending) {
                    pending = null;
                    request.abort();
                    update();
                }
            }
        }

        eye.addEventListener('click', () => {
            if (pending || !value.hidden) hide();
            else void useSecret(true);
        });
        copy.addEventListener('click', () => { if (!pending) void useSecret(false); });
        update();
        return hide;
    }

    const hideSecrets = Array.from(page.querySelectorAll('[data-secret-url]'), bindSecret);
    const clearSecrets = () => hideSecrets.forEach(hide => hide());
    window.addEventListener('pagehide', clearSecrets);

    const form = page.querySelector('[data-create]');
    const installs = page.querySelectorAll('[data-install-url]');
    const accountButtons = page.querySelectorAll('[data-account-action]');
    const submit = form?.querySelector('button[type="submit"]');
    const status = page.querySelector('[data-action-status]');
    const refresh = page.querySelector('[data-refresh]');
    const review = page.querySelector('[data-review]');
    const admissionButtons = page.querySelectorAll('[data-admission-action]');
    const removeLinks = page.querySelectorAll('[data-remove-link]');
    const dialog = page.querySelector('[data-admission-dialog]');
    const recover = page.querySelector('[data-reconcile]');
    const mutations = [...installs, ...accountButtons, ...[submit, recover].filter(Boolean)];
    const expected = { install: 'installed', create: 'created', disable: 'disabled', delete: 'deleted' };
    const installOutcomes = new Map([
        ['refused', 'installRefused'], ['busy', 'installBusy'], ['rolled_back', 'installRolledBack'],
        ['unknown', 'uncertain'], ['installed', 'installCleanupFailed'],
    ]);
    let busy = false, requireRefresh = false;
    let identityReview = false, reviewId = null, flow = null;
    const hex = (value, n) => typeof value === 'string' && value.length === n && /^[a-f0-9]+$/.test(value);
    const effectErrors = new Map([
        ['REBUILD_L2TP_IDENTITY_CHANGED', 'identityChanged'], ['REBUILD_L2TP_GRANT_CONFLICT', 'grantConflict'],
        ['REBUILD_L2TP_GRANT_CHANGED', 'grantConflict'],
        ...['UNAVAILABLE', 'INVALID', 'ENV_INVALID', 'REGISTRY_INVALID', 'PERSISTENCE_UNAVAILABLE']
            .map(suffix => [`REBUILD_L2TP_GRANT_${suffix}`, 'grantUnavailable']),
    ]);
    const admissionErrors = new Map([...effectErrors,
        ['REBUILD_L2TP_ADMISSION_CHALLENGE_INVALID', 'challengeInvalid'],
        ['REBUILD_L2TP_GRANT_LEGACY_SINGLETON_IN_USE', 'legacySingletonInUse'],
        ['REBUILD_L2TP_INSTALL_DISABLED', 'blocked'], ['REBUILD_L2TP_ACCOUNTS_BLOCKED', 'blocked'],
        ['REBUILD_BUSY', 'blocked'], ['REBUILD_LOCK_LOST', 'blocked'],
    ]);
    const accountBlocks = new Map([
        ['REBUILD_L2TP_ACCOUNTS_BLOCKED', 'accountReconcileRequired'],
        ['REBUILD_L2TP_ACCOUNTS_MANUAL_BLOCK', 'reconcileManualBlock'],
        ['REBUILD_L2TP_ACCOUNTS_PRE_EFFECT_BLOCKED', 'accountPreEffectBlocked'],
    ]);
    const unknownOutcome = data => data?.outcome === 'unknown' || data?.error?.outcome === 'unknown';
    const noRetry = data => unknownOutcome(data) || data?.retryAllowed === false || data?.error?.retryAllowed === false;
    function conflictNote(conflict) {
        const { field, sources } = conflict ?? {};
        const labels = admissionWords.conflictFields;
        const fieldNote = typeof field === 'string' && labels && Object.hasOwn(labels, field)
            ? ` ${admissionWords.conflictField.replace('{field}', labels[field])}` : '';
        const sourceNote = Array.isArray(sources) && sources.length >= 1 && sources.length <= 2
            && sources.every(source => source === 'env' || source === 'db')
            ? ` ${admissionWords.conflictSources.replace('{sources}', sources.map(source => source.toUpperCase()).join(', '))}` : '';
        return fieldNote + sourceNote;
    }
    const canReview = button => identityReview && reviewId !== null && button.dataset.admissionAction === 'reconfirm'
        && button.dataset.nodeId === reviewId;

    function updateMutations() {
        const locked = busy || !!flow || requireRefresh;
        for (const button of mutations) button.disabled = locked;
        for (const button of admissionButtons) button.disabled = busy || !!flow || (requireRefresh && !canReview(button));
        for (const link of removeLinks) link.setAttribute('aria-disabled', String(locked));
        refresh.hidden = !requireRefresh;
        if (review) {
            review.hidden = !identityReview;
            review.href = reviewId === null ? '#rebuild-l2tp-relays' : `#relay-${reviewId}`;
        }
    }

    function markIdentityReview(nodeId) {
        requireRefresh = true;
        identityReview = true;
        reviewId = hex(nodeId, 24) ? nodeId : null;
        clearSecrets();
        const row = reviewId && document.getElementById(`relay-${reviewId}`);
        return row?.querySelector('[data-env-grant]') ? ` ${admissionWords.envReadOnly}` : '';
    }

    for (const link of removeLinks) link.addEventListener('click', event => {
        if (busy || flow || requireRefresh) event.preventDefault();
    });

    if (dialog) {
        const field = name => dialog.querySelector(`[data-admission-${name}]`);
        const approvals = dialog.querySelectorAll('[data-admission-approve]');
        const cancel = field('cancel'), notice = field('status');
        const fields = ['name', 'endpoint', 'login', 'key', 'machine'];

        function draw(step, data) {
            flow.step = step;
            for (const item of dialog.querySelectorAll('[data-admission-step]')) item.hidden = item.dataset.admissionStep !== step;
            field('identity').hidden = !data;
            field('machine-row').hidden = step !== 'confirm';
            if (data) {
                const host = data.host.includes(':') && !data.host.startsWith('[') ? `[${data.host}]` : data.host;
                field('endpoint').textContent = `${host}:${data.port}`;
                field('login').textContent = data.username;
                field('key').textContent = data.sshHostKeySha256;
                field('machine').textContent = step === 'confirm' ? data.machineId : '';
            }
            for (const button of approvals) button.hidden = button.dataset.admissionApprove !== step;
        }

        function dismiss() {
            flow = null;
            for (const name of fields) field(name).textContent = '';
            notice.textContent = '';
            if (dialog.open) dialog.close();
            updateMutations();
        }

        function matchesReceipt(current, action, data) {
            if (data?.nodeId !== current.nodeId) return false;
            if (action === 'revoke') return true;
            if (typeof data.host !== 'string' || !data.host || typeof data.username !== 'string' || !data.username
                || !Number.isInteger(data.port) || !hex(data.sshHostKeySha256, 64)) return false;
            if (action !== 'probe' && (!hex(data.machineId, 32) || ['host', 'port', 'username', 'sshHostKeySha256']
                .some(key => data[key] !== current.identity?.[key]))) return false;
            if (action === 'confirm') return data.machineId === current.identity.machineId;
            return hex(data.challenge, 64) && data.challenge !== current.identity?.challenge;
        }

        async function advance(action) {
            const current = flow;
            if (!current || busy) return;
            busy = true;
            updateMutations();
            cancel.disabled = true;
            for (const button of approvals) button.disabled = true;
            notice.textContent = words.working;
            const mutating = action === 'confirm' || action === 'revoke';
            let errorText = mutating ? words.uncertain : admissionWords.checkUnavailable, stale = mutating;
            try {
                const body = action === 'verify' || action === 'confirm' ? { challenge: current.identity.challenge } : {};
                const { response, data } = await post(`${current.url}/${action}`, body);
                if (current !== flow) return;
                const blocked = noRetry(data);
                if (response.ok && !blocked && matchesReceipt(current, action, data)) {
                    if (mutating) {
                        requireRefresh = true;
                        identityReview = false;
                        clearSecrets();
                        status.textContent = admissionWords[action === 'confirm' ? 'granted' : 'revoked'];
                        dismiss();
                    } else {
                        current.identity = data;
                        draw(action === 'probe' ? 'verify' : 'confirm', data);
                        notice.textContent = '';
                    }
                    return;
                }
                if (response.ok && blocked) {
                    errorText = words.uncertain;
                    stale = true;
                } else if (!response.ok) {
                    const code = data?.error?.code, key = admissionErrors.get(code);
                    const reviewable = key === 'identityChanged' && response.status === 409 && data.error.outcome === 'refused';
                    stale = blocked || (key === 'identityChanged' && !reviewable) || code === 'REBUILD_L2TP_ACCOUNTS_BLOCKED'
                        || code === 'REBUILD_LOCK_LOST' || (mutating && (response.status >= 500 || response.status === 408));
                    if (unknownOutcome(data) || (key === 'identityChanged' && stale)) errorText = words.uncertain;
                    else if (response.status === 429) errorText = words.rateLimited;
                    else if (key) {
                        errorText = admissionWords[key];
                        if (code === 'REBUILD_L2TP_GRANT_CONFLICT') errorText += conflictNote(data.error.conflict);
                        if (reviewable) {
                            errorText += markIdentityReview(current.nodeId);
                            status.textContent = errorText;
                        }
                        if (key === 'grantUnavailable') stale = true;
                    }
                }
            } catch { /* Do not retry an ambiguous response or reuse its challenge. */ }
            finally {
                busy = false;
                cancel.disabled = false;
                for (const button of approvals) button.disabled = false;
                updateMutations();
            }
            if (flow !== current) return;
            current.identity = null;
            draw(null, null);
            notice.textContent = errorText;
            if (stale) {
                requireRefresh = true;
                identityReview = false;
                clearSecrets();
                status.textContent = errorText;
                updateMutations();
            }
        }

        for (const button of admissionButtons) button.addEventListener('click', () => {
            if (busy || flow || (requireRefresh && !canReview(button))) return;
            const { admissionAction, admissionUrl, nodeId, nodeName } = button.dataset;
            flow = { nodeId, url: admissionUrl, step: null, identity: null };
            field('name').textContent = nodeName;
            draw(admissionAction === 'revoke' ? 'revoke' : null, null);
            dialog.showModal();
            updateMutations();
            if (admissionAction !== 'revoke') void advance('probe');
        });
        for (const button of approvals) button.addEventListener('click', event => {
            if (event.detail <= 1 && button.dataset.admissionApprove === flow?.step) void advance(flow.step);
        });
        cancel.addEventListener('click', () => { if (!busy) dismiss(); });
        dialog.addEventListener('cancel', event => { event.preventDefault(); if (!busy) dismiss(); });
        window.addEventListener('pagehide', dismiss);
    }

    function closureNote(data, count) {
        return data?.sessionsTerminatedScope === 'request' && Number.isSafeInteger(count) && count >= 0
            ? ` ${words.requestClosures.replace('{count}', String(count))}` : '';
    }

    const inspectionMessages = new Map([
        ['host-inspection-unproved', 'reconcileHostInspection'],
        ['chap-projection-unproved', 'reconcileChapProjection'],
        ['ppp-unproved', 'reconcilePppInspection'],
        ['pidfd-getfd-eperm', 'reconcilePidfdGetfdEperm'],
        ['inspect-readback-unproved', 'reconcileInspectReadback'],
    ]);

    async function reconcileAccounts() {
        if (busy || flow || requireRefresh || !page.dataset.reconcileUrl) return;
        busy = true;
        updateMutations();
        status.textContent = words.working;
        let message = 'reconcileUnconfirmed', note = '';
        try {
            const { response, data } = await post(page.dataset.reconcileUrl, {});
            if (response.ok && data?.executionMode === 'rebuild') {
                if (data.status === 'settled') {
                    message = 'reconcileSettled';
                    note = closureNote(data, data.sessionsTerminated);
                }
                if (data.status === 'pending') message = 'reconcileStillPending';
                if (data.status === 'inspection-unproved' && data.retryAllowed === false) {
                    message = 'reconcileInspectionUnproved';
                    const detail = inspectionMessages.get(data.reason);
                    if (detail) note = ` ${words[detail]}`;
                }
            } else if (response.status === 429) {
                message = 'rateLimited';
            } else if (response.status === 409 && data?.error?.code === 'REBUILD_L2TP_RECONCILE_DISABLED') {
                message = 'recoveryIneligible';
            } else if (response.status === 409 && data?.error?.retryAllowed === false
                && data.error.code === 'REBUILD_L2TP_ACCOUNTS_MANUAL_BLOCK') {
                message = 'reconcileManualBlock';
            } else if (effectErrors.has(data?.error?.code)) {
                message = data.error.code === 'REBUILD_L2TP_IDENTITY_CHANGED' ? 'reconcileManualBlock' : effectErrors.get(data.error.code);
            }
        } catch { /* A lost response does not establish whether the fence cleared. */ }
        status.textContent = (words[message] ?? admissionWords[message]) + note;
        busy = false;
        // Never unlock this stale overview or automatically repeat recovery.
        requireRefresh = true;
        updateMutations();
    }

    async function mutate(action, url, body, match, nodeId) {
        if (busy || flow || requireRefresh) return;
        busy = true;
        updateMutations();
        status.textContent = words.working;
        let result = 'uncertain', note = '';
        const revocation = action === 'disable' || action === 'delete';
        try {
            const { response, data } = await post(url, body);
            const { code, outcome, check } = data?.error ?? {};
            const blocked = noRetry(data);
            if (response.ok && !blocked) {
                const canceled = action !== 'install' && data?.status === 'canceled' && data.recovered === true
                    && (!revocation || (data.sessionsTerminated === 0 && data.sessionsTerminatedScope === 'request'));
                if (data?.executionMode === 'rebuild' && (data.status === expected[action] || canceled) && match(data)) {
                    result = data.status;
                    requireRefresh = true;
                    if (result === 'created') form.reset();
                    if (revocation && data.recovered === true) note = closureNote(data, data.sessionsTerminated);
                    clearSecrets();
                }
            } else if (response.status === 409 && blocked && !unknownOutcome(data) && accountBlocks.has(code)) {
                result = accountBlocks.get(code);
                requireRefresh = true;
                clearSecrets();
            } else if (code === 'REBUILD_L2TP_IDENTITY_CHANGED') {
                if (response.status === 409 && !blocked && outcome === 'refused') {
                    result = 'identityChanged';
                    note = markIdentityReview(nodeId ?? data.error.nodeId);
                }
            } else if (!unknownOutcome(data) && effectErrors.has(code)) {
                result = effectErrors.get(code);
                requireRefresh = true;
                clearSecrets();
            } else if (action === 'install' && response.status === 409) {
                // Only show local copy; raw codes, exceptions and detail fields are never rendered.
                if ((!blocked || outcome === 'unknown' || (outcome === 'installed' && !unknownOutcome(data)))
                    && installOutcomes.has(outcome)
                    && (check === undefined || (typeof check === 'string' && Object.hasOwn(installChecks, check)))) {
                    result = installOutcomes.get(outcome);
                    if (check !== undefined) note = ` ${installChecks[check]}`;
                    if (outcome === 'installed' || outcome === 'rolled_back') {
                        requireRefresh = true;
                        clearSecrets();
                    }
                }
            } else if (!blocked && response.status !== 408 && response.status < 500) {
                result = response.status === 429 ? 'rateLimited' : 'requestFailed';
            } else if (revocation && data?.error?.retryAllowed === false) {
                note = closureNote(data.error, data.error.confirmedSessionsTerminated);
            }
        } catch { /* A lost response is not proof that the mutation failed. */ }
        if (result === 'uncertain') {
            requireRefresh = true;
            identityReview = false;
            clearSecrets();
        }
        status.textContent = (words[result] ?? admissionWords[result]) + note;
        busy = false;
        updateMutations();
    }

    function accountAction(action, login, password) {
        const body = action === 'create' ? { login, password } : { login };
        void mutate(action, `${page.dataset.accountUrl}/${action}`, body, data => data.login === login);
    }

    function generatePassword() {
        // 32 random bytes rendered as hex are accepted by the panel and CHAP backend.
        const bytes = window.crypto.getRandomValues(new Uint8Array(32));
        return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    for (const button of installs) {
        button.addEventListener('click', () => {
            void mutate('install', button.dataset.installUrl, {}, data => data.nodeId === button.dataset.nodeId, button.dataset.nodeId);
        });
    }
    for (const button of accountButtons) {
        button.addEventListener('click', () => {
            if (busy || flow || requireRefresh) return;
            const { accountAction: action, login, confirm } = button.dataset;
            if (action === 'disable' || (action === 'delete' && window.confirm(`${confirm}\n${login}`))) accountAction(action, login);
        });
    }
    form?.addEventListener('submit', event => {
        event.preventDefault();
        if (busy || flow || requireRefresh) return;
        const login = form.querySelector('input').value.trim();
        if (login === 'relay-bootstrap' || !/^[A-Za-z0-9._@-]{1,64}$/.test(login)) {
            status.textContent = words.invalidLogin;
            return;
        }
        let password;
        try { password = generatePassword(); }
        catch {
            status.textContent = words.cryptoUnavailable;
            return;
        }
        accountAction('create', login, password);
    });
    recover?.addEventListener('click', () => { void reconcileAccounts(); });
    updateMutations();
})();
