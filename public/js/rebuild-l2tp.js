(() => {
    'use strict';

    const page = document.getElementById('rebuild-l2tp');
    if (!page) return;
    const words = JSON.parse(page.dataset.messages);

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
    const mutations = [...installs, ...accountButtons, ...(submit ? [submit] : [])];
    const expected = { install: 'installed', create: 'created', disable: 'disabled', delete: 'deleted' };
    const uncertainInstallCodes = new Set([
        'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN', 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN',
        'REBUILD_L2TP_FINISH_OUTCOME_UNKNOWN', 'REBUILD_L2TP_RESERVATION_FAILED',
        'REBUILD_L2TP_RESERVATION_CLEANUP_FAILED', 'REBUILD_L2TP_ROLLBACK_CLEANUP_FAILED',
        'REBUILD_L2TP_INSTALLED_CLEANUP_FAILED',
    ]);
    let busy = false, requireRefresh = false;

    function updateMutations() {
        for (const button of mutations) button.disabled = busy || requireRefresh;
        refresh.hidden = !requireRefresh;
    }

    function closureNote(data, count) {
        return data?.sessionsTerminatedScope === 'request' && Number.isSafeInteger(count) && count >= 0
            ? ` ${words.requestClosures.replace('{count}', String(count))}` : '';
    }

    async function reconcileOnOpen() {
        busy = true;
        updateMutations();
        let message = 'reconcileUnconfirmed', note = '';
        try {
            const { response, data } = await post(page.dataset.reconcileUrl, {});
            if (response.ok && data?.executionMode === 'rebuild') {
                if (data.status === 'settled') {
                    message = 'reconcileSettled';
                    note = closureNote(data, data.sessionsTerminated);
                }
                if (data.status === 'pending') message = 'reconcileStillPending';
            }
        } catch { /* A lost response does not establish whether the fence cleared. */ }
        status.textContent = words[message] + note;
        busy = false;
        // Never unlock controls against this stale overview or reload into
        // another automatic POST. Any refresh is an explicit operator action.
        requireRefresh = true;
        updateMutations();
    }

    async function mutate(action, url, body, match) {
        if (busy || requireRefresh) return;
        busy = true;
        updateMutations();
        status.textContent = words.working;
        let result = 'uncertain', note = '';
        const revocation = action === 'disable' || action === 'delete';
        try {
            const { response, data } = await post(url, body);
            if (response.ok) {
                const canceled = action !== 'install' && data?.status === 'canceled' && data.recovered === true
                    && (!revocation || (data.sessionsTerminated === 0 && data.sessionsTerminatedScope === 'request'));
                if (data?.executionMode === 'rebuild' && (data.status === expected[action] || canceled) && match(data)) {
                    result = data.status;
                    requireRefresh = true;
                    if (result === 'created') form.reset();
                    if (revocation && data.recovered === true) note = closureNote(data, data.sessionsTerminated);
                    clearSecrets();
                }
            } else if (data?.retryAllowed !== false && data?.error?.retryAllowed !== false
                && !uncertainInstallCodes.has(data?.error?.code) && response.status !== 408 && response.status < 500) {
                result = response.status === 429 ? 'rateLimited' : 'requestFailed';
            } else if (revocation && data?.error?.retryAllowed === false) {
                note = closureNote(data.error, data.error.confirmedSessionsTerminated);
            }
            if (action === 'install' && typeof data?.error?.operatorAction === 'string') note = ` ${data.error.operatorAction}`;
        } catch { /* A lost response is not proof that the mutation failed. */ }
        if (result === 'uncertain') {
            requireRefresh = true;
            clearSecrets();
        }
        status.textContent = words[result] + note;
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
            void mutate('install', button.dataset.installUrl, {}, data => data.nodeId === button.dataset.nodeId);
        });
    }
    for (const button of accountButtons) {
        button.addEventListener('click', () => {
            if (busy || requireRefresh) return;
            const { accountAction: action, login, confirm } = button.dataset;
            if (action === 'disable' || (action === 'delete' && window.confirm(`${confirm}\n${login}`))) accountAction(action, login);
        });
    }
    form?.addEventListener('submit', event => {
        event.preventDefault();
        if (busy || requireRefresh) return;
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
    if (page.dataset.reconcileUrl) void reconcileOnOpen();
    else updateMutations();
})();
