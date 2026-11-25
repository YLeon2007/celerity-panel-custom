(() => {
    'use strict';

    const overviewUrl = '/panel/l2tp';
    const observation = 'x-rebuild-l2tp-observation';
    const interval = 2000, observationLimit = 300_000;
    const requestOptions = { mode: 'same-origin', credentials: 'same-origin', cache: 'no-store', redirect: 'error' };
    let reading, readVersion = 0, active = true;
    window.addEventListener('pagehide', () => { active = false; cancelRead(); });

    function cancelRead() {
        readVersion++;
        reading?.abort();
    }

    function nonce() {
        try { return Array.from(window.crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join(''); }
        catch { return null; } // Without a nonce, a lost response cannot be attributed.
    }

    async function request(url, body, headers, signal) {
        const response = await fetch(url, { ...requestOptions, method: 'POST', headers, body, signal });
        const data = await response.json().catch(() => null);
        return { response, data };
    }

    const unknownOutcome = data => data?.outcome === 'unknown' || data?.error?.outcome === 'unknown';
    const noRetry = data => unknownOutcome(data) || data?.retryAllowed === false || data?.error?.retryAllowed === false;
    const ambiguous = (response, data) => response.status === 408 || response.status >= 500 || unknownOutcome(data);
    const makeDeadline = duration => {
        const monotonic = performance.now() + duration, wall = Date.now() + duration;
        return () => Math.min(monotonic - performance.now(), wall - Date.now());
    };

    async function readOverview(csrf, token, remaining) {
        if (!active || remaining() <= 0) return null;
        cancelRead();
        const version = readVersion;
        const read = new AbortController();
        reading = read;
        const timer = setTimeout(() => read.abort(), Math.min(remaining(), interval));
        const canceled = new Promise(resolve => read.signal.addEventListener('abort', () => resolve(null), { once: true }));
        const current = () => active && version === readVersion && !read.signal.aborted && remaining() > 0;
        try {
            const fetchView = async () => {
                const response = await fetch(overviewUrl, { ...requestOptions, method: 'GET', signal: read.signal,
                    headers: { Accept: 'text/html', ...(token && { [observation]: token }) } });
                if (!current() || response.status !== 200 || response.redirected
                    || response.url !== new URL(overviewUrl, location.origin).href
                    || !/^text\/html(?:;|$)/i.test(response.headers.get('content-type') || '')
                    || !/(?:^|,)\s*no-store\s*(?:,|$)/i.test(response.headers.get('cache-control') || '')) return null;
                // Keep the full page inert: never insert layout, scripts, or a login page.
                const template = document.createElement('template');
                template.innerHTML = await response.text();
                if (!current()) return null;
                const root = template.content.querySelector('#rebuild-l2tp');
                const view = root?.querySelector('[data-l2tp-view]');
                if (!view || !csrf || root.dataset.csrf !== csrf) return null;
                const echo = token && response.headers.get(observation);
                return { view, current, outcome: echo?.startsWith(`${token}:`) ? echo.slice(token.length + 1) : null };
            };
            const result = await Promise.race([fetchView(), canceled]);
            return current() ? result : null;
        } catch { return null; }
        finally {
            clearTimeout(timer);
            if (reading === read) reading = null;
        }
    }

    async function pollOverview(csrf, token, accept, onTick) {
        const remaining = makeDeadline(observationLimit);
        onTick?.(remaining());
        let next = observationLimit - interval;
        while (active && next > 0 && remaining() > 0) {
            await new Promise(resolve => setTimeout(resolve, Math.max(0, remaining() - next)));
            if (!active || remaining() <= 0) break;
            onTick?.(remaining());
            const snapshot = await readOverview(csrf, token, remaining);
            if (snapshot?.current() && accept(snapshot) && remaining() > 0) return true;
            do next -= interval; while (next > remaining());
        }
        if (active && remaining() > 0) await new Promise(resolve => setTimeout(resolve, remaining()));
        return false;
    }

    const page = document.getElementById('rebuild-l2tp');
    if (!page) {
        const form = document.querySelector?.('[data-l2tp-remove]');
        if (form) bindRemove(form);
        return;
    }
    const words = JSON.parse(page.dataset.messages);
    const installChecks = JSON.parse(page.dataset.installChecks || '{}');
    const admissionWords = JSON.parse(page.dataset.admissionMessages || '{}');

    function post(url, body, signal, token, csrf = page.dataset.csrf) {
        return request(url, JSON.stringify(body), { 'Content-Type': 'application/json', 'x-csrf-token': csrf,
            ...(token && { [observation]: token }) }, signal);
    }

    function bindRemove(form) {
        const words = JSON.parse(form.dataset.messages);
        const status = form.querySelector('[data-remove-status]');
        const refresh = form.querySelector('[data-remove-refresh]');
        let submitted = false;
        form.addEventListener('submit', async event => {
            if (submitted || !active) { event.preventDefault(); return; }
            if (event.submitter?.value !== 'confirm') return; // Preserve the native Cancel.
            event.preventDefault();
            submitted = true;
            const csrf = form.elements.namedItem('_csrf').value;
            const body = new URLSearchParams({ decision: 'confirm', ticket: form.elements.namedItem('ticket').value });
            const token = nonce();
            for (const button of form.querySelectorAll('button')) button.disabled = true;
            status.textContent = words.working;
            let result;
            try { result = await request(form.action, body, { Accept: 'application/json', 'x-csrf-token': csrf,
                ...(token && { [observation]: token }) }); } catch { /* no reply */ }
            if (!active) return;
            const { response, data } = result ?? {};
            if (response?.ok && !noRetry(data) && !ambiguous(response, data) && data?.executionMode === 'rebuild'
                && data.status === 'not_installed' && data.nodeId === form.dataset.nodeId) {
                // The preview lives on the node card. Navigate by GET to the
                // current overview instead of reopening a consumed preview.
                location.assign(overviewUrl);
                return;
            }
            let message = 'requestFailed';
            if (!response || response.ok || ambiguous(response, data) || (noRetry(data) && !data?.error?.code)) {
                status.textContent = words.uncertain;
                if (await pollOverview(csrf, token, snapshot => snapshot.outcome === 'removed')) {
                    if (active) location.assign(overviewUrl);
                    return;
                }
                message = 'observationTimeout';
            } else if (response.status === 429) message = 'rateLimited';
            else if (response.status === 409 && data?.error?.code === 'REBUILD_L2TP_IDENTITY_CHANGED'
                && data.error.outcome === 'refused' && !noRetry(data) && /^[a-f0-9]{24}$/.test(form.dataset.nodeId)) {
                const id = form.dataset.nodeId;
                location.assign(`${overviewUrl}?identityChanged=${id}#relay-${id}`);
                return;
            }
            else if (data?.error?.outcome === 'removed') message = 'removeCleanupFailed';
            else if (data?.error?.code === 'REBUILD_L2TP_RUNTIME_FOREIGN_CHANGE') message = 'runtimeForeignChange';
            else if (data?.error?.code === 'REBUILD_L2TP_HOST_NOT_READY' && data.error.check === 'NETWORK_OBSERVATION_REQUIRED') {
                message = 'runtimeNetworkNotReady';
            }
            if (active) {
                status.textContent = words[message];
                refresh.hidden = false;
            }
        });
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
            if (!active || busy || requireRefresh || flow || !isCurrent(widget)) return;
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

    let hideSecrets = [], form, installs, installRecoveries, accountButtons, admissionButtons, removeLinks, recover, mutations, relayControls;
    const clearSecrets = () => hideSecrets.forEach(hide => hide());
    window.addEventListener('pagehide', clearSecrets);

    const status = page.querySelector('[data-action-status]');
    const refresh = page.querySelector('[data-refresh]');
    const review = page.querySelector('[data-review]');
    const dialog = page.querySelector('[data-admission-dialog]');
    const expected = { install: 'installed', create: 'created', disable: 'disabled', delete: 'deleted' };
    const installOutcomes = new Map([
        ['refused', 'installRefused'], ['busy', 'installBusy'], ['rolled_back', 'installRolledBack'],
        ['unknown', 'uncertain'], ['installed', 'installCleanupFailed'],
    ]);
    let busy = false, requireRefresh = false;
    let identityReview = false, reviewId = null, flow = null;
    const hex = (value, n) => typeof value === 'string' && value.length === n && /^[a-f0-9]+$/.test(value);
    const relayResults = new Map();
    function drawRelayResult(nodeId) {
        const row = page.querySelector(`#relay-${nodeId}`);
        const label = row?.querySelector('[data-relay-action-status]');
        const timer = row?.querySelector('[data-relay-action-timer]');
        if (!label || !timer) return;
        const { text = '', clock = '' } = relayResults.get(nodeId) ?? {};
        if (label.textContent !== text) label.textContent = text;
        label.hidden = !text;
        timer.textContent = clock;
        timer.hidden = !clock;
    }

    function setActionStatus(text, nodeId, clock = '') {
        if (status.textContent !== text) status.textContent = text;
        if (!hex(nodeId, 24)) return;
        relayResults.set(nodeId, { text, clock });
        drawRelayResult(nodeId);
    }

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
    const isCurrent = element => active && page.contains(element);
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

    function updateRelayControls() {
        for (const { wrapper, control, reason } of relayControls) {
            const blocked = control.disabled || control.getAttribute('aria-disabled') === 'true';
            if (blocked) wrapper.tabIndex = 0;
            else wrapper.removeAttribute('tabindex');
            reason.hidden = !requireRefresh || !active || busy;
            if (requireRefresh && !busy) reason.textContent = words.refreshRequired;
        }
    }

    function updateMutations() {
        const locked = !active || busy || !!flow || requireRefresh;
        for (const button of mutations) button.disabled = locked;
        for (const button of admissionButtons) button.disabled = !active || busy || !!flow || (requireRefresh && !canReview(button));
        for (const link of removeLinks) link.setAttribute('aria-disabled', String(locked));
        updateRelayControls();
        refresh.hidden = !requireRefresh || busy;
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

    function applyOverview({ view, current }) {
        if (!current()) return false;
        const previous = page.querySelector('[data-l2tp-view]');
        if (!previous) return false;
        clearSecrets();
        previous.replaceWith(view);
        bindView();
        for (const nodeId of relayResults.keys()) drawRelayResult(nodeId);
        return true;
    }

    async function refreshAcknowledged(csrf) {
        const snapshot = await readOverview(csrf, null, makeDeadline(interval));
        return (snapshot && applyOverview(snapshot)) || pollOverview(csrf, null, applyOverview);
    }

    async function finishAcknowledged(csrf, message, keepLocked = false, nodeId) {
        setActionStatus(message, nodeId);
        // Keep the old controls locked until a newer, validated response has
        // replaced the view. A reload is only the fallback if readback fails.
        requireRefresh = true;
        identityReview = false;
        updateMutations();
        const refreshed = await refreshAcknowledged(csrf);
        if (!active) return;
        requireRefresh = !refreshed || keepLocked;
        if (!refreshed) setActionStatus(`${message} ${words.refreshFailed}`, nodeId);
        updateMutations();
    }

    async function reconcileUnknown(csrf, token, accepted, nodeId) {
        requireRefresh = true;
        identityReview = false;
        updateMutations();
        let outcome;
        const confirmed = await pollOverview(csrf, token, snapshot => {
            if (applyOverview(snapshot) && accepted.includes(snapshot.outcome)) {
                outcome = snapshot.outcome;
                return true;
            }
            return false;
        }, hex(nodeId, 24) ? remaining => {
            const seconds = Math.max(0, Math.ceil(remaining / 1000));
            setActionStatus(words.checkingResult, nodeId, `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`);
        } : undefined);
        if (!confirmed) return null;
        requireRefresh = false;
        return outcome;
    }

    function lockForAction() {
        busy = true;
        clearSecrets();
        updateMutations();
    }

    function installProgress(nodeId, csrf, consented) {
        const initial = hex(nodeId, 24) && page.querySelector(`[data-install-progress][data-progress-node="${nodeId}"]`);
        if (initial) initial.hidden = false;
        const progress = new AbortController();
        window.addEventListener('pagehide', () => progress.abort(), { once: true, signal: progress.signal });
        try {
            const stop = window.rebuildL2tpInstallProgress?.start(page, nodeId, consented);
            if (stop) progress.signal.addEventListener('abort', stop, { once: true });
        } catch { /* Progress is observational only. */ }
        // Item 2 can observe the outstanding synchronous POST without access
        // to its write or receipt nonce. Superseded reads cannot replace newer DOM.
        window.dispatchEvent(new CustomEvent('rebuild-l2tp:install-start', { detail: {
            nodeId, signal: progress.signal,
            async refresh() {
                if (progress.signal.aborted) return false;
                const snapshot = await readOverview(csrf, null, makeDeadline(interval));
                return !!snapshot && !progress.signal.aborted && applyOverview(snapshot);
            },
        } }));
        return () => {
            progress.abort();
            if (initial) initial.hidden = true;
            cancelRead();
        };
    }

    let openAdmission;

    if (dialog) {
        const field = name => dialog.querySelector(`[data-admission-${name}]`);
        const approvals = dialog.querySelectorAll('[data-admission-approve]');
        const cancel = field('cancel'), notice = field('status');
        const consoleCheck = field('console'), copyStatus = field('copy-status');
        const fields = ['name', 'endpoint', 'login', 'key-type', 'key', 'machine'];
        const hostKeyTypes = new Set(['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa', 'ssh-dss']);

        function draw(step, data) {
            flow.step = step;
            for (const item of dialog.querySelectorAll('[data-admission-step]')) item.hidden = item.dataset.admissionStep !== step;
            field('identity').hidden = !data;
            field('machine-row').hidden = step !== 'confirm';
            consoleCheck.hidden = !data;
            copyStatus.textContent = '';
            if (data) {
                const host = data.host.includes(':') && !data.host.startsWith('[') ? `[${data.host}]` : data.host;
                field('endpoint').textContent = `${host}:${data.port}`;
                field('login').textContent = data.username;
                field('key-type').textContent = data.sshHostKeyType;
                field('key').textContent = data.sshHostKeySha256;
                field('machine').textContent = step === 'confirm' ? data.machineId : '';
            }
            for (const button of approvals) button.hidden = button.dataset.admissionApprove !== step;
        }

        function dismiss() {
            flow = null;
            for (const name of fields) field(name).textContent = '';
            notice.textContent = '';
            copyStatus.textContent = '';
            consoleCheck.hidden = true;
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
            if (!hostKeyTypes.has(data.sshHostKeyType) || (action === 'verify' && data.sshHostKeyType !== current.identity?.sshHostKeyType)) return false;
            return hex(data.challenge, 64) && data.challenge !== current.identity?.challenge;
        }

        async function advance(action) {
            const current = flow;
            if (!active || !current || busy) return;
            lockForAction();
            cancel.disabled = true;
            for (const button of approvals) button.disabled = true;
            notice.textContent = words.working;
            const mutating = action === 'confirm' || action === 'revoke';
            const success = action === 'confirm' ? 'granted' : 'revoked';
            const token = mutating ? nonce() : null;
            let errorText = mutating ? words.uncertain : admissionWords.checkUnavailable, stale = mutating, unknown = true;
            try {
                const body = action === 'verify' || action === 'confirm' ? { challenge: current.identity.challenge } : {};
                const { response, data } = await post(`${current.url}/${action}`, body, undefined, token, current.csrf);
                if (!active || current !== flow) return;
                const blocked = noRetry(data);
                unknown = ambiguous(response, data) || response.ok;
                if (response.ok && !ambiguous(response, data) && !blocked && matchesReceipt(current, action, data)) {
                    unknown = false;
                    if (mutating) {
                        dismiss();
                        await finishAcknowledged(current.csrf, admissionWords[success], false, current.nodeId);
                    } else {
                        if (!await refreshAcknowledged(current.csrf)) {
                            if (!active) return;
                            current.identity = null;
                            requireRefresh = true;
                            identityReview = false;
                            draw(null, null);
                            notice.textContent = words.refreshFailed;
                            setActionStatus(words.refreshFailed, current.nodeId);
                            return;
                        }
                        if (!active || flow !== current) return;
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
                            setActionStatus(errorText, current.nodeId);
                        }
                        if (key === 'grantUnavailable') stale = true;
                    }
                }
            } catch { /* Do not retry an ambiguous response or reuse its challenge. */ }
            finally {
                // GET cannot restore a lost approval challenge or reviewed identity.
                if (active && flow === current && unknown) {
                    current.identity = null;
                    draw(null, null);
                    notice.textContent = errorText;
                    setActionStatus(errorText, current.nodeId);
                    const outcome = await reconcileUnknown(current.csrf, token, mutating ? [success] : [], current.nodeId);
                    if (active && outcome) {
                        dismiss();
                        setActionStatus(admissionWords[outcome], current.nodeId);
                    } else if (active) {
                        stale = true;
                        errorText = words.observationTimeout;
                    }
                }
                busy = false;
                cancel.disabled = false;
                for (const button of approvals) button.disabled = false;
                updateMutations();
            }
            if (!active || flow !== current) return;
            current.identity = null;
            draw(null, null);
            notice.textContent = errorText;
            setActionStatus(errorText, current.nodeId);
            if (stale) {
                requireRefresh = true;
                identityReview = false;
                clearSecrets();
                updateMutations();
            }
        }

        openAdmission = button => {
            if (!isCurrent(button) || busy || flow || (requireRefresh && !canReview(button))) return;
            const { admissionAction, admissionUrl, nodeId, nodeName } = button.dataset;
            if (hex(nodeId, 24)) {
                relayResults.delete(nodeId);
                drawRelayResult(nodeId);
            }
            flow = { nodeId, url: admissionUrl, csrf: page.dataset.csrf, step: null, identity: null };
            field('name').textContent = nodeName;
            draw(admissionAction === 'revoke' ? 'revoke' : null, null);
            dialog.showModal();
            updateMutations();
            if (admissionAction !== 'revoke') void advance('probe');
        };
        for (const button of approvals) button.addEventListener('click', event => {
            if (event.detail <= 1 && button.dataset.admissionApprove === flow?.step) void advance(flow.step);
        });
        field('copy-command').addEventListener('click', async () => {
            const identity = flow?.identity;
            if (!identity || consoleCheck.hidden) return;
            let message = words.copied;
            try { await navigator.clipboard.writeText(field('command').textContent); }
            catch { message = words.copyFailed; }
            if (flow?.identity === identity) copyStatus.textContent = message;
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
        const url = recover?.dataset.reconcileUrl;
        if (!active || busy || flow || requireRefresh || !url) return;
        lockForAction();
        status.textContent = words.working;
        const csrf = page.dataset.csrf, token = nonce();
        let message = 'reconcileUnconfirmed', note = '';
        let unknown = true;
        try {
            const { response, data } = await post(url, {}, undefined, token, csrf);
            unknown = ambiguous(response, data) || response.ok;
            if (response.ok && !ambiguous(response, data) && data?.executionMode === 'rebuild') {
                if (data.status === 'settled' && !noRetry(data)) {
                    message = 'reconcileSettled';
                    note = closureNote(data, data.sessionsTerminated);
                    unknown = false;
                }
                if (data.status === 'pending') {
                    message = 'reconcileStillPending';
                    unknown = false;
                }
                if (data.status === 'inspection-unproved' && data.retryAllowed === false) {
                    unknown = false;
                    message = 'reconcileInspectionUnproved';
                    const detail = inspectionMessages.get(data.reason);
                    if (detail) note = ` ${words[detail]}`;
                }
            } else if (response.status === 429) {
                message = 'rateLimited';
            } else if (response.status === 409 && data?.error?.code === 'REBUILD_L2TP_RECONCILE_DISABLED') {
                message = 'recoveryIneligible';
            } else if (response.status === 409 && data?.error?.code === 'REBUILD_L2TP_RUNTIME_FOREIGN_CHANGE'
                && data.error.retryAllowed === false && data.error.outcome === undefined && data.outcome === undefined) {
                message = 'runtimeForeignChange';
            } else if (response.status === 409 && data?.error?.code === 'REBUILD_L2TP_HOST_NOT_READY'
                && data.error.check === 'NETWORK_OBSERVATION_REQUIRED' && data.error.retryAllowed === false
                && data.error.outcome === undefined && data.outcome === undefined) {
                message = 'runtimeNetworkNotReady';
                if (installChecks.NETWORK_OBSERVATION_REQUIRED) note = ` ${installChecks.NETWORK_OBSERVATION_REQUIRED}`;
            } else if (response.status === 409 && data?.error?.retryAllowed === false
                && data.error.code === 'REBUILD_L2TP_ACCOUNTS_MANUAL_BLOCK') {
                message = 'reconcileManualBlock';
            } else if (effectErrors.has(data?.error?.code)) {
                message = data.error.code === 'REBUILD_L2TP_IDENTITY_CHANGED' ? 'reconcileManualBlock' : effectErrors.get(data.error.code);
            }
        } catch { /* A lost response does not establish whether the fence cleared. */ }
        if (!active) return;
        status.textContent = (words[message] ?? admissionWords[message]) + note;
        requireRefresh = true;
        if (message === 'reconcileSettled') await finishAcknowledged(csrf, status.textContent);
        else if (unknown && token) {
            const outcome = await reconcileUnknown(csrf, token, ['settled']);
            if (active) status.textContent = words[outcome ? 'reconcileSettled' : 'observationTimeout'];
        }
        busy = false;
        updateMutations();
    }

    // Install conflict keys are identifiers, not paths. Never render paths,
    // names or descriptions supplied by the Install response.
    const foreignPaths = new Map([
        ['SWAN_PROFILE_PRESENT', ['/etc/strongswan.d/celerity-rebuild-l2tp.conf']],
        ['IKE_PROFILE_PRESENT', ['/etc/ipsec.d/celerity-rebuild-l2tp.conf']],
        ['OPTIONS_PRESENT', ['/etc/ppp/options.xl2tpd']],
        ['STARTER_NOT_STOCK', ['/etc/ipsec.conf']],
        ['SECRETS_NOT_EMPTY', ['/etc/ipsec.secrets']],
        ['CHAP_NOT_EMPTY', ['/etc/ppp/chap-secrets']],
        ['LNS_NOT_STOCK', ['/etc/xl2tpd/xl2tpd.conf']],
        ['XRAY_UNIT_0666', ['/etc/systemd/system/xray.service']],
        ['XRAY_BRIDGE_UNIT_0666', ['/etc/systemd/system/xray-bridge.service']],
        ['UNIT_WRITABLE', ['/etc/systemd/system/xray.service', '/etc/systemd/system/xray-bridge.service']],
        ['NFT_DIR_PRESENT', ['/etc/celerity-rebuild-l2tp/']],
        ['DROPIN_PRESENT', ['/etc/systemd/system/xl2tpd.service.d/']],
        ['MODULES_LOAD_FOREIGN', ['/etc/modules-load.d/c3-l2tp.conf']],
        ['NETWORK_UNIT_ORPHANED', ['/etc/systemd/system/celerity-rebuild-l2tp-network.service']],
        ['LEGACY_NFT_PRESENT', ['/etc/nftables.d/celerity-l2tp.nft']],
        ['IPSEC_D_FOREIGN_CONF', ['/etc/ipsec.d/']],
        ['SWAN_TREE_NOT_STOCK', ['/etc/strongswan.d/', '/etc/strongswan.conf']],
        ['CONFFILE_UNKNOWN', ['/etc/ipsec.conf', '/etc/ipsec.secrets', '/etc/xl2tpd/xl2tpd.conf']],
        ['INCLUDE_FOREIGN', ['/etc/ipsec.conf', '/etc/ipsec.secrets']],
    ]);
    const xrayModeKeys = new Set(['XRAY_UNIT_0666', 'XRAY_BRIDGE_UNIT_0666']);
    const foreignCode = 'REBUILD_L2TP_FOREIGN_CONFIG';
    const changedForeignCode = 'REBUILD_L2TP_FOREIGN_CONFIG_CHANGED';
    function cleanupChallenge(error) {
        if (!error || ![foreignCode, changedForeignCode].includes(error.code)
            || error.outcome !== 'refused' || error.check !== 'L2TP_FOREIGN_CONFIG') return;
        const { keys, cleanable, manual, cleanupToken } = error;
        if (![keys, cleanable, manual].every(list => Array.isArray(list) && list.length <= foreignPaths.size)
            || !keys.length || keys.length !== cleanable.length + manual.length) return;
        const partition = new Set([...cleanable, ...manual]);
        if (partition.size !== keys.length || new Set(keys).size !== keys.length
            || !keys.every(key => foreignPaths.has(key) && partition.has(key))) return;
        if (!manual.length && !hex(cleanupToken, 64)) return;
        return { cleanable, manual, token: cleanupToken, changed: error.code === changedForeignCode };
    }

    function askForeignCleanup(modal, relayName, { cleanable, manual, changed }) {
        const field = name => modal.querySelector(`[data-foreign-cleanup-${name}]`);
        const canConfirm = !manual.length;
        const confirm = field('confirm'), cancel = field('cancel');
        const xray = field('xray').querySelector('input');
        const modes = [...cleanable, ...manual].filter(key => xrayModeKeys.has(key));
        function list(name, keys) {
            const container = field(name);
            const items = keys.map(key => {
                const item = document.createElement('li'), reason = document.createElement('span');
                reason.textContent = installChecks[key];
                item.append(reason);
                for (const path of foreignPaths.get(key)) {
                    const label = document.createElement('code');
                    label.textContent = path;
                    item.append(' ', label);
                }
                return item;
            });
            container.querySelector('ul').replaceChildren(...items);
            container.hidden = !items.length;
        }
        field('title').textContent = modal.dataset.title.replace('{name}', () => relayName);
        field('changed').hidden = !changed;
        field('instructions').hidden = !canConfirm;
        list('files', cleanable.filter(key => !xrayModeKeys.has(key)));
        list('manual', manual);
        list('xray', modes);
        xray.checked = !!modes.length;
        xray.disabled = !modes.length || !canConfirm;
        confirm.hidden = confirm.disabled = !canConfirm;

        return new Promise((resolve, reject) => {
            const listeners = new AbortController();
            const options = { signal: listeners.signal };
            let choice, pressedOutside = false;
            const outside = event => {
                if (event.target !== modal) return false;
                const { left, right, top, bottom } = modal.getBoundingClientRect();
                return event.clientX < left || event.clientX >= right || event.clientY < top || event.clientY >= bottom;
            };
            modal.addEventListener('pointerdown', event => { pressedOutside = outside(event); }, options);
            modal.addEventListener('click', event => { if (pressedOutside && outside(event)) modal.close(); }, options);
            cancel.addEventListener('click', () => modal.close(), options);
            confirm.addEventListener('click', () => {
                if (!modal.open || !canConfirm || !active) return;
                choice = { fixXrayUnitMode: !!modes.length && xray.checked };
                modal.close();
            }, options);
            modal.addEventListener('close', () => { listeners.abort(); resolve(choice); }, options);
            window.addEventListener('pagehide', () => {
                listeners.abort();
                if (modal.open) modal.close();
                resolve();
            }, options);
            try { modal.showModal(); }
            catch (error) { listeners.abort(); reject(error); }
        });
    }

    async function mutate(action, url, body, match, nodeId, installButton) {
        if (!active || busy || flow || requireRefresh) return;
        lockForAction();
        setActionStatus(words.working, nodeId);
        const csrf = page.dataset.csrf;
        let token = nonce();
        let result = 'uncertain', note = '';
        const revocation = action === 'disable' || action === 'delete';
        const accepted = action === 'install' ? [expected[action]] : [expected[action], 'canceled'];
        let unknown = true;
        try {
            let response, data;
            for (;;) {
                unknown = true;
                const endProgress = action === 'install' ? installProgress(nodeId, csrf, !!body.foreignCleanup) : null;
                try { ({ response, data } = await post(url, body, undefined, token, csrf)); }
                finally { endProgress?.(); }
                if (!active) return;
                unknown = ambiguous(response, data);
                const challenge = action === 'install' && response.status === 409 && !noRetry(data)
                    && cleanupChallenge(data?.error);
                const modal = challenge && page.querySelector('[data-foreign-cleanup-dialog]');
                if (!modal || !isCurrent(installButton)) break;

                setActionStatus(words.installAwaitingCleanup, nodeId);
                const choice = await askForeignCleanup(modal, installButton.dataset.nodeName, challenge);
                if (!active) return;
                const confirmed = choice && isCurrent(installButton);
                const next = confirmed && nonce();
                if (!next || next === token) {
                    setActionStatus(words[confirmed ? 'cryptoUnavailable' : 'installCanceled'], nodeId);
                    busy = false;
                    updateMutations();
                    if (isCurrent(installButton)) installButton.focus();
                    return;
                }
                token = next;
                body = { foreignCleanup: { token: challenge.token, fixXrayUnitMode: choice.fixXrayUnitMode } };
                setActionStatus(words.working, nodeId);
                // A drift reply loops back to the dialog, not directly to another POST.
            }
            const { code, outcome, check } = data?.error ?? {};
            const blocked = noRetry(data);
            if (response.ok && !blocked && !unknown) {
                const canceled = action !== 'install' && data?.status === 'canceled' && data.recovered === true
                    && (!revocation || (data.sessionsTerminated === 0 && data.sessionsTerminatedScope === 'request'));
                if (data?.executionMode === 'rebuild' && (data.status === expected[action] || canceled) && match(data)) {
                    result = data.status;
                    requireRefresh = true;
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
                    && (check !== 'FOREIGN_CONFIG_RESTORED' || outcome === 'rolled_back')
                    && (check === undefined || (typeof check === 'string' && Object.hasOwn(installChecks, check)))) {
                    result = installOutcomes.get(outcome);
                    if (check !== undefined) note = ` ${installChecks[check]}`;
                    const keys = data.error.keys;
                    if ([foreignCode, changedForeignCode].includes(code) && outcome === 'refused' && check === 'L2TP_FOREIGN_CONFIG'
                        && Array.isArray(keys) && keys.length > 0 && keys.length <= 24 && new Set(keys).size === keys.length
                        && keys.every(key => foreignPaths.has(key) && Object.hasOwn(installChecks, key))) {
                        note += ` ${keys.map(key => installChecks[key]).join(' ')}`;
                    }
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
        if (!active) return;
        let message = (words[result] ?? admissionWords[result]) + note;
        if (action === 'install' && !accepted.includes(result) && !unknown
            && !['uncertain', 'installCleanupFailed', 'identityChanged'].includes(result)) {
            message = words.installStopped.replace('{reason}', () => message);
        }
        setActionStatus(message, nodeId);
        if (accepted.includes(result) || result === 'installCleanupFailed' || result === 'installRolledBack') {
            await finishAcknowledged(csrf, message, !accepted.includes(result), nodeId);
        } else if (unknown || result === 'uncertain') {
            if (token) {
                const outcome = await reconcileUnknown(csrf, token, accepted, nodeId);
                if (active) setActionStatus(words[outcome ?? 'observationTimeout'] + (outcome ? '' : note), nodeId);
            } else {
                // An unbound GET cannot settle this request; leave the explicit refresh fallback.
                requireRefresh = true;
            }
        }
        busy = false;
        updateMutations();
    }

    async function recoverInstall({ installRecoveryUrl, nodeId }) {
        if (!active || busy || flow || requireRefresh) return;
        lockForAction();
        setActionStatus(words.working, nodeId);
        const csrf = page.dataset.csrf, token = nonce();
        let message = 'installRecoveryUnconfirmed';
        try {
            const { response, data } = await post(installRecoveryUrl, {}, undefined, token, csrf);
            if (response.ok && !ambiguous(response, data) && !noRetry(data) && data?.executionMode === 'rebuild'
                && data.status === 'can_install_again' && data.nodeId === nodeId) message = 'canInstallAgain';
            else if (response.status === 409 && data?.error?.code === 'REBUILD_L2TP_INSTALL_RECOVERY_NO_STATE'
                && data.error.retryAllowed === false && data.error.outcome === undefined && data.outcome === undefined) {
                message = 'installRecoveryNoState';
            }
        } catch { /* An unconfirmed response is not permission to install. */ }
        if (!active) return;
        setActionStatus(words[message], nodeId);
        requireRefresh = true;
        if (message === 'canInstallAgain') await finishAcknowledged(csrf, status.textContent, false, nodeId);
        else if (message === 'installRecoveryUnconfirmed' && token) {
            const outcome = await reconcileUnknown(csrf, token, ['can_install_again'], nodeId);
            if (active) setActionStatus(words[outcome ? 'canInstallAgain' : message], nodeId);
        }
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

    function bindView() {
        hideSecrets = Array.from(page.querySelectorAll('[data-secret-url]'), bindSecret);
        form = page.querySelector('[data-create]');
        installs = page.querySelectorAll('[data-install-url]');
        installRecoveries = page.querySelectorAll('[data-install-recovery-url]');
        accountButtons = page.querySelectorAll('[data-account-action]');
        admissionButtons = page.querySelectorAll('[data-admission-action]');
        removeLinks = page.querySelectorAll('[data-remove-link]');
        recover = page.querySelector('[data-reconcile]');
        mutations = [...installs, ...installRecoveries, ...accountButtons,
            ...[form?.querySelector('button[type="submit"]'), recover].filter(Boolean)];
        relayControls = Array.from(page.querySelectorAll('[data-relay-control]'), wrapper => {
            const control = wrapper.firstElementChild;
            const reason = wrapper.parentElement.querySelector('[data-relay-refresh-reason]');
            const explain = event => {
                if (!isCurrent(wrapper) || !(control.disabled || control.getAttribute('aria-disabled') === 'true')) return;
                event.preventDefault();
                event.stopPropagation();
                if (!active) return;
                const message = busy || !requireRefresh ? words.working : words.refreshRequired;
                reason.textContent = message;
                reason.hidden = false;
            };
            wrapper.addEventListener('click', explain);
            wrapper.addEventListener('keydown', event => {
                if (event.key === 'Enter' || event.key === ' ') explain(event);
            });
            return { wrapper, control, reason };
        });

        for (const button of admissionButtons) button.addEventListener('click', () => openAdmission?.(button));
        for (const link of removeLinks) link.addEventListener('click', event => {
            if (!isCurrent(link) || busy || flow || requireRefresh) event.preventDefault();
        });
        for (const button of installs) button.addEventListener('click', () => {
            if (!isCurrent(button)) return;
            const { installUrl, nodeId } = button.dataset;
            void mutate('install', installUrl, {}, data => data.nodeId === nodeId, nodeId, button);
        });
        for (const button of installRecoveries) button.addEventListener('click', () => {
            if (isCurrent(button)) void recoverInstall(button.dataset);
        });
        for (const button of accountButtons) button.addEventListener('click', () => {
            if (!isCurrent(button) || busy || flow || requireRefresh) return;
            const { accountAction: action, login, confirm } = button.dataset;
            if (action === 'disable' || (action === 'delete' && window.confirm(`${confirm}\n${login}`))) accountAction(action, login);
        });
        form?.addEventListener('submit', event => {
            event.preventDefault();
            if (!isCurrent(event.currentTarget) || busy || flow || requireRefresh) return;
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
        const button = recover;
        button?.addEventListener('click', () => { if (isCurrent(button)) void reconcileAccounts(); });
        updateMutations();
    }
    bindView();
})();
