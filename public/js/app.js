// Hysteria Panel - Frontend JS

// Format bytes to human readable
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Toast notification
window.showToast = function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = 'toast show ' + type;
    setTimeout(() => { toast.className = 'toast'; }, 3000);
};

// Confirm before dangerous actions
document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', (e) => {
        if (!confirm(el.dataset.confirm)) {
            e.preventDefault();
        }
    });
});

(function initPanelSelfUpdate() {
    const widget = document.getElementById('panelUpdateWidget');
    const action = document.getElementById('panelUpdateAction');
    const modal = document.getElementById('panelUpdateModal');
    const closeBtn = document.getElementById('panelUpdateClose');
    const cancelBtn = document.getElementById('panelUpdateCancel');
    const applyBtn = document.getElementById('panelUpdateApply');
    const meta = document.getElementById('panelUpdateMeta');
    const changelog = document.getElementById('panelUpdateChangelog');
    const logBox = document.getElementById('panelUpdateLog');

    if (!widget || !action || !modal || !applyBtn) return;

    const i18n = {
        checking: document.documentElement.lang === 'ru' ? 'Проверка...' : 'Checking...',
        check: document.documentElement.lang === 'ru' ? 'Проверить обновление' : 'Check for update',
        available: document.documentElement.lang === 'ru' ? 'Доступно обновление' : 'Update available',
        apply: document.documentElement.lang === 'ru' ? 'Обновить' : 'Update',
        upToDate: document.documentElement.lang === 'ru' ? 'Обновлений нет' : 'Up to date',
        failed: document.documentElement.lang === 'ru' ? 'Ошибка проверки' : 'Check failed',
        applying: document.documentElement.lang === 'ru' ? 'Обновление запущено...' : 'Update started...',
        applied: document.documentElement.lang === 'ru' ? 'Обновление завершено успешно.' : 'Update completed successfully.',
        applyFailed: document.documentElement.lang === 'ru' ? 'Обновление завершилось ошибкой.' : 'Update failed.',
        polling: document.documentElement.lang === 'ru' ? 'Жду лог выполнения...' : 'Waiting for progress log...',
        reconnecting: document.documentElement.lang === 'ru'
            ? 'Backend перезапускается или временно недоступен; продолжаю ждать лог...'
            : 'Backend is restarting or temporarily unavailable; still waiting for the log...',
        noChangelog: document.documentElement.lang === 'ru' ? 'Changelog пуст или недоступен.' : 'Changelog is empty or unavailable.',
        noUpdateDetails: document.documentElement.lang === 'ru'
            ? 'Установлена последняя версия. Обновление не требуется.'
            : 'The latest version is already installed. No update is required.',
        confirmApply: document.documentElement.lang === 'ru'
            ? 'Запустить обновление панели? Будет создан backup и ROLLBACK.sh.'
            : 'Start panel update? Backup and ROLLBACK.sh will be created.',
    };

    const CHECK_INTERVAL_MS = 12 * 60 * 60 * 1000;
    const LAST_AUTO_CHECK_KEY = 'celerity:lastAutoUpdateCheckAt';
    let currentStatus = null;

    function setState(state) {
        widget.dataset.updateState = state;
        if (state === 'checking') action.textContent = i18n.checking;
        if (state === 'available') action.textContent = i18n.available;
        if (state === 'idle') action.textContent = i18n.check;
        if (state === 'error') action.textContent = i18n.failed;
    }

    function openModal() {
        modal.classList.add('active');
        modal.setAttribute('aria-hidden', 'false');
    }

    function closeModal() {
        modal.classList.remove('active');
        modal.setAttribute('aria-hidden', 'true');
    }

    function renderStatus(status) {
        currentStatus = status;
        const updateAvailable = Boolean(status && status.updateAvailable);
        setState(updateAvailable ? 'available' : 'idle');

        if (!meta || !changelog) return;
        const current = status.currentVersion || widget.dataset.currentVersion || 'unknown';
        const latest = status.latestVersion || status.latestSha || 'unknown';
        const branch = status.branch || 'main';
        const behind = status.behindBy || 0;

        meta.innerHTML = `
            <div><strong>Current:</strong> v${current} ${status.currentSha ? `(${status.currentSha})` : ''}</div>
            <div><strong>Latest:</strong> ${status.latestVersion ? `v${latest}` : latest}</div>
            <div><strong>Branch:</strong> ${branch}; <strong>Commits:</strong> ${behind}</div>
        `;

        if (Array.isArray(status.changelog) && status.changelog.length > 0) {
            changelog.innerHTML = `<ul>${status.changelog.map(item => (
                `<li><code>${item.sha || ''}</code> <span>${item.date || ''}</span> ${escapeHtml(item.subject || '')}</li>`
            )).join('')}</ul>`;
        } else {
            changelog.textContent = updateAvailable ? i18n.noChangelog : i18n.noUpdateDetails;
        }

        applyBtn.hidden = !updateAvailable;
        applyBtn.style.display = updateAvailable ? '' : 'none';
        applyBtn.disabled = !updateAvailable || Boolean(status.apply?.running);
        applyBtn.textContent = i18n.apply;
        if (status.apply) {
            renderApplyState(status.apply);
        }
    }

    function scrollLogToBottom() {
        if (logBox) logBox.scrollTop = logBox.scrollHeight;
    }

    function renderApplyState(apply) {
        if (!logBox || !apply) return;
        logBox.hidden = false;
        const lines = [];
        if (apply.startedAt) lines.push(`[ui] started: ${apply.startedAt}`);
        if (apply.log) lines.push(apply.log.trimEnd());
        else if (apply.running) lines.push(i18n.polling);
        if (apply.finishedAt) lines.push(`[ui] finished: ${apply.finishedAt}`);
        if (apply.success === true) lines.push(`[ui] ${i18n.applied}`);
        if (apply.success === false) lines.push(`[ui] ${i18n.applyFailed} ${apply.error || ''}`.trim());
        if (apply.backupDir) lines.push(`[ui] backup: ${apply.backupDir}`);
        if (apply.rollbackPath) lines.push(`[ui] rollback: ${apply.rollbackPath}`);
        logBox.textContent = lines.filter(Boolean).join('\n');
        scrollLogToBottom();
    }

    async function pollApplyUntilDone() {
        let transientFailures = 0;
        for (;;) {
            try {
                const status = await requestJson('/panel/update/status', { method: 'GET' });
                transientFailures = 0;
                currentStatus = status;
                renderApplyState(status.apply);

                if (!status.apply?.running) {
                    applyBtn.disabled = false;
                    applyBtn.textContent = status.apply?.success === false ? i18n.applyFailed : i18n.applied;
                    if (status.apply?.success === false) {
                        window.showToast(status.apply.error || i18n.applyFailed, 'error');
                    } else {
                        setState('idle');
                        window.showToast(i18n.applied, 'success');
                    }
                    return status;
                }
            } catch (error) {
                transientFailures += 1;
                // During self-update the backend container can restart, and older
                // deployments could also rate-limit status polling. Keep the modal
                // alive instead of freezing on the last line.
                renderApplyState({
                    running: true,
                    log: `[ui] ${i18n.reconnecting}
[ui] ${error.message || error}`,
                });
                if (transientFailures % 5 === 0) {
                    window.showToast(error.message || i18n.failed, 'warning');
                }
            }

            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }

    function escapeHtml(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    async function requestJson(url, options = {}) {
        const response = await fetch(url, {
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json', ...(options.headers || {}) },
            ...options,
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || response.statusText);
        return data;
    }

    async function checkUpdate({ force = false, open = false } = {}) {
        setState('checking');
        try {
            const status = await requestJson(force ? '/panel/update/check' : '/panel/update/status', {
                method: force ? 'POST' : 'GET',
            });
            renderStatus(status);
            if (open || status.updateAvailable) openModal();
            return status;
        } catch (error) {
            setState('error');
            window.showToast(error.message || i18n.failed, 'error');
            throw error;
        }
    }

    action.addEventListener('click', async () => {
        if (currentStatus?.updateAvailable) {
            renderStatus(currentStatus);
            openModal();
            return;
        }
        await checkUpdate({ force: true, open: true }).catch(() => {});
    });

    applyBtn.addEventListener('click', async () => {
        if (!confirm(i18n.confirmApply)) return;
        applyBtn.disabled = true;
        applyBtn.textContent = i18n.applying;
        try {
            const result = await requestJson('/panel/update/apply', { method: 'POST' });
            renderApplyState(result.apply || { running: true, log: i18n.applying });
            await pollApplyUntilDone();
        } catch (error) {
            window.showToast(error.message, 'error');
            applyBtn.disabled = false;
            applyBtn.textContent = i18n.apply;
        }
    });

    [closeBtn, cancelBtn].forEach(btn => btn?.addEventListener('click', closeModal));
    modal.addEventListener('click', (event) => {
        if (event.target === modal) closeModal();
    });

    const lastAutoCheck = Number(localStorage.getItem(LAST_AUTO_CHECK_KEY) || '0');
    if (!lastAutoCheck || Date.now() - lastAutoCheck > CHECK_INTERVAL_MS) {
        localStorage.setItem(LAST_AUTO_CHECK_KEY, String(Date.now()));
        checkUpdate({ force: false, open: false }).catch(() => {});
    }
})();

console.log('⚡ Hysteria Panel loaded');
