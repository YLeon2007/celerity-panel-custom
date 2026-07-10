// Access-logs dashboard: filters, summary, search, node status, purge.
(function () {
    'use strict';

    const app = document.getElementById('accessLogsApp');
    if (!app) return;
    const enabled = app.dataset.enabled === '1';
    const I18N = window.__AL_I18N || {};

    const $ = (id) => document.getElementById(id);
    const toast = (msg, type) => {
        if (typeof window.showToast === 'function') return window.showToast(msg, type);
        const t = $('toast'); if (!t) return;
        t.textContent = msg; t.className = 'toast show ' + (type || '');
        setTimeout(() => { t.className = 'toast'; }, 3000);
    };

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
        }[c]));
    }

    function fmtBytes(n) {
        n = Number(n) || 0;
        const u = ['B', 'KB', 'MB', 'GB', 'TB'];
        let i = 0;
        while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
        return n.toFixed(i ? 1 : 0) + ' ' + u[i];
    }

    function fmtTime(v) {
        if (!v) return I18N.never || '—';
        try { return new Date(v).toLocaleString(); } catch (_) { return String(v); }
    }

    // Collect filters from the form into a query string.
    function queryString() {
        const params = new URLSearchParams();
        const map = {
            from: 'alFrom', to: 'alTo', nodeId: 'alNode', email: 'alEmail',
            sourceIp: 'alSourceIp', destination: 'alDest', network: 'alNetwork', action: 'alAction',
        };
        for (const [key, id] of Object.entries(map)) {
            const el = $(id);
            if (el && el.value) {
                let v = el.value;
                if ((key === 'from' || key === 'to') && v) {
                    // datetime-local -> ISO
                    const d = new Date(v);
                    if (!isNaN(d.getTime())) v = d.toISOString();
                }
                params.set(key, v);
            }
        }
        return params.toString();
    }

    async function getJson(url) {
        const res = await fetch(url, { credentials: 'include' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
    }

    async function loadSummary() {
        try {
            const data = await getJson('/panel/access-logs/api/summary?' + queryString());
            if (!data.enabled) return;
            $('alDegraded').style.display = data.degraded ? '' : 'none';
            const totals = data.totals || {};
            $('alTotal').textContent = totals.total != null ? totals.total : '0';
            $('alUsers').textContent = totals.users != null ? totals.users : (data.topUsers ? data.topUsers.length : '0');
            $('alIps').textContent = totals.ips != null ? totals.ips : '—';

            renderTop($('alTopDest'), data.topDestinations, (r) => r.dest || r.key, (r) => r.hits);
            renderTop($('alTopUsers'), data.topUsers, (r) => r.email || r.key, (r) => r.hits);
        } catch (e) {
            toast('Summary error: ' + e.message, 'error');
        }
    }

    function renderTop(tbody, rows, keyFn, valFn) {
        if (!tbody) return;
        rows = rows || [];
        if (!rows.length) { tbody.innerHTML = '<tr><td class="hint">—</td></tr>'; return; }
        tbody.innerHTML = rows.map(r =>
            `<tr><td>${esc(keyFn(r))}</td><td style="text-align:right;">${esc(valFn(r))}</td></tr>`
        ).join('');
    }

    async function loadSearch() {
        try {
            const data = await getJson('/panel/access-logs/api/search?' + queryString() + '&limit=200');
            const rows = data.rows || [];
            const tbody = $('alResults');
            $('alNoResults').style.display = rows.length ? 'none' : '';
            $('alResultCount').textContent = rows.length ? (rows.length + '') : '';
            if (data.degraded) $('alDegraded').style.display = '';
            tbody.innerHTML = rows.map(r => {
                const src = [r.source_ip, r.source_port].filter(Boolean).join(':');
                const dest = [(r.dest_host || r.dest_ip), r.dest_port].filter(Boolean).join(':');
                return `<tr>
                    <td>${esc(fmtTime(r.ts))}</td>
                    <td>${esc(r.node_id || '')}</td>
                    <td>${esc(r.email || '')}</td>
                    <td>${esc(src)}</td>
                    <td>${esc(dest)}</td>
                    <td>${esc(r.network || '')}</td>
                    <td>${esc(r.action || '')}</td>
                </tr>`;
            }).join('');
        } catch (e) {
            toast('Search error: ' + e.message, 'error');
        }
    }

    async function loadStatus() {
        try {
            const data = await getJson('/panel/access-logs/api/status');
            if (data.spool) $('alSpool').textContent = fmtBytes(data.spool.bytes) + ' (' + data.spool.count + ')';
            const tbody = $('alNodeStatus');
            const nodes = data.nodes || [];
            tbody.innerHTML = nodes.length ? nodes.map(n =>
                `<tr>
                    <td>${esc(n.name)}</td>
                    <td>${esc(n.agentVersion || '—')}</td>
                    <td>${esc(n.status)}</td>
                    <td>${esc(fmtTime(n.lastBatchAt))}</td>
                    <td class="hint">${esc(n.lastError || '')}</td>
                </tr>`
            ).join('') : '<tr><td class="hint">—</td></tr>';
        } catch (e) {
            // status is non-critical; keep quiet
        }
    }

    function refreshAll() {
        loadSummary();
        loadSearch();
        loadStatus();
    }

    // Wire events (only when the feature is enabled).
    const form = $('alFilters');
    if (form) {
        form.addEventListener('submit', (e) => { e.preventDefault(); refreshAll(); });
    }
    const reset = $('alReset');
    if (reset) {
        reset.addEventListener('click', () => {
            form.reset();
            setDefaultRange();
            refreshAll();
        });
    }
    const purge = $('alPurge');
    if (purge) {
        purge.addEventListener('click', async () => {
            if (!window.confirm(I18N.purgeConfirm)) return;
            try {
                const res = await fetch('/panel/access-logs/api/purge', { method: 'POST', credentials: 'include' });
                if (!res.ok) throw new Error('HTTP ' + res.status);
                toast('OK', 'success');
                refreshAll();
            } catch (e) {
                toast('Purge error: ' + e.message, 'error');
            }
        });
    }

    // Default the time range to the last 24 h so the initial page load queries
    // only recent partitions instead of scanning the whole dataset.
    function setDefaultRange() {
        const from = $('alFrom');
        if (!from || from.value) return;
        const d = new Date(Date.now() - 24 * 60 * 60 * 1000);
        d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
        from.value = d.toISOString().slice(0, 16);
    }

    if (enabled) {
        setDefaultRange();
        refreshAll();
    } else {
        // Still show node/pipeline status so admins can see why nothing arrives.
        loadStatus();
    }
})();
