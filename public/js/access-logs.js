// Access-logs dashboard: filters, analytics overview (charts + user/top tables),
// on-demand event search, node status, purge.
//
// All DuckDB-backed data comes from a single /api/analytics call (the server
// runs the whole overview in one worker spawn). The raw-event search is a
// separate on-demand request. Requests are issued sequentially, never in
// parallel, because the panel intentionally allows only one heavy DuckDB query
// at a time (weak-hardware constraint) and parallel calls would be rejected.
(function () {
    'use strict';

    const app = document.getElementById('accessLogsApp');
    if (!app) return;
    const enabled = app.dataset.enabled === '1';
    const I18N = window.__AL_I18N || {};
    const L = (I18N.labels) || {};

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

    function fmtNum(n) {
        n = Number(n) || 0;
        return n.toLocaleString();
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

    // ─── Charts ────────────────────────────────────────────────────────────
    const Cc = {
        accepted: '#22c55e', rejected: '#f59e0b', blocked: '#ef4444',
        tcp: '#6366f1', udp: '#06b6d4', accent: '#7c3aed', grid: '#27272a', text: '#a1a1aa',
    };
    let timelineChart = null, actionChart = null, protoChart = null;

    function ensureChartDefaults() {
        if (!window.Chart) return false;
        Chart.defaults.color = Cc.text;
        Chart.defaults.borderColor = Cc.grid;
        Chart.defaults.font.family = "'Inter', sans-serif";
        Chart.defaults.plugins.legend.labels.boxWidth = 12;
        Chart.defaults.maintainAspectRatio = false;
        return true;
    }

    function renderTimeline(series) {
        if (!ensureChartDefaults()) return;
        const ctx = $('alTimeline'); if (!ctx) return;
        const labels = series.map(r => r.bucket);
        const ds = (key, color) => ({
            label: (L[key] || key), data: series.map(r => Number(r[key] || 0)),
            borderColor: color, backgroundColor: color + '33', fill: true, tension: 0.3,
            pointRadius: 0, borderWidth: 2,
        });
        const data = {
            labels,
            datasets: [ds('accepted', Cc.accepted), ds('rejected', Cc.rejected), ds('blocked', Cc.blocked)],
        };
        const options = {
            responsive: true,
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: { type: 'time', time: { tooltipFormat: 'PPpp' }, grid: { display: false } },
                y: { beginAtZero: true, stacked: true, ticks: { precision: 0 } },
            },
            plugins: { legend: { position: 'bottom' } },
            elements: { line: { fill: true } },
        };
        // Stacked areas read better for accepted/rejected/blocked composition.
        options.scales.y.stacked = true;
        data.datasets.forEach(d => { d.fill = true; });
        if (timelineChart) { timelineChart.data = data; timelineChart.options = options; timelineChart.update(); }
        else timelineChart = new Chart(ctx.getContext('2d'), { type: 'line', data, options });
    }

    function renderDonut(canvasId, ref, entries) {
        if (!ensureChartDefaults()) return null;
        const ctx = $(canvasId); if (!ctx) return ref;
        const data = {
            labels: entries.map(e => e.label),
            datasets: [{ data: entries.map(e => e.value), backgroundColor: entries.map(e => e.color), borderWidth: 0 }],
        };
        const options = { responsive: true, cutout: '62%', plugins: { legend: { position: 'bottom' } } };
        if (ref) { ref.data = data; ref.update(); return ref; }
        return new Chart(ctx.getContext('2d'), { type: 'doughnut', data, options });
    }

    // ─── Tables ────────────────────────────────────────────────────────────
    // Render a table body with an inline proportion bar on a numeric column.
    function renderBarRows(tbody, rows, cols) {
        if (!tbody) return;
        rows = rows || [];
        if (!rows.length) { tbody.innerHTML = '<tr><td class="hint" colspan="' + cols.length + '">—</td></tr>'; return; }
        const barCol = cols.find(c => c.bar);
        const max = barCol ? Math.max(1, ...rows.map(r => Number(r[barCol.key] || 0))) : 1;
        tbody.innerHTML = rows.map(r => {
            return '<tr>' + cols.map(c => {
                let v = r[c.key];
                if (c.fmt) v = c.fmt(v, r);
                const align = c.align ? ' style="text-align:' + c.align + ';"' : '';
                if (c.bar) {
                    const pct = Math.round((Number(r[c.key] || 0) / max) * 100);
                    return '<td class="al-bar-cell"' + align + '>'
                        + '<span class="al-bar" style="width:' + pct + '%;"></span>'
                        + '<span class="al-bar-label">' + esc(v) + '</span></td>';
                }
                return '<td' + align + '>' + (c.html ? v : esc(v)) + '</td>';
            }).join('') + '</tr>';
        }).join('');
    }

    function pct01(v) {
        const n = Number(v || 0);
        return Math.round(n * 100) + '%';
    }

    function renderUsers(users) {
        users = users || [];
        // Sharing lens: sorted by distinct IPs (server already sorts by ips).
        const byIp = users.slice().sort((a, b) => (b.ips - a.ips) || (b.events - a.events));
        renderBarRows($('alUsersByIp'), byIp, [
            { key: 'email', fmt: (v) => v || '—' },
            { key: 'ips', align: 'right', bar: true, fmt: fmtNum },
            { key: 'subnets', align: 'right', fmt: fmtNum },
            { key: 'events', align: 'right', fmt: fmtNum },
            { key: 'last_seen', align: 'right', fmt: (v) => fmtTime(v) },
        ]);
        // Fan-out lens: sorted by distinct destinations.
        const byFan = users.slice().sort((a, b) => (b.dests - a.dests) || (b.events - a.events));
        renderBarRows($('alUsersByFanout'), byFan, [
            { key: 'email', fmt: (v) => v || '—' },
            { key: 'dests', align: 'right', bar: true, fmt: fmtNum },
            { key: 'udp_share', align: 'right', fmt: pct01 },
            { key: 'events', align: 'right', fmt: fmtNum },
        ]);
    }

    function renderTops(data) {
        renderBarRows($('alTopDest'), data.topDestinations, [
            { key: 'dest', fmt: (v, r) => v || r.key || '—' },
            { key: 'hits', align: 'right', bar: true, fmt: fmtNum },
        ]);
        renderBarRows($('alTopPorts'), data.topPorts, [
            { key: 'port', fmt: (v) => (v == null ? '—' : v) },
            { key: 'hits', align: 'right', bar: true, fmt: fmtNum },
        ]);
        renderBarRows($('alTopBlocked'), data.topBlocked, [
            { key: 'dest', fmt: (v, r) => v || r.key || '—' },
            { key: 'hits', align: 'right', bar: true, fmt: fmtNum },
        ]);
    }

    // ─── Loaders ─────────────────────────────────────────────────────────────
    async function loadAnalytics() {
        try {
            const data = await getJson('/panel/access-logs/api/analytics?' + queryString());
            if (!data.enabled) return;
            const degraded = !!data.degraded;
            $('alDegraded').style.display = degraded ? '' : 'none';

            const totals = data.totals || {};
            $('alTotal').textContent = fmtNum(totals.total);
            $('alUsers').textContent = fmtNum(totals.users);
            $('alIps').textContent = totals.ips != null ? fmtNum(totals.ips) : '—';
            $('alDests').textContent = totals.dests != null ? fmtNum(totals.dests) : '—';
            const blocked = (totals.blocked != null ? totals.blocked : 0);
            $('alBlocked').textContent = fmtNum(blocked);

            renderTimeline(data.series || []);

            actionChart = renderDonut('alActionChart', actionChart, [
                { label: L.accepted || 'accepted', value: Number(totals.accepted || 0), color: Cc.accepted },
                { label: L.rejected || 'rejected', value: Number(totals.rejected || 0), color: Cc.rejected },
                { label: L.blocked || 'blocked', value: Number(totals.blocked || 0), color: Cc.blocked },
            ]);
            protoChart = renderDonut('alProtoChart', protoChart, [
                { label: L.tcp || 'tcp', value: Number(totals.tcp || 0), color: Cc.tcp },
                { label: L.udp || 'udp', value: Number(totals.udp || 0), color: Cc.udp },
            ]);

            renderUsers(data.users);
            renderTops(data);

            // In degraded mode the DuckDB-only widgets are empty; hint why.
            if (data.duckdbRequired) {
                const note = '<tr><td class="hint" colspan="6">' + esc(I18N.duckdbRequired) + '</td></tr>';
                if (!(data.users || []).length) { $('alUsersByIp').innerHTML = note; $('alUsersByFanout').innerHTML = note; }
                if (!(data.topPorts || []).length) $('alTopPorts').innerHTML = note;
                if (!(data.topBlocked || []).length) $('alTopBlocked').innerHTML = note;
            }
        } catch (e) {
            toast('Analytics error: ' + e.message, 'error');
        }
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
            ).join('') : '<tr><td class="hint" colspan="5">—</td></tr>';
        } catch (e) {
            // status is non-critical; keep quiet
        }
    }

    // Sequential refresh: analytics -> search -> status (never parallel, to
    // respect the single-concurrent-DuckDB-query limit).
    async function refreshAll() {
        await loadAnalytics();
        await loadSearch();
        await loadStatus();
    }

    // ─── Wiring ──────────────────────────────────────────────────────────────
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

    // Default the time range to the last 24 h so the initial load queries only
    // recent partitions instead of scanning the whole dataset.
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
        loadStatus();
    }
})();
