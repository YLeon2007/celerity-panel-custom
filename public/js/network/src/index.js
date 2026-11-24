/**
 * Rebuild network map entry point (loaded as an ES module the first time the
 * "Network map" tab is opened on the nodes page).
 *
 * Views share one store and one inspector and implement:
 *   mount(el, ctx) -> { update(change), focus(sel), resize(), destroy() }
 * Chains is bundled into the entry; Graph and Geo are lazy chunks.
 */

import { createStore } from './core/store.js';
import { createActions } from './core/actions.js';
import { t } from './core/i18n.js';
import { h, icon, clear, toast } from './ui/dom.js';
import { createToolbar } from './ui/toolbar.js';
import { createInspector } from './ui/inspector.js';
import { createClientConnections } from './ui/client-connections.js';
import * as chainsView from './views/chains.js';

const VIEWS = {
    chains: () => Promise.resolve(chainsView),
    graph: () => import('./views/graph.js'),
    geo: () => import('./views/geo.js'),
};

let formModule;
function loadForm() {
    return formModule ??= import('./ui/create-form.js').then(mod => mod.renderCreateForm, err => {
        formModule = null;
        throw err;
    });
}

function boot() {
    const viewRoot = document.getElementById('viewNetwork');
    const root = document.getElementById('networkRoot');
    if (!root || root.dataset.ready) return;
    root.dataset.ready = '1';

    const isVisible = () => viewRoot && viewRoot.style.display !== 'none';
    const store = createStore({ isVisible });
    const actions = root.dataset.linkActions === 'true' ? createActions(store) : null;
    const clientConnections = root.dataset.clientConnections === 'true'
        ? createClientConnections(root, { store, isVisible }) : null;

    const barEl = root.querySelector('.nm-bar');
    const stageEl = root.querySelector('.nm-stage');
    const inspEl = root.querySelector('.nm-insp');
    const stateEl = root.querySelector('.nm-state');

    let view = null;
    let viewName = null;
    let switchToken = 0;

    const focusInView = sel => { if (view && view.focus) view.focus(sel); };

    const toolbar = createToolbar(barEl, { store, onGoto: focusInView });
    const inspector = createInspector(inspEl, { store, actions, onGoto: focusInView, loadForm, isVisible, clientConnections });
    viewRoot?.addEventListener('network:hide', inspector.hide);
    viewRoot?.addEventListener('network:hide', () => clientConnections?.dismiss());
    window.addEventListener?.('pagehide', e => {
        clientConnections?.dismiss();
        if (e.persisted) inspector.hide();
        else inspector.dispose();
    });

    // ==================== STATE OVERLAY ====================

    function showState(kind) {
        clear(stateEl);
        if (!kind) { stateEl.hidden = true; return; }
        stateEl.hidden = false;
        if (kind === 'loading') {
            stateEl.append(icon('loader-2', 'nm-spin'), h('p', null, t('loadingTopology')));
        } else if (kind === 'error') {
            stateEl.append(icon('cloud-off'), h('p', null, t('networkError')),
                h('button.nm-btn', { type: 'button', on: { click: () => store.load() } }, icon('refresh'), t('refresh')));
        } else if (kind === 'empty') {
            stateEl.append(icon('topology-star-3'), h('p', null, t('noNodesOrLinks')));
        }
    }

    // ==================== VIEWS ====================

    function setHeaderActive(name) {
        document.querySelectorAll('#networkToolbar [data-nm-view]').forEach(btn => {
            const on = btn.dataset.nmView === name;
            btn.classList.toggle('active', on);
            btn.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
    }

    async function switchView(name) {
        if (!Object.prototype.hasOwnProperty.call(VIEWS, name)) name = 'chains';
        // A click on the mounted view also cancels a pending lazy view.
        const token = ++switchToken;
        setHeaderActive(name);
        if (name === viewName && view) return;
        clientConnections?.dismiss();
        inspector.cancelEditLoad();

        let mod;
        try {
            mod = await VIEWS[name]();
        } catch (err) {
            if (token !== switchToken) return;
            console.warn('[network] view load failed:', err.message);
            toast(t('networkError'), 'error');
            if (name !== 'chains') switchView('chains');
            return;
        }
        if (token !== switchToken) return;

        clientConnections?.dismiss(); // Also invalidate anything opened while the chunk was loading.
        if (view) {
            try { view.destroy(); } catch (err) { console.error('[network]', err); }
        }
        clear(stageEl);
        clear(toolbar.slot);
        view = null;
        viewName = name;
        toolbar.setStatsVisible(name !== 'chains');

        const el = h('div');
        stageEl.appendChild(el);
        view = mod.mount(el, { store, toolbar, canSavePositions: root.dataset.savePositions === 'true', clientConnections });
        if (store.state.loaded) view.update({ type: 'data', structural: true });
        const sel = store.state.selection;
        if (sel) focusInView(sel);
    }

    // ==================== STORE EVENTS ====================

    store.on('loading', loading => {
        if (loading && !store.state.loaded) showState('loading');
    });
    store.on('error', err => {
        if (!store.state.loaded) showState('error');
        else console.warn('[network] refresh failed:', err.message);
    });
    store.on('data', change => {
        showState(store.index.nodes.size ? null : 'empty');
        toolbar.update();
        if (view) view.update({ type: 'data', structural: change.structural });
        inspector.render();
        clientConnections?.reconcile();
    });
    store.on('select', () => {
        clientConnections?.dismiss();
        if (view) view.update({ type: 'select' });
        inspector.render();
    });
    store.on('filter', () => {
        clientConnections?.dismiss();
        if (view) view.update({ type: 'filter' });
    });

    // ==================== GLOBAL CONTROLS ====================

    document.querySelectorAll('#networkToolbar [data-nm-view]').forEach(btn => {
        btn.addEventListener('click', () => switchView(btn.dataset.nmView));
    });
    const refreshBtn = document.getElementById('btnNetworkRefresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', async () => {
            refreshBtn.disabled = true;
            await store.refresh();
            refreshBtn.disabled = false;
        });
    }
    const addBtn = document.getElementById('networkToolbar')?.querySelector('#btnAddLink');
    if (actions && addBtn) {
        // Wait for the first inventory before capturing the editor's endpoints.
        const stopWaitingForInventory = store.on('data', () => {
            addBtn.disabled = false;
            stopWaitingForInventory();
        });
        addBtn.addEventListener('click', async () => {
            if (addBtn.disabled || !isVisible()) return;
            addBtn.disabled = true;
            try {
                await inspector.openCreate();
            } catch (err) {
                console.warn('[network] create editor failed to open:', err.message);
                toast(t('networkError'), 'error');
            } finally {
                addBtn.disabled = false;
            }
        });
    }

    document.addEventListener('keydown', e => {
        if (!isVisible()) return;
        const typing = e.target.closest && e.target.closest('input, select, textarea, [contenteditable="true"]');
        if (e.key === 'Escape') {
            if (clientConnections?.escape()) return;
            toolbar.closePopover();
            if (typing) return;
            store.select(null);
            return;
        }
        if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
        if (e.key === '/') {
            e.preventDefault();
            toolbar.focusSearch();
        }
    });

    window._networkResize = () => {
        if (view && view.resize) view.resize();
        store.resume();
    };

    switchView('chains');
    store.load();
    store.startPolling();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();
