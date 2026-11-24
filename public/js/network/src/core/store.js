/**
 * Network map state: topology index, selection, filters and background refresh.
 *
 * Events:
 *   'data'      { structural: boolean } - topology changed (structural = nodes/links/roles changed)
 *   'select'    selection | null
 *   'filter'    filter state
 *   'loading'   boolean
 *   'error'     Error
 */

import model from './model.js';
import { fetchTopology as getTopology } from './api.js';

const POLL_INTERVAL_MS = 30000;
const MAX_OBSERVATION_MS = 90000;

export function createStore({ isVisible }) {
    const listeners = new Map();
    const state = {
        index: model.buildIndex({ nodes: [], edges: [] }),
        key: '',
        loaded: false,
        loading: false,
        selection: null,
        filter: { query: '', roles: new Set(), problemsOnly: false },
        lastFetch: 0,
    };

    let pollTimer = null;
    let observationTimer = null;
    let inflight = null;

    function on(evt, fn) {
        if (!listeners.has(evt)) listeners.set(evt, new Set());
        listeners.get(evt).add(fn);
        return () => listeners.get(evt).delete(fn);
    }

    function emit(evt, payload) {
        for (const fn of listeners.get(evt) || []) {
            try { fn(payload); } catch (err) { console.error('[network]', err); }
        }
    }

    // Reverse connectivity is a time-limited observation, not a permanent
    // assertion from the last GET. Invalidate locally even when a poll fails.
    function expireObservations(notify) {
        clearTimeout(observationTimer);
        const now = Date.now();
        let next = Infinity;
        let changed = false;
        for (const link of state.index.links.values()) {
            if (link.mode === 'forward' || link.status !== 'online') continue;
            const until = link.observationExpiresAt;
            if (Number.isSafeInteger(until) && now < until && until - now <= MAX_OBSERVATION_MS) {
                next = Math.min(next, until);
            } else {
                Object.assign(link, { status: 'deployed', latencyMs: null, tunnelState: 'unknown', lastHealthCheck: null });
                changed = true;
            }
        }
        if (Number.isFinite(next)) observationTimer = setTimeout(() => expireObservations(true), next - now);
        if (notify && changed) emit('data', { structural: false });
    }

    async function fetchTopology({ silent } = {}) {
        if (inflight) return inflight;
        if (!silent) { state.loading = true; emit('loading', true); }
        inflight = (async () => {
            try {
                const topo = await getTopology();
                const index = model.buildIndex(topo);
                const key = model.structureKey(index);
                const structural = !state.loaded || key !== state.key;
                state.index = index;
                expireObservations(false);
                state.key = key;
                state.loaded = true;
                state.lastFetch = Date.now();
                if (state.selection && !selectionExists(state.selection)) {
                    state.selection = null;
                    emit('select', null);
                }
                emit('data', { structural });
            } catch (err) {
                emit('error', err);
            } finally {
                inflight = null;
                if (!silent) { state.loading = false; emit('loading', false); }
            }
        })();
        return inflight;
    }

    function selectionExists(sel) {
        if (sel.kind === 'node') return !!model.nodeOf(state.index, sel.id);
        return !!model.edgeOf(state.index, sel.id);
    }

    function canPoll() {
        return !document.hidden && (!isVisible || isVisible());
    }

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(() => {
            if (canPoll()) fetchTopology({ silent: true });
        }, POLL_INTERVAL_MS);
        document.addEventListener('visibilitychange', onVisibility);
    }

    function stopPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
        document.removeEventListener('visibilitychange', onVisibility);
    }

    function onVisibility() {
        if (canPoll()) resume();
    }

    /** Called when the map tab becomes visible again. */
    function resume() {
        expireObservations(true);
        if (Date.now() - state.lastFetch > POLL_INTERVAL_MS) fetchTopology({ silent: true });
    }

    function select(sel) {
        const next = sel && sel.id ? { kind: sel.kind === 'link' ? 'link' : 'node', id: String(sel.id) } : null;
        const cur = state.selection;
        if (cur && next && cur.kind === next.kind && cur.id === next.id) return;
        if (!cur && !next) return;
        state.selection = next;
        emit('select', next);
    }

    function setFilter(patch) {
        Object.assign(state.filter, patch);
        emit('filter', state.filter);
    }

    function toggleRole(role) {
        const roles = state.filter.roles;
        if (roles.has(role)) roles.delete(role); else roles.add(role);
        emit('filter', state.filter);
    }

    /** True when the node passes the role filter and the search query. */
    function nodeVisible(node) {
        const f = state.filter;
        if (f.roles.size && f.roles.has(model.roleOf(node))) return false;
        return model.matchesQuery(node, f.query);
    }

    function destroy() {
        stopPolling();
        clearTimeout(observationTimer);
        listeners.clear();
    }

    return {
        state,
        model,
        on,
        emit,
        load: () => fetchTopology(),
        refresh: () => fetchTopology({ silent: true }),
        startPolling,
        stopPolling,
        resume,
        select,
        setFilter,
        toggleRole,
        nodeVisible,
        destroy,
        get index() { return state.index; },
    };
}
