/**
 * Map toolbar: search, a slot for view-specific controls, network summary
 * and the problems popover.
 */

import model from '../core/model.js';
import { t, plural } from '../core/i18n.js';
import { h, icon, clear, debounce } from './dom.js';
import { nodeTitle } from './format.js';

export function attentionLabel({ problems, unverified }, hasData, noSearchMatch = false) {
    if (noSearchMatch) return t('map.nothingFound');
    if (problems || unverified) {
        return [problems && t('map.countLabel', { n: problems, label: plural(problems, 'map.problemsPlural') }),
            unverified && t('map.unverifiedCount', { n: unverified })].filter(Boolean).join(' · ');
    }
    return t(hasData ? 'map.allGood' : 'map.noStatusData');
}

export function createToolbar(el, { store, onGoto }) {
    const searchInput = h('input.nm-input', {
        type: 'search',
        placeholder: t('map.searchPlaceholder'),
        autocomplete: 'off',
        spellcheck: 'false',
        'aria-label': t('map.searchPlaceholder'),
        maxlength: '100',
    });
    const slot = h('div.nm-bar-slot');
    const stats = h('div.nm-stats');
    const filterBtn = h('button.nm-btn.sm.nm-attention-filter', { type: 'button',
        on: { click: () => store.setFilter({ problemsOnly: !store.state.filter.problemsOnly }) },
    }, icon('filter'), h('span.lbl', null, t('map.problemsOnly')));
    const probBtn = h('button.nm-btn.nm-attention', { type: 'button', 'aria-haspopup': 'true', 'aria-expanded': 'false' });
    const pop = h('div.nm-pop', { hidden: true, role: 'menu' });

    const applyQuery = debounce(() => store.setFilter({ query: searchInput.value.trim().slice(0, 100) }), 120);
    searchInput.addEventListener('input', applyQuery);
    searchInput.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
            searchInput.value = '';
            applyQuery.flush();
            searchInput.blur();
        } else if (e.key === 'Enter') {
            const q = searchInput.value.trim();
            const hit = q && Array.from(store.index.nodes.values()).find(n => model.matchesQuery(n, q));
            if (hit) {
                searchInput.blur();
                store.select({ kind: 'node', id: hit.id });
                if (onGoto) onGoto({ kind: 'node', id: hit.id });
            }
        }
    });

    probBtn.addEventListener('click', e => {
        e.stopPropagation();
        setPop(pop.hidden);
    });
    document.addEventListener('click', e => {
        if (!pop.hidden && !pop.contains(e.target)) setPop(false);
    });

    el.append(
        h('div.nm-search', null, icon('search'), searchInput, h('span.nm-kbd', null, '/')),
        slot,
        filterBtn,
        h('div.nm-spacer'),
        stats,
        probBtn,
        pop);

    function setPop(open) {
        pop.hidden = !open;
        probBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (open) renderPop();
    }

    function problemTitle(p) {
        const index = store.index;
        if (p.kind === 'node') return nodeTitle(model.nodeOf(index, p.id));
        const l = index.links.get(p.id) || index.unmappedLinks?.get(p.id);
        return l?.label || p.id;
    }

    function renderPop() {
        const list = model.attentionItems(store.index);
        clear(pop);
        pop.append(...list.slice(0, 100).map(p => h(`button.nm-prob.${p.sev}`, {
            type: 'button',
            role: 'menuitem',
            disabled: p.kind === 'link' && !store.index.links.has(p.id),
            on: {
                click: () => {
                    setPop(false);
                    store.select({ kind: p.kind, id: p.id });
                    if (onGoto) onGoto({ kind: p.kind, id: p.id });
                },
            },
        }, icon(p.sev === 'error' ? 'alert-octagon' : p.sev === 'warn' ? 'alert-triangle' : 'help'),
        h('div', null, h('div.t', null, problemTitle(p)), h('div.d', null, p.detail || t(`map.problem.${p.code}`))))));
    }

    function update() {
        const s = model.stats(store.index);
        clear(stats);
        stats.append(
            h('span', { title: t('map.kpi.nodesOnline') }, icon('server-2'), h('b', null, String(s.online)), `/${s.nodes}`),
            h('span', { title: t('map.kpi.clients') }, icon('users'), h('b', null, String(s.users))),
            h('span.opt', { title: t('map.kpi.chainsOk') }, icon('route'), h('b', null, String(s.chainsOk)), `/${s.chains}`),
            s.avgLatency != null ? h('span.opt', { title: t('map.kpi.avgLatency') }, icon('clock'), h('b', null, String(s.avgLatency)), ` ${t('map.msUnit')}`) : null);

        const { problemsOnly, query } = store.state.filter;
        filterBtn.classList.toggle('on', problemsOnly);
        filterBtn.setAttribute('aria-pressed', String(problemsOnly));
        // Counts are global; suppress a green badge when a search has no results.
        const actionable = s.problems > 0 || s.unverified > 0;
        const noSearchMatch = !actionable && !!query && (problemsOnly
            || !Array.from(store.index.nodes.values()).some(n => model.matchesQuery(n, query)));
        const hasData = s.nodes + s.links > 0;
        const level = s.problems ? 'problem' : s.unverified ? 'unverified' : hasData && !noSearchMatch ? 'ok' : 'empty';
        probBtn.dataset.attention = level;
        probBtn.classList.toggle('nm-problems', level === 'ok' || level === 'problem');
        probBtn.classList.toggle('ok', level === 'ok');
        probBtn.disabled = !actionable;
        const glyph = { ok: 'circle-check', problem: 'alert-triangle', unverified: 'help', empty: 'search' }[level];
        probBtn.replaceChildren(icon(glyph), ` ${attentionLabel(s, hasData, noSearchMatch)}`,
            ...(actionable ? [icon('chevron-down')] : []));
        if (!actionable) setPop(false);
        else if (!pop.hidden) renderPop();
    }

    store.on('filter', update);
    update();

    return {
        slot,
        update,
        focusSearch: () => { searchInput.focus(); searchInput.select(); },
        setStatsVisible: visible => { stats.style.display = visible ? '' : 'none'; },
        closePopover: () => setPop(false),
    };
}
