import { fetchClientConnections, isObjectId } from '../core/api.js';
import { t } from '../core/i18n.js';
import { h, tip } from './dom.js';

const REFRESH_MS = 15_000;
const REQUEST_TIMEOUT_MS = 10_000;
const focusSelector = 'button, [tabindex]';

const fields = ['username', 'ip', 'country', 'region', 'city', 'asn', 'isp', 'lastSeen'];
const eligible = node => node && isObjectId(node.id) && node.type !== 'cdn' && node.type !== 'internet'
    && (node.cascadeRole === 'portal' || node.cascadeRole === 'standalone');
const text = value => typeof value === 'string' || Number.isFinite(value) ? String(value) : '—';

export function createClientConnections(root, { store, isVisible }) {
    const anchors = new WeakMap();
    let active = null;
    let restoringFocus = false;
    let pointerFocus = false;

    function dismiss(scope) {
        if (!active || (scope && (active.redrawing || !scope.contains(active.anchor)))) return false;
        const { request, anchor, focusTarget, panel, refresh } = active;
        active = null; // Invalidate before aborting, even if transport ignores the signal.
        clearInterval(refresh);
        if (request) {
            clearTimeout(request.timeout);
            request.ctrl.abort();
        }
        anchor.removeAttribute('aria-describedby');
        focusTarget?.removeAttribute('aria-describedby');
        panel.replaceChildren();
        panel.remove();
        return true;
    }

    function current(s) {
        return active === s && !document.hidden && isVisible() && root.contains(s.anchor) && s.anchor.getClientRects().length > 0
            && eligible(store.index.nodes.get(s.id));
    }

    function place(s) {
        const r = s.anchor.getBoundingClientRect();
        const w = s.panel.offsetWidth, height = s.panel.offsetHeight;
        const below = r.bottom + height <= window.innerHeight - 8 || r.top < height + 8;
        s.panel.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - w - 8))}px`;
        s.panel.style.top = `${Math.max(8, Math.min(below ? r.bottom : r.top - height, window.innerHeight - height - 8))}px`;
    }

    function status(s, state, rows = []) {
        // Replace the contents atomically, not the panel, and retain its scroll.
        const left = s.body.scrollLeft, top = s.body.scrollTop;
        if (state === 'ready' && rows.length) {
            const table = h('table', null,
                h('thead', null, h('tr', null, fields.map(key => h('th', { scope: 'col' }, t(`map.connections.${key}`))))),
                h('tbody', null, rows.map(row => h('tr', null, fields.map(key => h('td', null, text(row?.[key])))))));
            s.body.replaceChildren(table);
        } else {
            s.body.replaceChildren(h('p', { role: 'status' }, t(`map.connections.${state === 'ready' ? 'empty' : state}`)));
        }
        s.body.scrollLeft = left;
        s.body.scrollTop = top;
        place(s);
    }

    async function refresh(s) {
        if (!current(s)) { if (active === s) dismiss(); return; }
        if (s.request) return;
        const ctrl = new AbortController();
        const timeout = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
        s.request = { ctrl, timeout };
        try {
            const result = await fetchClientConnections(s.id, ctrl.signal);
            if (!current(s)) return;
            if (ctrl.signal.aborted) status(s, 'unavailable');
            else if (result.state === 'forbidden') dismiss();
            else {
                status(s, result.state, result.rows);
                if (result.state === 'ready') {
                    const users = new Set(result.rows.map(row => row?.username)
                        .filter(name => typeof name === 'string' && name.length));
                    store.setOnlineUsers(s.id, users.size);
                }
            }
        } catch {
            if (current(s)) status(s, 'unavailable');
        } finally {
            clearTimeout(timeout);
            s.request = null;
            if (active === s && !current(s)) dismiss();
        }
    }

    function show(anchor, id, source, focusTarget = null) {
        if (document.hidden || !isVisible() || !root.contains(anchor) || !anchor.getClientRects().length || !eligible(store.index.nodes.get(id))) return;
        if (active?.anchor === anchor) {
            active[source] = true;
            if (focusTarget) {
                active.focusTarget = focusTarget;
                focusTarget.setAttribute('aria-describedby', active.panel.id);
            }
            return;
        }
        dismiss();
        tip.hide();
        const body = h('div.nm-client-body');
        const link = h('a', {
            href: 'https://db-ip.com/', target: '_blank', rel: 'noopener noreferrer', tabindex: '-1',
        }, 'IP Geolocation by DB-IP');
        const panel = h('div.nm-client-popover', { id: 'networkClientConnections', role: 'region', 'aria-label': t('map.connections.title') },
            h('strong', null, t('map.connections.title')), body, h('footer', null, link));
        const s = { id, slot: anchors.get(anchor).slot, anchor, focusTarget, panel, body, link, [source]: true };
        active = s;
        panel.addEventListener('pointerenter', () => { s.pointerInPanel = true; });
        panel.addEventListener('pointerleave', e => {
            s.pointerInPanel = false;
            if (s.anchor.contains(e.relatedTarget)) s.hover = true;
            if (active === s && !s.hover && !s.focus && !panel.contains(document.activeElement)) dismiss();
        });
        panel.addEventListener('focusout', e => {
            if (active === s && !panel.contains(e.relatedTarget) && e.relatedTarget !== s.focusTarget && !s.hover && !s.pointerInPanel) dismiss();
        });
        panel.addEventListener('keydown', e => {
            if (e.key !== 'Tab' || !s.focusTarget?.isConnected) return;
            // Return to the count; on forward Tab let the browser continue from it.
            s.focusTarget.focus({ preventScroll: true });
            if (e.shiftKey) e.preventDefault();
            else dismiss();
        });
        document.body.append(panel);
        (focusTarget || anchor).setAttribute('aria-describedby', panel.id);
        status(s, 'loading');
        s.refresh = setInterval(() => refresh(s), REFRESH_MS);
        refresh(s);
    }

    function count(node, slot, spec, ...content) {
        const anchor = h(spec, null, ...content);
        if (!eligible(node)) return anchor;
        anchor.classList.add('nm-client-count');
        anchors.set(anchor, { id: node.id, slot });
        if (active?.redrawing && active.id === node.id && active.slot === slot) active.replacement = anchor;
        anchor.addEventListener('pointerenter', e => {
            if (e.pointerType !== 'touch') show(anchor, node.id, 'hover');
        });
        anchor.addEventListener('pointerleave', e => {
            const s = active;
            if (s?.anchor !== anchor || s.redrawing) return;
            s.hover = false;
            if (s.panel.contains(e.relatedTarget)) s.pointerInPanel = true;
            if (!s.focus && !s.pointerInPanel && !s.panel.contains(document.activeElement)) dismiss();
        });
        return anchor;
    }

    // Chains, Graph cards and the inspector can replace their DOM on a poll.
    // Follow only the same node and display slot; never reopen or refetch here.
    function preserve(render) {
        const s = active;
        if (!s) return render();
        const restore = document.activeElement === s.focusTarget;
        s.redrawing = true;
        try { render(); }
        finally {
            s.redrawing = false;
            if (active === s) {
                if (!root.contains(s.anchor) && s.replacement && root.contains(s.replacement)) {
                    s.anchor.removeAttribute('aria-describedby');
                    s.focusTarget?.removeAttribute('aria-describedby');
                    s.anchor = s.replacement;
                    s.focusTarget = s.focusTarget ? s.anchor.closest(focusSelector) : null;
                    (s.focusTarget || s.anchor).setAttribute('aria-describedby', s.panel.id);
                    if (restore) {
                        restoringFocus = true;
                        try { s.focusTarget?.focus({ preventScroll: true }); } finally { restoringFocus = false; }
                    }
                }
                s.replacement = null;
                if (current(s)) place(s);
                else dismiss();
            }
        }
    }

    function focusAnchor(target) {
        return anchors.has(target) ? target : target.querySelector?.('.nm-client-count');
    }
    root.addEventListener('pointerdown', () => {
        // A click on the card can focus its button without ever hovering
        // the count. Only the pointer's default focus action is suppressed.
        pointerFocus = true;
        setTimeout(() => { pointerFocus = false; }, 0);
    }, true);
    root.addEventListener('focusin', e => {
        if (restoringFocus || pointerFocus) return;
        const anchor = focusAnchor(e.target);
        if (anchors.has(anchor)) show(anchor, anchors.get(anchor).id, 'focus', e.target);
    });
    root.addEventListener('focusout', e => {
        const s = active;
        if (s?.focusTarget !== e.target || s.redrawing) return;
        s.focus = false;
        if (!s.panel.contains(e.relatedTarget) && !s.hover && !s.pointerInPanel) dismiss();
    });
    root.addEventListener('keydown', e => {
        if (e.key === 'Tab' && !e.shiftKey && active?.focusTarget === e.target) {
            e.preventDefault();
            active.link.focus({ preventScroll: true });
        }
    });
    // If a redraw moved the anchor out from under a stationary pointer,
    // the old anchor cannot deliver pointerleave on the next mouse movement.
    document.addEventListener('pointermove', e => {
        const s = active;
        if (!s?.hover || s.anchor.contains(e.target) || s.panel.contains(e.target)) return;
        s.hover = false;
        if (!s.focus && !s.pointerInPanel && !s.panel.contains(document.activeElement)) dismiss();
    });
    document.addEventListener('visibilitychange', () => { if (document.hidden) dismiss(); });
    window.addEventListener('blur', () => dismiss());
    window.addEventListener('resize', () => dismiss());
    document.addEventListener('scroll', e => {
        const s = active;
        if (!s || s.panel.contains(e.target)) return;
        // Native Tab can scroll a count into view after focusin. Reposition a
        // keyboard-opened panel rather than immediately closing it on that scroll.
        const r = s.anchor.getBoundingClientRect();
        const hit = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
        if ((s.focus || s.panel.contains(document.activeElement)) && s.anchor.contains(hit)) place(s);
        else dismiss();
    }, true);
    return {
        eligible,
        count,
        dismiss,
        preserve,
        escape() {
            const target = active?.panel.contains(document.activeElement) ? active.focusTarget : null;
            if (!dismiss()) return false;
            if (target?.isConnected) {
                restoringFocus = true;
                try { target.focus({ preventScroll: true }); } finally { restoringFocus = false; }
            }
            return true;
        },
        focusable(anchor) {
            if (anchors.has(anchor)) anchor.tabIndex = 0;
            return anchor;
        },
    };
}
