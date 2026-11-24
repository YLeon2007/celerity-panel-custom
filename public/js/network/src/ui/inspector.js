/**
 * Details and available actions for the selection (bottom sheet on mobile).
 */

import model from '../core/model.js';
import { isObjectId, linkIdOf } from '../core/api.js';
import { t } from '../core/i18n.js';
import { h, icon, clear, toast } from './dom.js';
import {
    roleName, roleDesc, statusName, nodeTitle, ms, typeName, ago,
    roleTag, statusPill, dot, modeIcon, linkStatusDetail, nodeStatusDetail, lastErrorText,
    hasUnappliedChanges,
} from './format.js';

export function createInspector(el, { store, actions, onGoto, loadForm, isVisible = () => true, clientConnections }) {
    let mode = null;
    let formSession = null;
    let editLoad = null;
    let createLoad = null;
    let disposed = false;
    let awaitingLink = null;

    function close() {
        clientConnections?.dismiss(el);
        mode = null;
        el.classList.remove('open');
        clear(el);
    }

    function closeButton() {
        return h('button.nm-btn.ghost.icon.sm', {
            type: 'button',
            title: t('map.closeEsc'),
            'aria-label': t('map.close'),
            on: { click: () => store.select(null) },
        }, icon('x'));
    }

    function goto(sel) {
        store.select(sel);
        if (onGoto) onGoto(sel);
    }

    function head(avatar, avatarCls, title, sub) {
        return h('div.nm-insp-head', null,
            h(`div.nm-avatar${avatarCls ? `.${avatarCls}` : ''}`, null, avatar),
            h('div.nm-insp-title', null, h('h3', { title }, title), h('div.sub', null, sub)),
            closeButton());
    }

    function copyChip(value) {
        if (!value) return null;
        if (!navigator.clipboard) return h('span.mono', null, value);
        return h('button.nm-copy', {
            type: 'button',
            title: t('map.copy'),
            on: {
                click: async () => {
                    try { await navigator.clipboard.writeText(value); } catch (_) { return; }
                    toast(t('map.toast.copied', { value }), 'success');
                },
            },
        }, value, icon('copy'));
    }

    function prop(iconName, label, value, hint) {
        return h('div.nm-prop', null,
            h('div.k', null, icon(iconName), label),
            h('div.v', null, value, hint ? h('span.hint', null, hint) : null));
    }

    function kpi(iconName, label, value, small) {
        return h('div.nm-kpi', null,
            h('div.k', null, icon(iconName), label),
            h('div.v', null, value, small ? [' ', h('small', null, small)] : null));
    }

    function inspectBtn(cls, iconName, label, onClick, busy = false) {
        return h(`button.nm-btn${cls}`, {
            type: 'button', disabled: busy, 'aria-busy': busy ? 'true' : null, on: { click: onClick },
        }, icon(iconName), label);
    }

    // ==================== PATH ====================

    function hops(chain, curLinkId, now) {
        const index = store.index;
        const items = [h('span.nm-hop.ext', null, icon('users'), t('map.client')), h('span.nm-hop-arrow', null, icon('arrow-narrow-right'))];
        chain.nodes.forEach((nid, i) => {
            const n = model.nodeOf(index, nid);
            if (i > 0) {
                const l = index.links.get(chain.links[i - 1]);
                const detail = l && linkStatusDetail(l, now);
                const status = detail?.status;
                items.push(h(`span.nm-hop-arrow${status === 'error' ? '.error' : ''}`, null,
                    icon('arrow-narrow-right'),
                    detail?.latencyMs != null ? h('span.ms', null, ms(detail.latencyMs))
                        : status === 'error' ? icon('alert-triangle') : null));
            }
            const cur = curLinkId && (chain.links[i - 1] === curLinkId || chain.links[i] === curLinkId);
            items.push(h(`button.nm-hop${cur ? '.cur' : ''}`, { type: 'button', on: { click: () => goto({ kind: 'node', id: nid }) } }, nodeTitle(n)));
        });
        items.push(h('span.nm-hop-arrow', null, icon('arrow-narrow-right')), h('span.nm-hop.ext', null, `🌐 ${t('map.internet')}`));
        return h('div.nm-path', null, items);
    }

    // ==================== NODE ====================

    function unknownNodeAlert(detail) {
        return h('div.nm-alert.muted', null, icon('info-circle'), h('div.msg', null,
            detail.description, detail.synced ? h('span.meta', null, detail.synced) : null));
    }

    function internetView() {
        const index = store.index;
        const exits = Array.from(index.nodes.values()).filter(n => n.type !== 'cdn' && model.isExitNode(n));
        return [
            head('🌐', null, t('map.internet'), t('map.internetSub')),
            h('div.nm-insp-body', null,
                h('div', null,
                    h('div.nm-sec-title', null, t('map.exitPoints', { n: exits.length })),
                    h('div.nm-chain-list', null, exits.map(x => h('button.nm-chain-row', {
                        type: 'button', on: { click: () => goto({ kind: 'node', id: x.id }) },
                    }, dot(model.attentionStatus('node', x)), h('span.lbl', null, nodeTitle(x)), roleTag(model.roleOf(x))))))),
        ];
    }

    function nodeView(id) {
        const index = store.index;
        if (id === model.INTERNET_ID) return internetView();
        const n = model.nodeOf(index, id);
        if (!n) return null;
        const role = model.roleOf(n);
        if (role === 'cdn') return cdnNodeView(n);

        const outs = model.outLinks(index, id);
        const ins = model.inLinks(index, id);
        const chainList = model.chainsThrough(index, 'node', id);
        const cdns = model.cdnFor(index, id);

        const detail = nodeStatusDetail(n);
        const diagnostic = lastErrorText(n.lastError);
        let alert = null;
        if (detail.status === 'error') {
            alert = h('div.nm-alert.error', null, icon('alert-octagon'), h('div.msg', null,
                h('b', null, t('map.alert.nodeError')),
                diagnostic ? [h('br'), diagnostic] : null,
                detail.synced ? h('span.meta', null, detail.synced) : null));
        } else if (detail.status === 'offline') {
            alert = h('div.nm-alert.muted', null, icon('plug-connected-x'), h('div.msg', null,
                h('b', null, t('map.alert.nodeOffline')),
                detail.synced ? h('span.meta', null, detail.synced) : null,
                diagnostic ? h('span.meta', null, diagnostic) : null));
        } else if (detail.status === 'syncing') {
            alert = h('div.nm-alert.warn', null, icon('loader-2', 'nm-spin'), h('div.msg', null, t('map.alert.nodeSyncing')));
        } else if (detail.status === 'unknown') {
            alert = unknownNodeAlert(detail);
        }

        const online = detail.status === 'unknown' ? '—' : String(n.onlineUsers || 0);
        const kpis = h('div.nm-kpis', null,
            kpi('users', t('map.kpi.online'), clientConnections?.focusable(clientConnections.count(n, 'inspector', 'span', online)) ?? online),
            kpi('link', t('map.kpi.links'), String(outs.length + ins.length), t('map.kpi.inOut', { in: ins.length, out: outs.length })),
            kpi('cpu', t('map.kpi.type'), typeName(n.type), n.port ? `:${n.port}` : ''),
            kpi('clock', t('map.kpi.sync'), ago(n.lastSync) || '—'));

        const chainsBlock = chainList.length
            ? h('div', null,
                h('div.nm-sec-title', null, t('map.chainsThrough', { n: chainList.length })),
                h('div.nm-chain-list', null, chainList.slice(0, 30).map(c => {
                    const sum = model.chainSummary(index, c);
                    const target = c.links.find(lid => {
                        const l = index.links.get(lid);
                        return l && (l.source === id || l.target === id);
                    }) || c.links[0];
                    return h('button.nm-chain-row', { type: 'button', on: { click: () => goto({ kind: 'link', id: target }) } },
                        dot(sum.status),
                        h('span.lbl', null, `${c.nodes.map(x => {
                            const xn = model.nodeOf(index, x);
                            return `${xn && xn.flag ? `${xn.flag} ` : ''}${model.shortName(xn)}`;
                        }).join(' → ')} → 🌐`),
                        h('span.ms', null, sum.status === 'online' ? ms(sum.latencyMs) : statusName(sum.status)));
                })))
            : h('div.nm-alert.muted', null, icon('route-off'), h('div.msg', null, t('map.notInCascade')));

        return [
            head(n.flag || icon('server-2'), role, n.label || n.ip || '', [statusPill(detail.status), roleTag(role), copyChip(n.ip)]),
            h('div.nm-insp-body', null,
                alert,
                kpis,
                chainsBlock,
                h('div.nm-props', null,
                    prop('info-circle', t('map.prop.role'), roleName(role), roleDesc(role)),
                    n.domain ? prop('world-www', t('map.prop.domain'), h('span.mono', null, n.domain)) : null,
                    n.country ? prop('flag', t('map.prop.country'), n.country) : null,
                    cdns.length ? prop('cloud', 'CDN', cdns.map(c => c.domain || c.label).join(', ')) : null)),
        ];
    }

    function cdnNodeView(n) {
        const index = store.index;
        const originId = index.originByCdn.get(n.id);
        const origin = originId ? model.nodeOf(index, originId) : null;
        const detail = nodeStatusDetail(n);
        return [
            head(icon('cloud'), 'cdn', n.label || n.domain || 'CDN', [statusPill(detail.status), roleTag('cdn'), copyChip(n.domain)]),
            h('div.nm-insp-body', null,
                detail.description ? unknownNodeAlert(detail) : null,
                h('div.nm-alert.muted', null, icon('info-circle'), h('div.msg', null, t('map.cdnNodeDesc'))),
                h('div.nm-props', null,
                    prop('world-www', t('map.prop.domain'), h('span.mono', null, n.domain || '—')),
                    origin ? prop('door-enter', t('map.prop.origin'),
                        h('button.nm-hop', { type: 'button', on: { click: () => goto({ kind: 'node', id: origin.id }) } }, nodeTitle(origin))) : null)),
        ];
    }

    // ==================== LINK ====================
    function canEdit(link) {
        return typeof actions?.loadEdit === 'function' && typeof loadForm === 'function'
            && link?.canEdit === true && !link.isCdnEdge && !link.isInternetEdge && !!linkIdOf(link.id);
    }

    function selectedEditableLink(id) {
        const sel = store.state.selection;
        if (sel?.kind !== 'link' || sel.id !== id) return null;
        const link = store.index.links.get(id);
        return canEdit(link) ? link : null;
    }

    function editStillSelected(load) {
        const link = selectedEditableLink(load.id);
        return isVisible() && link && link.source === load.source && link.target === load.target
            && hasUnappliedChanges(link) === load.unapplied;
    }

    async function openEdit(id) {
        if (disposed || formSession || editLoad || !isVisible() || actions.isBusy?.()) return;
        const link = selectedEditableLink(id);
        if (!link) return;
        createLoad = null; // A newer editor intent supersedes a pending Add Link import.
        const load = { id, source: link.source, target: link.target, unapplied: hasUnappliedChanges(link) };
        editLoad = load;
        const current = () => editLoad === load && editStillSelected(load);
        try {
            render();
            const projection = await actions.loadEdit(id);
            if (!current()) return;
            if (!projection) { toast(t('map.edit.loadFailed'), 'error'); return; }
            const renderForm = await loadForm();
            if (!current() || actions.isBusy?.()) return;
            openForm(renderForm, { edit: projection });
        } catch (_) {
            if (current()) toast(t('map.edit.loadFailed'), 'error');
        } finally {
            if (editLoad === load) {
                editLoad = null;
                render();
            }
        }
    }

    function linkActions(link) {
        if (!actions || link.isInternetEdge || !linkIdOf(link.id)) return null;
        const id = link.id;
        const unapplied = hasUnappliedChanges(link);
        const run = name => () => {
            cancelEditLoad();
            return actions[name](id);
        };
        return h('div.nm-insp-foot.nm-link-actions', null,
            h('div.row', null,
                inspectBtn(unapplied ? '.primary.nm-apply-btn' : '.primary', 'cloud-upload',
                    t(unapplied ? 'map.edit.apply' : 'map.linkActions.deploy'), run('deploy')),
                inspectBtn('', 'route', t('map.linkActions.deployChain'), run('deployChain'))),
            h('div.row', null,
                inspectBtn('', 'stethoscope', t('map.linkActions.checkHealth'), run('checkHealth')),
                inspectBtn('.danger', 'trash', t('map.linkActions.remove'), run('remove'))),
            canEdit(link) && store.index.links.has(id) ? h('div.row', null,
                inspectBtn('.block.nm-edit-btn', 'pencil', t('map.edit.open'), () => openEdit(id), editLoad?.id === id)) : null,
            h('small', null, t('map.linkActions.reconnectHint')));
    }


    function cdnEdgeView(e) {
        const index = store.index;
        const cdn = model.nodeOf(index, e.source);
        const origin = model.nodeOf(index, e.target);
        return [
            head(icon('cloud'), 'cdn', t('map.cdnEntry'), `${cdn ? cdn.domain || cdn.label : ''} → ${origin ? origin.label : ''}`),
            h('div.nm-insp-body', null,
                h('div.nm-alert.muted', null, icon('info-circle'), h('div.msg', null, t('map.cdnEdgeDesc')))),
            h('div.nm-insp-foot', null, cdn ? inspectBtn('.block', 'cloud', t('map.openCdnNode'), () => goto({ kind: 'node', id: cdn.id })) : null),
        ];
    }

    function linkView(id) {
        const index = store.index;
        const l = model.edgeOf(index, id);
        if (!l) return null;
        if (l.isCdnEdge) return cdnEdgeView(l);

        const s = model.nodeOf(index, l.source);
        const tn = model.nodeOf(index, l.target);
        const chain = model.chainsThrough(index, 'link', l.id)[0] || { nodes: [l.source, l.target], links: [l.id] };
        const sec = l.tunnelSecurity || 'none';
        const isFwd = l.mode === 'forward';
        const sName = s ? s.label : '';
        const tName = tn ? tn.label : '';

        const now = Date.now();
        const detail = linkStatusDetail(l, now);
        const [style, glyph, title] = {
            error: ['error', 'alert-octagon', 'map.alert.linkError'],
            offline: ['warn', 'plug-connected-x', 'map.alert.linkOffline'],
            syncing: ['warn', 'loader-2', 'map.alert.linkSyncing'],
            pending: ['muted', 'cloud-upload', 'map.alert.linkPending'],
        }[detail.status] || ['muted', 'info-circle'];
        const alert = detail.status !== 'online' || detail.description
            ? h(`div.nm-alert.${style}`, null, icon(glyph, detail.status === 'syncing' ? 'nm-spin' : ''), h('div.msg', null,
                h('b', null, title ? t(title) : detail.title),
                detail.description ? h('div', null, detail.description) : null,
                detail.checked ? h('span.meta', null, detail.checked) : null,
                detail.expires ? h('span.meta', null, detail.expires) : null,
                detail.error ? h('div', null, detail.error) : null,
                detail.status === 'error' && tn
                    ? h('div.actions', null, inspectBtn('.sm', 'server-2', t('map.openName', { name: model.shortName(tn) }), () => goto({ kind: 'node', id: tn.id }))) : null))
            : null;

        const sub = [
            statusPill(detail.status, detail.title),
            detail.latencyMs !== null ? h('span.mono', null, ms(detail.latencyMs)) : null,
            l.publishedExit ? h('span.nm-role.cdn', null, t('map.inSubscription', { id: l.routeId })) : null,
        ];

        return [
            head(icon(modeIcon(l.mode)), 'edge', l.label || `${sName} → ${tName}`, sub),
            h('div.nm-insp-body', null,
                hasUnappliedChanges(l) ? h('div.nm-alert.warn.nm-insp-unapplied', null,
                    icon('pencil'), h('div.msg', null, t('map.edit.unapplied'))) : null,
                alert,
                h('div', null, h('div.nm-sec-title', null, t('routePath')), hops(chain, l.id, now)),
                h('div.nm-props', null,
                    prop('route', t('map.prop.mode'), isFwd ? 'Forward' : 'Reverse',
                        isFwd ? t('map.modeForwardDesc', { a: sName, b: tName }) : t('map.modeReverseDesc', { a: sName, b: tName })),
                    prop('shield-lock', t('map.prop.tunnel'), h('div.nm-tags', null,
                        h('span.nm-tag', null, String(l.tunnelProtocol || '').toUpperCase()),
                        h('span.nm-tag', null, String(l.tunnelTransport || '').toUpperCase()),
                        h(`span.nm-tag${sec !== 'none' ? '.good' : ''}`, null, sec === 'none' ? t('map.secNone') : sec.toUpperCase()),
                        l.muxEnabled ? h('span.nm-tag', null, 'MUX') : null)),
                    prop('plug', t('map.port'), h('span.mono', null, String(l.tunnelPort || '—')),
                        t('map.listensOn', { name: isFwd ? tName : sName })),
                    typeof l.publishedExit === 'boolean' ? prop('list-details', t('map.prop.subscription'),
                        l.publishedExit ? t('map.subPublished', { id: l.routeId })
                            : isFwd ? t('map.subForward') : t('map.subNotPublished')) : null,
                    !alert && detail.checked ? prop('stethoscope', t('map.prop.checked'), ago(l.lastHealthCheck, now)) : null)),
            linkActions(l),
        ];
    }

    // ==================== RENDER ====================

    async function openCreate() {
        if (!actions || disposed || formSession || createLoad || !isVisible()) return;
        cancelEditLoad();
        const load = {};
        createLoad = load;
        try {
            const renderForm = await loadForm();
            if (createLoad !== load || !isVisible()) return;
            const sel = store.state.selection;
            const node = sel?.kind === 'node' ? store.index.nodes.get(sel.id) : null;
            const source = node && isObjectId(node.id) && model.roleOf(node) !== 'cdn' ? node.id : undefined;
            openForm(renderForm, { source });
        } catch (err) {
            if (createLoad === load && isVisible()) throw err;
        } finally {
            if (createLoad === load) createLoad = null;
        }
    }

    function cancelEditLoad() {
        if (!editLoad) return;
        editLoad = null;
        render();
    }

    function hide() {
        createLoad = null;
        cancelEditLoad();
    }

    function dispose() {
        disposed = true;
        hide();
        awaitingLink = null;
        const session = formSession;
        formSession = null;
        try { session?.dispose?.(); } finally { close(); }
    }

    function openForm(renderForm, options) {
        clientConnections?.dismiss();
        awaitingLink = null;
        const session = {};
        formSession = session;
        clear(el);
        el.classList.add('open');

        function leave() {
            if (formSession !== session) return false;
            formSession = null;
            try { session.dispose?.(); } finally { close(); }
            return true;
        }

        try {
            // Only the form owns and displays an unconfirmed save; no host callback resets it.
            const disposeForm = renderForm(el, {
                store, actions, ...options,
                onCancel() { if (leave()) render(); },
                onCreated(linkId) {
                    if (!leave()) return;
                    const id = isObjectId(linkId) ? `link-${linkId}` : linkIdOf(linkId) ? linkId : null;
                    if (id && store.index.links.has(id)) {
                        goto({ kind: 'link', id });
                    } else {
                        store.select(null);
                        // Wait for a later read of that exact saved edge; never submit again.
                        awaitingLink = id;
                    }
                    if (!mode) render(); // Selection may already have been on this edge.
                },
            });
            if (formSession === session) session.dispose = disposeForm;
            else disposeForm?.(); // A synchronous completion may already have left this mount.
        } catch (err) {
            if (leave()) render();
            throw err;
        }
    }

    function render() {
        if (disposed) return;
        // Keep the actual form (including its in-flight or unknown outcome)
        // alive on topology refreshes and map selection changes.
        if (formSession) return;
        if (editLoad && !editStillSelected(editLoad)) editLoad = null;
        const sel = store.state.selection;
        if (awaitingLink) {
            if (sel) awaitingLink = null;
            else if (store.index.links.has(awaitingLink)) {
                const id = awaitingLink;
                awaitingLink = null;
                goto({ kind: 'link', id });
                return;
            }
        }
        if (!sel) { if (mode) close(); return; }
        const content = sel.kind === 'node' ? nodeView(sel.id) : linkView(sel.id);
        if (!content) { store.select(null); return; }
        const prevBody = el.querySelector('.nm-insp-body');
        const scroll = prevBody ? prevBody.scrollTop : 0;
        const sameTarget = mode === `${sel.kind}:${sel.id}`;
        clientConnections?.dismiss(el);
        clear(el);
        content.forEach(part => part && el.appendChild(part));
        mode = `${sel.kind}:${sel.id}`;
        el.classList.add('open');
        const body = el.querySelector('.nm-insp-body');
        if (body && sameTarget) body.scrollTop = scroll;
    }

    return { render, openCreate, cancelEditLoad, hide, dispose };
}
