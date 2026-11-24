/**
 * Details and available actions for the selection (bottom sheet on mobile).
 */

import model from '../core/model.js';
import { isObjectId, linkIdOf } from '../core/api.js';
import { t } from '../core/i18n.js';
import { h, icon, clear, toast } from './dom.js';
import {
    roleName, roleDesc, statusName, nodeTitle, ms, typeName, ago,
    roleTag, statusPill, dot, modeIcon,
} from './format.js';

export function createInspector(el, { store, actions, onGoto }) {
    let mode = null;
    let createSession = null;
    let awaitingLink = null;

    function close() {
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

    function inspectBtn(cls, iconName, label, onClick) {
        return h(`button.nm-btn${cls}`, { type: 'button', on: { click: onClick } }, icon(iconName), label);
    }

    // ==================== PATH ====================

    function hops(chain, curLinkId) {
        const index = store.index;
        const items = [h('span.nm-hop.ext', null, icon('users'), t('map.client')), h('span.nm-hop-arrow', null, icon('arrow-narrow-right'))];
        chain.nodes.forEach((nid, i) => {
            const n = model.nodeOf(index, nid);
            if (i > 0) {
                const l = index.links.get(chain.links[i - 1]);
                items.push(h(`span.nm-hop-arrow${l && l.status === 'error' ? '.error' : ''}`, null,
                    icon('arrow-narrow-right'),
                    l && l.status === 'online' && typeof l.latencyMs === 'number' ? h('span.ms', null, ms(l.latencyMs))
                        : l && l.status === 'error' ? icon('alert-triangle') : null));
            }
            const cur = curLinkId && (chain.links[i - 1] === curLinkId || chain.links[i] === curLinkId);
            items.push(h(`button.nm-hop${cur ? '.cur' : ''}`, { type: 'button', on: { click: () => goto({ kind: 'node', id: nid }) } }, nodeTitle(n)));
        });
        items.push(h('span.nm-hop-arrow', null, icon('arrow-narrow-right')), h('span.nm-hop.ext', null, `🌐 ${t('map.internet')}`));
        return h('div.nm-path', null, items);
    }

    // ==================== NODE ====================

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
                    }, dot(x.status), h('span.lbl', null, nodeTitle(x)), roleTag(model.roleOf(x))))))),
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

        let alert = null;
        if (n.status === 'error') {
            alert = h('div.nm-alert.error', null, icon('alert-octagon'), h('div.msg', null,
                h('b', null, t('map.alert.nodeError')),
                n.lastError ? [h('br'), n.lastError] : null,
                n.lastSync ? h('span.meta', null, t('map.lastSync', { when: ago(n.lastSync) })) : null));
        } else if (n.status === 'offline') {
            alert = h('div.nm-alert.muted', null, icon('plug-connected-x'), h('div.msg', null,
                h('b', null, t('map.alert.nodeOffline')),
                n.lastSync ? h('span.meta', null, t('map.lastSync', { when: ago(n.lastSync) })) : null,
                n.lastError ? h('span.meta', null, n.lastError) : null));
        } else if (n.status === 'syncing') {
            alert = h('div.nm-alert.warn', null, icon('loader-2', 'nm-spin'), h('div.msg', null, t('map.alert.nodeSyncing')));
        }

        const kpis = h('div.nm-kpis', null,
            kpi('users', t('map.kpi.online'), String(n.onlineUsers || 0)),
            kpi('link', t('map.kpi.links'), String(outs.length + ins.length), t('map.kpi.inOut', { in: ins.length, out: outs.length })),
            kpi('cpu', t('map.kpi.type'), typeName(n.type), n.port ? `:${n.port}` : ''),
            kpi('clock', t('map.kpi.sync'), n.lastSync ? ago(n.lastSync) : '—'));

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
            head(n.flag || icon('server-2'), role, n.label || n.ip || '', [statusPill(n.status), roleTag(role), copyChip(n.ip)]),
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
        return [
            head(icon('cloud'), 'cdn', n.label || n.domain || 'CDN', [statusPill(n.status), roleTag('cdn'), copyChip(n.domain)]),
            h('div.nm-insp-body', null,
                h('div.nm-alert.muted', null, icon('info-circle'), h('div.msg', null, t('map.cdnNodeDesc'))),
                h('div.nm-props', null,
                    prop('world-www', t('map.prop.domain'), h('span.mono', null, n.domain || '—')),
                    origin ? prop('door-enter', t('map.prop.origin'),
                        h('button.nm-hop', { type: 'button', on: { click: () => goto({ kind: 'node', id: origin.id }) } }, nodeTitle(origin))) : null)),
        ];
    }

    // ==================== LINK ====================
    function linkActions(link) {
        if (!actions || link.isInternetEdge || !linkIdOf(link.id)) return null;
        const id = link.id;
        return h('div.nm-insp-foot.nm-link-actions', null,
            h('div.row', null,
                inspectBtn('.primary', 'cloud-upload', t('map.linkActions.deploy'), () => actions.deploy(id)),
                inspectBtn('', 'route', t('map.linkActions.deployChain'), () => actions.deployChain(id))),
            h('div.row', null,
                inspectBtn('', 'stethoscope', t('map.linkActions.checkHealth'), () => actions.checkHealth(id)),
                inspectBtn('.danger', 'trash', t('map.linkActions.remove'), () => actions.remove(id))),
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

        let alert = null;
        if (l.status === 'error') {
            alert = h('div.nm-alert.error', null, icon('alert-octagon'), h('div.msg', null,
                h('b', null, t('map.alert.linkError')),
                l.lastError ? [h('br'), l.lastError] : null,
                l.lastHealthCheck ? h('span.meta', null, t('map.lastCheck', { when: ago(l.lastHealthCheck) })) : null,
                tn ? h('div.actions', null, inspectBtn('.sm', 'server-2', t('map.openName', { name: model.shortName(tn) }), () => goto({ kind: 'node', id: tn.id }))) : null));
        } else if (l.status === 'pending') {
            alert = h('div.nm-alert.muted', null, icon('cloud-upload'), h('div.msg', null,
                h('b', null, t('map.alert.linkPending')), h('br'),
                l.tunnelVerification === 'mkcp_apply_unconfirmed' ? t('mkcpApplyUnconfirmed') : t('map.alert.linkPendingDesc')));
        } else if (l.status === 'offline') {
            alert = h('div.nm-alert.warn', null, icon('plug-connected-x'), h('div.msg', null,
                h('b', null, t('map.alert.linkOffline')),
                l.lastError ? [h('br'), l.lastError] : null,
                l.lastHealthCheck ? h('span.meta', null, t('map.lastCheck', { when: ago(l.lastHealthCheck) })) : null));
        } else if (l.status === 'syncing') {
            alert = h('div.nm-alert.warn', null, icon('loader-2', 'nm-spin'), h('div.msg', null, t('map.alert.linkSyncing')));
        } else if (l.status === 'deployed' && l.tunnelVerification === 'mkcp_runtime_unsupported') {
            alert = h('div.nm-alert.muted', null, icon('info-circle'), h('div.msg', null,
                h('b', null, t('mkcpAppliedUnverified')), h('br'), t('mkcpRuntimeUnsupported')));
        }

        const sub = [
            statusPill(l.status),
            l.status === 'online' && typeof l.latencyMs === 'number' ? h('span.mono', null, ms(l.latencyMs)) : null,
            l.publishedExit ? h('span.nm-role.cdn', null, t('map.inSubscription', { id: l.routeId })) : null,
        ];

        return [
            head(icon(modeIcon(l.mode)), 'edge', l.label || `${sName} → ${tName}`, sub),
            h('div.nm-insp-body', null,
                alert,
                h('div', null, h('div.nm-sec-title', null, t('routePath')), hops(chain, l.id)),
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
                    l.lastHealthCheck ? prop('stethoscope', t('map.prop.checked'), ago(l.lastHealthCheck)) : null)),
            linkActions(l),
        ];
    }

    // ==================== RENDER ====================

    function openCreate(renderCreateForm) {
        if (!actions || createSession) return;
        awaitingLink = null;
        const sel = store.state.selection;
        const node = sel?.kind === 'node' ? store.index.nodes.get(sel.id) : null;
        const source = node && isObjectId(node.id) && model.roleOf(node) !== 'cdn' ? node.id : undefined;
        const session = {};
        createSession = session;
        clear(el);
        el.classList.add('open');

        function leave() {
            if (createSession !== session) return false;
            createSession = null;
            session.dispose?.();
            close();
            return true;
        }

        try {
            // Only the form owns and displays an unconfirmed save; no host callback resets it.
            session.dispose = renderCreateForm(el, {
                store, actions, source,
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
        } catch (err) {
            if (leave()) render();
            throw err;
        }
    }

    function render() {
        // Keep the actual form (including its in-flight or unknown outcome)
        // alive on topology refreshes and map selection changes.
        if (createSession) return;
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
        clear(el);
        content.forEach(part => part && el.appendChild(part));
        mode = `${sel.kind}:${sel.id}`;
        el.classList.add('open');
        const body = el.querySelector('.nm-insp-body');
        if (body && sameTarget) body.scrollTop = scroll;
    }

    return { render, openCreate };
}
