/**
 * Shared label/format helpers (translated).
 */

import model from '../core/model.js';
import { t, plural } from '../core/i18n.js';
import { h, icon } from './dom.js';

export const ROLE_ORDER = ['portal', 'relay', 'bridge', 'standalone', 'cdn'];

export const ROLE_ICON = {
    portal: 'door-enter',
    relay: 'arrows-right',
    bridge: 'door-exit',
    standalone: 'server-2',
    cdn: 'cloud',
    internet: 'world',
};

export function roleName(role) {
    return t(`map.role.${role}`);
}

export function roleDesc(role) {
    return t(`map.roleDesc.${role}`);
}

export function statusName(status) {
    if (status === 'unverified') return t('map.details.unverifiedShort');
    return t(`map.status.${status || 'pending'}`);
}

export function nodeTitle(node) {
    if (!node) return '';
    if (node.id === model.INTERNET_ID) return t('map.internet');
    return `${node.flag ? `${node.flag} ` : ''}${node.label || node.ip || ''}`;
}

export function ms(value) {
    return typeof value === 'number' ? t('map.ms', { n: value }) : '—';
}

export function typeName(type) {
    if (type === 'xray') return 'Xray';
    if (type === 'hysteria') return 'Hysteria 2';
    if (type === 'cdn') return 'CDN';
    return type || '—';
}

export function count(n, key) {
    return `${n} ${plural(n, key)}`;
}

let rtf = null;
/** "5 minutes ago" in the page language; '' for missing/invalid dates. */
export function ago(value, now = Date.now()) {
    if (!value || (typeof value !== 'string' && typeof value !== 'number')) return '';
    const time = new Date(value).getTime();
    if (!Number.isFinite(time)) return '';
    if (!rtf) {
        try { rtf = new Intl.RelativeTimeFormat(document.documentElement.lang || 'en', { numeric: 'auto' }); } catch (_) { rtf = null; }
    }
    const diff = Math.round((time - now) / 1000);
    const abs = Math.abs(diff);
    const [val, unit] = abs < 60 ? [diff, 'second']
        : abs < 3600 ? [Math.round(diff / 60), 'minute']
        : abs < 86400 ? [Math.round(diff / 3600), 'hour']
        : [Math.round(diff / 86400), 'day'];
    return rtf ? rtf.format(val, unit) : new Date(time).toLocaleString();
}

export function roleTag(role) {
    return h(`span.nm-role.${role}`, null, roleName(role));
}

export function statusPill(status, label = statusName(status)) {
    return h(`span.nm-st.${status || 'pending'}`, null, label);
}

export function dot(status) {
    return h(`span.nm-dot.${status || 'pending'}`);
}

export function modeIcon(mode) {
    return mode === 'forward' ? 'arrow-right' : 'arrows-exchange';
}

export function linkDisplayStatus(link, now) {
    return model.attentionStatus('link', link, now);
}

export function hasUnappliedChanges(link) {
    return link.hasUnappliedChanges === true && !link.isCdnEdge && !link.isInternetEdge;
}

export function linkPillLabel(link, status) {
    if (link.isCdnEdge) return t('map.cdnEntry');
    const name = `${link.label || ''}: ${statusName(status)}`;
    return hasUnappliedChanges(link) ? `${name} · ${t('map.edit.unapplied')}` : name;
}

function linkLatency(link, status) {
    return status === 'online' && Number.isFinite(link.latencyMs) && link.latencyMs >= 0 ? link.latencyMs : null;
}

function mkcpReason(link, status, reason) {
    // Only the corresponding projected state warrants the specific Apply explanation.
    return link.status === status && link.tunnelTransport === 'kcp' && link.tunnelVerification === reason;
}

/** Only display an explicit string diagnostic, never a raw response or object. */
export function lastErrorText(value) {
    if (typeof value !== 'string') return '';
    const limit = 240;
    const message = value.slice(0, limit + 1).replace(/\s+/g, ' ').trim();
    if (!message) return '';
    return t('map.details.lastError', { message: value.length > limit ? `${message.slice(0, limit)}…` : message });
}

export function linkStatusDetail(link, now = Date.now()) {
    const status = linkDisplayStatus(link, now);
    const expiry = link.observationExpiresAt;
    const until = status === 'online' && link.mode !== 'forward' ? model.observationExpiry(link, now) : null;
    let title = statusName(status);
    let description = '';
    let expires = '';
    if (mkcpReason(link, 'deployed', 'mkcp_runtime_unsupported')) {
        title = t('mkcpAppliedUnverified');
        description = t('mkcpRuntimeUnsupported');
    } else if (status === 'pending') {
        description = mkcpReason(link, 'pending', 'mkcp_apply_unconfirmed') ? t('mkcpApplyUnconfirmed') : t('map.alert.linkPendingDesc');
    } else if (status === 'deployed' || status === 'unknown') {
        // The retained timestamp can explain a reverse expiry; it does not set severity.
        const expired = !hasUnappliedChanges(link) && !link.missingEndpoint && link.mode !== 'forward'
            && link.tunnelTransport !== 'kcp' && !link.tunnelVerification
            && Number.isSafeInteger(expiry) && expiry <= now;
        description = t(expired ? 'map.details.linkObservationStaleDesc' : 'map.details.linkUnverifiedDesc');
    } else if (until !== null) {
        title = t('map.details.linkObserved');
        description = t('map.details.linkObservedDesc');
        expires = t('map.details.observationExpires', { when: ago(until, now) });
    }
    const checked = ago(link.lastHealthCheck, now);
    return { status, title, description, checked: checked ? t('map.lastCheck', { when: checked }) : '', expires,
        error: status !== 'online' && status !== 'syncing' ? lastErrorText(link.lastError) : '',
        latencyMs: linkLatency(link, status) };
}

/**
 * Inline link label used on connectors (chains + graph).
 */
export function pillContent(link, now) {
    if (link.isCdnEdge) return [icon('cloud'), ' CDN'];
    const m = modeIcon(link.mode);
    const status = linkDisplayStatus(link, now);
    let health;
    switch (status) {
        case 'error': health = [icon('alert-triangle'), ` ${t('map.pill.error')}`]; break;
        case 'syncing': health = [icon('loader-2', 'nm-spin'), ` ${t('map.pill.syncing')}`]; break;
        case 'offline': health = [icon(m), ` ${t('map.pill.offline')}`]; break;
        case 'online': health = [icon(m), h('span.ms', null, ms(linkLatency(link, status)))]; break;
        default: health = [icon(m), ` ${t('map.details.unverifiedShort')}`];
    }
    if (hasUnappliedChanges(link)) health.push(h('span.nm-pill-unapplied', {
        title: t('map.edit.unapplied'), 'aria-hidden': 'true',
    }, icon('pencil')));
    return health;
}

export function linkTip(index, link) {
    if (link.isCdnEdge) {
        const origin = model.nodeOf(index, link.target);
        return [h('div.t', null, icon('cloud'), t('map.cdnEntry')), h('div.m', null, t('map.cdnEntryDesc', { name: origin ? origin.label : '' }))];
    }
    const sec = link.tunnelSecurity && link.tunnelSecurity !== 'none' ? ` / ${link.tunnelSecurity.toUpperCase()}` : '';
    const detail = linkStatusDetail(link);
    return [
        h('div.t', null, dot(detail.status), link.label || ''),
        h('div.m', null,
            `${link.mode === 'forward' ? 'Forward' : 'Reverse'} · ${String(link.tunnelProtocol || '').toUpperCase()} / ${String(link.tunnelTransport || '').toUpperCase()}${sec} · ${t('map.port')} ${link.tunnelPort || '—'}`,
            h('br'),
            h('b', null, detail.title),
            detail.latencyMs !== null ? [' · ', t('map.latencyValue', { n: detail.latencyMs })] : null,
            hasUnappliedChanges(link) ? h('div.nm-tip-unapplied', null, t('map.edit.unapplied')) : null,
            detail.description ? h('div', null, detail.description) : null,
            detail.checked ? h('div', null, detail.checked) : null,
            detail.expires ? h('div', null, detail.expires) : null,
            detail.error ? h(detail.status === 'error' ? 'div.err' : 'div', null, detail.error) : null),
    ];
}

export function nodeStatusDetail(node) {
    const display = model.attentionStatus('node', node);
    const status = ['online', 'offline', 'error', 'syncing'].includes(display) ? display : 'unknown';
    const when = ago(node.lastSync);
    return { status, description: status === 'unknown' ? t('map.details.nodeUnknownDesc') : '',
        synced: when ? t('map.lastSync', { when }) : '' };
}

export function nodeTip(node) {
    const role = model.roleOf(node);
    const detail = nodeStatusDetail(node);
    return [
        h('div.t', null, nodeTitle(node)),
        h('div.m', null,
            `${roleName(role)} · ${statusName(detail.status)}${detail.status === 'online' && node.onlineUsers ? ` · ${t('map.onlineN', { n: node.onlineUsers })}` : ''}`,
            detail.description ? h('div', null, detail.description) : null,
            detail.description && detail.synced ? h('div', null, detail.synced) : null,
            node.ip ? [h('br'), h('span.mono', null, node.ip)] : null),
    ];
}
