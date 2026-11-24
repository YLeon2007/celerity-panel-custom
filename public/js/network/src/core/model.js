/**
 * Pure topology model for the network map.
 *
 * Input is the GET /api/cascade/topology payload ({ nodes: [{data, position}], edges: [{data}] }).
 * Everything here is DOM-free and i18n-free so it can be unit-tested in Node;
 * views and UI translate the returned codes themselves.
 */
'use strict';

const INTERNET_ID = 'internet';
const MAX_OBSERVATION_MS = 90_000;

/** Upper bound for enumerated root-to-leaf paths; protects weak clients from path explosion. */
const MAX_CHAINS = 400;

/** Worst-first ordering used to pick the status that represents a group of links. */
const STATUS_SEVERITY = { error: 5, offline: 4, pending: 3, syncing: 2, deployed: 1, online: 0 };

const SHORT_NAME_NOISE = /^(exit|cloud|cdn|node|server|vps)$/i;

function roleOf(node) {
    if (!node) return 'standalone';
    if (node.type === 'cdn') return 'cdn';
    if (node.type === 'internet' || node.id === INTERNET_ID) return 'internet';
    return node.cascadeRole || 'standalone';
}

function isExitNode(node) {
    const role = roleOf(node);
    return role === 'bridge' || role === 'standalone';
}

function severity(status) {
    return STATUS_SEVERITY[status] ?? 3;
}

function worstStatus(statuses) {
    let worst = 'online';
    for (const s of statuses) {
        if (severity(s) > severity(worst)) worst = s;
    }
    return worst;
}

function isSynthetic(kind, data) {
    if (!data) return false;
    if (kind === 'link') return !!(data.isCdnEdge || data.isInternetEdge);
    const role = roleOf(data);
    return role === 'cdn' || role === 'internet';
}

/** Expiry of projected reverse evidence, or null if missing, expired or out of bounds. */
function observationExpiry(link, now = Date.now()) {
    const until = link.observationExpiresAt;
    return Number.isSafeInteger(until) && now < until && until - now <= MAX_OBSERVATION_MS ? until : null;
}

/** Map health, not deployment state. Synthetic mirrors contribute no attention. */
function attention(kind, data, now = Date.now()) {
    if (isSynthetic(kind, data)) return 'ok';
    const status = data?.status;
    if (status === 'error' || status === 'offline') return 'problem';
    if (status !== 'online' || data.missingEndpoint) return 'unverified';
    if (kind === 'link' && (data.tunnelTransport === 'kcp' || data.tunnelVerification === 'mkcp_runtime_unsupported'
        || data.tunnelVerification === 'mkcp_apply_unconfirmed'
        || (data.mode !== 'forward' && !observationExpiry(data, now)))) return 'unverified';
    return 'ok';
}

/** Neutral presentation for unverified data, retaining distinct deployment/failure labels. */
function attentionStatus(kind, data, now = Date.now()) {
    if (attention(kind, data, now) !== 'unverified') return data.status;
    const status = data?.status;
    if (status === 'online' && !data.missingEndpoint) return data.tunnelVerification === 'mkcp_apply_unconfirmed' ? 'pending' : 'deployed';
    return ['pending', 'deployed', 'syncing'].includes(status) ? status : 'unknown';
}

function measuredLatency(link, now) {
    return attention('link', link, now) === 'ok' && Number.isFinite(link.latencyMs) && link.latencyMs >= 0
        ? link.latencyMs : null;
}

/**
 * Build lookup tables. Cascade links, CDN edges and Internet edges are kept apart
 * because views treat them differently.
 */
function buildIndex(topology) {
    const nodes = new Map();
    const links = new Map();
    const unmappedLinks = new Map();
    const cdnEdges = new Map();
    const out = new Map();
    const inc = new Map();
    const cdnByOrigin = new Map();
    const originByCdn = new Map();
    let internet = null;

    for (const raw of (topology && topology.nodes) || []) {
        const data = raw && raw.data;
        if (!data || typeof data.id !== 'string') continue;
        if (data.id === INTERNET_ID) {
            internet = { ...data };
            continue;
        }
        nodes.set(data.id, { ...data, position: raw.position || null });
        out.set(data.id, []);
        inc.set(data.id, []);
    }

    for (const raw of (topology && topology.edges) || []) {
        const data = raw && raw.data;
        if (!data || typeof data.id !== 'string') continue;
        if (data.isInternetEdge) continue;
        if (!nodes.has(data.source) || !nodes.has(data.target)) {
            // An omitted endpoint makes the link undrawable, not healthy. Keep
            // its diagnostic in the global inventory without creating a fake node.
            if (!data.isCdnEdge) unmappedLinks.set(data.id, { ...data, missingEndpoint: true });
            continue;
        }
        if (data.isCdnEdge) {
            cdnEdges.set(data.id, { ...data });
            if (!cdnByOrigin.has(data.target)) cdnByOrigin.set(data.target, []);
            cdnByOrigin.get(data.target).push(data.source);
            originByCdn.set(data.source, data.target);
            continue;
        }
        const link = { ...data };
        links.set(link.id, link);
        out.get(link.source).push(link);
        inc.get(link.target).push(link);
    }

    for (const list of out.values()) list.sort(compareLinks);

    return {
        nodes, links, unmappedLinks, cdnEdges, out, in: inc, cdnByOrigin, originByCdn, internet,
        _chains: null, _chainsByNode: null, _chainsByLink: null,
    };
}

function compareLinks(a, b) {
    return String(a.label || '').localeCompare(String(b.label || '')) || (a.id < b.id ? -1 : 1);
}

function nodeOf(index, id) {
    return index.nodes.get(id) || (id === INTERNET_ID ? index.internet : null) || null;
}

function edgeOf(index, id) {
    return index.links.get(id) || index.cdnEdges.get(id) || null;
}

function outLinks(index, id) {
    return index.out.get(id) || [];
}

function inLinks(index, id) {
    return index.in.get(id) || [];
}

function cdnFor(index, originId) {
    return (index.cdnByOrigin.get(originId) || []).map(id => index.nodes.get(id)).filter(Boolean);
}

function isCascadeNode(index, id) {
    return outLinks(index, id).length > 0 || inLinks(index, id).length > 0;
}

/** Nodes that start a cascade: no incoming links, at least one outgoing. */
function roots(index) {
    const res = [];
    for (const node of index.nodes.values()) {
        if (node.type === 'cdn') continue;
        if (inLinks(index, node.id).length === 0 && outLinks(index, node.id).length > 0) res.push(node);
    }
    return res.sort(compareNodes);
}

/** Non-CDN nodes outside any cascade. */
function soloNodes(index) {
    const res = [];
    for (const node of index.nodes.values()) {
        if (node.type === 'cdn') continue;
        if (!isCascadeNode(index, node.id)) res.push(node);
    }
    return res.sort(compareNodes);
}

function compareNodes(a, b) {
    return String(a.label || '').localeCompare(String(b.label || '')) || (a.id < b.id ? -1 : 1);
}

/**
 * All root-to-leaf paths through cascade links: [{ nodes: [ids], links: [edgeIds] }].
 * Links that are only reachable through a cycle get their source treated as an extra root,
 * so every link appears in at least one chain.
 */
function chains(index) {
    if (index._chains) return index._chains;
    const res = [];
    const covered = new Set();

    function walk(nodeId, pathNodes, pathLinks) {
        if (res.length >= MAX_CHAINS) return;
        const next = outLinks(index, nodeId).filter(l => !pathNodes.includes(l.target));
        if (!next.length) {
            res.push({ nodes: pathNodes.slice(), links: pathLinks.slice() });
            pathLinks.forEach(id => covered.add(id));
            return;
        }
        for (const l of next) {
            walk(l.target, pathNodes.concat(l.target), pathLinks.concat(l.id));
        }
    }

    for (const r of roots(index)) walk(r.id, [r.id], []);
    for (const link of index.links.values()) {
        if (res.length >= MAX_CHAINS) break;
        if (!covered.has(link.id)) walk(link.source, [link.source], []);
    }

    index._chains = res;
    index._chainsByNode = new Map();
    index._chainsByLink = new Map();
    res.forEach((c, i) => {
        c.nodes.forEach(id => pushTo(index._chainsByNode, id, i));
        c.links.forEach(id => pushTo(index._chainsByLink, id, i));
    });
    return res;
}

function pushTo(map, key, value) {
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(value);
}

function chainsThrough(index, kind, id) {
    const all = chains(index);
    const map = kind === 'node' ? index._chainsByNode : index._chainsByLink;
    return (map.get(id) || []).map(i => all[i]);
}

/** Status and summed latency of a chain. */
function chainSummary(index, chain, now = Date.now()) {
    const links = chain.links.map(id => index.links.get(id));
    const statuses = [
        ...(chain.nodes || []).map(id => nodeOf(index, id)).filter(n => !isSynthetic('node', n))
            .map(n => attentionStatus('node', n, now)),
        ...links.map(l => attentionStatus('link', l, now)),
    ];
    const status = statuses.length ? worstStatus(statuses) : 'unknown';
    let latency = 0;
    let measured = links.length > 0;
    for (const l of links) {
        const ms = l ? measuredLatency(l, now) : null;
        if (ms != null) latency += ms;
        else measured = false;
    }
    return { status, latencyMs: measured ? latency : null };
}

/**
 * Nodes and links that share a chain with the given element (plus attached CDN fronts).
 * Used for hover/selection highlighting.
 */
function related(index, kind, id) {
    const nodes = new Set();
    const links = new Set();
    if (kind === 'node') {
        nodes.add(id);
        const origin = index.originByCdn.get(id);
        if (origin) return related(index, 'node', origin);
    } else {
        const edge = edgeOf(index, id);
        if (!edge) return { nodes, links };
        links.add(edge.id);
        nodes.add(edge.source);
        nodes.add(edge.target);
        if (edge.isCdnEdge) {
            const rel = related(index, 'node', edge.target);
            rel.nodes.forEach(n => nodes.add(n));
            rel.links.forEach(l => links.add(l));
            links.add(edge.id);
            nodes.add(edge.source);
            return { nodes, links };
        }
    }
    for (const c of chainsThrough(index, kind, id)) {
        c.nodes.forEach(n => nodes.add(n));
        c.links.forEach(l => links.add(l));
    }
    for (const nid of Array.from(nodes)) {
        for (const cdnId of index.cdnByOrigin.get(nid) || []) {
            nodes.add(cdnId);
            for (const e of index.cdnEdges.values()) {
                if (e.source === cdnId && e.target === nid) links.add(e.id);
            }
        }
    }
    return { nodes, links };
}

/** Visit real topology entities once, optionally scoped to a lane. */
function* healthEntries(index, scope, now = Date.now()) {
    const collections = [['node', index.nodes, scope?.nodes], ['link', index.links, scope?.links]];
    if (!scope && index.unmappedLinks) collections.push(['link', index.unmappedLinks]);
    for (const [kind, map, ids] of collections) {
        for (const id of ids || map.keys()) {
            const data = map.get(id);
            if (!data || isSynthetic(kind, data)) continue;
            yield { kind, data, level: attention(kind, data, now) };
        }
    }
}

function attentionSummary(index, scope) {
    const summary = { total: 0, problems: 0, unverified: 0, status: 'online' };
    const now = Date.now();
    for (const { kind, data, level } of healthEntries(index, scope, now)) {
        summary.total++;
        if (level === 'problem') summary.problems++;
        if (level === 'unverified') summary.unverified++;
        const status = attentionStatus(kind, data, now);
        if (severity(status) > severity(summary.status)) summary.status = status;
    }
    if (!summary.total) summary.status = 'unknown';
    return summary;
}

/** Popover rows: errors first, then confirmed offline, then unverified. */
function attentionItems(index) {
    const errors = [], offline = [], unverified = [];
    for (const { kind, data, level } of healthEntries(index)) {
        if (level === 'problem') {
            const error = data.status === 'error';
            (error ? errors : offline).push({ kind, id: data.id, sev: error ? 'error' : 'warn',
                code: `${kind}${error ? 'Error' : 'Offline'}`, detail: data.lastError || '' });
        } else if (level === 'unverified') {
            unverified.push({ kind, id: data.id, sev: 'unverified', code: `${kind}Unverified`, detail: '' });
        }
    }
    return errors.concat(offline, unverified);
}

function problems(index) {
    return attentionItems(index).filter(item => item.sev !== 'unverified');
}

/** Render all non-ok items and keep real endpoints of non-ok links as context. */
function attentionScope(index) {
    const nodes = new Set(), links = new Set();
    for (const { kind, data, level } of healthEntries(index)) {
        if (level === 'ok') continue;
        if (kind === 'node') nodes.add(data.id);
        else {
            links.add(data.id);
            nodes.add(data.source);
            nodes.add(data.target);
        }
    }
    return { nodes, links };
}

function stats(index) {
    let nodeCount = 0;
    let online = 0;
    let users = 0;
    let linkCount = 0;
    let linksOk = 0;
    let problems = 0;
    let unverified = 0;
    const lat = [];
    const now = Date.now();
    for (const { kind, data, level } of healthEntries(index, null, now)) {
        if (level === 'problem') problems++;
        if (level === 'unverified') unverified++;
        if (kind === 'node') {
            nodeCount++;
            if (level === 'ok') online++;
            users += Number(data.onlineUsers) || 0;
        } else {
            linkCount++;
            if (level === 'ok') linksOk++;
            const ms = measuredLatency(data, now);
            if (ms != null) lat.push(ms);
        }
    }
    const allChains = chains(index);
    const chainsOk = allChains.filter(c => chainSummary(index, c, now).status === 'online').length;
    return {
        nodes: nodeCount,
        online,
        users,
        links: linkCount,
        linksOk,
        chains: allChains.length,
        chainsOk,
        avgLatency: lat.length ? Math.round(lat.reduce((a, b) => a + b, 0) / lat.length) : null,
        problems,
        unverified,
    };
}

/** Compact label for tight spots: drops provider noise words and keeps the last word. */
function shortName(node) {
    const label = String((node && (node.label || node.ip)) || '').trim();
    const words = label.split(/\s+/).filter(w => w && !SHORT_NAME_NOISE.test(w));
    const res = words.length ? words[words.length - 1] : label;
    return res.length > 18 ? `${res.slice(0, 17)}…` : res;
}

/**
 * ISO 3166-1 alpha-2 code from a flag emoji (pair of regional indicators),
 * falling back to a two-letter `country` field. Returns null when unknown.
 */
function countryFromFlag(flag, country) {
    const cps = Array.from(String(flag || '')).map(ch => ch.codePointAt(0));
    const ri = cps.filter(cp => cp >= 0x1F1E6 && cp <= 0x1F1FF);
    if (ri.length >= 2) {
        return String.fromCharCode(ri[0] - 0x1F1E6 + 65, ri[1] - 0x1F1E6 + 65);
    }
    const c = String(country || '').trim();
    if (/^[A-Za-z]{2}$/.test(c)) return c.toUpperCase();
    return null;
}

/** Search match against name, IP, domain and country. */
function matchesQuery(node, query) {
    if (!query) return true;
    const q = String(query).toLowerCase();
    return [node.label, node.ip, node.domain, node.country]
        .some(v => typeof v === 'string' && v.toLowerCase().includes(q));
}

/**
 * Fingerprint of everything that affects layout (ids, endpoints, roles, labels).
 * Status/latency changes keep the same key, so views can patch instead of rebuild.
 */
function structureKey(index) {
    const parts = [];
    for (const n of index.nodes.values()) {
        parts.push(`n|${n.id}|${n.label}|${n.flag}|${n.type}|${n.cascadeRole}|${n.country}|${n.ip}`);
    }
    for (const l of index.links.values()) {
        parts.push(`l|${l.id}|${l.source}|${l.target}|${l.mode}|${l.label}`);
    }
    for (const e of index.cdnEdges.values()) parts.push(`c|${e.id}`);
    parts.sort();
    return parts.join('\n');
}

module.exports = {
    INTERNET_ID,
    MAX_CHAINS,
    roleOf,
    isExitNode,
    severity,
    worstStatus,
    attention,
    attentionStatus,
    attentionSummary,
    attentionItems,
    attentionScope,
    observationExpiry,
    buildIndex,
    nodeOf,
    edgeOf,
    outLinks,
    inLinks,
    cdnFor,
    isCascadeNode,
    roots,
    soloNodes,
    chains,
    chainsThrough,
    chainSummary,
    related,
    problems,
    stats,
    shortName,
    countryFromFlag,
    matchesQuery,
    structureKey,
};
