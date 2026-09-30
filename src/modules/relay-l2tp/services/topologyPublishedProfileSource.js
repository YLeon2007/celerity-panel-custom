'use strict';

// Deliberately un-wired: caller must supply pinned, current portal metadata and
// a private consumer (e.g. TopologyClientProfileProbe.probe). Profiles cross only
// that callback boundary; public return values never contain credentials.
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_RESPONSE_BYTES = 262144;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fail = () => ({ ok: false });

function validPortal(node) {
    return node && typeof node === 'object' && !Array.isArray(node)
        && typeof node._id === 'string' && node._id.length > 0
        && node.active === true && node.type === 'xray' && node.cascadeRole === 'portal'
        && typeof node.name === 'string' && node.name.length > 0
        && typeof (node.domain || node.ip) === 'string' && !!(node.domain || node.ip)
        && Number.isInteger(node.port) && node.port > 0 && node.port <= 65535
        && node.xray?.transport === 'tcp' && node.xray?.security === 'reality'
        && typeof node.xray.realityPublicKey === 'string' && !!node.xray.realityPublicKey
        && typeof node.xray.realitySni?.[0] === 'string' && !!node.xray.realitySni[0]
        && Array.isArray(node.xray.realityShortIds) && node.xray.realityShortIds.length > 0;
}

function matchingProfile(profile, node, uuid) {
    if (!profile || typeof profile !== 'object' || Array.isArray(profile)
        || profile.remarks !== `${node.flag || ''} ${node.name}`.trim()
        || !Array.isArray(profile.outbounds) || profile.routing?.balancers?.length) return false;
    const proxies = profile.outbounds.filter(o => o?.protocol === 'vless');
    if (proxies.length !== 1 || proxies[0].tag !== 'proxy'
        || profile.outbounds.some(o => o !== proxies[0] && !['freedom', 'blackhole'].includes(o?.protocol))) return false;
    const proxy = proxies[0];
    const servers = proxy.settings?.vnext;
    if (!Array.isArray(servers) || servers.length !== 1 || !Array.isArray(servers[0].users)
        || servers[0].users.length !== 1) return false;
    const s = servers[0];
    const expectedShortId = node.xray.realityShortIds.find(id => typeof id === 'string' && id.length) || node.xray.realityShortIds[0] || '';
    return s.address === (node.domain || node.ip) && s.port === node.port
        && s.users[0].id === uuid && s.users[0].encryption === 'none'
        && proxy.streamSettings?.network === 'tcp' && proxy.streamSettings.security === 'reality'
        && proxy.streamSettings.realitySettings?.publicKey === node.xray.realityPublicKey
        && proxy.streamSettings.realitySettings.serverName === node.xray.realitySni[0]
        && proxy.streamSettings.realitySettings.shortId === expectedShortId;
}

class TopologyPublishedProfileSource {
    constructor({ HyUser = require('../../../models/hyUserModel'), probeUserId = process.env.TOPOLOGY_PROBE_USER_ID,
        fetchImpl = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
        this.HyUser = HyUser;
        this.probeUserId = probeUserId;
        this.fetchImpl = fetchImpl;
        this.timeoutMs = timeoutMs;
    }

    /**
     * consumeProfile(nodeId, exactPublishedProfile) runs only after *all* portal
     * matches have been validated. It must not log or persist the profile, and
     * should call the synthetic Xray probe; even success is NOT phone/Happ proof.
     * Only its `ok === true` bit is retained. No raw DB/network errors escape.
     */
    async load({ portalNodes, consumeProfile } = {}) {
        if (typeof this.probeUserId !== 'string' || !this.probeUserId.trim()
            || !Array.isArray(portalNodes) || portalNodes.length === 0
            || typeof consumeProfile !== 'function' || typeof this.fetchImpl !== 'function'
            || !Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 30000) return fail();
        const ids = new Set();
        for (const node of portalNodes) {
            if (!validPortal(node) || ids.has(node._id)) return fail();
            ids.add(node._id);
        }
        try {
            const user = await this.HyUser.findOne({ userId: this.probeUserId, enabled: true })
                .select('enabled expireAt trafficLimit traffic.tx traffic.rx subscriptionToken xrayUuid').lean();
            if (!user?.enabled || (user.expireAt && new Date(user.expireAt).getTime() <= Date.now())
                || (user.trafficLimit > 0 && (user.traffic?.tx || 0) + (user.traffic?.rx || 0) >= user.trafficLimit)
                || typeof user.subscriptionToken !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(user.subscriptionToken)
                || typeof user.xrayUuid !== 'string' || !UUID_PATTERN.test(user.xrayUuid)) return fail();
            const controller = new AbortController();
            let timer;
            let response;
            try {
                // Hard deadline also covers injected fetch/text implementations which ignore signal.
                const timeout = new Promise((_, reject) => {
                    timer = setTimeout(() => { controller.abort(); reject(Error('timeout')); }, this.timeoutMs);
                });
                const request = async () => {
                    const url = `http://127.0.0.1:3000/api/files/${user.subscriptionToken}?format=xray-json`;
                    const res = await this.fetchImpl(url, { method: 'GET', headers: { 'User-Agent': 'Happ/1.0 (Android)', Accept: 'application/json' }, signal: controller.signal, redirect: 'error' });
                    if (!res?.ok || res.status !== 200 || !/^application\/json\b/i.test(res.headers?.get('content-type') || '')
                        || Number(res.headers?.get('content-length')) > MAX_RESPONSE_BYTES) return null;
                    return res.text();
                };
                response = await Promise.race([request(), timeout]);
            } finally {
                clearTimeout(timer);
                controller.abort();
            }
            if (typeof response !== 'string' || Buffer.byteLength(response) > MAX_RESPONSE_BYTES) return fail();
            const profiles = JSON.parse(response);
            if (!Array.isArray(profiles) || profiles.length === 0 || profiles.length > 256) return fail();
            const matches = [];
            const used = new Set();
            for (const node of portalNodes) {
                const remark = `${node.flag || ''} ${node.name}`.trim();
                // A second advertised entry with the same name, even with an
                // obsolete UUID/key/endpoint, makes selection ambiguous.
                const named = profiles.map((p, i) => p?.remarks === remark ? i : -1).filter(i => i >= 0);
                if (named.length !== 1 || !matchingProfile(profiles[named[0]], node, user.xrayUuid)
                    || used.has(named[0])) return fail();
                used.add(named[0]);
                matches.push([node._id, profiles[named[0]]]);
            }
            for (const [nodeId, profile] of matches) {
                if ((await consumeProfile(nodeId, profile))?.ok !== true) return fail();
            }
            return { ok: true, verifiedCount: matches.length };
        } catch {
            return fail();
        }
    }
}

function createTopologyPublishedProfileSource(options) {
    return new TopologyPublishedProfileSource(options);
}

module.exports = { TopologyPublishedProfileSource, createTopologyPublishedProfileSource };
