'use strict';
const { setTimeout: sleep } = require('node:timers/promises');
const { performance } = require('node:perf_hooks');

// Application-RPC propagation only: neither TCP/SSH handshake nor packet delay.
function makeLink(rttMs, delay = sleep) {
    if (rttMs !== 0 && rttMs !== 150) throw new TypeError('expected RTT 0 or 150');
    const calls = new Map();
    return {
        async call(kind, effect) {
            calls.set(kind, (calls.get(kind) || 0) + 1);
            if (rttMs) await delay(rttMs / 2);
            try { return await effect(); }
            finally { if (rttMs) await delay(rttMs / 2); }
        },
        counts() { return Object.fromEntries(calls); },
        async calibrate(samples = 5) {
            const result = [];
            for (let i = 0; i < samples; i++) {
                const start = performance.now();
                await this.call('echo', () => undefined);
                result.push(performance.now() - start);
            }
            return result;
        },
    };
}

const LIMIT_MS = 300_000;
function classify(e) {
    if (e.status !== 'succeeded' || e.proofs !== 2 || e.lockCount !== 0 || e.heldAdmission !== false
        || e.admissionCount !== 0 || e.remoteAdmissionCount !== 0 || e.exactCandidates !== true
        || ![e.startupMs, e.dataPlaneMs, e.combinedMs].every(n => Number.isFinite(n) && n >= 0)
        || e.combinedMs < Math.max(e.startupMs, e.dataPlaneMs)) return 'unproven';
    return e.combinedMs < LIMIT_MS ? 'local-e2e-under-5m' : 'local-e2e-over-budget';
}

// Closed launch policy for the one fixture graph. Staged bytes and runner
// proofs are never changed. The launch copy is intentionally not PROD bytes.
function loopbackConfig(input, originPort) {
    const conf = structuredClone(input);
    const need = value => { if (!value) throw new Error('unsafe Xray launch projection'); };
    need(Object.keys(conf).every(k => ['log', 'inbounds', 'outbounds', 'routing', 'reverse', 'api', 'policy', 'stats'].includes(k)));
    const port = p => Number.isInteger(p) && p >= 1024 && p < 65536;
    for (const i of conf.inbounds) {
        need(['vless', 'dokodemo-door', 'reverse', 'tunnel', 'socks'].includes(i.protocol));
        need(['127.0.0.1', '0.0.0.0'].includes(i.listen) && port(i.port));
        need(!i.settings?.fallbacks && !i.settings?.accounts && !i.settings?.followRedirect);
        if (i.settings?.address !== undefined) need(i.settings.address === '127.0.0.1');
        need(i.streamSettings?.security === undefined || i.streamSettings.security === 'none');
        i.listen = '127.0.0.1';
        if (i.sniffing) i.sniffing.enabled = false;
    }
    for (const o of conf.outbounds) {
        need(['freedom', 'blackhole', 'vless'].includes(o.protocol));
        need(o.streamSettings?.security === undefined || o.streamSettings.security === 'none');
        if (o.protocol === 'vless') {
            need(o.settings?.vnext?.length === 1 && o.settings.vnext.every(v => v.address === '127.0.0.1' && port(v.port)));
        }
        if (o.protocol === 'freedom') {
            need(!o.settings?.redirect);
            // Only the bridge can reach the local origin. Other direct paths
            // cannot make the data-plane probe pass or escape loopback.
            o.settings = { redirect: port(originPort) ? `127.0.0.1:${originPort}` : '127.0.0.1:0' };
            if (!port(originPort)) { o.protocol = 'blackhole'; delete o.settings; }
        }
    }
    conf.log = { loglevel: 'warning', access: 'none' };
    if (conf.routing) conf.routing.domainStrategy = 'AsIs';
    return conf;
}

module.exports = { makeLink, classify, loopbackConfig, LIMIT_MS };
