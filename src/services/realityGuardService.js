'use strict';

const net = require('node:net');
const { createHash } = require('node:crypto');
const dns = require('node:dns/promises');
const tls = require('node:tls');
const { isDeepStrictEqual: equal } = require('node:util');

const CLIENT_ROLES = ['standalone', 'portal'];
const FAIL_THRESHOLD = 3;
const HOUR = 60 * 60 * 1000;
const TLS_TIMEOUT = 5000;
const MAX_NODES = 24;
const MAX_PAIRS = 20;
const MAX_NAMES = 5;
const MAX_OBSERVATIONS = 1024;
const OBSERVATION_TTL = 24 * HOUR;
const DEAD = 'node.reality_dest_dead';
const healthy = warning => ({ state: 'healthy', warning });
const failed = reason => ({ state: 'failed', reason });
const unknown = () => ({ state: 'unknown', reason: 'unavailable' });

// A syntactically valid endpoint need not be a public one. Restrict both
// literal and DNS-resolved peers; use the selected numeric peer on BOTH probes.
const excluded4 = new net.BlockList();
for (const [ip, bits] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
    ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24],
    ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3]]) {
    excluded4.addSubnet(ip, bits);
}
const global6 = new net.BlockList();
global6.addSubnet('2000::', 3, 'ipv6');
const excluded6 = new net.BlockList();
for (const [ip, bits] of [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]]) {
    excluded6.addSubnet(ip, bits, 'ipv6');
}
function publicIp(ip) {
    const family = net.isIP(ip);
    return family === 4 ? !excluded4.check(ip) : family === 6 && !ip.includes('%')
        && global6.check(ip, 'ipv6') && !excluded6.check(ip, 'ipv6');
}
function hostName(name) {
    if (typeof name !== 'string' || name.length > 253 || /[^a-z0-9.-]/i.test(name)) return false;
    const labels = name.split('.');
    return labels.length >= 2 && /^[a-z]/i.test(labels.at(-1))
        && !['local', 'localhost', 'internal', 'home'].includes(labels.at(-1).toLowerCase())
        && labels.every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}
function parseDest(dest) {
    if (typeof dest !== 'string' || dest.length > 262 || /\s/.test(dest)) return null;
    const match = /^(?:\[([^\]]+)\]|([^:[\]]+)):(\d{1,5})$/.exec(dest);
    if (!match) return null;
    const host = (match[1] || match[2]).toLowerCase();
    const port = Number(match[3]);
    if (!port || port > 65535 || (match[1] ? net.isIP(host) !== 6 || !publicIp(host) : !publicIp(host) && !hostName(host))) return null;
    return { host, port };
}
const address = (host, port) => `${net.isIP(host) === 6 ? `[${host}]` : host}:${port}`;
const eligible = node => node?.active === true && node.type === 'xray' && CLIENT_ROLES.includes(node.cascadeRole)
    && (node.role === undefined || node.role === node.cascadeRole) && publicIp(node.ip)
    && (node.useCustomConfig === undefined || node.useCustomConfig === false) && !!node._id
    && node.xray?.realityGuard?.mode === 'notify';

function collectRealityTargets(xray) {
    const extras = xray?.extraInbounds;
    if (extras !== undefined && (!Array.isArray(extras) || extras.length >= MAX_PAIRS)) return [];
    const groups = new Map();
    for (const inbound of [xray, ...(extras || [])]) {
        if (inbound?.security !== 'reality') continue;
        const parsed = parseDest(inbound.realityDest);
        if (!parsed) continue;
        const dest = address(parsed.host, parsed.port);
        if (!groups.has(dest)) groups.set(dest, { ...parsed, dest, snis: [], blocked: false });
        const target = groups.get(dest);
        const snis = inbound.realitySni;
        if (!Array.isArray(snis) || !snis.length || snis.length > MAX_NAMES || !snis.every(hostName)) {
            target.blocked = true;
            continue;
        }
        target.snis = [...new Set([...target.snis, ...snis.map(name => name.toLowerCase())])];
    }
    const targets = [...groups.values()].filter(t => !t.blocked && t.snis.length <= MAX_NAMES)
        .map(({ blocked, ...target }) => target);
    return targets.reduce((n, t) => n + t.snis.length, 0) <= MAX_PAIRS ? targets : [];
}

function classifyTlsError(code) {
    if (code === 'ERR_TLS_CERT_ALTNAME_INVALID') return failed('cert_name');
    if (code === 'CERT_HAS_EXPIRED') return failed('cert_expired');
    if (['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH'].includes(code)) return failed('connect');
    if (['ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION', 'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE',
        'ERR_SSL_TLSV1_UNRECOGNIZED_NAME', 'ERR_SSL_WRONG_VERSION_NUMBER'].includes(code)) return failed('tls');
    // Local trust store, setup and other unattributed failures are inconclusive.
    return unknown();
}

function tlsHandshake({ host, port, sni, ip: pinned }, {
    lookup = dns.lookup, connect = tls.connect, timeout = TLS_TIMEOUT, allow = () => true, signal,
} = {}) {
    if (!hostName(sni) || !Number.isInteger(port) || port < 1 || port > 65535
        || !(publicIp(host) || hostName(host)) || (pinned !== undefined && !publicIp(pinned))) return Promise.resolve(unknown());
    return new Promise(resolve => {
        let done = false, socket, ip;
        const finish = result => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            signal?.removeEventListener('abort', cancel);
            socket?.destroy();
            resolve({ ...result, ...(ip ? { ip } : {}) });
        };
        const cancel = () => finish(unknown());
        const timer = setTimeout(() => finish(ip ? failed('timeout') : unknown()), timeout);
        if (signal?.aborted) return cancel();
        signal?.addEventListener('abort', cancel, { once: true });
        (async () => {
            if (!await allow() || done) return finish(unknown());
            const candidate = pinned || (net.isIP(host) ? host : (await lookup(`${host}.`))?.address);
            if (done || !publicIp(candidate)) return finish(unknown());
            if (!await allow(candidate) || done) return finish(unknown());
            ip = candidate;
            socket = connect({ host: ip, port, servername: sni, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
                ecdhCurve: 'X25519', ALPNProtocols: ['h2', 'http/1.1'], rejectUnauthorized: true });
            socket.on('error', err => finish(classifyTlsError(err.code)));
            socket.once('close', () => finish(unknown()));
            socket.once('secureConnect', () => finish(socket.authorized === true && socket.getProtocol() === 'TLSv1.3'
                ? healthy(socket.alpnProtocol !== 'h2' ? 'no_h2' : undefined) : unknown()));
        })().catch(() => finish(unknown()));
    });
}

function nodeCheckCommand({ ip, port, sni }) {
    if (!publicIp(ip) || !hostName(sni) || !Number.isInteger(port) || port < 1 || port > 65535) return null;
    return `LC_ALL=C timeout -k 1s 6s openssl s_client -brief -tls1_3 -groups X25519 -alpn h2,http/1.1 -verify_return_error `
        + `-connect '${address(ip, port)}' -servername '${sni}' -verify_hostname '${sni}' </dev/null`;
}
function classifyNodeCheck(result) {
    const { code, stdout = '', stderr = '' } = result || {};
    if (typeof stdout !== 'string' || typeof stderr !== 'string' || stdout.length + stderr.length > 8192) return unknown();
    const text = `${stderr}\n${stdout}`;
    if (code === 0 && /^Protocol version: TLSv1\.3\r?$/m.test(text) && /^Verification: OK\r?$/m.test(text)) return healthy();
    if (code === 124) return failed('timeout'); // the fixed remote timeout, not a transport timeout
    if (code !== 1) return unknown();
    if (/^verify error:num=62:hostname mismatch\r?$/m.test(text)) return failed('cert_name');
    if (/^verify error:num=10:certificate has expired\r?$/m.test(text)) return failed('cert_expired');
    if (/BIO_connect:.*(?:Connection refused|No route to host|Network is unreachable)/i.test(text)) return failed('connect');
    if (/:(?:tlsv1 alert protocol version|wrong version number|sslv3 alert handshake failure|tlsv1 unrecognized name):/i.test(text)) return failed('tls');
    return unknown();
}

async function runLimited(items, worker, concurrency = 4) {
    let next = 0;
    const joined = await Promise.allSettled(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
        while (next < items.length) await worker(items[next++]);
    }));
    // Do not release overlap admission or shutdown's join while siblings probe.
    if (joined.some(result => result.status === 'rejected')) throw new Error('reality guard batch interrupted');
}
const clip = value => typeof value === 'string' ? value.replace(/[\p{C}\u2028\u2029]/gu, '').slice(0, 300) : '';
const publicReason = result => ['cert_name', 'cert_expired', 'tls', 'connect', 'timeout'].includes(result?.reason)
    ? result.reason : 'unavailable';
// Both paths use the same raw profile fields, before ODM defaults/casting.
// Ignore display/health edits and never bind to credentials or REALITY keys.
const inboundProfile = inbound => inbound && ({ security: inbound.security,
    dest: inbound.realityDest, sni: inbound.realitySni });
function binding(node) {
    const extras = node.xray.extraInbounds;
    return { ip: node.ip, cascadeRole: node.cascadeRole,
        role: node.role, useCustomConfig: node.useCustomConfig, createdAt: node.createdAt,
        port: node.ssh?.port, username: node.ssh?.username,
        main: inboundProfile(node.xray),
        extras: Array.isArray(extras) ? extras.map(i => i && ({ id: i.id, ...inboundProfile(i) })) : extras,
    };
}
const fingerprintOf = profile => createHash('sha256').update(JSON.stringify(profile)).digest('hex');
const observations = new Map();
const clearRealityGuardObservations = () => observations.clear();
const forgetRealityGuardObservation = id => observations.delete(String(id));
function getRealityGuardObservation(node) {
    if (!eligible(node)) return;
    const entry = observations.get(String(node._id));
    if (!entry?.sample || Date.now() - entry.sample.lastCheckAt >= OBSERVATION_TTL) return;
    if (entry.fingerprint === fingerprintOf(binding(node))) return entry.sample;
}
const severity = { ok: 0, unknown: 1, failing: 2, dead: 3 };
const readGlobalPolicy = () => require('../models/realityGuardPolicy').isGloballyEnabled();

function createRealityGuard({ listNodes, readNode, isBusy, isClientProfile,
    panelProbe = (pair, allow, signal) => tlsHandshake(pair, { allow, signal }),
    withNodeProbe, notify, isGloballyEnabled = readGlobalPolicy, now = Date.now, log = () => {} }) {
    const states = new Map();
    let running, controller, stopping = false, cursor;

    function pause() {
        controller?.abort();
        states.clear();
        clearRealityGuardObservations();
        cursor = undefined;
    }

    async function allowed() {
        if (stopping || controller.signal.aborted) return false;
        try {
            if (await isGloballyEnabled() === true) return !stopping && !controller.signal.aborted;
        } catch { /* fail closed on policy read failure */ }
        pause();
        return false;
    }

    async function inspect(node, snapshot, forSsh = false) {
        if (!await allowed()) return null;
        const fresh = await readNode(node._id);
        if (!eligible(fresh) || !equal(fresh._id, node._id) || !equal(snapshot, binding(fresh))
            || (forSsh && fresh.status === 'offline')) return null;
        if (await isBusy(fresh) || !await isClientProfile(fresh) || !await allowed()) return null;
        return fresh;
    }

    async function watch(node, time) {
        if (!eligible(node)) return;
        const targets = collectRealityTargets(node.xray);
        if (!targets.length) return;
        const id = String(node._id), snapshot = binding(node);
        let state = states.get(id);
        if (!state || !equal(state.snapshot, snapshot)) {
            state = { snapshot, failures: new Map(), reported: new Set() };
            states.set(id, state);
        }
        state.lastSeen = time;
        const fingerprint = fingerprintOf(snapshot);
        const previous = observations.get(id);
        const entry = previous?.fingerprint === fingerprint ? previous : { fingerprint };
        observations.delete(id);
        observations.set(id, entry);
        if (observations.size > MAX_OBSERVATIONS) observations.delete(observations.keys().next().value);
        let observation, lastCheckAt;
        const observe = (status, details) => {
            lastCheckAt = now();
            if (!observation || severity[status] > severity[observation.status]
                || (status === 'failing' && details.failCount > observation.failCount)) {
                observation = { status, ...details };
            }
        };
        const sameHost = new net.BlockList();
        sameHost.addAddress(node.ip, net.isIPv4(node.ip) ? 'ipv4' : 'ipv6');
        const usablePeer = ip => publicIp(ip) && !sameHost.check(ip, net.isIPv4(ip) ? 'ipv4' : 'ipv6');
        const guard = async ip => {
            if (ip !== undefined && !usablePeer(ip)) return false;
            if (await inspect(node, snapshot)) return true;
            state.failures.clear();
            if (observations.get(id) === entry) observations.delete(id);
            return false;
        };
        for (const target of targets) {
            if (controller.signal.aborted || !(await guard())) return;
            let recovered = true, failCount = 0, warning;
            const suspect = [];
            for (const sni of target.snis) {
                const pair = { host: target.host, port: target.port, sni };
                const result = await panelProbe(pair, guard, controller.signal);
                if (controller.signal.aborted) return;
                recovered &&= result?.state === 'healthy';
                if (result?.warning === 'no_h2') warning = 'no_h2';
                const key = `${target.dest}/${sni}`;
                if (result?.state !== 'failed' || !usablePeer(result.ip)) {
                    state.failures.delete(key);
                    continue;
                }
                const past = state.failures.get(key);
                const count = Math.min(FAIL_THRESHOLD, (past?.ip === result.ip ? past.count : 0) + 1);
                state.failures.set(key, { ip: result.ip, count });
                failCount = Math.max(failCount, count);
                if (count === FAIL_THRESHOLD) suspect.push({ key, pair: { ...pair, ip: result.ip } });
            }
            if (recovered) state.reported.delete(target.dest);
            if (!suspect.length || state.reported.has(target.dest)) {
                if (failCount) observe('failing', { failCount });
                else if (recovered) observe('ok', { warning });
                else observe('unknown');
                continue;
            }
            const current = () => inspect(node, snapshot, true);
            const fresh = await current();
            if (!fresh) { state.failures.clear(); observe('unknown'); continue; }
            // A normal later sample can start a new streak. No immediate retry,
            // alternate transport or death notification on inconclusive evidence.
            for (const { key } of suspect) state.failures.delete(key);
            let confirmed;
            try {
                confirmed = await withNodeProbe(fresh, async probe => {
                    for (const { pair } of suspect) {
                        if (!await current()) return;
                        const finding = await probe(pair);
                        if (finding?.state === 'failed') return finding;
                    }
                }, current);
            } catch { log('node confirmation unavailable'); }
            if (confirmed?.state !== 'failed' || !await current()) { observe('unknown'); continue; }
            observe('dead', { lastError: publicReason(confirmed) });
            await notify(DEAD, { nodeId: id, name: clip(fresh.name), dest: target.dest,
                reason: publicReason(confirmed), cause: 'notify_mode' }, {
                signal: controller.signal,
                // The real sender loads its settings asynchronously; gate the
                // actual POST, and latch once admitted (never replay lost ACKs).
                beforeDispatch: async () => {
                    if (!await current() || controller.signal.aborted) return false;
                    state.reported.add(target.dest);
                    return true;
                },
            });
        }
        if (observation && !controller.signal.aborted && observations.get(id) === entry) {
            entry.sample = Object.freeze({ ...observation, lastCheckAt });
        }
    }

    async function tick() {
        const time = now();
        const nodes = await listNodes(cursor, MAX_NODES);
        if (controller.signal.aborted) return;
        cursor = nodes.length === MAX_NODES ? nodes.at(-1)._id : undefined;
        await runLimited(nodes, async node => {
            if (controller.signal.aborted) return;
            try { await watch(node, time); }
            catch {
                states.get(String(node?._id))?.failures.clear();
                log('observation unavailable');
            }
        });
        for (const [id, state] of states) if (time - state.lastSeen > 24 * HOUR) states.delete(id);
    }

    return { pause, drain() { stopping = true; pause(); return running; }, checkAll() {
        if (stopping || running) return Promise.resolve();
        controller = new AbortController();
        running = Promise.resolve().then(async () => { if (await allowed()) await tick(); })
            .catch(() => log('check failed')).finally(() => { running = controller = undefined; });
        return running;
    } };
}

const profileProjection = Object.freeze({ name: 1, ip: 1, type: 1, active: 1, status: 1, cascadeRole: 1, role: 1, createdAt: 1,
    useCustomConfig: 1, 'xray.security': 1, 'xray.realityDest': 1, 'xray.realitySni': 1,
    'xray.extraInbounds.id': 1, 'xray.extraInbounds.security': 1, 'xray.extraInbounds.realityDest': 1,
    'xray.extraInbounds.realitySni': 1, 'xray.realityGuard.mode': 1, 'ssh.port': 1, 'ssh.username': 1 });
const readOptions = { readPreference: 'primary', readConcern: { level: 'majority' }, timeoutMS: 5000 };

function createRuntimeRealityGuard() {
    // Resolve the existing native connection only after checkAll's flag read.
    // No hydration, defaults, collection initialization or persistence.
    const collection = name => require('mongoose').connection.db.collection(name);
    const log = reason => require('../utils/logger').warn(`[Reality Guard] ${reason}`);
    const presence = { ...readOptions, projection: { _id: 1 } };
    const exists = (name, filter) => collection(name).findOne(filter, presence);
    const refs = node => ({ $in: [node._id, String(node._id)] });
    const isBusy = async node => node.status === 'syncing'
        || !!await exists('c3_rebuild_locks', { _id: 'apply' })
        || !!await exists('nodeoperationlocks', { node: refs(node) })
        || !!await exists('l2tpoperations', { node: refs(node), status: { $nin: ['succeeded', 'rolled_back', 'cancelled'] } })
        || !!await exists('remoteadmissions', { nodeId: String(node._id), phase: { $ne: 'completed' } });
    const isClientProfile = async node => {
        // A stale portal label cannot override incoming transit membership or
        // relay enrollment. A second Xray card at the endpoint is ambiguous.
        const ref = refs(node), transit = [{ bridgeNode: ref }];
        if (node.cascadeRole === 'standalone') transit.push({ portalNode: ref });
        return !await exists('cascadelinks', { active: { $ne: false }, $or: transit })
            && !await exists('relayl2tpstates', { node: ref })
            && !await exists('l2tpusers', { relayNode: ref })
            && !await exists('c3_rebuild_l2tp_relay_grants', { $or: [{ nodeId: String(node._id) }, { host: node.ip }] })
            && !await exists('hynodes', { ip: node.ip, type: 'xray', _id: { $ne: node._id } });
    };
    return createRealityGuard({ log,
        listNodes: (after, limit) => collection('hynodes').find({ active: true, type: 'xray', cascadeRole: { $in: CLIENT_ROLES },
            'xray.realityGuard.mode': 'notify', ...(after ? { _id: { $gt: after } } : {}),
        }, { ...readOptions, projection: profileProjection, sort: { _id: 1 }, limit }).toArray(),
        readNode: id => collection('hynodes').findOne({ _id: id }, { ...readOptions, projection: profileProjection }),
        isBusy, isClientProfile,
        async withNodeProbe(node, work, current) {
            const { ip, ssh: { port, username } = {} } = node;
            if (!Number.isInteger(port) || port < 1 || port > 65535
                || typeof username !== 'string' || !/^[a-z0-9_][a-z0-9_.-]{0,63}$/i.test(username)) return;
            // Honor an existing native enrollment's host key and exact endpoint,
            // never an offered key or caller-supplied pin. Ordinary cards retain
            // the existing endpoint-bound direct SSH behavior.
            const readEnrollment = () => collection('topologyexecutionenrollments').find({ nodeId: String(node._id) }, {
                ...readOptions, limit: 2, projection: { targetProfile: 1, endpoint: 1, 'nodeIdentity.sshHostKeySha256': 1 },
            }).toArray();
            const enrollment = await readEnrollment();
            const endpoint = { ip, port, username };
            let options;
            if (enrollment.length) {
                const [pin] = enrollment;
                const digest = pin.nodeIdentity?.sshHostKeySha256;
                if (enrollment.length !== 1 || pin.targetProfile !== 'xray-main' || !equal(pin.endpoint, endpoint)
                    || typeof digest !== 'string' || !/^[a-f0-9]{64}$/.test(digest)) return;
                options = { expectedEndpoint: endpoint, expectedHostKeySha256: digest };
            }
            const sameEnrollment = async () => equal(await readEnrollment(), enrollment);
            if (!await current()) return;
            // Bind credential reads to the same raw card and endpoint. These
            // are ordinary node credentials, not a relay enrollment or TOFU.
            const readAuth = () => collection('hynodes').findOne({ _id: node._id, ip, 'ssh.port': port, 'ssh.username': username,
                active: true, type: 'xray', cascadeRole: node.cascadeRole, 'xray.realityGuard.mode': 'notify',
            }, { ...readOptions, projection: { 'ssh.password': 1, 'ssh.privateKey': 1 } });
            const auth = (await readAuth())?.ssh;
            if (!(typeof auth?.privateKey === 'string' && auth.privateKey
                || typeof auth?.password === 'string' && auth.password) || !await current()) return;
            const SSH = require('./nodeSSH');
            const ssh = new SSH(Object.freeze({ _id: node._id, ip, ssh: Object.freeze({ port, username,
                privateKey: auth.privateKey, password: auth.password }) }), options);
            ssh.usePool = false;
            try {
                const exec = await ssh.connectObserverOnce(async () => {
                    if (!await current()) return false;
                    return await sameEnrollment() && equal((await readAuth())?.ssh, auth) && !!await current();
                });
                const finding = await work(async pair => {
                    const command = nodeCheckCommand(pair);
                    return command && await sameEnrollment() && await current()
                        ? classifyNodeCheck(await exec(command)) : unknown();
                });
                return await current() && await sameEnrollment() ? finding : unknown();
            } finally { ssh.disconnect(); }
        },
        notify: (...args) => require('./webhookService').send(...args),
    });
}

module.exports = { createRealityGuard, createRuntimeRealityGuard, collectRealityTargets,
    parseDest, tlsHandshake, nodeCheckCommand, classifyNodeCheck,
    getRealityGuardObservation, clearRealityGuardObservations, forgetRealityGuardObservation };
