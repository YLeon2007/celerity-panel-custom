'use strict';
// Default PROD producer, over the existing physical exclusion/OFD and original
// effects contracts. Flags select context, never evidence. No TEST transport.
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD, matchesTopologyExecutionContext } = require('../domain/topologyExecutionContext');
const { freeze, UUID, validTerminalReceipt } = require('../models/topologyExecutionBindingContract');
const CONFIG = '/etc/celerity/topology-production.json';
const COMMAND = '/usr/bin/python3 -I -B /usr/local/libexec/c3-production-physical.py';
const sha = value => createHash('sha256').update(value).digest('hex');
const profiles = Object.freeze({
    'xray-main': { configPath: '/usr/local/etc/xray/config.json', unitPath: '/etc/systemd/system/xray.service', service: 'xray' },
    'xray-bridge': { configPath: '/usr/local/etc/xray-bridge/config.json', unitPath: '/etc/systemd/system/xray-bridge.service', service: 'xray-bridge' },
});
function fail(code = 'PRODUCTION_PHYSICAL_AUTHORITY_UNKNOWN_RETAINED') { throw Object.assign(new Error(code), { code }); }
function need(value) { if (!value) fail(); }
function privateRead(file) {
    need(path.isAbsolute(file) && path.normalize(file) === file);
    for (let p = file; ; p = path.dirname(p)) {
        const st = fs.lstatSync(p); need(st.uid === 0 && !(st.mode & 0o022) && !st.isSymbolicLink());
        if (p === '/') break;
    }
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try { const st = fs.fstatSync(fd); need(st.isFile() && !(st.mode & 0o077) && st.size <= 1024 * 1024); return fs.readFileSync(fd); }
    finally { fs.closeSync(fd); }
}
function validate(input) {
    const config = structuredClone(input);
    need(config?.version === 1 && same(config.executionContext, PROD) && ['enroll', 'runtime'].includes(config.mode)
        && Array.isArray(config.nodes) && config.nodes.length > 0 && config.nodes.length <= 32 && config.nodes.every(n => n.kind === 'node')
        && config.host?.kind === 'host' && config.admission?.serverContext && same(config.admission.serverContext, PROD));
    const ids = new Set(), machines = new Set(), endpoints = new Set();
    for (const n of [config.host, ...config.nodes]) {
        need(['host', 'node'].includes(n.kind) && /^[a-f0-9]{64}$/.test(n.policySha256)
            && /^[a-f0-9]{32}$/.test(n.physical?.machineId) && UUID.test(n.physical?.bootId)
            && /^[a-f0-9]{64}$/.test(n.physical?.sshHostKeySha256)
            && require('node:net').isIP(n.endpoint?.ip) && Number.isSafeInteger(n.endpoint.port)
            && n.endpoint.port > 0 && n.endpoint.port <= 65535 && n.endpoint.username === 'root'
            && typeof n.privateKeyPath === 'string' && n.privateKeyPath.startsWith('/etc/celerity/')
            && UUID.test(n.maintenanceId));
        if (n.kind === 'node') {
            need(/^[a-f0-9]{24}$/.test(n.nodeId) && !ids.has(n.nodeId) && Object.hasOwn(profiles, n.targetProfile)
                && !machines.has(n.physical.machineId) && !endpoints.has(n.endpoint.ip + ':' + n.endpoint.port)
                && typeof n.proofRef === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(n.proofRef)
                && n.originalSnapshot?.source === 'node-readback' && ['configSha256', 'unitSha256'].every(k => /^[a-f0-9]{64}$/.test(n.originalSnapshot[k]))
                && ['active', 'inactive'].includes(n.originalSnapshot.serviceActive) && ['enabled', 'disabled'].includes(n.originalSnapshot.serviceEnabled)
                && ['absent', 'classic', 'topology'].includes(n.acceptedOwner?.owner));
            if (n.acceptedOwner.owner !== 'absent') need(UUID.test(n.acceptedOwner.generation));
            if (config.mode === 'runtime') need(n.acceptedOwner.owner === 'topology' && UUID.test(n.originalScope?.epoch)
                && n.originalScope.ownerGeneration === n.acceptedOwner.generation && /^[a-f0-9]{64}$/.test(n.originalScope.bundleSha256));
            ids.add(n.nodeId); machines.add(n.physical.machineId); endpoints.add(n.endpoint.ip + ':' + n.endpoint.port);
        }
    }
    return freeze(config);
}
async function openSsh(pin, read) {
    const { Client } = require('ssh2'); const client = new Client();
    const stream = await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => { client.destroy(); reject(new Error('PRODUCTION_AUTHORITY_CONNECT_TIMEOUT')); }, 15000);
        client.once('error', () => { clearTimeout(timeout); client.destroy(); reject(new Error('PRODUCTION_AUTHORITY_CONNECT_FAILED')); });
        client.once('ready', () => client.exec(COMMAND, (error, value) => {
            clearTimeout(timeout); if (error) { client.destroy(); reject(new Error('PRODUCTION_AUTHORITY_EXEC_FAILED')); } else resolve(value);
        }));
        client.connect({ host: pin.endpoint.ip, port: pin.endpoint.port, username: pin.endpoint.username,
            privateKey: read(pin.privateKeyPath), readyTimeout: 15000, keepaliveInterval: 1000, keepaliveCountMax: 15,
            hostVerifier: key => Buffer.isBuffer(key) && sha(key) === pin.physical.sshHostKeySha256 });
    });
    let alive = true, pending, buffer = '';
    const close = () => { if (!alive) return; alive = false; pending?.reject(new Error('PRODUCTION_AUTHORITY_CHANNEL_LOST')); pending = undefined; client.end(); };
    client.once('close', close); stream.once('close', close); stream.once('error', close); stream.stderr.on('data', close);
    stream.on('data', chunk => {
        buffer += chunk.toString(); if (buffer.length > 8 * 1024 * 1024) return close();
        const i = buffer.indexOf('\n'); if (i < 0) return;
        try {
            need(i === buffer.length - 1 && pending); const reply = JSON.parse(buffer.slice(0, i)); buffer = '';
            need(reply.nonce === pending.nonce && Object.keys(reply).sort().join() === 'nonce,result');
            const p = pending; pending = undefined; p.resolve(reply.result);
        } catch { close(); }
    });
    return { get alive() { return alive; }, close,
        async request(action, value = null) {
            need(alive && !pending); let timer;
            try { return await new Promise((resolve, reject) => {
                const nonce = randomUUID(); pending = { nonce, resolve, reject };
                timer = setTimeout(close, ['prepare', 'restore', 'verify', 'capture'].includes(action) ? 130000 : 15000);
                stream.write(JSON.stringify({ nonce, action, value }) + '\n');
            }); } finally { clearTimeout(timer); }
        } };
}
function createProductionPhysicalAuthority({ config: input, read = privateRead, open = pin => openSsh(pin, read) } = {}) {
    const config = validate(input), channels = new Map(), originals = new Map();
    let busy = false, poisoned = false, closed = false, dispatchClosed = false;
    const pins = [config.host, ...config.nodes];
    // A panel host may also own ONE selected node profile. Share the actual
    // helper/OFD only for an independently identical complete physical policy,
    // not merely the same IP. Logical host and node observations stay distinct.
    const sharedHostNode = config.nodes.find(n => n.policySha256 === config.host.policySha256
        && same(n.physical, config.host.physical) && same(n.endpoint, config.host.endpoint)
        && n.privateKeyPath === config.host.privateKeyPath && n.maintenanceId === config.host.maintenanceId);
    const key = pin => pin.kind === 'host' ? 'host' : pin.nodeId;
    const controller = {
        executionContext: PROD,
        // undefined runnerTransport deliberately keeps the normal shell/SFTP bootstrapper.
        admission: config.admission,
        async withHeldAuthority(context, work) {
            need(matchesTopologyExecutionContext(context, PROD) && !busy && !poisoned && !closed);
            busy = true; let scopeOpen = true; const observations = new Map();
            const refresh = async () => {
                need(scopeOpen && !poisoned && !closed);
                // A co-located host/node was opened as one independently pinned helper.
                // Share its observation only within this checkpoint; validate both logical pins.
                // Never cache across callbacks, lease transitions or physical commands.
                let hostObservation;
                for (const pin of pins) {
                    const channel = channels.get(key(pin)); need(channel?.alive);
                    const v = pin === sharedHostNode && channel === channels.get('host')
                        ? hostObservation : await channel.request('observe');
                    if (pin === config.host) hostObservation = v;
                    const pairedKind = v.kind === pin.kind || (pin.kind === 'host' && sharedHostNode && v.kind === 'node'
                        && v.nodeId === sharedHostNode.nodeId && v.targetProfile === sharedHostNode.targetProfile);
                    need(scopeOpen && channel.alive && same(v.serverContext, PROD) && pairedKind && v.held === true
                        && v.policySha256 === pin.policySha256 && same(v.physical, pin.physical) && same(v.endpoint, pin.endpoint)
                        && v.maintenanceId === pin.maintenanceId);
                    if (pin.kind === 'node') need(v.nodeId === pin.nodeId && v.targetProfile === pin.targetProfile);
                    observations.set(key(pin), v);
                    const original = originals.get(key(pin));
                    if (original && !original.released) {
                        const held = await channel.request(original.restored ? 'verify' : 'read');
                        need(held.epoch === original.epoch && held.bundleSha256 === original.bundleSha256 && held.ownerGeneration === original.ownerGeneration);
                    }
                }
                need(scopeOpen && !closed);
            };
            const pinFor = id => { const n = config.nodes.find(n => n.nodeId === id); need(n); return n; };
            const oldBackend = () => {
                const v = observations.get('host').oldBackend;
                need(v && typeof v.instanceId === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(v.instanceId)
                    && Number.isSafeInteger(v.pid) && v.pid > 1 && typeof v.processStartTime === 'string' && /^\d+$/.test(v.processStartTime));
                return { ...v, processTree: 'stopped', dispatch: 'disabled' };
            };
            const checkOriginal = n => need(same(observations.get(n.nodeId).current, n.originalSnapshot));
            try {
                for (const pin of pins) if (!channels.has(key(pin))) channels.set(key(pin),
                    pin === sharedHostNode ? channels.get('host') : await open(pin));
                await refresh(); oldBackend();
                const capability = {
                    assertHeld: refresh,
                    async withCapturedOwnerEnrollment(callback, preflight) {
                        need(!dispatchClosed);
                        const plan = freeze({ mode: config.mode, executionContext: PROD,
                            ...(config.legacyTopology === undefined ? {} : { legacyTopology: config.legacyTopology }), nodes: config.nodes.map(n => ({
                            nodeId: n.nodeId, targetProfile: n.targetProfile, endpoint: n.endpoint,
                            nodeIdentity: { machineId: n.physical.machineId, sshHostKeySha256: n.physical.sshHostKeySha256 },
                            bootId: n.physical.bootId, acceptedOwner: n.acceptedOwner,
                            originalSnapshot: { proofRef: n.proofRef, ...Object.fromEntries(Object.entries(n.originalSnapshot).filter(([k]) => k !== 'source')) },
                        })) });
                        const readClassicProfile = async nodeId => {
                            need(config.mode === 'enroll' && !dispatchClosed);
                            const pin = pinFor(nodeId);
                            await refresh();
                            const reply = await channels.get(nodeId).request('profile');
                            need(typeof reply?.configBase64 === 'string');
                            const bytes = Buffer.from(reply.configBase64, 'base64');
                            need(bytes.length <= 1024 * 1024 && bytes.toString('base64') === reply.configBase64
                                && sha(bytes) === pin.originalSnapshot.configSha256);
                            await refresh();
                            return bytes.toString('utf8');
                        };
                        if (preflight) { await preflight(plan, refresh, readClassicProfile); await refresh(); }
                        if (config.mode === 'enroll') for (const n of config.nodes) {
                            const observed = observations.get(n.nodeId);
                            need(observed.journal === null && observed.pristine === true); checkOriginal(n);
                        }
                        for (const n of config.nodes) if (!originals.has(n.nodeId)) {
                            const c = channels.get(n.nodeId);
                            const held = await c.request(config.mode === 'enroll' ? 'capture' : 'attach', config.mode === 'enroll' ? null : n.originalScope);
                            need(UUID.test(held.epoch) && /^[a-f0-9]{64}$/.test(held.bundleSha256)
                                && held.phase === 'captured-held' && held.ownerGeneration === (config.mode === 'enroll' ? null : n.acceptedOwner.generation));
                            if (config.mode === 'runtime') need(held.epoch === n.originalScope.epoch
                                && held.bundleSha256 === n.originalScope.bundleSha256);
                            originals.set(n.nodeId, { ...held, restored: false, handed: false, released: false });
                        }
                        await refresh();
                        const result = await callback(plan, refresh); await refresh(); return result;
                    },
                    // Read-only prerequisite for a first reservation interrupted before
                    // either prepare. This observation alone never grants a lease or
                    // proves that a command with an ambiguous delivery can be replayed.
                    async checkPristineReservationPair(pair) {
                        need(config.mode === 'runtime' && !dispatchClosed && Array.isArray(pair) && pair.length === 2
                            && new Set(pair.map(e => e?.nodeId)).size === 2);
                        await refresh();
                        for (const e of pair) {
                            const n = pinFor(e.nodeId), o = originals.get(n.nodeId), v = observations.get(n.nodeId);
                            need(o && !o.restored && !o.handed && !o.released && n.acceptedOwner.owner === 'topology'
                                && e.ownerGeneration === o.ownerGeneration && e.ownerGeneration === n.acceptedOwner.generation
                                && e.targetProfile === n.targetProfile && e.maintenanceId === n.maintenanceId
                                && e.bootId === n.physical.bootId && same(e.endpoint, n.endpoint)
                                && same(e.nodeIdentity, { machineId: n.physical.machineId, sshHostKeySha256: n.physical.sshHostKeySha256 })
                                && v.pristine === true && v.journal === null);
                            checkOriginal(n);
                        }
                        return true;
                    },
                    // Both snapshots come from the pinned holders, not from DB state
                    // or an unsuccessful status request for a never-issued close ID.
                    async readUnclosedPair(bindings) {
                        need(!dispatchClosed && bindings.length === 2);
                        await refresh();
                        const pair = [];
                        for (const b of bindings) {
                            const n = pinFor(b.nodeId), o = originals.get(b.nodeId);
                            need(o && !o.restored && !o.released && n.targetProfile === b.targetProfile
                                && b.maintenanceId === n.maintenanceId && b.bootId === n.physical.bootId);
                            const v = await channels.get(b.nodeId).request('observe-unclosed');
                            need(v.held === true && v.kind === 'node' && same(v.serverContext, PROD)
                                && v.policySha256 === n.policySha256 && same(v.endpoint, n.endpoint)
                                && same(v.physical, n.physical) && v.maintenanceId === n.maintenanceId
                                && v.current?.unitSha256 === n.originalSnapshot.unitSha256
                                && v.current?.serviceEnabled === n.originalSnapshot.serviceEnabled);
                            pair.push(v);
                        }
                        await refresh();
                        return pair;
                    },
                    async withVerifiedMaintenance({ binding, proofRef }, callback) {
                        need(same(binding.executionContext, PROD) && ['adopt', 'handback'].includes(binding.action));
                        const n = pinFor(binding.node), original = originals.get(n.nodeId);
                        need(original && n.targetProfile === binding.profile && same(binding.paths, profiles[n.targetProfile])
                            && proofRef === n.proofRef && same(binding.nodeIdentity, { machineId: n.physical.machineId, sshHostKeySha256: n.physical.sshHostKeySha256 }));
                        await refresh(); checkOriginal(n);
                        if (binding.action === 'adopt') {
                            need(!dispatchClosed && original.ownerGeneration === null && observations.get(n.nodeId).journal === null);
                            const bound = await channels.get(n.nodeId).request('bind', { ownerGeneration: binding.nextGeneration });
                            need(bound.epoch === original.epoch && bound.bundleSha256 === original.bundleSha256 && bound.ownerGeneration === binding.nextGeneration);
                            original.ownerGeneration = binding.nextGeneration; // before CAS; uncertainty retains it
                        } else need(dispatchClosed && original.restored && !original.handed && original.ownerGeneration === binding.generation);
                        let callbackOpen = true;
                        const check = async () => { need(callbackOpen); await refresh(); checkOriginal(n); need(callbackOpen); };
                        try {
                            await check(); const result = await callback(freeze({ status: 'verified', authority: 'external-maintenance-v1', binding,
                                proofId: randomUUID(), maintenanceId: n.maintenanceId, maintenance: 'held', allWriters: 'drained',
                                oldBackend: oldBackend(), readback: observations.get(n.nodeId).current }), check);
                            await check(); if (binding.action === 'handback') original.handed = true; return result;
                        } finally { callbackOpen = false; }
                    },
                    async withVerifiedAuthority(challenge, callback) {
                        need(!dispatchClosed && same(challenge?.executionContext, PROD)); await refresh();
                        const e = challenge.enrollment, n = pinFor(e?.nodeId), v = observations.get(n.nodeId), o = originals.get(n.nodeId);
                        need(o && o.ownerGeneration === e.ownerGeneration && e.bootId === n.physical.bootId && e.targetProfile === n.targetProfile
                            && same(e.endpoint, n.endpoint) && same(e.nodeIdentity, { machineId: n.physical.machineId, sshHostKeySha256: n.physical.sshHostKeySha256 }));
                        let predecessor;
                        if (challenge.predecessor) {
                            const b = challenge.predecessor.binding, r = v.journal?.generations?.[b.generation];
                            const receipt = { ...r?.commands?.[b.commandIds.close]?.receipt, command: 'status' };
                            need(r?.phase === 'closed' && validTerminalReceipt(receipt, b));
                            predecessor = { bindingId: challenge.predecessor.bindingId, generation: b.generation, headGeneration: v.journal.head,
                                bootId: n.physical.bootId, status: 'terminal', receipt };
                        } else if (challenge.action === 'enroll') {
                            need(e.predecessorGeneration === 'none' && v.journal === null && v.pristine === true);
                            predecessor = { generation: 'none', bootId: n.physical.bootId, status: 'empty', protocolVersion: 2,
                                journal: 'absent', legacyState: 'absent', writers: 'excluded' };
                        } else {
                            need(v.journal === null || v.journal.head === challenge.expected?.generation);
                            predecessor = { generation: e.predecessorGeneration, bootId: n.physical.bootId, status: 'pre-enrolled' };
                        }
                        const identity = e.nodeIdentity;
                        const result = await callback(freeze({ authority: 'external-execution-maintenance-v1', status: 'verified', challenge,
                            proofId: randomUUID(), maintenanceId: n.maintenanceId, maintenance: 'held', allWriters: 'drained', bootstrapWriters: 'excluded',
                            owner: 'topology', physicalIdentity: identity, predecessor, oldBackend: oldBackend(),
                            connectionAttestation: { authority: 'server-physical-ssh-endpoint-v1', endpoint: n.endpoint, physicalIdentity: identity,
                                maintenanceId: n.maintenanceId, aliases: 'excluded', hostKeyDigest: 'raw-ssh-public-key-sha256', endpointReassignment: 'excluded' } }));
                        await refresh(); return result;
                    },
                };
                const result = await work(Object.freeze(capability)); await refresh(); return result;
            } catch (error) { poisoned = true; throw error; }
            finally { scopeOpen = false; busy = false; }
        },
        drainOriginals() { need(!busy && !poisoned && !dispatchClosed && config.nodes.every(n => originals.get(n.nodeId)?.ownerGeneration)); dispatchClosed = true; },
        async readOriginalRestoreCurrent() {
            return controller.withHeldAuthority(PROD, async cap => { need(dispatchClosed); await cap.assertHeld(); const out = {};
                for (const n of config.nodes) out[n.nodeId] = await channels.get(n.nodeId).request('current'); return freeze(out); });
        },
        async restoreOriginals(pins) {
            need(same(Object.keys(pins).sort(), config.nodes.map(n => n.nodeId).sort()));
            return controller.withHeldAuthority(PROD, async cap => { need(dispatchClosed); await cap.assertHeld();
                for (const n of config.nodes) { const o = originals.get(n.nodeId); need(o && !o.restored);
                    const prepared = await channels.get(n.nodeId).request('prepare', { epoch: o.epoch, ownerGeneration: o.ownerGeneration, current: pins[n.nodeId] });
                    need(prepared.epoch === o.epoch && prepared.ownerGeneration === o.ownerGeneration && prepared.bundleSha256 === o.bundleSha256); }
                for (const n of config.nodes) { const o = originals.get(n.nodeId), r = await channels.get(n.nodeId).request('restore');
                    need(r.phase === 'restored-held' && r.epoch === o.epoch && r.bundleSha256 === o.bundleSha256 && r.ownerGeneration === o.ownerGeneration); o.restored = true; }
                await cap.assertHeld(); });
        },
        async releaseOriginals() {
            return controller.withHeldAuthority(PROD, async cap => { need(dispatchClosed && config.nodes.every(n => originals.get(n.nodeId)?.handed));
                await cap.assertHeld(); for (const n of config.nodes) { const o = originals.get(n.nodeId), r = await channels.get(n.nodeId).request('release');
                    need(r.phase === 'handback-released' && r.epoch === o.epoch && r.ownerGeneration === o.ownerGeneration); o.released = true; } });
        },
        close() { closed = true; for (const c of channels.values()) c.close(); },
    };
    return Object.freeze(controller);
}
function createRootProductionPhysicalAuthority({ env = process.env, read = privateRead, open } = {}) {
    if (env.PANEL_DOMAIN !== PROD.hostIdentity || env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED !== 'true') return undefined;
    need(env.L2TP_EXECUTION_ENABLED === 'true' && env.L2TP_MIGRATIONS_ENABLED === 'true' && env.TOPOLOGY_TEST_EXECUTION_ENABLED !== 'true');
    let config;
    try { config = JSON.parse(read(CONFIG)); } catch { fail('PRODUCTION_PHYSICAL_ACTIVATION_REQUIRED'); }
    return createProductionPhysicalAuthority({ config, read, ...(open ? { open } : {}) });
}
function createRootTopologyExecutionAuthority(options) {
    return options?.env?.PANEL_DOMAIN === PROD.hostIdentity
        ? createRootProductionPhysicalAuthority(options)
        : require('./testPhysicalController').createRootTestPhysicalAuthority(options);
}
module.exports = { createRootTopologyExecutionAuthority, createRootProductionPhysicalAuthority, createProductionPhysicalAuthority };
