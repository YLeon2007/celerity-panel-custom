'use strict';
// Dedicated finite bridge; no SSH shell fallback and no changes to the existing
// root coordinator/RestorationChannel wire grammar.
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { randomBytes, randomUUID, createHash } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../modules/relay-l2tp/domain/topologyExecutionContext');
const { exact, freeze } = require('../modules/relay-l2tp/models/topologyExecutionBindingContract');
const { NODES, settlementInventory } = require('./heldTestOwnerSettlement');
const CONFIG = '/etc/celerity/topology-test-owner-settlement.json';
const BRIDGE = '/usr/local/libexec/c3-test-owner-restoration-channel.py';
const COORDINATOR = '/usr/local/libexec/c3-test-coordinated-restore.py';
const FRESH_CONFIG = '/etc/celerity/topology-test-fresh-owner-settlement.json';
const FRESH_BRIDGE = '/usr/local/libexec/c3-test-fresh-owner-restoration-channel.py';
const RESTORE_CONFIG = '/etc/c3-test-coordinated-restore.json';
const INVENTORY = '/etc/celerity/topology-test-inventory.json';
const NETWORK_PLAN = '/etc/c3-test-fresh-network.json';
const SHARED_PLAN = '/etc/c3-test-node-isolation.json';
const FRESH_POLICY = '/etc/c3-test-fresh-classic.json';
const SHARED = '/usr/local/libexec/c3-test-shared-host.py';
const ISOLATION = '/usr/local/libexec/c3-test-node-isolation';
const FREEZER = '/usr/local/libexec/c3-panel-host-freezer.py';
const FRESH = '/usr/local/libexec/c3-test-fresh-classic.py';
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
// JSON.parse validates syntax; this second lexical pass refuses duplicate keys,
// including escaped aliases, rather than accepting a last-key-wins selector.
function parseJSON(raw) {
    const text = raw.toString(), value = JSON.parse(text), stack = [];
    for (const token of text.match(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\],:]|[^{}\[\],:\s]+/g) || []) {
        const top = stack.at(-1);
        if (token === '{') stack.push({ keys: new Set(), key: true });
        else if (token === '[') stack.push(null);
        else if (token === '}' || token === ']') stack.pop();
        else if (token === ',' && top) top.key = true;
        else if (token === ':' && top) top.key = false;
        else if (top?.key && token.startsWith('"')) { const key = JSON.parse(token); need(!top.keys.has(key)); top.keys.add(key); }
    }
    return value;
}
const canonical = value => JSON.stringify(value, (_key, v) => v && !Array.isArray(v) && typeof v === 'object'
    ? Object.fromEntries(Object.keys(v).sort().map(k => [k, v[k]])) : v).replace(/[\u007f-\uffff]/g,
    c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
function need(ok) { if (!ok) throw new Error('HELD_OWNER_RESTORATION_UNKNOWN_RETAINED'); }
const sha = raw => createHash('sha256').update(raw).digest('hex');
function trustedRead(file) {
    for (let current = file; ; current = path.dirname(current)) {
        const st = fs.lstatSync(current); need(st.uid === 0 && st.gid === 0 && !st.isSymbolicLink() && !(st.mode & 0o022));
        if (current === '/') break;
    }
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try { const st = fs.fstatSync(fd); need(st.isFile() && st.nlink === 1 && st.size <= 8 * 1024 * 1024 && !(st.mode & 0o007)); return fs.readFileSync(fd); }
    finally { fs.closeSync(fd); }
}
function operationalInputs() { return readOperationalInputs(false); }
function freshOperationalInputs() { return readOperationalInputs(true); }
function readOperationalInputs(fresh) {
    need(process.getuid() === 0);
    const configPath = fresh ? FRESH_CONFIG : CONFIG;
    const raw = trustedRead(configPath), config = parseJSON(raw), restoreRaw = trustedRead(RESTORE_CONFIG), restore = parseJSON(restoreRaw);
    const networkOwned = Object.hasOwn(config, 'networkPlanSha256');
    need(!networkOwned || (fresh && config.version === 2 && digest(config.networkPlanSha256)));
    need([1, 2].includes(config.version) && config.version === restore.version
        && exact(config, ['version', 'mongoUri', 'bridgeSha256', 'coordinatorSha256', 'plan', 'acceptedOriginalsBase64', 'oldBackend',
            ...(fresh ? ['freshBridgeSha256'] : []), ...(config.version === 2 ? ['inventorySha256'] : []),
            ...(networkOwned ? ['networkPlanSha256'] : [])]));
    const inventoryRaw = config.version === 2 ? trustedRead(INVENTORY) : undefined;
    const inventory = inventoryRaw ? settlementInventory(parseJSON(inventoryRaw), config.inventorySha256) : undefined;
    const nodes = inventory ? Object.fromEntries(inventory.nodes.map(p => [p.nodeId, p.targetProfile])) : NODES;
    need(typeof config.mongoUri === 'string' && config.mongoUri.startsWith('mongodb://')
        && sha(trustedRead(BRIDGE)) === config.bridgeSha256 && sha(trustedRead(COORDINATOR)) === config.coordinatorSha256
        && restore.context === TEST.hostIdentity && same(Object.keys(restore.nodes).sort(), Object.keys(nodes).sort())
        && same(Object.keys(config.acceptedOriginalsBase64).sort(), Object.keys(nodes).sort())
        && Array.isArray(config.plan?.nodes) && config.plan.nodes.length === Object.keys(nodes).length
        && new Set(config.plan.nodes.map(n => n.nodeId)).size === config.plan.nodes.length
        && config.plan.nodes.every(n => Object.hasOwn(nodes, n.nodeId) && n.targetProfile === nodes[n.nodeId]));
    if (inventory) {
        const shared = inventory.nodes.find(p => p.nodeId === inventory.sharedNodeId);
        need(restore.inventorySha256 === config.inventorySha256 && restore.origin?.machineId === shared.physical.machineId
            && restore.origin.bootId === shared.physical.bootId);
    }
    if (fresh) need(sha(trustedRead(FRESH_BRIDGE)) === config.freshBridgeSha256);
    // This is a root-selected consumer contract, not authority inferred from a
    // receipt's shape or mere presence of ordinaryOwner in some request.
    const networkPins = new Map();
    if (networkOwned) {
        const read = file => { const raw = trustedRead(file); networkPins.set(file, raw); return raw; };
        const networkRaw = read(NETWORK_PLAN), network = parseJSON(networkRaw);
        const shared = parseJSON(read(SHARED_PLAN)), policy = parseJSON(read(FRESH_POLICY));
        const accepted = inventory.nodes.find(p => p.nodeId === inventory.sharedNodeId), pin = restore.nodes[accepted.nodeId];
        need(sha(networkRaw) === config.networkPlanSha256 && network.version === 1 && network.context === TEST.hostIdentity
            && network.machine === accepted.physical.machineId && network.boot === accepted.physical.bootId
            && exact(network.ordinaryOwner, ['version', 'stopConfigSha256']) && network.ordinaryOwner.version === 1
            && digest(network.ordinaryOwner.stopConfigSha256));
        need(shared.version === 2 && shared.mode === 'shared-test' && shared.nodeId === accepted.nodeId
            && shared.targetProfile === accepted.targetProfile && shared.endpointIp === accepted.endpoint.ip
            && shared.inventorySha256 === config.inventorySha256
            && Object.entries(accepted.physical).every(([key, value]) => shared[key] === value)
            && exact(shared.hostHold, ['owner', 'freezerSha256', 'expected', 'networkPlanSha256'])
            && shared.hostHold.networkPlanSha256 === config.networkPlanSha256
            && same(shared.hostHold.expected?.host, { machineId: network.machine, bootId: network.boot })
            && sha(canonical(shared)) === pin.identity.planHash && shared.hostHold.freezerSha256 === pin.files.freezer);
        need(policy.version === 1 && policy.context === TEST.hostIdentity
            && policy.inventory?.networkPlanSha256 === config.networkPlanSha256
            && policy.inventory.coordinatorSha256 === sha(canonical(restore))
            && policy.inventory.sourceSha256 === config.coordinatorSha256
            && policy.files?.[COORDINATOR] === config.coordinatorSha256 && digest(policy.files[FRESH]));
        for (const [file, expected] of [[SHARED, pin.files.shared], [ISOLATION, pin.files.isolation], [FREEZER, pin.files.freezer],
            [FRESH, policy.files[FRESH]]]) need(digest(expected) && sha(read(file)) === expected);
    }
    const old = config.oldBackend;
    need(exact(old, ['instanceId', 'pid', 'processStartTime']) && typeof old.instanceId === 'string' && old.instanceId
        && Number.isSafeInteger(old.pid) && old.pid > 1 && typeof old.processStartTime === 'string' && /^\d+$/.test(old.processStartTime));
    const pins = config.plan.nodes.map(n => {
        const pin = restore.nodes[n.nodeId], encoded = config.acceptedOriginalsBase64[n.nodeId];
        need(pin && typeof encoded === 'string' && encoded.length < 1024 * 1024);
        const acceptedRaw = Buffer.from(encoded, 'base64');
        need(acceptedRaw.toString('base64') === encoded && sha(acceptedRaw) === pin.files.accepted
            && pin.files.self === config.coordinatorSha256 && pin.identity.nodeId === n.nodeId && pin.identity.targetProfile === n.targetProfile);
        if (inventory) {
            const p = inventory.nodes.find(p => p.nodeId === n.nodeId);
            need(pin.identity.inventorySha256 === config.inventorySha256 && same(pin.profiles, p.profiles)
                && pin.identity.endpointIp === p.endpoint.ip
                && Object.entries(p.physical).every(([k, v]) => pin.identity[k] === v));
        }
        const accepted = JSON.parse(acceptedRaw);
        for (const [key, value] of Object.entries(pin.identity)) need(same(accepted[key], value));
        if (inventory) need(same(Object.keys(accepted.profiles).sort(), [...pin.profiles].sort()));
        const p = accepted.profiles[n.targetProfile];
        need(p && /^[a-f0-9]{64}$/.test(p.files?.config?.sha256) && /^[a-f0-9]{64}$/.test(p.files?.unit?.sha256)
            && ['active', 'inactive'].includes(p.service?.ActiveState) && ['enabled', 'disabled'].includes(p.service?.UnitFileState));
        return freeze({ ...n, maintenanceId: pin.identity.maintenanceId, bootId: pin.identity.bootId,
            endpoint: { ip: pin.identity.endpointIp, port: 2222, username: 'c3-test-runner' },
            nodeIdentity: { machineId: pin.identity.machineId, sshHostKeySha256: pin.identity.sshHostKeySha256 },
            originalSnapshot: { configSha256: p.files.config.sha256, unitSha256: p.files.unit.sha256,
                serviceActive: p.service.ActiveState, serviceEnabled: p.service.UnitFileState } });
    });
    return { config: freeze(config), pins: freeze(pins), inventory, assertPins() { need(trustedRead(configPath).equals(raw) && trustedRead(RESTORE_CONFIG).equals(restoreRaw)
        && (!inventoryRaw || trustedRead(INVENTORY).equals(inventoryRaw))
        && [...networkPins].every(([file, expected]) => trustedRead(file).equals(expected))
        && sha(trustedRead(BRIDGE)) === config.bridgeSha256 && sha(trustedRead(COORDINATOR)) === config.coordinatorSha256
        && (!fresh || sha(trustedRead(FRESH_BRIDGE)) === config.freshBridgeSha256)); } };
}
class RestorationPipe {
    #child; #closed = false; #failed = false; #pending; #buffer = ''; #tail = Promise.resolve(); #finishing = false; #exit; #fresh; #networkOwned;
    constructor(child, { fresh = false, networkOwned = false } = {}) {
        need(typeof networkOwned === 'boolean' && (!networkOwned || fresh));
        this.#child = child; this.#fresh = fresh; this.#networkOwned = networkOwned;
        const lost = () => { this.#failed = true; this.close(); };
        this.#exit = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
        child.on('error', lost); child.on('exit', () => { if (!this.#finishing || this.#pending) lost(); }); child.stderr.on('data', lost);
        child.stdin.on('error', lost); child.stdout.on('error', lost); child.stdout.on('end', () => { if (!this.#finishing) lost(); });
        child.stdout.on('data', raw => {
            if (this.#closed) return;
            this.#buffer += raw.toString('utf8');
            if (Buffer.byteLength(this.#buffer) > 4096) return lost();
            if (!this.#buffer.includes('\n')) return;
            try {
                const [line, extra] = this.#buffer.split('\n'); need(!extra && this.#buffer.indexOf('\n') === this.#buffer.length - 1);
                this.#buffer = ''; const reply = parseJSON(line), pending = this.#pending;
                const networkReply = this.#networkOwned && pending?.op === 'fresh-handback';
                need(pending && exact(reply, pending.op === 'check' ? ['version', 'op', 'nonce'] :
                    ['version', 'op', 'nonce', 'commitSha256', ...(networkReply ? ['networkOwnershipSha256'] : [])]) && reply.version === 1
                    && reply.op === (pending.op === 'check' ? 'checked' : pending.op+'-ack') && reply.nonce === pending.nonce);
                if (pending.op !== 'check') need(digest(reply.commitSha256));
                if (networkReply) need(digest(reply.networkOwnershipSha256));
                this.#pending = undefined; clearTimeout(pending.timer);
                pending.resolve(networkReply ? freeze({ commitSha256: reply.commitSha256, networkOwnershipSha256: reply.networkOwnershipSha256 }) : reply.commitSha256);
            } catch { lost(); }
        });
    }
    check() { return this.request('check'); }
    request(op, proof) {
        need((this.#fresh ? ['check', 'fresh-handback'] : ['check', 'commit-handoff', 'activate-classic', 'complete-handoff']).includes(op));
        const run = () => new Promise((resolve, reject) => {
            if (this.#closed) return reject(new Error('RESTORATION_PIPE_REVOKED'));
            const nonce = randomBytes(32).toString('hex');
            if (op === 'complete-handoff' || op === 'fresh-handback') this.#finishing = true;
            this.#pending = { nonce, op, resolve, reject, timer: setTimeout(() => this.close(), 15000) };
            const request = { version: 1, op, nonce, ...(['commit-handoff', 'fresh-handback'].includes(op) ? { proof } : {}) };
            const raw = JSON.stringify(request) + '\n'; need(Buffer.byteLength(raw) <= 131072);
            this.#child.stdin.write(raw);
        });
        const result = this.#tail.then(run); this.#tail = result.catch(() => {}); return result;
    }
    async waitNatural() {
        const timer = setTimeout(() => { this.#failed = true; this.close(); this.#child.kill('SIGKILL'); }, 5000);
        try { const exit = await this.#exit; need(!this.#failed && !this.#pending && this.#buffer === '' && exit.code === 0 && exit.signal === null); }
        finally { clearTimeout(timer); }
    }
    async dispose() {
        this.close();
        const timer = setTimeout(() => this.#child.kill('SIGKILL'), 3000);
        try { await this.#exit; } finally { clearTimeout(timer); }
    }
    close() {
        if (this.#closed) return;
        this.#closed = true;
        if (this.#pending) { clearTimeout(this.#pending.timer); this.#pending.reject(new Error('RESTORATION_PIPE_REVOKED')); this.#pending = undefined; }
        this.#child.stdin.destroy(); this.#child.stdout.destroy(); this.#child.kill('SIGTERM');
    }
}
async function withOperationalRestoration(inputs, work, options = {}) { return withRestoration(inputs, work, options, false); }
async function withFreshOperationalRestoration(inputs, work, options = {}) { return withRestoration(inputs, work, options, true); }
async function withRestoration(inputs, work, { openBridge } = {}, fresh) {
    // openBridge is an internal programmatic SIMULATED fixture seam only; the
    // fixed root executable supplies neither flags, commands nor callbacks.
    inputs.assertPins();
    const networkOwned = Object.hasOwn(inputs.config, 'networkPlanSha256');
    need(!networkOwned || (fresh && inputs.config.version === 2 && digest(inputs.config.networkPlanSha256)));
    const child = openBridge ? openBridge() : spawn('/usr/bin/python3', ['-I', fresh ? FRESH_BRIDGE : BRIDGE], { stdio: ['pipe', 'pipe', 'pipe'],
        env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C', HOME: '/root' } });
    const pipe = new RestorationPipe(child, { fresh, networkOwned });
    let open = true, poisoned = false, committed = false, completed = false, commitAttempted = false, terminalAttempted = false, primary;
    const check = async () => { try { need(open && !poisoned); inputs.assertPins(); await pipe.check(); need(open && !poisoned); inputs.assertPins(); } catch (e) { poisoned = true; throw e; } };
    const guarded = work => async (...args) => { try { return await work(...args); } catch (error) { poisoned = true; throw error; } };
    const scope = Object.freeze({ check,
        ...(networkOwned ? { freshNetworkOwnershipRequired: true } : {}),
        ...(fresh ? { freshHandback: guarded(async proof => {
            await check(); need(!terminalAttempted); terminalAttempted = true;
            const digest = await pipe.request('fresh-handback', proof);
            committed = true;
            await pipe.waitNatural(); completed = true;
            return digest; // terminal: h is released; no all-five check
        }) } : {}),
        commitHandoff: guarded(async proof => {
            need(!fresh); await check(); need(!commitAttempted); commitAttempted = true;
            const digest = await pipe.request('commit-handoff', proof); committed = true;
            await check(); return digest;
        }),
        activateClassic: guarded(async () => { need(!fresh); await check(); need(committed); await pipe.request('activate-classic'); await check(); }),
        completeHandoff: guarded(async () => {
            need(!fresh); await check(); need(committed); await pipe.request('complete-handoff');
            await pipe.waitNatural(); completed = true;
        }),
        verifyEnrollment: guarded(async e => {
            await check();
            const n = inputs.pins.find(p => p.nodeId === e.nodeId);
            need(n && e._id === n.enrollmentId && e.executionContext === TEST.hostIdentity
                && e.targetProfile === n.targetProfile && e.ownerGeneration === n.ownerGeneration
                && e.bootId === n.bootId && e.maintenanceId === n.maintenanceId
                && same(e.nodeIdentity, n.nodeIdentity) && same(e.endpoint, n.endpoint));
            await check();
        }),
        withVerifiedMaintenance: guarded(async ({ binding, proofRef }, callback) => {
            await check();
            const n = inputs.pins.find(p => p.nodeId === binding.node && p.targetProfile === binding.profile);
            need(n && binding.action === 'handback' && same(binding.executionContext, TEST)
                && same(binding.nodeIdentity, n.nodeIdentity) && binding.generation === n.ownerGeneration && proofRef === n.enrollmentId);
            // Existing RestorationChannel.check -> all five NodeServer checks ->
            // held.verify compares actual bytes/unit/service/runtime with the
            // exact accepted manifest whose raw hash was pinned above. These
            // digests are a projection of that live check, never a JSON GO.
            const proof = freeze({ status: 'verified', authority: 'external-maintenance-v1', binding,
                proofId: randomUUID(), maintenanceId: n.maintenanceId, maintenance: 'held', allWriters: 'drained',
                oldBackend: { ...inputs.config.oldBackend, processTree: 'stopped', dispatch: 'disabled' },
                readback: { source: 'node-readback', ...n.originalSnapshot } });
            await callback(proof); await check();
        }),
        async retain() { while (open) { await check(); await new Promise(resolve => setTimeout(resolve, 250)); } },
    });
    try { await check(); const result = await work(scope); if (!completed) await check(); return result; }
    catch (error) {
        primary = error;
        if (terminalAttempted || committed) error.code = 'COMMITTED_ACTIVATION_UNKNOWN';
        else if (commitAttempted) error.code = 'COMMIT_UNKNOWN_NO_ACTIVATION';
        throw error;
    } finally {
        open = false;
        try { await pipe.dispose(); } catch (error) {
            if (terminalAttempted || committed) error.code = 'COMMITTED_ACTIVATION_UNKNOWN';
            if (primary) { (primary.cleanupErrors ||= []).push(error); }
            else throw error;
        }
    }
}
module.exports = { operationalInputs, freshOperationalInputs, withOperationalRestoration, withFreshOperationalRestoration, RestorationPipe };
