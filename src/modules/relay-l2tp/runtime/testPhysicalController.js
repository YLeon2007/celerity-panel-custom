'use strict';
// TEST-only operational adapter over the installed finite readback helper. It
// NEVER arms/restores a fence or adopts a historical receipt. Operator-owned
// host-hold/recovery SSH channels must already be running and remain running.
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomBytes, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, matchesTopologyExecutionContext } = require('../domain/topologyExecutionContext');
const { freeze, UUID, exact, validTerminalReceipt } = require('../models/topologyExecutionBindingContract');
const { withAttestedPreinstalledRunner } = require('../services/topologyRunnerBootstrapper');
const CONFIG = '/etc/celerity/topology-test-physical.json';
const COMMAND = '/usr/bin/sudo -n /usr/local/libexec/c3-test-physical-attestor';
const SHARED = '6ab189dc63913ebd4a917399';
const NODES = Object.freeze({
    '6ab18adc63913ebd4a917471': ['132.243.230.19', 'xray-main'],
    '6ab93ad2646b4b7d2f43c907': ['94.103.2.186', 'xray-main'],
    '6ab18d9c63913ebd4a917670': ['50.114.160.63', 'xray-bridge'],
    '6ab4b53bc4c0304573e06c72': ['104.143.201.72', 'xray-bridge'],
    [SHARED]: ['212.119.42.100', 'xray-main'],
});
function refuse() { throw Object.assign(new Error('TEST_PHYSICAL_AUTHORITY_UNKNOWN_RETAINED'), { code: 'TEST_PHYSICAL_AUTHORITY_UNKNOWN_RETAINED' }); }
function need(ok) { if (!ok) refuse(); }
function digest(value, length) { return typeof value === 'string' && new RegExp(`^[a-f0-9]{${length}}$`).test(value); }
function uuid(value) { return typeof value === 'string' && UUID.test(value); }
function privateRead(file) {
    need(typeof file === 'string' && path.isAbsolute(file) && path.normalize(file) === file);
    // Every ancestor is root-controlled; administrators are part of the TCB.
    for (let current = file; ; current = path.dirname(current)) {
        const st = fs.lstatSync(current);
        need(st.uid === 0 && !(st.mode & 0o022) && !st.isSymbolicLink());
        if (current === '/') break;
    }
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try { const st = fs.fstatSync(fd); need(st.isFile() && st.size <= 1024 * 1024 && !(st.mode & 0o007)); return fs.readFileSync(fd); }
    finally { fs.closeSync(fd); }
}
function validateConfig(input) {
    const config = structuredClone(input);
    need(exact(config, ['version', 'executionContext', 'nodes', 'host']) && config.version === 1 && matchesTopologyExecutionContext(config.executionContext, TEST));
    need(Array.isArray(config.nodes) && config.nodes.length === 5 && config.host);
    const seen = new Set(), machines = new Set(), keys = new Set();
    for (const pin of config.nodes) {
        need(exact(pin, ['nodeId', 'targetProfile', 'endpoint', 'physical', 'maintenanceId', 'planHash', 'guard', 'operatorKeyPath'])
            && typeof pin.nodeId === 'string' && !seen.has(pin.nodeId) && NODES[pin.nodeId]); seen.add(pin.nodeId);
        const [ip, targetProfile] = NODES[pin.nodeId];
        need(equal(pin.endpoint, { ip, port: 2222, username: 'c3-test-runner' }) && pin.targetProfile === targetProfile);
        need(exact(pin.physical, ['machineId', 'bootId', 'sshHostKeySha256']) && digest(pin.physical?.machineId, 32) && digest(pin.physical?.sshHostKeySha256, 64) && uuid(pin.physical?.bootId)
            && uuid(pin.maintenanceId) && digest(pin.planHash, 64));
        if (pin.nodeId === SHARED) need(pin.physical.machineId === '7fa266f995fe4aa69e96cf7d01359e34');
        need(!machines.has(pin.physical.machineId) && !keys.has(pin.physical.sshHostKeySha256));
        machines.add(pin.physical.machineId); keys.add(pin.physical.sshHostKeySha256);
        need(exact(pin.guard, ['pid', 'start', 'socket']) && Number.isSafeInteger(pin.guard.pid) && pin.guard.pid > 1
            && typeof pin.guard.start === 'string' && /^\d+$/.test(pin.guard.start)
            && pin.guard.socket === '/var/lib/c3-test-node-isolation/recovery.sock');
        need(typeof pin.operatorKeyPath === 'string' && pin.operatorKeyPath.startsWith('/etc/celerity/'));
    }
    need(exact(config.host, ['owner', 'guard', 'backend']) && uuid(config.host.owner) && config.host.guard?.owner === config.host.owner
        && Number.isSafeInteger(config.host.guard.pid) && config.host.guard.pid > 1
        && digest(config.host.backend?.instanceId, 64) && Number.isSafeInteger(config.host.backend.pid)
        && config.host.backend.pid > 1 && typeof config.host.backend.processStartTime === 'string' && /^\d+$/.test(config.host.backend.processStartTime)
        && exact(config.host.guard, ['pid', 'start', 'socket', 'owner', 'planHash', 'session'])
        && typeof config.host.guard.start === 'string' && /^\d+$/.test(config.host.guard.start)
        && config.host.guard.socket === '/var/lib/c3-test-node-isolation/host.sock'
        && config.host.guard.planHash === config.nodes.find(pin => pin.nodeId === SHARED).planHash
        && exact(config.host.guard.session, ['pid', 'start']) && Number.isSafeInteger(config.host.guard.session.pid)
        && config.host.guard.session.pid > 1 && typeof config.host.guard.session.start === 'string' && /^\d+$/.test(config.host.guard.session.start));
    return freeze(config);
}
class AttestationChannel {
    #input; #output; #owner; #closed = false; #pending; #buffer = ''; #tail = Promise.resolve(); #timeout;
    constructor(input, output, owner, { timeoutMs = 15000 } = {}) {
        this.#input = input; this.#output = output; this.#owner = owner; this.#timeout = timeoutMs;
        const lost = () => this.close();
        input.on('data', chunk => {
            if (this.#closed) return;
            this.#buffer += chunk.toString('utf8');
            if (Buffer.byteLength(this.#buffer) > 2 * 1024 * 1024) return lost();
            let index;
            while ((index = this.#buffer.indexOf('\n')) !== -1) {
                const line = this.#buffer.slice(0, index); this.#buffer = this.#buffer.slice(index + 1);
                try {
                    const reply = JSON.parse(line), pending = this.#pending;
                    need(pending && reply.nonce === pending.nonce && reply.observation);
                    this.#pending = undefined; clearTimeout(pending.timer); pending.resolve(reply.observation);
                } catch { lost(); }
            }
        });
        input.on('end', lost); input.on('close', lost); input.on('error', lost); output.on('error', lost);
        owner.on('error', lost); owner.on('close', lost);
        if (owner.stderr) owner.stderr.on('data', lost);
    }
    get alive() { return !this.#closed; }
    request(predecessor = null) {
        const run = () => new Promise((resolve, reject) => {
            if (!this.alive) return reject(new Error('ATTESTATION_CHANNEL_LOST'));
            const nonce = randomBytes(32).toString('hex');
            const timer = setTimeout(() => this.close(), this.#timeout);
            this.#pending = { nonce, resolve, reject, timer };
            this.#output.write(JSON.stringify({ nonce, predecessor }) + '\n');
        });
        const result = this.#tail.then(run); this.#tail = result.catch(() => {}); return result;
    }
    close() {
        if (this.#closed) return;
        this.#closed = true;
        if (this.#pending) { clearTimeout(this.#pending.timer); this.#pending.reject(new Error('ATTESTATION_CHANNEL_LOST')); this.#pending = undefined; }
        this.#output.destroy(); this.#input.destroy(); this.#owner.end?.();
    }
}
async function openSshChannel(pin) {
    const { Client } = require('ssh2');
    // Read the operator key only AFTER exact server context/config selection.
    const privateKey = privateRead(pin.operatorKeyPath);
    const client = new Client();
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { client.destroy(); reject(new Error('ATTESTATION_CONNECT_TIMEOUT')); }, 15000);
        client.once('error', () => { clearTimeout(timer); client.destroy(); reject(new Error('ATTESTATION_CONNECT_FAILED')); });
        client.once('ready', () => client.exec(COMMAND, (error, stream) => {
            clearTimeout(timer);
            if (error) { client.destroy(); return reject(new Error('ATTESTATION_EXEC_FAILED')); }
            const channel = new AttestationChannel(stream, stream, client);
            stream.stderr.on('data', () => channel.close()); resolve(channel);
        }));
        client.connect({ host: pin.endpoint.ip, port: 2222, username: 'c3-test-operator', privateKey,
            readyTimeout: 15000, keepaliveInterval: 1000, keepaliveCountMax: 2,
            hostVerifier: raw => Buffer.isBuffer(raw) && createHash('sha256').update(raw).digest('hex') === pin.physical.sshHostKeySha256 });
    });
}
function createTestPhysicalController({ config: input, openChannel = openSshChannel } = {}) {
    const config = validateConfig(input), channels = new Map();
    let opening, busy = false, poisoned = false;
    const alive = scope => { need(!poisoned && scope?.open && [...channels.values()].every(channel => channel.alive)); };
    const connect = async () => {
        if (!opening) opening = (async () => {
            try { for (const pin of config.nodes) { need(!poisoned); const channel = await openChannel(pin); channels.set(pin.nodeId, channel); need(!poisoned); } }
            catch { poisoned = true; for (const channel of channels.values()) channel.close(); refuse(); }
        })();
        await opening;
    };
    return Object.freeze({
        runnerTransport: 'preinstalled-attested-v1',
        async withHeldAuthority(context, work) {
            need(matchesTopologyExecutionContext(context, TEST) && !busy && !poisoned);
            busy = true; const scope = { open: true }; let observations;
            const refresh = async (selected, predecessor) => {
                try {
                    alive(scope);
                    const pairs = await Promise.all(config.nodes.map(async pin => {
                        const value = await channels.get(pin.nodeId).request(pin.nodeId === selected ? predecessor : null);
                        alive(scope);
                        need(value.nodeId === pin.nodeId && value.targetProfile === pin.targetProfile && value.maintenanceId === pin.maintenanceId
                            && value.planHash === pin.planHash && equal(value.physical, pin.physical) && equal(value.endpoint, pin.endpoint)
                            && equal(value.guard, pin.guard) && (pin.nodeId === SHARED ? equal(value.host, config.host) : value.host === null));
                        return [pin.nodeId, value];
                    }));
                    alive(scope);
                    observations = new Map(pairs); return observations;
                } catch { poisoned = true; refuse(); }
            };
            const assertHeld = async () => { await refresh(); };
            const selectedPin = (nodeId, targetProfile, bootId) => {
                const pin = config.nodes.find(pin => pin.nodeId === nodeId);
                need(pin && pin.targetProfile === targetProfile && pin.physical.bootId === bootId); return pin;
            };
            try {
                await connect(); await assertHeld();
                const result = await work(Object.freeze({ assertHeld,
                    async withVerifiedAuthority(challenge, callback) {
                        alive(scope); need(matchesTopologyExecutionContext(challenge?.executionContext, TEST));
                        const e = challenge.enrollment;
                        const pin = selectedPin(e?.nodeId, e?.targetProfile, e?.bootId);
                        const identity = { machineId: pin.physical.machineId, sshHostKeySha256: pin.physical.sshHostKeySha256 };
                        need(equal(e.endpoint, pin.endpoint) && equal(e.nodeIdentity, identity));
                        const values = await refresh(pin.nodeId, challenge.predecessor ?? null), value = values.get(pin.nodeId);
                        let predecessor;
                        if (challenge.predecessor) {
                            const prior = challenge.predecessor;
                            need(validTerminalReceipt(value.runnerState.terminal, prior.binding));
                            need((challenge.action === 'successor' ? [prior.binding.generation] : [prior.binding.generation, challenge.expected?.generation]).includes(value.runnerState.head));
                            predecessor = { bindingId: prior.bindingId, generation: prior.binding.generation, headGeneration: value.runnerState.head,
                                bootId: pin.physical.bootId, status: 'terminal', receipt: value.runnerState.terminal };
                        } else if (challenge.action === 'enroll') {
                            need(e.predecessorGeneration === 'none' && value.runnerState.head === null && value.runnerState.journal === 'absent' && value.runnerState.legacyState === 'absent');
                            predecessor = { generation: 'none', bootId: value.physical.bootId, status: 'empty', protocolVersion: 2, journal: 'absent', legacyState: 'absent', writers: 'excluded' };
                        } else {
                            need(e.predecessorGeneration === 'none' && [null, challenge.expected?.generation].includes(value.runnerState.head));
                            predecessor = { generation: e.predecessorGeneration, bootId: value.physical.bootId, status: 'pre-enrolled' };
                        }
                        const proof = freeze({ authority: 'external-execution-maintenance-v1', status: 'verified', challenge: structuredClone(challenge),
                            proofId: randomUUID(), maintenanceId: value.maintenanceId, maintenance: 'held', allWriters: 'drained', bootstrapWriters: 'excluded', owner: 'topology',
                            physicalIdentity: { machineId: value.physical.machineId, sshHostKeySha256: value.physical.sshHostKeySha256 }, predecessor,
                            connectionAttestation: { authority: 'server-physical-ssh-endpoint-v1', endpoint: value.endpoint, physicalIdentity: identity,
                                maintenanceId: value.maintenanceId, aliases: 'excluded', hostKeyDigest: 'raw-ssh-public-key-sha256', endpointReassignment: 'excluded' },
                            oldBackend: { ...values.get(SHARED).host.backend, processTree: 'stopped', dispatch: 'disabled' } });
                        const result = await callback(proof); await assertHeld(); return result;
                    },
                    async withVerifiedPreinstalledRunner(challenge, callback) {
                        alive(scope); const b = challenge?.binding;
                        need(b?.executionContext === TEST.hostIdentity);
                        const pin = selectedPin(b.nodeId, b.targetProfile, b.bootId);
                        need(b.maintenanceId === pin.maintenanceId && equal(challenge.connection, {
                            expectedEndpoint: pin.endpoint, expectedHostKeySha256: pin.physical.sshHostKeySha256 }));
                        await assertHeld(); const value = observations.get(pin.nodeId);
                        const proof = freeze({ authority: 'server-preinstalled-topology-runner-v1', binding: structuredClone(b), bootId: value.physical.bootId,
                            maintenanceId: value.maintenanceId, connection: { expectedEndpoint: value.endpoint, expectedHostKeySha256: value.physical.sshHostKeySha256 },
                            runner: value.installation.runner, profile: value.installation.profile, writers: 'excluded' });
                        let callbackOpen = true;
                        const check = async () => {
                            need(callbackOpen); await assertHeld();
                            need(equal(observations.get(pin.nodeId).installation, { runner: proof.runner, profile: proof.profile }));
                            need(callbackOpen);
                        };
                        try {
                            // Reuse the shipped exact installation contract, not a second
                            // expected hash/unit implementation or a no-op bootstrapper.
                            return await withAttestedPreinstalledRunner({ withVerifiedPreinstalledRunner: async (_, validate) => validate(proof, check) }, challenge,
                                async () => { const result = await callback(proof, check); await check(); return result; });
                        } finally { callbackOpen = false; }
                    },
                }));
                await assertHeld(); return result;
            } catch { poisoned = true; refuse(); }
            finally { scope.open = false; busy = false; }
        },
        close() { poisoned = true; for (const channel of channels.values()) channel.close(); },
    });
}
function createRootTestPhysicalAuthority({ env = process.env, read = privateRead, openChannel } = {}) {
    // Flags select eligibility only; NEVER authorize or choose pins/endpoints.
    if (env.L2TP_EXECUTION_ENABLED !== 'true' || env.TOPOLOGY_TEST_EXECUTION_ENABLED !== 'true'
        || env.PANEL_DOMAIN !== TEST.hostIdentity || env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'true'
        || env.L2TP_PRODUCTION_EXECUTION_ENABLED === 'true') return undefined;
    let raw;
    try { raw = read(CONFIG); } catch (error) { if (error.code === 'ENOENT') return undefined; refuse(); }
    return createTestPhysicalController({ config: JSON.parse(raw), ...(openChannel ? { openChannel } : {}) });
}
module.exports = { createTestPhysicalController, createRootTestPhysicalAuthority, AttestationChannel };
