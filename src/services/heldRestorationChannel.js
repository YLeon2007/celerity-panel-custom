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
const { NODES } = require('./heldTestOwnerSettlement');
const CONFIG = '/etc/celerity/topology-test-owner-settlement.json';
const BRIDGE = '/usr/local/libexec/c3-test-owner-restoration-channel.py';
const COORDINATOR = '/usr/local/libexec/c3-test-coordinated-restore.py';
const RESTORE_CONFIG = '/etc/c3-test-coordinated-restore.json';
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
function operationalInputs() {
    need(process.getuid() === 0);
    const raw = trustedRead(CONFIG), config = JSON.parse(raw), restoreRaw = trustedRead(RESTORE_CONFIG), restore = JSON.parse(restoreRaw);
    need(exact(config, ['version', 'mongoUri', 'bridgeSha256', 'coordinatorSha256', 'plan', 'acceptedOriginalsBase64', 'oldBackend'])
        && config.version === 1 && typeof config.mongoUri === 'string' && config.mongoUri.startsWith('mongodb://')
        && sha(trustedRead(BRIDGE)) === config.bridgeSha256 && sha(trustedRead(COORDINATOR)) === config.coordinatorSha256
        && restore.context === TEST.hostIdentity && same(Object.keys(restore.nodes).sort(), Object.keys(NODES).sort())
        && same(Object.keys(config.acceptedOriginalsBase64).sort(), Object.keys(NODES).sort()));
    const old = config.oldBackend;
    need(exact(old, ['instanceId', 'pid', 'processStartTime']) && typeof old.instanceId === 'string' && old.instanceId
        && Number.isSafeInteger(old.pid) && old.pid > 1 && typeof old.processStartTime === 'string' && /^\d+$/.test(old.processStartTime));
    const pins = config.plan.nodes.map(n => {
        const pin = restore.nodes[n.nodeId], encoded = config.acceptedOriginalsBase64[n.nodeId];
        need(pin && typeof encoded === 'string' && encoded.length < 1024 * 1024);
        const acceptedRaw = Buffer.from(encoded, 'base64');
        need(acceptedRaw.toString('base64') === encoded && sha(acceptedRaw) === pin.files.accepted
            && pin.files.self === config.coordinatorSha256 && pin.identity.nodeId === n.nodeId && pin.identity.targetProfile === n.targetProfile);
        const accepted = JSON.parse(acceptedRaw);
        for (const [key, value] of Object.entries(pin.identity)) need(same(accepted[key], value));
        const p = accepted.profiles[n.targetProfile];
        need(p && /^[a-f0-9]{64}$/.test(p.files?.config?.sha256) && /^[a-f0-9]{64}$/.test(p.files?.unit?.sha256)
            && ['active', 'inactive'].includes(p.service?.ActiveState) && ['enabled', 'disabled'].includes(p.service?.UnitFileState));
        return freeze({ ...n, maintenanceId: pin.identity.maintenanceId, bootId: pin.identity.bootId,
            endpoint: { ip: pin.identity.endpointIp, port: 2222, username: 'c3-test-runner' },
            nodeIdentity: { machineId: pin.identity.machineId, sshHostKeySha256: pin.identity.sshHostKeySha256 },
            originalSnapshot: { configSha256: p.files.config.sha256, unitSha256: p.files.unit.sha256,
                serviceActive: p.service.ActiveState, serviceEnabled: p.service.UnitFileState } });
    });
    return { config: freeze(config), pins: freeze(pins), assertPins() { need(trustedRead(CONFIG).equals(raw) && trustedRead(RESTORE_CONFIG).equals(restoreRaw)
        && sha(trustedRead(BRIDGE)) === config.bridgeSha256 && sha(trustedRead(COORDINATOR)) === config.coordinatorSha256); } };
}
class RestorationPipe {
    #child; #closed = false; #pending; #buffer = ''; #tail = Promise.resolve();
    constructor(child) {
        this.#child = child;
        const lost = () => this.close();
        child.on('error', lost); child.on('exit', lost); child.stderr.on('data', lost);
        child.stdin.on('error', lost); child.stdout.on('error', lost); child.stdout.on('end', lost);
        child.stdout.on('data', raw => {
            if (this.#closed) return;
            this.#buffer += raw.toString('utf8');
            if (Buffer.byteLength(this.#buffer) > 4096) return lost();
            if (!this.#buffer.includes('\n')) return;
            try {
                const [line, extra] = this.#buffer.split('\n'); need(!extra && this.#buffer.indexOf('\n') === this.#buffer.length - 1);
                this.#buffer = ''; const reply = JSON.parse(line), pending = this.#pending;
                need(pending && exact(reply, ['version', 'op', 'nonce']) && reply.version === 1 && reply.op === 'checked' && reply.nonce === pending.nonce);
                this.#pending = undefined; clearTimeout(pending.timer); pending.resolve();
            } catch { lost(); }
        });
    }
    check() {
        const run = () => new Promise((resolve, reject) => {
            if (this.#closed) return reject(new Error('RESTORATION_PIPE_REVOKED'));
            const nonce = randomBytes(32).toString('hex');
            this.#pending = { nonce, resolve, reject, timer: setTimeout(() => this.close(), 15000) };
            this.#child.stdin.write(JSON.stringify({ version: 1, op: 'check', nonce }) + '\n');
        });
        const result = this.#tail.then(run); this.#tail = result.catch(() => {}); return result;
    }
    close() {
        if (this.#closed) return;
        this.#closed = true;
        if (this.#pending) { clearTimeout(this.#pending.timer); this.#pending.reject(new Error('RESTORATION_PIPE_REVOKED')); this.#pending = undefined; }
        this.#child.stdin.destroy(); this.#child.stdout.destroy(); this.#child.kill('SIGTERM');
    }
}
async function withOperationalRestoration(inputs, work, { openBridge } = {}) {
    // openBridge is an internal programmatic SIMULATED fixture seam only; the
    // fixed root executable supplies neither flags, commands nor callbacks.
    inputs.assertPins();
    const child = openBridge ? openBridge() : spawn('/usr/bin/python3', ['-I', BRIDGE], { stdio: ['pipe', 'pipe', 'pipe'],
        env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C', HOME: '/root' } });
    const pipe = new RestorationPipe(child);
    let open = true, poisoned = false;
    const check = async () => { try { need(open && !poisoned); inputs.assertPins(); await pipe.check(); need(open && !poisoned); inputs.assertPins(); } catch (e) { poisoned = true; throw e; } };
    const guarded = work => async (...args) => { try { return await work(...args); } catch (error) { poisoned = true; throw error; } };
    const scope = Object.freeze({ check,
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
    try { await check(); const result = await work(scope); await check(); return result; }
    finally { open = false; pipe.close(); }
}
module.exports = { operationalInputs, withOperationalRestoration, RestorationPipe };
