'use strict';
// Explicit internal TEST entry. Uses the existing public handback CAS unchanged.
// Never clears uncertain locks/admissions or history; handback enables only
// the explicitly bounded classic backend after the durable all-five commit.
const { createHash } = require('node:crypto');
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const { isDeepStrictEqual: same } = require('node:util');
const { TopologyConfigTransfer } = require('./topologyConfigTransfer');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../modules/relay-l2tp/domain/topologyExecutionContext');
const { UUID, exact, freeze } = require('../modules/relay-l2tp/models/topologyExecutionBindingContract');
const NODES = Object.freeze({
    '6ab18adc63913ebd4a917471': 'xray-main', '6ab93ad2646b4b7d2f43c907': 'xray-main',
    '6ab18d9c63913ebd4a917670': 'xray-bridge', '6ab4b53bc4c0304573e06c72': 'xray-bridge',
    '6ab189dc63913ebd4a917399': 'xray-bridge',
});
const OPT = { maxTimeMS: 5000, timeoutMS: 5000 };
function need(ok) { if (!ok) throw Object.assign(new Error('TEST_OWNER_SETTLEMENT_UNKNOWN_RETAINED'), { code: 'TEST_OWNER_SETTLEMENT_UNKNOWN_RETAINED' }); }
const uuid = value => typeof value === 'string' && UUID.test(value);
// Consume the EXISTING accepted-test-v1 inventory (same canonical digest as
// isolation/capture). Only trusted root inputs supply it, never the plan/env.
function settlementInventory(inventory, inventorySha256) {
    if (inventory === undefined && inventorySha256 === undefined) return undefined;
    const canonical = value => JSON.stringify(value, (_key, v) => v && !Array.isArray(v) && typeof v === 'object'
        ? Object.fromEntries(Object.keys(v).sort().map(k => [k, v[k]])) : v);
    const digest = (value, size) => typeof value === 'string' && new RegExp(`^[a-f0-9]{${size}}$`).test(value);
    need(digest(inventorySha256, 64) && exact(inventory, ['version', 'profile', 'executionContext', 'nodes', 'sharedNodeId'])
        && inventory.version === 1 && inventory.profile === 'accepted-test-v1' && same(inventory.executionContext, TEST)
        && Array.isArray(inventory.nodes) && inventory.nodes.length >= 1 && inventory.nodes.length <= 5
        && createHash('sha256').update(canonical(inventory)).digest('hex') === inventorySha256);
    const ids = new Set(), machines = new Set(), keys = new Set(), endpoints = new Set();
    for (const p of inventory.nodes) {
        need(exact(p, ['nodeId', 'targetProfile', 'endpoint', 'physical', 'profiles']) && digest(p.nodeId, 24) && !ids.has(p.nodeId)
            && ['xray-main', 'xray-bridge'].includes(p.targetProfile)); ids.add(p.nodeId);
        const ip = p.endpoint?.ip;
        need(exact(p.endpoint, ['ip', 'port', 'username']) && typeof ip === 'string' && require('node:net').isIPv4(ip)
            && (ip.startsWith('10.') || ip.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip))
            && p.endpoint.port === 2222 && p.endpoint.username === 'c3-test-runner' && !endpoints.has(ip)); endpoints.add(ip);
        need(exact(p.physical, ['machineId', 'bootId', 'sshHostKeySha256']) && digest(p.physical.machineId, 32)
            && uuid(p.physical.bootId) && digest(p.physical.sshHostKeySha256, 64)
            && !machines.has(p.physical.machineId) && !keys.has(p.physical.sshHostKeySha256));
        machines.add(p.physical.machineId); keys.add(p.physical.sshHostKeySha256);
        need(same(p.profiles, [p.targetProfile]) || same(p.profiles, ['xray-main', 'xray-bridge']));
    }
    const shared = inventory.nodes.find(p => p.nodeId === inventory.sharedNodeId);
    need(shared?.targetProfile === 'xray-bridge' && same(shared.profiles, ['xray-main', 'xray-bridge']));
    return freeze(structuredClone(inventory));
}
class HeldTestOwnerSettlement {
    #models; #authority; #journal; #freshUsed = false; #inventory; #nodes;
    constructor({ withRestorationScope, models, journal, inventory, inventorySha256 } = {}) {
        if (typeof withRestorationScope !== 'function') throw new TypeError('Trusted continuously-live restoration scope required');
        const names = ['Owner', 'Enrollment', 'Binding', 'Operation', 'Lock', 'Topology', 'Intent', 'Queue', 'Link', 'L2tpOperation'];
        need(models && names.every(name => models[name]?.db && typeof models[name].findOne === 'function')
            && new Set(names.map(name => models[name].db)).size === 1);
        const client = models.Owner.db.getClient();
        need(!client.options.directConnection && client.topology?.description?.type === 'ReplicaSetWithPrimary');
        need(journal && ['start', 'beforeNode', 'afterNode', 'complete'].every(key => typeof journal[key] === 'function'));
        this.#inventory = settlementInventory(inventory, inventorySha256);
        this.#nodes = this.#inventory ? Object.fromEntries(this.#inventory.nodes.map(p => [p.nodeId, p.targetProfile])) : NODES;
        this.#models = Object.freeze({ ...models }); this.#authority = withRestorationScope; this.#journal = journal;
    }
    async settle(input) { return this.#run(input, false); }
    async handback(input) { return this.#run(input, true); }
    async freshHandback(input) {
        if (this.#freshUsed) throw Object.assign(new Error('FRESH_REPLAY_FORBIDDEN'), { code: 'FRESH_REPLAY_FORBIDDEN' });
        this.#freshUsed = true;
        return this.#run(input, 'fresh');
    }
    async #run(input, combined) {
        need(exact(input, ['nodes', 'revision', 'deployedRevision'])
            && Array.isArray(input.nodes) && input.nodes.length === Object.keys(this.#nodes).length
            && new Set(input.nodes.map(n => n.nodeId)).size === input.nodes.length
            && input.nodes.every(n => exact(n, ['nodeId', 'targetProfile', 'enrollmentId', 'ownerGeneration'])
                && Object.hasOwn(this.#nodes, n.nodeId) && n.targetProfile === this.#nodes[n.nodeId]
                && uuid(n.enrollmentId) && uuid(n.ownerGeneration))
            && [input.revision, input.deployedRevision].every(n => Number.isSafeInteger(n) && n >= 0));
        const plan = freeze(structuredClone(input));
        let open = true, invoked = false, finished = false, pending, result;
        const callback = scope => {
            need(open && !invoked); invoked = true;
            pending = (async () => {
                need(scope && typeof scope.check === 'function' && typeof scope.withVerifiedMaintenance === 'function'
                    && typeof scope.verifyEnrollment === 'function');
                let poisoned = false;
                const check = async () => { try { need(open && !poisoned); await scope.check(); need(open && !poisoned); } catch (e) { poisoned = true; throw e; } };
                const awaited = async promise => { const result = await promise; await check(); return result; };
                await check();
                const m = this.#models;
                const rows = (Model, filter = {}) => Model.find(filter).read('primary').readConcern('majority').setOptions(OPT).limit(1001).lean()
                    .then(found => { need(found.length <= 1000); return found; });
                let quietSha256;
                const quiet = async () => {
                    await check();
                    // One awaited read-only batch, followed immediately by a
                    // fresh all-five held check. External exclusion, not these
                    // snapshots, is the execution-spanning writer fence.
                    const [states, locks, operations, intents, l2tp, links, queues] = await awaited(Promise.all([
                        rows(m.Topology, { _id: 'singleton' }), rows(m.Lock), rows(m.Operation), rows(m.Intent),
                        rows(m.L2tpOperation), rows(m.Link), rows(m.Queue),
                    ]));
                    const state = states[0];
                    need(states.length === 1 && state.revision === plan.revision && state.deployedRevision === plan.deployedRevision
                        && state.topologyAdmissionCount === 0 && state.remoteAdmissionCount === 0
                        && state.remoteDrain === undefined && state.replacementReservation === undefined);
                    // Any outstanding lock (including expired/uncertain/foreign),
                    // queued operation or retained admission must be reconciled by
                    // its existing finalizer first, never invented away here.
                    need(locks.length === 0);
                    need(operations.every(o => ['succeeded', 'failed', 'rolled_back'].includes(o.status)
                        && o.heldTopologyAdmission === false));
                    need(intents.every(o => ['succeeded', 'failed'].includes(o.status)));
                    need(l2tp.every(o => ['succeeded', 'failed', 'rolled_back', 'cancelled'].includes(o.status)));
                    need(links.every(link => typeof link.active === 'boolean'
                        && (!link.active || ['deployed', 'online', 'offline'].includes(link.status))));
                    need(queues.length === 1 && queues[0]._id === 'create-v1' && queues[0].outstanding === 0);
                    quietSha256 = sha([states, locks, operations, intents, l2tp, links, queues]);
                    await check();
                };
                await quiet();
                const enrollments = [], originals = [];
                for (const n of plan.nodes) {
                    const [entries, owners] = await awaited(Promise.all([rows(m.Enrollment, { nodeId: n.nodeId }),
                        rows(m.Owner, { node: n.nodeId, profile: n.targetProfile })]));
                    const e = entries[0], owner = owners[0];
                    need(entries.length === 1 && e._id === n.enrollmentId && e.executionContext === TEST.hostIdentity
                        && e.targetProfile === n.targetProfile && e.ownerGeneration === n.ownerGeneration
                        && owners.length === 1 && same(owner.executionContext, TEST) && owner.owner === 'topology'
                        && owner.generation === n.ownerGeneration && same(e.nodeIdentity, owner.nodeIdentity)
                        && owner.adoptionReceipt?.toGeneration === n.ownerGeneration && owner.handbackReceipt === undefined);
                    if (this.#inventory) {
                        const p = this.#inventory.nodes.find(p => p.nodeId === n.nodeId);
                        need(same(e.endpoint, p.endpoint) && e.bootId === p.physical.bootId
                            && same(e.nodeIdentity, { machineId: p.physical.machineId, sshHostKeySha256: p.physical.sshHostKeySha256 }));
                    }
                    await awaited(scope.verifyEnrollment(e));
                    enrollments.push(e); originals.push(owner);
                }
                // A durable no-replay intent precedes the FIRST owner CAS. A
                // partial/unknown run can never auto-adopt or resume on startup.
                await awaited(this.#journal.start(plan));
                const transfer = new TopologyConfigTransfer({ executionContext: TEST, TopologyConfigOwner: m.Owner,
                    withVerifiedMaintenance: (challenge, work) => scope.withVerifiedMaintenance(challenge, work) });
                const confirmed = [];
                for (let index = 0; index < plan.nodes.length; index++) {
                    const n = plan.nodes[index];
                    await quiet();
                    await awaited(this.#journal.beforeNode(n.nodeId));
                    const owner = await awaited(transfer.handback({ node: n.nodeId, profile: n.targetProfile,
                        generation: n.ownerGeneration, proofRef: n.enrollmentId }));
                    need(owner.owner === 'classic' && owner.generation !== n.ownerGeneration
                        && owner.handbackReceipt?.fromGeneration === n.ownerGeneration
                        && owner.handbackReceipt.toGeneration === owner.generation
                        && same(owner.originalSnapshot, originals[index].originalSnapshot)
                        && same(owner.adoptionReceipt, originals[index].adoptionReceipt));
                    confirmed.push(owner);
                    await awaited(this.#journal.afterNode(n.nodeId, owner.generation));
                }
                await quiet();
                for (let i = 0; i < plan.nodes.length; i++) {
                    const n = plan.nodes[i];
                    const [current, currentEnrollment] = await awaited(Promise.all([
                        rows(m.Owner, { node: n.nodeId, profile: n.targetProfile }), rows(m.Enrollment, { _id: n.enrollmentId }),
                    ]));
                    need(current.length === 1 && same(current[0], confirmed[i]));
                    need(currentEnrollment.length === 1 && same(currentEnrollment[0], enrollments[i]));
                }
                await awaited(this.#journal.complete());
                result = freeze({ code: 'TEST_DB_SETTLED_ALL_EXTERNAL_HOLDS_RETAINED', ownerCount: plan.nodes.length,
                    outstandingLocks: 0, topologyAdmissionCount: 0, remoteAdmissionCount: 0,
                    handbackAllowed: false, externalAdmission: 'closed' });
                await check();
                if (combined) {
                    need((combined === 'fresh' ? typeof scope.freshHandback === 'function' :
                        ['commitHandoff', 'activateClassic', 'completeHandoff'].every(k => typeof scope[k] === 'function'))
                        && typeof this.#journal.committed === 'function');
                    await quiet();
                    const proof = JSON.parse(JSON.stringify({ context: TEST.hostIdentity,
                        revision: plan.revision, deployedRevision: plan.deployedRevision, quietSha256,
                        nodes: plan.nodes.map((n, i) => ({ nodeId: n.nodeId, targetProfile: n.targetProfile,
                            enrollmentId: n.enrollmentId, enrollmentSha256: sha(enrollments[i]),
                            priorOwnerGeneration: n.ownerGeneration, owner: confirmed[i] })) }));
                    if (combined === 'fresh') {
                        // One terminal capability after the unchanged all-five CAS/readbacks.
                        // It releases h: NO subsequent check/legacy activation/complete call.
                        try {
                            // Selection comes from the trusted root scope, never
                            // from public request keys or the returned shape.
                            const networkOwned = scope.freshNetworkOwnershipRequired === true;
                            const terminal = await scope.freshHandback(freeze(proof));
                            const commitSha256 = networkOwned ? terminal?.commitSha256 : terminal;
                            need(typeof commitSha256 === 'string' && /^[a-f0-9]{64}$/.test(commitSha256));
                            if (networkOwned) need(exact(terminal, ['commitSha256', 'networkOwnershipSha256'])
                                && typeof terminal.networkOwnershipSha256 === 'string' && /^[a-f0-9]{64}$/.test(terminal.networkOwnershipSha256));
                            await this.#journal.committed(commitSha256);
                            result = freeze({ code: networkOwned ? 'COMMITTED_FRESH_NETWORK_OWNED' : 'COMMITTED_FRESH_ACTIVATION_CONFIRMED', ownerCount: plan.nodes.length,
                                externalAdmission: 'closed', activationSet: ['fresh-classic-process'],
                                retained: ['node-masks', 'candidate', 'docker', 'containerd', 'updater', 'relaunch-barriers'], commitSha256,
                                ...(networkOwned ? { networkOwnershipSha256: terminal.networkOwnershipSha256 } : {}) });
                            finished = true; return result;
                        } catch (error) {
                            error.code = 'COMMITTED_ACTIVATION_UNKNOWN';
                            throw error; // sent terminal may have executed; never no-activation
                        }
                    }
                    let committed = false, attempted = false;
                    try {
                        attempted = true;
                        const commitSha256 = await scope.commitHandoff(freeze(proof));
                        need(typeof commitSha256 === 'string' && /^[a-f0-9]{64}$/.test(commitSha256));
                        committed = true; // file/parent fsync + exact readback, before writer enable
                        await check();
                        await this.#journal.committed(commitSha256);
                        await check();
                        await scope.activateClassic();
                        await check();
                        await scope.completeHandoff();
                        result = freeze({ code: 'COMMITTED_BOUNDED_ACTIVATION_CONFIRMED', ownerCount: plan.nodes.length,
                            externalAdmission: 'closed', activationSet: ['existing-classic-backend'],
                            retained: ['node-masks', 'candidate', 'docker', 'containerd', 'updater', 'relaunch-barriers'], commitSha256 });
                    } catch (error) {
                        error.code = committed ? 'COMMITTED_ACTIVATION_UNKNOWN' :
                            (attempted ? 'COMMIT_UNKNOWN_NO_ACTIVATION' : 'TEST_OWNER_SETTLEMENT_UNKNOWN_RETAINED');
                        throw error;
                    }
                }
                finished = true; return result;
            })();
            pending.catch(() => {}); return pending;
        };
        try { await this.#authority(callback); need(invoked && finished); return result; }
        finally { open = false; if (pending) await pending.catch(() => {}); }
    }
}
module.exports = { HeldTestOwnerSettlement, NODES, settlementInventory };
