'use strict';
// Explicit internal TEST entry. Uses the existing public handback CAS unchanged.
// Does not clear an uncertain lock/admission, rewrite history, or release hosts.
const { isDeepStrictEqual: same } = require('node:util');
const { TopologyConfigTransfer } = require('./topologyConfigTransfer');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../modules/relay-l2tp/domain/topologyExecutionContext');
const { UUID, exact, freeze } = require('../modules/relay-l2tp/models/topologyExecutionBindingContract');
const NODES = Object.freeze({
    '6ab18adc63913ebd4a917471': 'xray-main', '6ab93ad2646b4b7d2f43c907': 'xray-main',
    '6ab18d9c63913ebd4a917670': 'xray-bridge', '6ab4b53bc4c0304573e06c72': 'xray-bridge',
    '6ab189dc63913ebd4a917399': 'xray-main',
});
const OPT = { maxTimeMS: 5000, timeoutMS: 5000 };
function need(ok) { if (!ok) throw Object.assign(new Error('TEST_OWNER_SETTLEMENT_UNKNOWN_RETAINED'), { code: 'TEST_OWNER_SETTLEMENT_UNKNOWN_RETAINED' }); }
const uuid = value => typeof value === 'string' && UUID.test(value);
class HeldTestOwnerSettlement {
    #models; #authority; #journal;
    constructor({ withRestorationScope, models, journal } = {}) {
        if (typeof withRestorationScope !== 'function') throw new TypeError('Trusted continuously-live restoration scope required');
        const names = ['Owner', 'Enrollment', 'Binding', 'Operation', 'Lock', 'Topology', 'Intent', 'Queue', 'Link', 'L2tpOperation'];
        need(models && names.every(name => models[name]?.db && typeof models[name].findOne === 'function')
            && new Set(names.map(name => models[name].db)).size === 1);
        const client = models.Owner.db.getClient();
        need(!client.options.directConnection && client.topology?.description?.type === 'ReplicaSetWithPrimary');
        need(journal && ['start', 'beforeNode', 'afterNode', 'complete'].every(key => typeof journal[key] === 'function'));
        this.#models = Object.freeze({ ...models }); this.#authority = withRestorationScope; this.#journal = journal;
    }
    async settle(input) {
        need(exact(input, ['nodes', 'revision', 'deployedRevision'])
            && Array.isArray(input.nodes) && input.nodes.length === 5
            && new Set(input.nodes.map(n => n.nodeId)).size === 5
            && input.nodes.every(n => exact(n, ['nodeId', 'targetProfile', 'enrollmentId', 'ownerGeneration'])
                && Object.hasOwn(NODES, n.nodeId) && n.targetProfile === NODES[n.nodeId]
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
                result = freeze({ code: 'TEST_DB_SETTLED_ALL_EXTERNAL_HOLDS_RETAINED', ownerCount: 5,
                    outstandingLocks: 0, topologyAdmissionCount: 0, remoteAdmissionCount: 0,
                    handbackAllowed: false, externalAdmission: 'closed' });
                await check(); finished = true; return result;
            })();
            pending.catch(() => {}); return pending;
        };
        try { await this.#authority(callback); need(invoked && finished); return result; }
        finally { open = false; if (pending) await pending.catch(() => {}); }
    }
}
module.exports = { HeldTestOwnerSettlement, NODES };
