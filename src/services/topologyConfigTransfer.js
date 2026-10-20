'use strict';
const { randomUUID } = require('node:crypto');
const {
    PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD,
    TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST,
    matchesTopologyExecutionContext,
} = require('../modules/relay-l2tp/domain/topologyExecutionContext');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const PROFILES = Object.freeze({
    'xray-main': Object.freeze({ configPath: '/usr/local/etc/xray/config.json', unitPath: '/etc/systemd/system/xray.service', service: 'xray' }),
    'xray-bridge': Object.freeze({ configPath: '/usr/local/etc/xray-bridge/config.json', unitPath: '/etc/systemd/system/xray-bridge.service', service: 'xray-bridge' }),
});
function failure(code) { return Object.assign(new Error(code), { code }); }
function snapshot(readback) {
    if (readback?.source !== 'node-readback'
        || !/^[a-f0-9]{64}$/.test(readback.configSha256)
        || !/^[a-f0-9]{64}$/.test(readback.unitSha256)
        || !['active', 'inactive'].includes(readback.serviceActive)
        || !['enabled', 'disabled', 'masked'].includes(readback.serviceEnabled)) {
        throw failure('CONFIG_TRANSFER_PROOF_INVALID');
    }
    const { configSha256, unitSha256, serviceActive, serviceEnabled } = readback;
    return { configSha256, unitSha256, serviceActive, serviceEnabled };
}
const { isDeepStrictEqual } = require('node:util');

// Dormant internal contract: no HTTP/MCP entry point or runtime wiring.
// See topologyConfigTransfer.md: classic writers do NOT yet hold a shared
// durable remote scope; PROD must stay QUIESCENCE_UNPROVEN, even with a row.
// withVerifiedMaintenance is an EXTERNAL authority, not a flag/DB marker. It
// must hold dispatch exclusion across callback + majority confirmation, including
// old backend PID/process-tree exit and revocation of its future dispatch.
class TopologyConfigTransfer {
    constructor({ executionContext, withVerifiedMaintenance, TopologyConfigOwner } = {}) {
        const context = [TEST, PROD].find(candidate => matchesTopologyExecutionContext(executionContext, candidate));
        if (!context) {
            throw new TypeError('Explicit server-owned TEST or production context required');
        }
        if (typeof withVerifiedMaintenance !== 'function') {
            throw new TypeError('External maintenance authority required');
        }
        Object.defineProperty(this, 'executionContext', { value: context, enumerable: true });
        this.withVerifiedMaintenance = withVerifiedMaintenance;
        this.Model = TopologyConfigOwner || require('../models/topologyConfigOwnerModel');
    }

    async #requireUniqueIndex() {
        // Index provisioning belongs to future startup/migration wiring. Do not
        // silently create a production adoption namespace from a request.
        let indexes;
        try { indexes = await this.Model.collection.indexes({ maxTimeMS: 5000 }); }
        catch { throw failure('CONFIG_OWNERSHIP_INDEX_REQUIRED'); }
        if (!indexes.some(index => isDeepStrictEqual(index.key, { node: 1, profile: 1 })
            && index.unique === true && !index.sparse && !index.partialFilterExpression)) {
            throw failure('CONFIG_OWNERSHIP_INDEX_REQUIRED');
        }
    }

    async initializeClassic({ node, profile, nodeIdentity }) {
        if (!Object.hasOwn(PROFILES, profile)) throw new TypeError('Unknown config profile');
        if (!/^[a-f0-9]{24}$/.test(node)) throw failure('CONFIG_TRANSFER_BINDING_INVALID');
        await this.#requireUniqueIndex();
        const generation = randomUUID();
        // Internal server inventory only; this never changes an existing owner.
        await this.Model.create([{ executionContext: this.executionContext, node, profile, nodeIdentity,
            owner: 'classic', generation }], { writeConcern: { w: 'majority' } });
        const confirmed = await this.Model.findOne({ executionContext: this.executionContext, node, profile, generation, owner: 'classic' })
            .read('primary').readConcern('majority').maxTimeMS(5000).lean();
        if (!confirmed) throw failure('CONFIG_TRANSFER_UNCONFIRMED');
        return confirmed;
    }

    async adopt(input) { return this.#transfer('adopt', input); }
    async handback(input) { return this.#transfer('handback', input); }

    async #transfer(action, { node, profile, generation, proofRef } = {}) {
        if (!/^[a-f0-9]{24}$/.test(node) || !Object.hasOwn(PROFILES, profile) || !UUID.test(generation)) {
            throw failure('CONFIG_TRANSFER_BINDING_INVALID');
        }
        if (typeof proofRef !== 'string' || !proofRef.trim() || proofRef.length > 1024) {
            throw failure('CONFIG_TRANSFER_PROOF_INVALID');
        }
        await this.#requireUniqueIndex();
        const nextOwner = action === 'adopt' ? 'topology' : 'classic';
        const query = { node, profile, executionContext: this.executionContext,
            owner: action === 'adopt' ? 'classic' : 'topology', generation };
        const row = await this.Model.findOne(query).read('primary').readConcern('majority').maxTimeMS(5000).lean();
        if (!row || !/^[a-f0-9]{32}$/.test(row.nodeIdentity?.machineId)
            || !/^[a-f0-9]{64}$/.test(row.nodeIdentity?.sshHostKeySha256)) {
            throw failure('CONFIG_OWNERSHIP_CONFLICT');
        }
        const binding = Object.freeze({ executionContext: this.executionContext, node, profile,
            nodeIdentity: Object.freeze({ ...row.nodeIdentity }), generation, nextGeneration: randomUUID(),
            action, paths: PROFILES[profile] });
        let invoked = false;
        let scopeOpen = true;
        let confirmed;
        const work = async proof => {
            if (!scopeOpen || invoked) throw failure('CONFIG_TRANSFER_PROOF_INVALID');
            invoked = true;
            if (proof?.status !== 'verified' || proof.authority !== 'external-maintenance-v1'
                || !UUID.test(proof.proofId) || !UUID.test(proof.maintenanceId)
                || !isDeepStrictEqual(proof.binding, binding)
                || proof.maintenance !== 'held' || proof.allWriters !== 'drained'
                || proof.oldBackend?.processTree !== 'stopped' || proof.oldBackend?.dispatch !== 'disabled'
                || typeof proof.oldBackend.instanceId !== 'string' || !proof.oldBackend.instanceId
                || !Number.isSafeInteger(proof.oldBackend.pid) || proof.oldBackend.pid < 1
                || typeof proof.oldBackend.processStartTime !== 'string' || !proof.oldBackend.processStartTime) {
                throw failure('CONFIG_TRANSFER_PROOF_INVALID');
            }
            const readback = snapshot(proof.readback);
            if (action === 'handback' && (!row.adoptionReceipt
                || row.adoptionReceipt.toGeneration !== generation
                || !isDeepStrictEqual(row.originalSnapshot, readback))) {
                throw failure('CONFIG_RESTORATION_MISMATCH');
            }
            const receipt = { proofId: proof.proofId, maintenanceId: proof.maintenanceId,
                fromGeneration: generation, toGeneration: binding.nextGeneration,
                oldBackendInstanceId: proof.oldBackend.instanceId, oldPid: proof.oldBackend.pid,
                oldProcessStartTime: proof.oldBackend.processStartTime, verifiedAt: new Date() };
            // External verification/remote reads NEVER run inside Mongo retry.
            await this.Model.db.transaction(async session => {
                if (!scopeOpen) throw failure('CONFIG_TRANSFER_PROOF_INVALID');
                const fence = { ...query, nodeIdentity: row.nodeIdentity,
                    ...(action === 'handback' ? { originalSnapshot: row.originalSnapshot, adoptionReceipt: row.adoptionReceipt } : {}) };
                const fields = action === 'adopt'
                    ? { originalSnapshot: readback, adoptionReceipt: receipt }
                    : { handbackReceipt: receipt };
                const updated = await this.Model.findOneAndUpdate(fence,
                    { $set: { owner: nextOwner, generation: binding.nextGeneration, ...fields },
                        ...(action === 'adopt' ? { $unset: { handbackReceipt: 1 } } : {}) },
                    { session, new: true, runValidators: true });
                if (!scopeOpen) throw failure('CONFIG_TRANSFER_PROOF_INVALID');
                if (!updated) throw failure('CONFIG_OWNERSHIP_CONFLICT');
            }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
            confirmed = await this.Model.findOne({ ...query, owner: nextOwner, generation: binding.nextGeneration })
                .read('primary').readConcern('majority').maxTimeMS(5000).lean();
            if (!confirmed) throw failure('CONFIG_TRANSFER_UNCONFIRMED');
        };
        try {
            await this.withVerifiedMaintenance({ binding, proofRef }, work);
        } finally { scopeOpen = false; }
        // An authority returning a boolean/row without executing the held scope
        // cannot manufacture a verified transition.
        if (!invoked || !confirmed) throw failure('CONFIG_TRANSFER_PROOF_INVALID');
        return confirmed;
    }
}
module.exports = { TopologyConfigTransfer };
