'use strict';

const { randomUUID } = require('node:crypto');
const { topologyExecutionContext, matchesTopologyExecutionContext } = require('../domain/topologyExecutionContext');
const { matchesTopologyOperationClaimBinding } = require('../domain/topologyOperationClaimBinding');

// The injector must run a real client ingress→default exit check (not a config,
// listener, PPP, or user-row check), return {passed:true} only on positive proof,
// and honor the AbortSignal. This worker deliberately has no runtime side effects.
class TopologyClientReadinessWorker {
    constructor({ repository, probeOperation, executionContext, owner = randomUUID(), now = () => new Date(),
        leaseMs = 120000, probeTimeoutMs = 30000, retryMs = 60000 } = {}) {
        const context = topologyExecutionContext(executionContext?.target, executionContext?.hostIdentity);
        if (!matchesTopologyExecutionContext(executionContext, context)) {
            throw new TypeError('Client readiness worker requires an exact execution context');
        }
        if (!repository?.claimNextClientProof || !repository?.completeClientProof
            || !owner || typeof now !== 'function' || probeOperation !== undefined && typeof probeOperation !== 'function'
            || !Number.isSafeInteger(probeTimeoutMs) || probeTimeoutMs < 1
            || !Number.isSafeInteger(leaseMs) || leaseMs <= probeTimeoutMs
            || !Number.isSafeInteger(retryMs) || retryMs < 1) {
            throw new TypeError('Invalid client readiness worker dependencies');
        }
        Object.assign(this, { repository, probeOperation, owner, now, leaseMs, probeTimeoutMs, retryMs });
        Object.defineProperty(this, 'executionContext', { value: context, enumerable: true });
    }

    hasCurrentClaim(operation) {
        return matchesTopologyOperationClaimBinding(operation, this.executionContext)
            && operation.status === 'succeeded' && operation.clientReadiness === 'unverified'
            && !(operation.kind === 'link.apply' && operation.staged === true && operation.admissionScope !== 'selected')
            && [undefined, 'selected'].includes(operation.admissionScope)
            && (operation.admissionScope !== 'selected' || operation.heldTopologyAdmission === false
                && typeof operation.admissionFingerprint === 'string'
                && /^[a-f0-9]{64}$/.test(operation.admissionFingerprint)
                && ['complete', 'no_portal_input'].includes(operation.routeState))
            && Number.isSafeInteger(operation.clientProofAttempts)
            && operation.clientProofAttempts >= 1 && operation.clientProofAttempts <= 3
            && operation.clientProofLeaseOwner === this.owner
            && operation.clientProofLeaseUntil instanceof Date
            && operation.clientProofLeaseUntil > this.now();
    }

    async runOnce() {
        const operation = await this.repository.claimNextClientProof({
            executionContext: this.executionContext,
            owner: this.owner, now: this.now(), leaseMs: this.leaseMs,
        });
        if (!this.hasCurrentClaim(operation)) return null;
        let passed = false;
        let proof;
        let reason = 'probe_unavailable';
        if (this.probeOperation) {
            const controller = new AbortController();
            let timer;
            try {
                const result = await Promise.race([
                    Promise.resolve().then(() => this.hasCurrentClaim(operation)
                        ? this.probeOperation(operation, { signal: controller.signal }) : undefined),
                    new Promise((_, reject) => {
                        timer = setTimeout(() => {
                            controller.abort();
                            reject(new Error('client proof timed out'));
                        }, this.probeTimeoutMs);
                    }),
                ]);
                passed = result?.passed === true;
                proof = result;
                reason = 'probe_failed';
            } catch (_) {
                // Never persist/log exception text, returned diagnostics, or credentials.
            } finally {
                clearTimeout(timer);
                controller.abort();
            }
        }
        if (!this.hasCurrentClaim(operation)) return null;
        return this.repository.completeClientProof({ operation, owner: this.owner, executionContext: this.executionContext,
            now: this.now(), getNow: this.now, passed, proof, reason, retryMs: this.retryMs });
    }
}

module.exports = { TopologyClientReadinessWorker };
