'use strict';

const { randomUUID } = require('node:crypto');

// The injector must run a real client ingress→default exit check (not a config,
// listener, PPP, or user-row check), return {passed:true} only on positive proof,
// and honor the AbortSignal. This worker deliberately has no runtime side effects.
class TopologyClientReadinessWorker {
    constructor({ repository, probeOperation, owner = randomUUID(), now = () => new Date(),
        leaseMs = 120000, probeTimeoutMs = 30000, retryMs = 60000 } = {}) {
        if (!repository?.claimNextClientProof || !repository?.completeClientProof
            || !owner || probeOperation !== undefined && typeof probeOperation !== 'function'
            || !Number.isSafeInteger(probeTimeoutMs) || probeTimeoutMs < 1
            || !Number.isSafeInteger(leaseMs) || leaseMs <= probeTimeoutMs
            || !Number.isSafeInteger(retryMs) || retryMs < 1) {
            throw new TypeError('Invalid client readiness worker dependencies');
        }
        Object.assign(this, { repository, probeOperation, owner, now, leaseMs, probeTimeoutMs, retryMs });
    }

    async runOnce() {
        const operation = await this.repository.claimNextClientProof({
            owner: this.owner, now: this.now(), leaseMs: this.leaseMs,
        });
        if (!operation) return null;
        let passed = false;
        let reason = 'probe_unavailable';
        if (this.probeOperation) {
            const controller = new AbortController();
            let timer;
            try {
                const result = await Promise.race([
                    Promise.resolve().then(() => this.probeOperation(operation, { signal: controller.signal })),
                    new Promise((_, reject) => {
                        timer = setTimeout(() => {
                            controller.abort();
                            reject(new Error('client proof timed out'));
                        }, this.probeTimeoutMs);
                    }),
                ]);
                passed = result?.passed === true;
                reason = 'probe_failed';
            } catch (_) {
                // Never persist/log exception text, returned diagnostics, or credentials.
            } finally {
                clearTimeout(timer);
                controller.abort();
            }
        }
        return this.repository.completeClientProof({ operation, owner: this.owner,
            now: this.now(), passed, reason, retryMs: this.retryMs });
    }
}

module.exports = { TopologyClientReadinessWorker };
