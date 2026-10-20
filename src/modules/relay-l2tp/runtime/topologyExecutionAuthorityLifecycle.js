'use strict';
const { AsyncLocalStorage } = require('node:async_hooks');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, matchesTopologyExecutionContext } = require('../domain/topologyExecutionContext');
const { failure } = require('../models/topologyExecutionBindingContract');

// This holder does NOT implement host exclusion. An external server controller
// must acquire and sustain old-PID/classic/bootstrap/alias/endpoint exclusion
// through withHeldAuthority(context, work), including awaited cleanup. Its scoped
// assertHeld must check revocation; withVerifiedAuthority uses the store's existing
// independently attested challenge contract. No environment or request adapter.
class TopologyExecutionAuthorityLifecycle {
    #controller;
    #held = new AsyncLocalStorage();
    constructor({ executionContext, controller } = {}) {
        if (!matchesTopologyExecutionContext(executionContext, TEST)
            || typeof controller?.withHeldAuthority !== 'function') throw failure();
        this.#controller = controller;
    }
    async run(work) {
        let invoked = false, finished = false, open = true, pending, result, scope;
        const callback = capability => {
            if (!open || invoked || typeof capability?.assertHeld !== 'function'
                || typeof capability?.withVerifiedAuthority !== 'function') throw failure();
            invoked = true;
            const state = scope = { open: true, revoked: false, capability };
            pending = this.#held.run(state, async () => {
                try {
                    await this.assertHeld();
                    result = await work();
                    await this.assertHeld();
                    finished = true;
                    return result;
                } finally { state.open = false; }
            });
            pending.catch(() => {});
            return pending;
        };
        try {
            await this.#controller.withHeldAuthority(TEST, callback);
            if (!invoked || !finished) throw failure();
            return result;
        } finally {
            open = false;
            if (scope) scope.open = false;
            // A controller returning without awaiting revokes escaped callbacks.
            // Wait for their local work to join without treating it as authority.
            if (pending) await pending.catch(() => {});
        }
    }
    async assertHeld() {
        const state = this.#held.getStore();
        if (!state?.open || state.revoked) throw failure();
        try { await state.capability.assertHeld(); }
        catch { state.revoked = true; throw failure(); }
        if (!state.open || state.revoked) throw failure();
    }
    async withVerifiedPreinstalledRunner(challenge, work) {
        await this.assertHeld();
        const state = this.#held.getStore();
        if (typeof state.capability.withVerifiedPreinstalledRunner !== 'function') {
            state.revoked = true;
            throw failure();
        }
        let invoked = false, finished = false, open = true, pending, result;
        const callback = (proof, externalCheck) => {
            if (!open || invoked || typeof externalCheck !== 'function') {
                state.revoked = true;
                throw failure();
            }
            invoked = true;
            let callbackOpen = true;
            const check = async () => {
                if (!open || !callbackOpen) throw failure();
                await this.assertHeld();
                try { await externalCheck(); }
                catch { state.revoked = true; throw failure(); }
                await this.assertHeld();
                if (!open || !callbackOpen) throw failure();
            };
            pending = (async () => {
                try {
                    await check();
                    result = await work(proof, check);
                    await check();
                    finished = true;
                    return result;
                } finally { callbackOpen = false; }
            })();
            pending.catch(() => {});
            return pending;
        };
        try {
            await state.capability.withVerifiedPreinstalledRunner(challenge, callback);
            if (!invoked || !finished) throw failure();
            await this.assertHeld();
            return result;
        } catch {
            state.revoked = true;
            throw failure();
        } finally {
            open = false;
            if (pending) await pending.catch(() => {});
        }
    }
    async withVerifiedMaintenance(challenge, work) {
        await this.assertHeld();
        const state = this.#held.getStore();
        if (typeof state.capability.withVerifiedMaintenance !== 'function') {
            state.revoked = true;
            throw failure();
        }
        let invoked = false, finished = false, open = true, pending, result;
        const callback = (proof, externalCheck) => {
            if (!open || invoked || typeof externalCheck !== 'function') {
                state.revoked = true;
                throw failure();
            }
            invoked = true;
            let callbackOpen = true;
            const check = async () => {
                if (!open || !callbackOpen) throw failure();
                await this.assertHeld();
                try { await externalCheck(); }
                catch { state.revoked = true; throw failure(); }
                await this.assertHeld();
                if (!open || !callbackOpen) throw failure();
            };
            pending = (async () => {
                try {
                    await check(); result = await work(proof, check); await check();
                    finished = true; return result;
                } finally { callbackOpen = false; }
            })();
            pending.catch(() => {});
            return pending;
        };
        try {
            await state.capability.withVerifiedMaintenance(challenge, callback);
            if (!invoked || !finished) throw failure();
            await this.assertHeld(); return result;
        } catch {
            state.revoked = true; throw failure();
        } finally {
            open = false;
            if (pending) await pending.catch(() => {});
        }
    }
    async withVerifiedAuthority(challenge, work) {
        await this.assertHeld();
        const state = this.#held.getStore();
        const result = await state.capability.withVerifiedAuthority(challenge, async proof => {
            await this.assertHeld();
            const result = await work(proof);
            await this.assertHeld();
            return result;
        });
        await this.assertHeld();
        return result;
    }
}
module.exports = { TopologyExecutionAuthorityLifecycle };
