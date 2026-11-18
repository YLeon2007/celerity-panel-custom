'use strict';
const { AsyncLocalStorage } = require('node:async_hooks');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, topologyExecutionContext, matchesTopologyExecutionContext } = require('../domain/topologyExecutionContext');
const { failure } = require('../models/topologyExecutionBindingContract');

// This holder does NOT implement host exclusion. An external server controller
// must acquire and sustain old-PID/classic/bootstrap/alias/endpoint exclusion
// through withHeldAuthority(context, work), including awaited cleanup. Its scoped
// assertHeld must check revocation; withVerifiedAuthority uses the store's existing
// independently attested challenge contract. No environment or request adapter.
class TopologyExecutionAuthorityLifecycle {
    #controller;
    #context;
    #held = new AsyncLocalStorage();
    constructor({ executionContext, controller } = {}) {
        const context = topologyExecutionContext(executionContext?.target, executionContext?.hostIdentity);
        // Only TEST preserves the legacy undeclared-controller ABI. A declared
        // context is a server-side pairing contract, not physical attestation.
        if (!matchesTopologyExecutionContext(executionContext, context)
            || typeof controller?.withHeldAuthority !== 'function'
            || ((context !== TEST || 'executionContext' in controller)
                && !matchesTopologyExecutionContext(controller.executionContext, context))) throw failure();
        this.#context = context;
        this.#controller = controller;
    }
    get executionContext() { return this.#context; }
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
            await this.#controller.withHeldAuthority(this.#context, callback);
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
    async withTestBootstrapCancellation(request, work) {
        await this.assertHeld();
        const state = this.#held.getStore();
        if (this.#context !== TEST || typeof state.capability.withBootstrapCancellation !== 'function') throw failure();
        let invoked = false, open = true, pending, result;
        try {
            await state.capability.withBootstrapCancellation(request, (proof, externalCheck) => {
                if (!open || invoked || typeof externalCheck !== 'function') throw failure();
                invoked = true;
                const check = async () => { if (!open) throw failure(); await this.assertHeld(); await externalCheck(); if (!open) throw failure(); };
                pending = (async () => { await check(); result = await work(proof, check); await check(); })();
                pending.catch(() => {});
                return pending;
            });
            if (!invoked) throw failure();
            return result;
        } finally { open = false; if (pending) await pending.catch(() => {}); }
    }
    async withTestAbsentSuccessorCancellation(request, work) {
        await this.assertHeld(); const state=this.#held.getStore();
        if(this.#context!==TEST||typeof state.capability.withAbsentSuccessorCancellation!=='function')throw failure();
        let open=true,invoked=false,pending,result;
        try {
            await state.capability.withAbsentSuccessorCancellation(request,(proof,externalCheck)=>{
                if(!open||invoked||typeof externalCheck!=='function')throw failure();invoked=true;
                const check=async()=>{if(!open)throw failure();await this.assertHeld();await externalCheck();if(!open)throw failure();};
                pending=(async()=>{await check();result=await work(proof,check);await check();})();pending.catch(()=>{});return pending;
            });
            if(!invoked)throw failure();return result;
        } finally {open=false;if(pending)await pending.catch(()=>{});}
    }
    async withTestUndispatchedPreparation(bindings, work) {
        await this.assertHeld(); const state=this.#held.getStore();
        if(this.#context!==TEST||typeof state.capability.withUndispatchedPreparation!=='function')throw failure();
        let open=true,invoked=false,pending,result;
        try {
            await state.capability.withUndispatchedPreparation(bindings,(proof,externalCheck)=>{
                if(!open||invoked||typeof externalCheck!=='function')throw failure();invoked=true;
                const check=async()=>{if(!open)throw failure();await this.assertHeld();await externalCheck();if(!open)throw failure();};
                pending=(async()=>{await check();result=await work(proof,check);await check();})();pending.catch(()=>{});return pending;
            });
            if(!invoked)throw failure();return result;
        } finally {open=false;if(pending)await pending.catch(()=>{});}
    }
    async readUnclosedPair(bindings) {
        await this.assertHeld();
        const state = this.#held.getStore();
        if (this.#context.target !== 'production' || typeof state.capability.readUnclosedPair !== 'function') throw failure();
        const pair = await state.capability.readUnclosedPair(bindings);
        await this.assertHeld();
        return pair;
    }
    async withTestRetainedVerifyObservation(bindings, work) {
        await this.assertHeld();const state=this.#held.getStore();
        if(this.#context!==TEST||typeof state.capability.withRetainedVerifyObservation!=='function')throw failure();
        let open=true,invoked=false,pending,result;
        try {
            await state.capability.withRetainedVerifyObservation(bindings,(proof,externalCheck)=>{
                if(!open||invoked||typeof externalCheck!=='function')throw failure();invoked=true;
                const check=async()=>{if(!open)throw failure();await this.assertHeld();await externalCheck();if(!open)throw failure();};
                pending=(async()=>{await check();result=await work(proof,check);await check();})();pending.catch(()=>{});return pending;
            });
            if(!invoked)throw failure();return result;
        } finally {open=false;if(pending)await pending.catch(()=>{});}
    }
    async assertHeld() {
        const state = this.#held.getStore();
        if (!state?.open || state.revoked) throw failure();
        try { await state.capability.assertHeld(); }
        catch (cause) {
            state.revoked = true;
            const error = failure();
            error.cause = cause;
            throw error;
        }
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
    async withCapturedTestOwnerEnrollment(work) {
        if (this.#context !== TEST) throw failure();
        return this.#withCapturedOwnerEnrollment('withCapturedTestOwnerEnrollment', work);
    }
    async withCapturedOwnerEnrollment(work, preflight) {
        if (this.#context === TEST) throw failure();
        return this.#withCapturedOwnerEnrollment('withCapturedOwnerEnrollment', work, preflight);
    }
    async #withCapturedOwnerEnrollment(method, work, preflight) {
        await this.assertHeld();
        const state = this.#held.getStore();
        if (typeof state.capability[method] !== 'function') {
            state.revoked = true;
            const code = method === 'withCapturedTestOwnerEnrollment' ? 'TEST_DURABLE_ORIGINALS_CAPTURE_REQUIRED' : 'PRODUCTION_ORIGINALS_CAPTURE_REQUIRED';
            throw Object.assign(new Error(code), { code });
        }
        let invoked = false, finished = false, open = true, pending, result;
        const callback = (plan, externalCheck) => {
            if (!open || invoked || typeof externalCheck !== 'function') { state.revoked = true; throw failure(); }
            invoked = true;
            const check = async () => {
                try {
                    if (!open) throw failure();
                    await this.assertHeld(); await externalCheck(); await this.assertHeld();
                    if (!open) throw failure();
                } catch { state.revoked = true; throw failure(); }
            };
            pending = (async () => {
                await check(); result = await work(plan, check); await check(); finished = true; return result;
            })();
            pending.catch(() => {}); return pending;
        };
        try {
            await state.capability[method](callback, preflight === undefined ? undefined : async (plan, externalCheck, readProfile) => {
                if (!open || invoked || typeof externalCheck !== 'function') throw failure();
                const check = async () => { if (!open) throw failure(); await this.assertHeld(); await externalCheck(); await this.assertHeld(); if (!open) throw failure(); };
                const readClassicProfile = async nodeId => {
                    await check();
                    if (typeof readProfile !== 'function') throw failure();
                    const bytes = await readProfile(nodeId);
                    await check();
                    return bytes;
                };
                await check(); await preflight(plan, check, readClassicProfile); await check();
            });
            if (!invoked || !finished) throw failure();
            await this.assertHeld(); return result;
        } catch (error) {
            state.revoked = true;
            // Informational refusals still revoke the capability; retain their
            // bounded public diagnostics instead of hiding them as a fence loss.
            if (['CLASSIC_BASELINE_IMPORT_REFUSED', 'TOPOLOGY_BUSINESS_REENTRY_BLOCKED',
                'TOPOLOGY_REENTRY_POLICY_UNAVAILABLE'].includes(error?.code)) throw error;
            throw failure();
        }
        finally { open = false; if (pending) await pending.catch(() => {}); }
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
