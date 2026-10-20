'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { AsyncResource } = require('node:async_hooks');
const { TopologyExecutionAuthorityLifecycle: Lifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const { failure } = require('../models/topologyExecutionBindingContract');
function simulatedController() {
    let held = false, revoked = false, calls = 0;
    return {
        controller: { async withHeldAuthority(context, work) {
            assert.strictEqual(context, TEST); assert.equal(held, false); held = true;
            try { return await work({ async assertHeld() { if (!held || revoked) throw failure(); },
                async withVerifiedAuthority(challenge, work) { calls++; return work({ challenge }); } }); }
            finally { held = false; }
        } },
        revoke() { revoked = true; }, restore() { revoked = false; }, calls: () => calls,
    };
}
test('TEST lifecycle refuses absent, malformed and PROD controllers', () => {
    for (const options of [{}, { executionContext: PROD, controller: simulatedController().controller },
        { executionContext: TEST, controller: true }, { executionContext: { ...TEST, extra: true }, controller: simulatedController().controller }]) {
        assert.throws(() => new Lifecycle(options));
    }
});
test('held lifecycle joins multiple authority calls and rejects escaped async contexts', async () => {
    const f = simulatedController(), lifecycle = new Lifecycle({ executionContext: TEST, controller: f.controller });
    let escaped;
    await assert.rejects(lifecycle.withVerifiedAuthority({}, () => {}));
    assert.equal(await lifecycle.run(async () => {
        escaped = new AsyncResource('escaped-held-capability');
        assert.deepEqual(await lifecycle.withVerifiedAuthority({ nonce: 'first' }, proof => proof), { challenge: { nonce: 'first' } });
        await lifecycle.withVerifiedAuthority({ nonce: 'second' }, async () => lifecycle.assertHeld());
        return 'joined';
    }), 'joined');
    assert.equal(f.calls(), 2);
    try { await assert.rejects(escaped.runInAsyncScope(() => lifecycle.withVerifiedAuthority({}, () => {}))); }
    finally { escaped.emitDestroy(); }
});
test('revocation is sticky within a held scope even if controller later recovers', async () => {
    const f = simulatedController(), lifecycle = new Lifecycle({ executionContext: TEST, controller: f.controller });
    await assert.rejects(lifecycle.run(async () => {
        await lifecycle.assertHeld(); f.revoke();
        await assert.rejects(lifecycle.assertHeld()); f.restore();
        await assert.rejects(lifecycle.withVerifiedAuthority({}, () => assert.fail('revoked authority invoked')));
    }));
    assert.equal(f.calls(), 0);
});
test('controller returning before callback completion revokes and joins its pending work', async () => {
    let release, joined = false;
    const gate = new Promise(resolve => { release = resolve; });
    const lifecycle = new Lifecycle({ executionContext: TEST, controller: {
        async withHeldAuthority(context, work) {
            work({ async assertHeld() {}, async withVerifiedAuthority(challenge, work) { return work({ challenge }); } });
            release();
        },
    } });
    await assert.rejects(lifecycle.run(async () => {
        await gate;
        await new Promise(resolve => setImmediate(resolve));
        try { await assert.rejects(lifecycle.assertHeld()); } finally { joined = true; }
    }));
    assert.equal(joined, true);
});

test('runner attestor checks are sticky and cannot escape their callback or outer authority scope', async () => {
    let runnerRevoked = false, savedCheck, escaped;
    const lifecycle = new Lifecycle({ executionContext: TEST, controller: {
        async withHeldAuthority(context, work) {
            return work({ async assertHeld() {}, async withVerifiedAuthority() {},
                async withVerifiedPreinstalledRunner(challenge, work) {
                    return work({ simulated: true }, async () => { if (runnerRevoked) throw failure(); });
                } });
        },
    } });
    await assert.rejects(lifecycle.withVerifiedPreinstalledRunner({}, () => assert.fail()));
    await assert.rejects(lifecycle.run(async () => {
        await lifecycle.withVerifiedPreinstalledRunner({}, async (proof, check) => {
            assert.deepEqual(proof, { simulated: true });
            savedCheck = check;
            escaped = new AsyncResource('escaped-runner-attestation');
            await check();
        });
        await assert.rejects(savedCheck());
        runnerRevoked = true;
        await assert.rejects(lifecycle.withVerifiedPreinstalledRunner({}, () => assert.fail()));
        runnerRevoked = false;
        await assert.rejects(lifecycle.withVerifiedPreinstalledRunner({}, () => assert.fail()));
    }));
    try { await assert.rejects(escaped.runInAsyncScope(() => lifecycle.withVerifiedPreinstalledRunner({}, () => assert.fail()))); }
    finally { escaped.emitDestroy(); }
});
test('runner attestor returning before its callback completes joins work but authorizes no dispatch', async () => {
    let release, enter, joined = false, dispatches = 0;
    const gate = new Promise(resolve => { release = resolve; });
    const entered = new Promise(resolve => { enter = resolve; });
    const lifecycle = new Lifecycle({ executionContext: TEST, controller: {
        async withHeldAuthority(context, work) {
            return work({ async assertHeld() {}, async withVerifiedAuthority() {},
                async withVerifiedPreinstalledRunner(challenge, work) {
                    work({}, async () => {});
                    await entered;
                    release();
                } });
        },
    } });
    await assert.rejects(lifecycle.run(async () => {
        await assert.rejects(lifecycle.withVerifiedPreinstalledRunner({}, async (proof, check) => {
            try {
                enter();
                await gate;
                await new Promise(resolve => setImmediate(resolve));
                await check();
                dispatches++;
            } finally { joined = true; }
        }));
        await assert.rejects(lifecycle.assertHeld());
    }), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.equal(joined, true);
    assert.equal(dispatches, 0);
});
