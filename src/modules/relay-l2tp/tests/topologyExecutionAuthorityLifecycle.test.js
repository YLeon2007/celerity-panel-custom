'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { AsyncResource } = require('node:async_hooks');
const { TopologyExecutionAuthorityLifecycle: Lifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const { failure } = require('../models/topologyExecutionBindingContract');
// Local capability simulation only; this is not operational/physical PROD authority.
function simulatedController(executionContext = TEST) {
    let held = false, revoked = false, calls = 0;
    return {
        controller: { async withHeldAuthority(context, work) {
            assert.strictEqual(context, executionContext); assert.equal(held, false); held = true;
            try { return await work({ async assertHeld() { if (!held || revoked) throw failure(); },
                async withVerifiedAuthority(challenge, work) { calls++; return work({ challenge }); } }); }
            finally { held = false; }
        } },
        revoke() { revoked = true; }, restore() { revoked = false; }, calls: () => calls,
    };
}
test('authority primary wave: external assertion retains its exact cause and revocation stays sticky', async () => {
    const original=Object.assign(Error('LOCAL_CONTROLLER_PRIMARY'),{code:'LOCAL_CONTROLLER_PRIMARY'});
    let fail=false,escaped;
    const lifecycle=new Lifecycle({executionContext:TEST,controller:{async withHeldAuthority(_context,work){return work({async assertHeld(){if(fail)throw original;},async withVerifiedAuthority(){}});}}});
    await assert.rejects(lifecycle.run(async()=>{
        escaped=()=>lifecycle.assertHeld();fail=true;
        await assert.rejects(lifecycle.assertHeld(),e=>e.code==='TOPOLOGY_EXECUTION_BINDING_UNPROVEN'&&e.cause===original);
        fail=false;
        await assert.rejects(lifecycle.assertHeld(),{code:'TOPOLOGY_EXECUTION_BINDING_UNPROVEN'});
    }),{code:'TOPOLOGY_EXECUTION_BINDING_UNPROVEN'});
    await assert.rejects(escaped(),{code:'TOPOLOGY_EXECUTION_BINDING_UNPROVEN'});
});

test('TEST lifecycle refuses absent, malformed and PROD controllers', () => {
    for (const options of [{}, { executionContext: PROD, controller: simulatedController().controller },
        { executionContext: TEST, controller: true }, { executionContext: { ...TEST, extra: true }, controller: simulatedController().controller }]) {
        assert.throws(() => new Lifecycle(options));
    }
});
test('TEST lifecycle rejects explicitly malformed or cross-context controller declarations before invocation', () => {
    let calls = 0;
    for (const executionContext of [undefined, null, true, {}, PROD,
        { ...TEST, extra: true }, { target: TEST.target, hostIdentity: PROD.hostIdentity },
        { target: [TEST.target], hostIdentity: TEST.hostIdentity }]) {
        assert.throws(() => new Lifecycle({ executionContext: TEST, controller: {
            executionContext, withHeldAuthority() { calls++; },
        } }), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    }
    assert.equal(calls, 0);
});
test('TEST lifecycle preserves undeclared controller ABI and accepts an exact declaration', async () => {
    for (const declared of [false, true]) {
        const { controller } = simulatedController();
        if (declared) controller.executionContext = { ...TEST };
        const lifecycle = new Lifecycle({ executionContext: { ...TEST }, controller });
        assert.equal(await lifecycle.run(async () => 'test-held'), 'test-held');
    }
});
for (const context of [TEST, PROD]) {
    test(`${context.target} lifecycle pins and forwards the canonical read-only context despite caller mutation (SIMULATED controller)`, async () => {
        const executionContext = { ...context }, declaration = { ...context };
        const { controller } = simulatedController(context);
        controller.executionContext = declaration;
        const lifecycle = new Lifecycle({ executionContext, controller });
        assert.strictEqual(lifecycle.executionContext, context);
        assert.equal(Object.isFrozen(lifecycle.executionContext), true);
        assert.throws(() => { lifecycle.executionContext = context === TEST ? PROD : TEST; }, TypeError);
        assert.throws(() => { lifecycle.executionContext.hostIdentity = 'foreign.invalid'; }, TypeError);
        Object.assign(executionContext, context === TEST ? PROD : TEST);
        Object.assign(declaration, context === TEST ? PROD : TEST);
        controller.executionContext = { target: 'foreign', hostIdentity: 'foreign.invalid' };
        assert.strictEqual(lifecycle.executionContext, context);
        assert.equal(await lifecycle.run(async () => {
            await lifecycle.assertHeld();
            return lifecycle.withVerifiedAuthority({ nonce: 'canonical' }, proof => proof.challenge.nonce);
        }), 'canonical');
    });
}
test('PROD requires an explicit exact controller declaration before invocation', () => {
    let calls = 0;
    for (const declaration of [{}, ...[undefined, null, true, {}, TEST,
        { ...PROD, extra: true }, { target: PROD.target, hostIdentity: TEST.hostIdentity },
        { target: PROD.target, hostIdentity: [PROD.hostIdentity] }].map(executionContext => ({ executionContext }))]) {
        assert.throws(() => new Lifecycle({ executionContext: PROD, controller: {
            ...declaration, production: true, withHeldAuthority() { calls++; },
        } }), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    }
    assert.equal(calls, 0);
});
test('lifecycle rejects malformed and cross-paired caller identities despite a declared PROD controller', () => {
    let calls = 0;
    for (const executionContext of [undefined, null, true, {}, { ...PROD, extra: true },
        { target: PROD.target, hostIdentity: TEST.hostIdentity },
        { target: TEST.target, hostIdentity: PROD.hostIdentity },
        { target: [PROD.target], hostIdentity: PROD.hostIdentity },
        { target: 'production', hostIdentity: 'foreign.invalid' }]) {
        assert.throws(() => new Lifecycle({ executionContext, controller: {
            executionContext: PROD, withHeldAuthority() { calls++; },
        } }), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    }
    assert.equal(calls, 0);
});
test('PROD refuses TEST owner enrollment without reading or invoking its hook (SIMULATED controller)', async () => {
    let hookReads = 0, captures = 0, enrollments = 0;
    const executionContext = { ...PROD };
    const controller = { executionContext: { ...PROD }, async withHeldAuthority(context, work) {
        assert.strictEqual(context, PROD);
        return work({ async assertHeld() {}, async withVerifiedAuthority() {},
            get withCapturedTestOwnerEnrollment() {
                hookReads++;
                return async callback => { captures++; return callback({}, async () => {}); };
            },
        });
    } };
    const lifecycle = new Lifecycle({ executionContext, controller });
    Object.assign(executionContext, TEST);
    controller.executionContext = TEST;
    await assert.rejects(lifecycle.withCapturedTestOwnerEnrollment(() => { enrollments++; }),
        { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    await lifecycle.run(async () => {
        await assert.rejects(lifecycle.withCapturedTestOwnerEnrollment(() => { enrollments++; }),
            { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    });
    assert.equal(hookReads, 0);
    assert.equal(captures, 0);
    assert.equal(enrollments, 0);
});
test('TEST captured owner enrollment remains held and rejects an escaped check', async () => {
    let captures = 0, savedCheck;
    const plan = { simulated: true };
    const lifecycle = new Lifecycle({ executionContext: TEST, controller: {
        async withHeldAuthority(context, work) {
            assert.strictEqual(context, TEST);
            return work({ async assertHeld() {}, async withVerifiedAuthority() {},
                async withCapturedTestOwnerEnrollment(callback) { captures++; return callback(plan, async () => {}); },
            });
        },
    } });
    assert.equal(await lifecycle.run(() => lifecycle.withCapturedTestOwnerEnrollment(async (actual, check) => {
        assert.strictEqual(actual, plan); savedCheck = check; await check(); return 'enrolled';
    })), 'enrolled');
    await assert.rejects(savedCheck(), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.equal(captures, 1);
});
test('TEST captured owner enrollment still requires its explicit capability', async () => {
    const { controller } = simulatedController();
    const lifecycle = new Lifecycle({ executionContext: TEST, controller });
    await assert.rejects(lifecycle.run(async () => {
        await assert.rejects(lifecycle.withCapturedTestOwnerEnrollment(() => assert.fail('missing capture invoked')),
            { code: 'TEST_DURABLE_ORIGINALS_CAPTURE_REQUIRED' });
        await assert.rejects(lifecycle.assertHeld(), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    }), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
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
