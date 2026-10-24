'use strict';
const assert = require('node:assert/strict');
const { AsyncResource } = require('node:async_hooks');
const test = require('node:test');
const { TopologyOperationWorker: Worker } = require('../workers/topologyOperationWorker');
const { TopologyExecutionAuthorityLifecycle: Lifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
const { TopologyExecutionBindingStore: Store } = require('../repositories/topologyExecutionBindingStore');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const NOW = new Date('2026-10-24T00:00:00.000Z');
const OPERATION = 'worker-authority-entry';
const UNPROVEN = 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN';

// No Mongo connection: only constructor prerequisites are modeled. Every model,
// persistence/transport/lock/ID allocation/heartbeat method is a refusal trap.
// The independent physical controller below is SIMULATED, not PROD authority.
function fixture(context = PROD) {
    const trace = [], forbidden = [];
    const deny = name => () => { forbidden.push(name); assert.fail(`Forbidden side effect: ${name}`); };
    const methods = names => Object.fromEntries(names.map(name => [name, deny(name)]));
    const state = { held: false, revoked: false, checks: 0, claims: 0, probes: 0 };
    const controller = { executionContext: { ...context }, async withHeldAuthority(selected, work) {
        assert.ok(selected === context);
        assert.equal(state.held, false);
        state.held = true;
        try { return await work({ async assertHeld() {
            state.checks++;
            assert.equal(state.held, true);
            if (state.revoked || state.rejectCheck === state.checks) throw Object.assign(new Error('revoked'), { code: UNPROVEN });
        }, withVerifiedAuthority: deny('physical attestation') }); }
        finally { state.held = false; }
    } };
    const lifecycle = new Lifecycle({ executionContext: { ...context }, controller });
    const db = { getClient: () => ({ options: { directConnection: false },
        topology: { description: { type: 'ReplicaSetWithPrimary' } } }) };
    const models = Object.fromEntries(['Operation', 'Lock', 'Owner', 'Enrollment', 'Binding', 'HyNode']
        .map(name => [name, { db, findOne: deny(`${name}.findOne`) }]));
    const sourceContext = { ...context };
    const provisioner = new Store({ executionContext: sourceContext, ...models,
        withVerifiedAuthority: deny('store authority'), assertAuthorityHeld: () => lifecycle.assertHeld() });
    // This must never mint IDs or query the modeled models in the null-claim test.
    provisioner.reserveBinding = deny('reserveBinding');
    const options = { executionContext: { ...context }, bindingLifecycle: lifecycle, bindingProvisioner: provisioner,
        allowUnprovenTestExecution: false,
        operationRepository: { ...methods(['renewLease', 'recordNode', 'setPhase', 'finishClaimed']),
            async claim(request) {
                state.claims++;
                await lifecycle.assertHeld();
                assert.ok(request.executionContext === context);
                assert.deepEqual(request, { executionContext: context, operationId: OPERATION,
                    owner: 'authority-worker', leaseMs: 30000, now: NOW });
                trace.push('held claim');
                return null;
            } },
        executor: { executionProtocolVersion: 2, ...methods(['prepare', 'commit', 'verify', 'cleanupPrepared', 'rollback']) },
        finalizer: { ...methods(['finalizeSucceeded', 'finalizeV2Succeeded', 'persistV2TerminalProofs']),
            async probeV2Settlement(request) {
                state.probes++;
                await lifecycle.assertHeld();
                assert.deepEqual(request, { operationId: OPERATION });
                trace.push('held recovery probe');
                return null;
            } },
        lockService: methods(['acquire', 'renew', 'release', 'releaseVerified']),
        timer: methods(['setInterval', 'clearInterval']),
        workerId: 'authority-worker', leaseMs: 30000, clock: { now: () => NOW } };
    return { options, trace, forbidden, state, controller, lifecycle, provisioner, sourceContext };
}

test('paired canonical PROD lifecycle + same-context provisioner + V2 executor + allowUnprovenTestExecution=false reaches one held context-fenced claim', async () => {
    const f = fixture();
    const worker = new Worker(f.options);
    const previousDomain = process.env.PANEL_DOMAIN;
    try {
        Object.assign(f.options.executionContext, TEST);
        Object.assign(f.sourceContext, TEST);
        process.env.PANEL_DOMAIN = TEST.hostIdentity;
        assert.ok(worker.executionContext === PROD);
        assert.deepEqual(await worker.run({ operationId: OPERATION, executionContext: TEST,
            allowUnprovenTestExecution: true }), { claimed: false, operationId: OPERATION });
        assert.deepEqual(f.trace, ['held recovery probe', 'held claim']);
        assert.equal(f.state.claims, 1);
        assert.equal(f.state.probes, 1);
        assert.equal(worker.running.size, 0);
        assert.equal(f.state.held, false);
        await assert.rejects(f.lifecycle.assertHeld(), { code: UNPROVEN });
        assert.deepEqual(f.forbidden, []);
    } finally {
        if (previousDomain === undefined) delete process.env.PANEL_DOMAIN;
        else process.env.PANEL_DOMAIN = previousDomain;
    }
});

function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}
function bindingRefusal(result) {
    assert.equal(result.stopped, true);
    assert.equal(result.drainUncertain, true);
    assert.equal(result.errorCode, UNPROVEN);
    assert.equal(result.operationId, OPERATION);
}

for (const bypass of [false, true]) {
    test(`PROD absent pair cannot use TEST bypass=${bypass}`, async () => {
        const f = fixture();
        delete f.options.bindingLifecycle;
        delete f.options.bindingProvisioner;
        f.options.allowUnprovenTestExecution = bypass;
        assert.deepEqual(await new Worker(f.options).run(OPERATION), {
            claimed: false, operationId: OPERATION, stopped: true,
            errorCode: 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN',
        });
        assert.deepEqual(f.trace, []);
        assert.equal(f.state.claims, 0);
        assert.deepEqual(f.forbidden, []);
        assert.equal(f.state.checks, 0);
    });
}

const invalidPairs = [
    ['missing provisioner', f => { delete f.options.bindingProvisioner; }],
    ['missing lifecycle', f => { delete f.options.bindingLifecycle; }],
    ['null pair', f => { f.options.bindingProvisioner = null; f.options.bindingLifecycle = null; }],
    ['run-only lifecycle', f => { f.options.bindingLifecycle = { executionContext: PROD, run() { assert.fail('not authority'); } }; }],
    ['missing run', f => { f.options.bindingLifecycle = { executionContext: PROD, assertHeld() { assert.fail(); } }; }],
    ['missing reserveBinding', f => { f.options.bindingProvisioner = { executionContext: PROD }; }],
    ['foreign provisioner', f => { f.options.bindingProvisioner = { executionContext: TEST, reserveBinding() { assert.fail(); } }; }],
    ['foreign lifecycle', f => { f.options.bindingLifecycle = fixture(TEST).lifecycle; }],
    ['both foreign', f => { const other = fixture(TEST); f.options.bindingProvisioner = other.provisioner; f.options.bindingLifecycle = other.lifecycle; }],
    ...[undefined, null, {}, { ...PROD, extra: true }, { target: PROD.target, hostIdentity: TEST.hostIdentity },
        { target: [PROD.target], hostIdentity: PROD.hostIdentity }].flatMap((executionContext, index) => [
        [`malformed provisioner context ${index}`, f => { f.options.bindingProvisioner = { executionContext, reserveBinding() { assert.fail(); } }; }],
        [`malformed lifecycle context ${index}`, f => { f.options.bindingLifecycle = { executionContext, run() { assert.fail(); }, assertHeld() { assert.fail(); } }; }],
    ]),
    ...[undefined, 1, '2', true].map(version => [`non-V2 executor ${String(version)}`, f => { f.options.executor.executionProtocolVersion = version; }]),
];
for (const [name, change] of invalidPairs) {
    test(`PROD rejects ${name} before authority/recovery/claim even with bypass=true`, () => {
        const f = fixture();
        f.options.allowUnprovenTestExecution = true;
        change(f);
        assert.throws(() => new Worker(f.options), /context-paired V2 binding lifecycle/);
        assert.deepEqual(f.trace, []);
        assert.equal(f.state.claims, 0);
        assert.deepEqual(f.forbidden, []);
        assert.equal(f.state.checks, 0);
    });
}

test('worker awaits a fresh held assertion before recovery, not just lifecycle entry', async () => {
    const f = fixture();
    f.state.rejectCheck = 2; // Lifecycle entry succeeds; the worker check rejects.
    const worker = new Worker(f.options);
    bindingRefusal(await worker.run(OPERATION));
    assert.equal(f.state.checks, 2);
    assert.equal(f.state.probes, 0);
    assert.deepEqual(f.trace, []);
    assert.equal(f.state.claims, 0);
    assert.deepEqual(f.forbidden, []);
    assert.equal(worker.running.size, 0);
});

test('no recovery runs while the worker-held assertion is still awaiting', async () => {
    const f = fixture(), entered = deferred(), gate = deferred();
    const originalCheck = f.lifecycle.assertHeld.bind(f.lifecycle);
    let calls = 0;
    f.lifecycle.assertHeld = async () => {
        if (++calls === 2) { entered.resolve(); await gate.promise; }
        return originalCheck();
    };
    const worker = new Worker(f.options), pending = worker.run(OPERATION);
    await entered.promise;
    assert.deepEqual(f.trace, []);
    assert.equal(f.state.claims, 0);
    f.state.revoked = true;
    gate.resolve();
    bindingRefusal(await pending);
    assert.deepEqual(f.trace, []);
    assert.equal(f.state.claims, 0);
    assert.deepEqual(f.forbidden, []);
});

test('revocation during awaited recovery refuses before claim with ownership untouched', async () => {
    const f = fixture(), entered = deferred(), gate = deferred();
    f.options.finalizer.probeV2Settlement = async () => {
        await f.lifecycle.assertHeld();
        f.trace.push('held recovery probe');
        entered.resolve();
        await gate.promise;
        return null;
    };
    const worker = new Worker(f.options), pending = worker.run(OPERATION);
    await entered.promise;
    assert.equal(f.state.held, true);
    assert.deepEqual(f.trace, ['held recovery probe']);
    assert.equal(f.state.claims, 0);
    f.state.revoked = true;
    gate.resolve();
    bindingRefusal(await pending);
    assert.deepEqual(f.trace, ['held recovery probe']);
    assert.equal(f.state.claims, 0);
    assert.deepEqual(f.forbidden, []);
    assert.equal(worker.running.size, 0);
    assert.equal(f.state.held, false);
});

test('preclaim held assertion is awaited even when no recovery method exists', async () => {
    const f = fixture();
    delete f.options.finalizer.probeV2Settlement;
    f.state.rejectCheck = 3; // Lifecycle entry, worker entry, actual preclaim.
    bindingRefusal(await new Worker(f.options).run(OPERATION));
    assert.equal(f.state.checks, 3);
    assert.deepEqual(f.trace, []);
    assert.equal(f.state.claims, 0);
    assert.deepEqual(f.forbidden, []);
});

test('a controller callback escaped past worker return cannot start recovery or claim', async () => {
    const f = fixture();
    let escaped;
    f.controller.withHeldAuthority = async (context, work) => { escaped = work; };
    bindingRefusal(await new Worker(f.options).run(OPERATION));
    await assert.rejects(Promise.resolve().then(() => escaped({ async assertHeld() {}, async withVerifiedAuthority() {} })),
        { code: UNPROVEN });
    assert.deepEqual(f.trace, []);
    assert.equal(f.state.claims, 0);
    assert.deepEqual(f.forbidden, []);
});

test('async authority captured in recovery is closed after the awaited null claim', async () => {
    const f = fixture();
    let escaped;
    const probe = f.options.finalizer.probeV2Settlement;
    f.options.finalizer.probeV2Settlement = async request => {
        escaped = new AsyncResource('escaped-worker-held-entry');
        return probe(request);
    };
    assert.deepEqual(await new Worker(f.options).run(OPERATION), { claimed: false, operationId: OPERATION });
    try { await assert.rejects(escaped.runInAsyncScope(() => f.lifecycle.assertHeld()), { code: UNPROVEN }); }
    finally { escaped.emitDestroy(); }
    assert.deepEqual(f.trace, ['held recovery probe', 'held claim']);
    assert.deepEqual(f.forbidden, []);
});

test('early-returning controller revokes and joins awaited recovery without claiming', async () => {
    const f = fixture(), entered = deferred(), gate = deferred();
    let joined = false;
    f.controller.withHeldAuthority = async (context, work) => {
        assert.ok(context === PROD);
        f.state.held = true;
        work({ async assertHeld() { assert.equal(f.state.held, true); }, async withVerifiedAuthority() { assert.fail(); } });
        await entered.promise;
        f.state.held = false;
        setImmediate(gate.resolve);
        // Deliberately do not await the work promise.
    };
    f.options.finalizer.probeV2Settlement = async () => {
        await f.lifecycle.assertHeld();
        f.trace.push('held recovery probe');
        entered.resolve();
        try { await gate.promise; return null; }
        finally { joined = true; }
    };
    const worker = new Worker(f.options);
    bindingRefusal(await worker.run(OPERATION));
    assert.equal(joined, true);
    assert.equal(worker.running.size, 0);
    assert.deepEqual(f.trace, ['held recovery probe']);
    assert.equal(f.state.claims, 0);
    assert.deepEqual(f.forbidden, []);
});

test('early-returning controller cannot bypass an awaiting entry check', async () => {
    const f = fixture(), gate = deferred();
    f.controller.withHeldAuthority = async (context, work) => {
        work({ async assertHeld() { await gate.promise; }, async withVerifiedAuthority() { assert.fail(); } });
        setImmediate(gate.resolve);
    };
    bindingRefusal(await new Worker(f.options).run(OPERATION));
    assert.deepEqual(f.trace, []);
    assert.equal(f.state.claims, 0);
    assert.deepEqual(f.forbidden, []);
});

test('the same held scope spans awaited recovery and the entire awaited null claim', async () => {
    const f = fixture(), entered = deferred(), gate = deferred();
    const claim = f.options.operationRepository.claim;
    f.options.operationRepository.claim = async request => {
        const result = await claim(request);
        entered.resolve();
        await gate.promise;
        await f.lifecycle.assertHeld();
        return result;
    };
    const worker = new Worker(f.options), pending = worker.run(OPERATION);
    await entered.promise;
    assert.equal(f.state.held, true);
    assert.equal(worker.running.size, 1);
    gate.resolve();
    assert.deepEqual(await pending, { claimed: false, operationId: OPERATION });
    assert.equal(f.state.held, false);
    assert.equal(worker.running.size, 0);
    assert.deepEqual(f.trace, ['held recovery probe', 'held claim']);
    assert.deepEqual(f.forbidden, []);
});

for (const context of [TEST, PROD]) {
    test(`${context.target} actual store exposes only immutable canonical context without persistence`, () => {
        const f = fixture(context);
        assert.ok(f.provisioner.executionContext === context);
        Object.assign(f.sourceContext, context === TEST ? PROD : TEST);
        assert.ok(f.provisioner.executionContext === context);
        assert.equal(Object.isFrozen(f.provisioner.executionContext), true);
        assert.throws(() => { f.provisioner.executionContext = TEST; }, TypeError);
        assert.throws(() => { f.provisioner.executionContext.target = 'other'; }, TypeError);
        assert.throws(() => Object.defineProperty(f.provisioner, 'executionContext', { value: TEST }), TypeError);
        const descriptor = Object.getOwnPropertyDescriptor(f.provisioner, 'executionContext');
        assert.equal(typeof descriptor.get, 'function');
        assert.equal(descriptor.set, undefined);
        assert.equal(descriptor.configurable, false);
        assert.deepEqual(f.forbidden, []);
        assert.equal(f.state.checks, 0);
    });
}

test('TEST paired held V2 route reaches null claim with bypass=false', async () => {
    const f = fixture(TEST);
    assert.deepEqual(await new Worker(f.options).run(OPERATION), { claimed: false, operationId: OPERATION });
    assert.deepEqual(f.trace, ['held recovery probe', 'held claim']);
    assert.deepEqual(f.forbidden, []);
});

test('TEST legacy fake executor bypass remains independent of any authority pair', async () => {
    const f = fixture(TEST);
    delete f.options.bindingLifecycle;
    delete f.options.bindingProvisioner;
    f.options.executor.executionProtocolVersion = 1;
    f.options.allowUnprovenTestExecution = true;
    f.options.operationRepository.claim = async request => {
        assert.ok(request.executionContext === TEST);
        f.trace.push('TEST fake claim');
        return null;
    };
    assert.deepEqual(await new Worker(f.options).run(OPERATION), { claimed: false, operationId: OPERATION });
    assert.deepEqual(f.trace, ['TEST fake claim']);
    assert.deepEqual(f.forbidden, []);
    assert.equal(f.state.checks, 0);
});

test('TEST without pair or explicit bypass keeps the original quiescence refusal', async () => {
    const f = fixture(TEST);
    delete f.options.bindingLifecycle;
    delete f.options.bindingProvisioner;
    const result = await new Worker(f.options).run(OPERATION);
    assert.equal(result.errorCode, 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN');
    assert.equal(result.claimed, false);
    assert.deepEqual(f.trace, []);
    assert.equal(f.state.claims, 0);
    assert.deepEqual(f.forbidden, []);
});
