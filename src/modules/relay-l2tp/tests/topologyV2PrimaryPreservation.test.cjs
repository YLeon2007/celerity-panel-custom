'use strict';
// Isolated error-boundary regression, NOT ab620 historical-cause reproduction.
// No proof brands, time substitution, DB/network/SSH, runtime or external packages.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const Module = require('node:module');
const ROOT = process.env.C3_ANALYSIS_SOURCE_ROOT || path.join(__dirname, '../../../..');
const settlementRelative = 'src/modules/relay-l2tp/repositories/topologyV2Settlement.js';
const diagnosticsRelative = 'src/routes/topologyTestDiagnostics.js';
const finalizerRelative = 'src/modules/relay-l2tp/services/topologyOperationFinalizer.js';
const repositoryRelative = 'src/modules/relay-l2tp/repositories/topologyOperationFinalizationRepository.js';
const diagnosticsLog = [];
const unused = new Proxy({}, { get(target, key) { return function unusedDependency() { throw Error('Unused dependency called: ' + String(key)); }; } });
const cache = new Map();
function load(relative) {
    if (cache.has(relative)) return cache.get(relative).exports;
    const filename = path.join(ROOT, relative);
    let source = fs.readFileSync(filename, 'utf8');
    // Test-only lexical seam; once() is unchanged. Never proposed as product export.
    if (relative === settlementRelative) source += '\nmodule.exports.__unitOnce = once;\n';
    const module = { exports: {} };
    cache.set(relative, module);
    const ownRequire = name => {
        if (name === 'node:util' || name === 'node:path') return require(name);
        if (name === 'node:fs') return new Proxy({}, { get() { return () => { throw Error('Filesystem diagnostics disabled in isolated test'); }; } });
        const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(relative), name + (name.endsWith('.js') ? '' : '.js')));
        if ([settlementRelative, diagnosticsRelative, finalizerRelative, repositoryRelative].includes(resolved)) return load(resolved);
        if (relative === settlementRelative && name.startsWith('.')) return unused;
        throw Error('Unexpected module import: ' + name);
    };
    vm.runInThisContext(Module.wrap(source), { filename })(module.exports, ownRequire, module, filename, path.dirname(filename));
    return module.exports;
}
const diagnostics = load(diagnosticsRelative);
diagnostics.logTopologyTestFailure = input => diagnosticsLog.push(input);
const settlement = load(settlementRelative);
const { TopologyOperationFinalizer } = load(finalizerRelative);
const { TopologyOperationFinalizationRepository } = load(repositoryRelative);
function primaryError() {
    return Object.assign(new TypeError('PRIVATE_ORIGINAL_MESSAGE'), { code: 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED' });
}
function fixture({ workError, sessionError, transitionError, inTransactionError, syncAbortError, asyncAbortError, endError, commitError } = {}) {
    diagnosticsLog.length = 0;
    const calls = { start: 0, abort: 0, end: 0, commit: 0, transition: 0, confirm: 0 };
    const session = {
        transaction: { transition() { calls.transition++; if (transitionError) throw transitionError; } },
        startTransaction() {},
        inTransaction() { if (inTransactionError) throw inTransactionError; return true; },
        abortTransaction() { calls.abort++; if (syncAbortError) throw syncAbortError; return asyncAbortError ? Promise.reject(asyncAbortError) : Promise.resolve(); },
        async endSession() { calls.end++; if (endError) throw endError; },
    };
    const db = {
        async startSession() { calls.start++; if (sessionError) throw sessionError; return session; },
        getClient() { return { db() { return { async command() { calls.commit++; if (commitError) throw commitError; return { ok: 1 }; } }; } }; },
    };
    const repository = Object.create(TopologyOperationFinalizationRepository.prototype);
    repository.TopologyOperation = { db, findById() { throw workError || Error('No model reads expected'); } };
    const finalizer = new TopologyOperationFinalizer({ repository, clock: { now: () => new Date() } });
    const request = { operationId: '1234567890abcdef12345678', owner: 'local-unit-test-only',
        leaseUntil: new Date(), topologyRevision: 3, priorDeployedRevision: 0, proofs: [], sideEffects: {} };
    return { calls, repository, request, finalizer,
        persist: () => finalizer.persistV2TerminalProofs(request),
        commit: () => settlement.__unitOnce(repository, async () => 'unit-result', async () => { calls.confirm++; }, request, 'persist') };
}
function safeDiagnostics() {
    assert.equal(JSON.stringify(diagnosticsLog).includes('PRIVATE_'), false);
    return diagnosticsLog.map(row => diagnostics.formatTopologyDiagnostic(row));
}
test('public finalizer -> repository -> persist: endSession rejection preserves original identity', async () => {
    const original = primaryError(), f = fixture({ workError: original, endError: Error('PRIVATE_END') });
    await assert.rejects(f.persist(), error => error === original);
    assert.deepEqual(diagnosticsLog.map(row => row.phase), ['persist.work', 'persist.end']);
    assert.equal(f.calls.abort, 1); assert.equal(f.calls.end, 1); assert.equal(f.calls.commit, 0);
    safeDiagnostics();
});
test('session acquisition rejection is recorded at settlement boundary before worker generic catch', async () => {
    const original = primaryError(), f = fixture({ sessionError: original });
    await assert.rejects(f.persist(), error => error === original);
    assert.equal(diagnosticsLog.length, 1, 'startSession failure needs an original diagnostic');
    assert.equal(diagnosticsLog[0].phase, 'persist.session');
    assert.equal(safeDiagnostics()[0].errorType, 'TypeError');
    assert.equal(f.calls.end, 0); assert.equal(f.calls.commit, 0);
});
test('commit command rejection is not replaced by driver transition rejection', async () => {
    const original = primaryError(), f = fixture({ commitError: original, transitionError: Error('PRIVATE_TRANSITION') });
    await assert.rejects(f.commit(), error => error === original, 'commit original must survive transition finally');
    const rows = safeDiagnostics();
    assert.ok(rows.some(row => row.phase === 'persist.commit' && row.errorType === 'TypeError'));
    assert.ok(rows.some(row => row.phase === 'persist.transition'));
    assert.equal(f.calls.commit, 1); assert.equal(f.calls.transition, 1);
    assert.equal(f.calls.abort, 0); assert.equal(f.calls.confirm, 0); assert.equal(f.calls.end, 1);
});
test('successful commit plus failed transition is still failure, never publication/readback', async () => {
    const secondary = Error('PRIVATE_TRANSITION'), f = fixture({ transitionError: secondary });
    await assert.rejects(f.commit(), error => error === secondary);
    assert.equal(f.calls.commit, 1); assert.equal(f.calls.confirm, 0); assert.equal(f.calls.abort, 0);
    safeDiagnostics();
});
test('original work rejection survives synchronous inTransaction failure', async () => {
    const original = primaryError(), f = fixture({ workError: original, inTransactionError: Error('PRIVATE_IN_TRANSACTION') });
    await assert.rejects(f.persist(), error => error === original);
    assert.equal(f.calls.abort, 0); assert.equal(f.calls.commit, 0); assert.equal(f.calls.end, 1);
    safeDiagnostics();
});
test('original work rejection survives synchronous abortTransaction failure', async () => {
    const original = primaryError(), f = fixture({ workError: original, syncAbortError: Error('PRIVATE_SYNC_ABORT') });
    await assert.rejects(f.persist(), error => error === original);
    assert.equal(f.calls.abort, 1); assert.equal(f.calls.commit, 0); assert.equal(f.calls.end, 1);
    safeDiagnostics();
});
test('original work rejection survives asynchronous abortTransaction failure', async () => {
    const original = primaryError(), f = fixture({ workError: original, asyncAbortError: Error('PRIVATE_ASYNC_ABORT') });
    await assert.rejects(f.persist(), error => error === original);
    assert.equal(f.calls.abort, 1); assert.equal(f.calls.commit, 0); assert.equal(f.calls.end, 1);
    safeDiagnostics();
});
test('successful one-shot commit keeps successful return, with no replay', async () => {
    const f = fixture();
    assert.equal(await f.commit(), 'unit-result');
    assert.equal(f.calls.commit, 1); assert.equal(f.calls.confirm, 1); assert.equal(f.calls.end, 1);
    assert.equal(f.calls.abort, 0); assert.equal(diagnosticsLog.length, 0);
});
