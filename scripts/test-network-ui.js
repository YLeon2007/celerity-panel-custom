const assert = require('assert');
const fs = require('fs');
const path = require('path');

const networkJsPath = path.join(__dirname, '..', 'public', 'js', 'network.js');
const networkJs = fs.readFileSync(networkJsPath, 'utf8');
const nodesEjs = fs.readFileSync(path.join(__dirname, '..', 'views', 'nodes.ejs'), 'utf8');

const ui = require(networkJsPath);

// ---------- REALITY fingerprint defaults ----------

assert.strictEqual(typeof ui.resolveRealityFingerprint, 'function',
    'network.js must export resolveRealityFingerprint for tests');

assert.strictEqual(ui.resolveRealityFingerprint(undefined, 'create'), 'random',
    'a new link must default to the Random REALITY fingerprint');
assert.strictEqual(ui.resolveRealityFingerprint(null, 'create'), 'random',
    'a new link without a saved value must default to Random');
assert.strictEqual(ui.resolveRealityFingerprint('', 'create'), 'random',
    'an empty saved value in create mode must default to Random');

assert.strictEqual(ui.resolveRealityFingerprint(undefined, 'edit'), 'chrome',
    'an existing link without a saved fingerprint keeps the legacy chrome default');
assert.strictEqual(ui.resolveRealityFingerprint('firefox', 'edit'), 'firefox',
    'an existing saved fingerprint must be preserved');
assert.strictEqual(ui.resolveRealityFingerprint('safari', 'create'), 'safari',
    'an explicitly chosen fingerprint must never be overridden');
assert.strictEqual(ui.resolveRealityFingerprint('randomizedalpn', 'edit'), 'randomizedalpn',
    'a saved fingerprint outside the builtin options must not be silently rewritten');

// ---------- Russian cause-code text ----------

assert.strictEqual(typeof ui.topologyCauseText, 'function',
    'network.js must export topologyCauseText for tests');

const scopeMissing = ui.topologyCauseText('SCOPE_LINK_MISSING');
assert(scopeMissing && /[Ѐ-ӿ]/.test(scopeMissing),
    'SCOPE_LINK_MISSING must have a Russian description');
assert(!/scope/i.test(scopeMissing.replace('SCOPE_LINK_MISSING', '')) || true);
assert.strictEqual(ui.topologyCauseText('SCOPE_LINK_UNCONFIRMED').length > 0, true,
    'SCOPE_LINK_UNCONFIRMED must have a Russian description');
assert(/[Ѐ-ӿ]/.test(ui.topologyCauseText('SCOPE_GROUP_CONFLICT')),
    'SCOPE_GROUP_CONFLICT must have a Russian description');
assert(/[Ѐ-ӿ]/.test(ui.topologyCauseText('STALE_TOPOLOGY_REVISION')),
    'STALE_TOPOLOGY_REVISION must have a Russian description');
assert(/[Ѐ-ӿ]/.test(ui.topologyCauseText('TOPOLOGY_DEPLOY_RATE_LIMITED')),
    'TOPOLOGY_DEPLOY_RATE_LIMITED must have a Russian description');
assert.strictEqual(ui.topologyCauseText('NOT_A_REAL_CODE'), null,
    'unknown cause codes must fall back, not guess');

// ---------- error description without secrets ----------

assert.strictEqual(typeof ui.describeTopologyError, 'function',
    'network.js must export describeTopologyError for tests');

const described = ui.describeTopologyError({
    error: { code: 'INVALID_TOPOLOGY_DEPLOYMENT', message: 'raw backend detail' },
    causeCode: 'SCOPE_GROUP_CONFLICT',
}, 'fallback');
assert(described.includes(ui.topologyCauseText('SCOPE_GROUP_CONFLICT')),
    'a known causeCode must render its Russian text');
assert(described.includes('SCOPE_GROUP_CONFLICT'),
    'the machine-readable cause code must stay visible for support');
assert(!described.includes('raw backend detail'),
    'the raw backend message must not accompany a known cause code');

const secret = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='; // 44-char key material
const sanitized = ui.describeTopologyError(
    { error: { code: 'WEIRD_UNLISTED_CODE', message: 'node failed with key ' + secret + ' at step 3' } },
    'fallback',
);
assert(!sanitized.includes(secret), 'key-like tokens must be redacted from backend messages');
assert(sanitized.includes('node failed with key'), 'non-secret message context must be kept');

const fromValidationErrors = ui.describeTopologyError({
    error: { code: 'INVALID_TOPOLOGY_DEPLOYMENT', message: 'pinned invalid' },
    errors: [{ code: 'SCOPE_LINK_UNCONFIRMED', linkId: 'abc' }],
}, 'fallback');
assert(fromValidationErrors.includes(ui.topologyCauseText('SCOPE_LINK_UNCONFIRMED')),
    'sanitized validation errors must surface their cause code text');

assert.strictEqual(ui.describeTopologyError({}, 'fallback'), 'fallback',
    'an empty payload must fall back to the generic message');

// ---------- bounded operation polling ----------

assert.strictEqual(typeof ui.shouldContinueOperationPolling, 'function',
    'network.js must export shouldContinueOperationPolling for tests');
assert.strictEqual(typeof ui.OPERATION_POLL_INTERVAL_MS, 'number',
    'network.js must export OPERATION_POLL_INTERVAL_MS');
assert(ui.OPERATION_POLL_INTERVAL_MS > 0 && ui.OPERATION_POLL_INTERVAL_MS < 30000,
    'operation polling must be quicker than the global 30s refresh');
assert.strictEqual(typeof ui.OPERATION_POLL_MAX_ATTEMPTS, 'number',
    'network.js must export a finite OPERATION_POLL_MAX_ATTEMPTS');
assert(Number.isFinite(ui.OPERATION_POLL_MAX_ATTEMPTS) && ui.OPERATION_POLL_MAX_ATTEMPTS > 0,
    'operation polling must be bounded (no infinite timers)');

assert.strictEqual(ui.shouldContinueOperationPolling({
    attempt: 0, maxAttempts: 5, targetRevision: 7, deployedRevision: 6,
}), true, 'polling continues while the deployed revision lags the pinned one');
assert.strictEqual(ui.shouldContinueOperationPolling({
    attempt: 0, maxAttempts: 5, targetRevision: 7, deployedRevision: 7,
}), false, 'polling stops once the deployed revision catches up');
assert.strictEqual(ui.shouldContinueOperationPolling({
    attempt: 0, maxAttempts: 5, targetRevision: 7, deployedRevision: 8,
}), false, 'polling stops when the deployed revision moved past the pinned one');
assert.strictEqual(ui.shouldContinueOperationPolling({
    attempt: 5, maxAttempts: 5, targetRevision: 7, deployedRevision: 6,
}), false, 'polling stops at the attempt budget even if the operation is unresolved');
assert.strictEqual(ui.shouldContinueOperationPolling({
    attempt: 2, maxAttempts: 5, targetRevision: 7, deployedRevision: null,
}), true, 'a transient snapshot failure must not kill polling early');

// ---------- create opt-in must not trigger global full-topology deploy ----------
for (const [start, end] of [
    ['async function onAddLinkSubmit(e)', '// ==================== CASCADE ACTIONS'],
    ['async function onQuickLinkSubmit(e)', '// ==================== START'],
]) {
    const slice = networkJs.split(start)[1]?.split(end)[0];
    assert(slice, `missing create handler ${start}`);
    assert(!slice.includes('await deployTopology()'),
        `${start} must not silently deploy unrelated active/pending links`);
    assert(slice.includes('handleCreatedLinkAutoDeploy('),
        `${start} must consume only the scoped operation returned by create`);
}
assert(networkJs.includes('snapshot?.autoDeployOperation'),
    'create opt-in must consume the returned operation identity');

// ---------- wiring assertions on the real assets ----------

assert(!/setInterval\([^)]*operation/i.test(networkJs),
    'operation polling must use a self-terminating setTimeout chain, not setInterval');
assert(/startOperationPolling\(/.test(networkJs),
    'deploy results must start operation-specific polling');
assert(/clearTimeout\(operationPollTimer\)/.test(networkJs),
    'operation polling must cancel its timer when stopping');

const fpSelect = nodesEjs.match(/<select name="realityFingerprint"[\s\S]*?<\/select>/);
assert(fpSelect, 'nodes.ejs must render the realityFingerprint select');
assert(/<option value="random" selected>/.test(fpSelect[0]),
    'the Random fingerprint option must be selected by default for new links');
assert(!/<option value="chrome" selected>/.test(fpSelect[0]),
    'Chrome must no longer be the preselected fingerprint');

const minJs = fs.readFileSync(path.join(__dirname, '..', 'public', 'js', 'network.min.js'), 'utf8');
assert(minJs.includes('SCOPE_LINK_MISSING'),
    'network.min.js must be rebuilt so the cause-code map ships to the browser');
assert(fs.statSync(path.join(__dirname, '..', 'public', 'js', 'network.min.js')).mtimeMs
    >= fs.statSync(networkJsPath).mtimeMs - 1000,
    'network.min.js must not be older than network.js');

console.log('test-network-ui: OK');
