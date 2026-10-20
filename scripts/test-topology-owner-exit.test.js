'use strict';
// Actual exported main/default root + actual SSH pool. Mongo and physical
// authority only are simulated; no sockets, live DB, SSH or process.exit().
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
for (const variant of ['capture-refusal', 'success', 'composition-error', 'stop-error', 'connect-error']) {
    test(`one-shot CLI ${variant} naturally joins and closes its actual imported SSH pool`, () => {
        const script = String.raw`
const root = process.argv[1], variant = process.argv[2];
const Module = require('node:module');
const load = Module._load;
const inert = new Proxy({}, { get: () => () => {} });
Module._load = function(id, parent, main) {
  if (id.includes('logger')) return inert;
  return load.call(this, id, parent, main);
};
const mongoose = require('mongoose');
let disconnected = false, stopped = false;
mongoose.connect = async () => { if (variant === 'connect-error') throw Error('fixture-connect'); };
mongoose.disconnect = async () => { disconnected = true; };
require(root + '/src/modules/relay-l2tp/runtime/testPhysicalController').createRootTestPhysicalAuthority = () => undefined;
const lifecycle = require(root + '/src/modules/l2tpRuntimeLifecycleHook');
const create = lifecycle.createL2tpRootLifecycle;
lifecycle.createL2tpRootLifecycle = (...args) => {
  // Create the real default dependency graph before the injected terminal
  // outcome, as a partially constructed maintenance host can do too.
  lifecycle.createL2tpRootHostDependencies();
  const actual = create(...args);
  if (variant === 'composition-error') throw Error('fixture-composition');
  const entry = { ...actual, stop: async () => {
    try { await actual.stop(); } finally { stopped = true; }
    if (variant === 'stop-error') throw Error('fixture-stop');
  }};
  if (variant === 'success' || variant === 'stop-error')
    entry.enrollTestOwnersAfterDatabase = async () => ({ status: 'fixture-enrolled' });
  return entry;
};
require(root + '/scripts/test-topology-owner').main(['enroll']).then(
  code => finish('success', code), error => finish('refused', 1));
function finish(state, code) {
  const cached = require.cache[require.resolve(root + '/src/services/sshPoolService')];
  if (!cached) throw Error('Default root did not create pool');
  const pool = cached.exports;
  console.log(JSON.stringify({ state, disconnected, stopped,
    destroyed: pool.cleanupTimer._destroyed, connections: pool.connections.size }));
  process.exitCode = code;
}
`;
        const result = spawnSync(process.execPath, ['-e', script, root, variant], {
            encoding: 'utf8', timeout: 4000,
            env: { ...process.env, NODE_ENV: 'test', PANEL_DOMAIN: 'test.infograd.online',
                L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true',
                TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false', L2TP_PRODUCTION_EXECUTION_ENABLED: 'false',
                ACME_EMAIL: 'fixture@example.invalid', ENCRYPTION_KEY: 'synthetic-not-a-production-encryption-key', SESSION_SECRET: 'synthetic-only' },
        });
        assert.equal(result.error, undefined, `Natural exit failed (${variant}): ${result.error?.code}`);
        assert.equal(result.signal, null);
        assert.equal(result.status, variant === 'success' ? 0 : 1);
        assert.equal(result.stderr, '');
        const lines = result.stdout.trim().split('\n');
        const observed = JSON.parse(lines.at(-1));
        assert.equal(observed.state, variant === 'success' ? 'success' : 'refused');
        assert.equal(observed.disconnected, true);
        assert.equal(observed.stopped, variant !== 'composition-error');
        assert.equal(observed.destroyed, true);
        assert.equal(observed.connections, 0);
    });
}
