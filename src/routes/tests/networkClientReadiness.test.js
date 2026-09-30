'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.resolve(__dirname, '../../../public/js/network.js'), 'utf8');
const network = require('../../../public/js/network');

test('deployment outcomes never claim client readiness from queue or apply success alone', () => {
    assert.match(network.deployResultMessage({ status: 'queued' }), /готовность клиента не подтверждена/i);
    assert.match(network.deployResultMessage({ status: 'succeeded' }), /готовность клиента не подтверждена/i);
    assert.match(source, /state\.kind === 'link\.apply'[\s\S]*?готовность клиента не подтверждена/);
    assert.match(source, /i18n\.operationApplied[\s\S]*?готовность клиента не подтверждена/);
});

test('edge readiness fails closed without current explicit client proof', () => {
    const label = network.clientReadinessMessage;
    assert.match(label(null, 7, 7), /не подтверждена/i);
    assert.match(label({ status: 'succeeded', topologyRevision: 7 }, 7, 7), /не подтверждена/i);
    assert.match(label({ status: 'ready', clientProbe: 'passed', topologyRevision: 6 }, 7, 7), /не подтверждена/i);
    const scopedProof = { status: 'ready', clientProbe: 'passed', topologyRevision: 7, priorDeployedRevision: 6 };
    assert.match(label(scopedProof, 7, 6), /подтверждена проверкой клиента/i);
    assert.match(label(scopedProof, 7, 7), /не подтверждена/i);
    assert.match(label({ ...scopedProof, priorDeployedRevision: 5 }, 7, 6), /не подтверждена/i);
    assert.match(label({ ...scopedProof, topologyRevision: 8 }, 7, 6), /не подтверждена/i);
    assert.match(label({ ...scopedProof, clientProbe: 'failed' }, 7, 6), /не подтверждена/i);
    assert.match(label({ ...scopedProof, status: 'pending' }, 7, 6), /не подтверждена/i);
    assert.match(label({ status: 'ready', clientProbe: 'passed', topologyRevision: 7 }, 7, 6), /не подтверждена/i);
    assert.match(label(scopedProof, undefined, 6), /не подтверждена/i);
    assert.match(label(scopedProof, 7, undefined), /не подтверждена/i);
    assert.match(label({ ...scopedProof, priorDeployedRevision: '6' }, 7, 6), /не подтверждена/i);
    assert.match(label({ ...scopedProof, priorDeployedRevision: 7 }, 7, 7), /подтверждена проверкой клиента/i);
    assert.doesNotMatch(label({ status: 'failed', message: '<img src=x onerror=alert(1)>' }, 7, 7), /<img|alert/);
    assert.match(source, /clientReadinessMessage\(d\.clientReadiness, topologyRevision, deployedRevision\)/);
    assert.match(source, /ele\.data\('clientReadiness', e\.data\.clientReadiness\)/);
});

test('operation polling waits for client verification after execution succeeds', () => {
    const shouldContinue = network.shouldContinueOperationPolling;
    const base = { attempt: 2, maxAttempts: 3, status: 'succeeded' };
    assert.equal(shouldContinue({ ...base, clientReadiness: 'unverified' }), true);
    assert.equal(shouldContinue({ ...base, clientReadiness: 'verified' }), false);
    assert.equal(shouldContinue({ ...base, clientReadiness: 'unverified', clientProofState: 'degraded' }), false);
    assert.equal(shouldContinue({ ...base, attempt: 3, clientReadiness: 'unverified' }), false);
    assert.equal(shouldContinue({ ...base, status: 'failed' }), false);
    assert.equal(shouldContinue({ ...base, status: 'rolled_back' }), false);
    assert.equal(shouldContinue({ ...base, status: 'queued' }), true);
});

test('operation poll does not toast readiness before server verifies it', async () => {
    const pollSource = source.match(/    let operationPollTimer = null;[\s\S]*?(?=\n    window\._cascadeDeploy =)/)?.[0];
    assert.ok(pollSource, 'operation polling code is available');
    const toasts = [];
    const timers = [];
    let operation = { status: 'succeeded', clientReadiness: 'unverified' };
    let topologyLoads = 0;
    const operationId = 'a'.repeat(24);
    const context = {
        OPERATION_POLL_INTERVAL_MS: network.OPERATION_POLL_INTERVAL_MS,
        OPERATION_POLL_MAX_ATTEMPTS: network.OPERATION_POLL_MAX_ATTEMPTS,
        shouldContinueOperationPolling: network.shouldContinueOperationPolling,
        fetch: async url => url.includes('/operations/')
            ? { ok: true, json: async () => ({ operationId, ...operation }) }
            : { ok: false },
        setTimeout: fn => { timers.push(fn); return timers.length; },
        clearTimeout: () => {},
        loadTopology: async () => { topologyLoads += 1; },
        showToast: (message, type) => { toasts.push({ message, type }); },
        i18n: {},
    };
    const { runOperationPollStep } = vm.runInNewContext(
        pollSource + '\n({ runOperationPollStep })', context,
    );
    const state = { operationId, kind: 'link.apply' };
    await runOperationPollStep(state, 0, 0);
    assert.equal(timers.length, 1);
    assert.equal(topologyLoads, 0);
    assert.deepEqual(toasts, []);

    operation = { status: 'succeeded', clientReadiness: 'verified' };
    await runOperationPollStep(state, 1, 0);
    assert.equal(timers.length, 1);
    assert.equal(topologyLoads, 1);
    assert.equal(toasts.length, 1);
    assert.doesNotMatch(toasts[0].message, /не подтверждена/i);
});

test('operation poll stops on degraded proof or exhausted budget without ready toast', async () => {
    const pollSource = source.match(/    let operationPollTimer = null;[\s\S]*?(?=\n    window\._cascadeDeploy =)/)?.[0];
    const toasts = [];
    let scheduled = 0;
    let operation = { status: 'succeeded', clientReadiness: 'unverified', clientProofState: 'degraded' };
    const operationId = 'a'.repeat(24);
    const { runOperationPollStep } = vm.runInNewContext(
        pollSource + '\n({ runOperationPollStep })', {
            OPERATION_POLL_INTERVAL_MS: network.OPERATION_POLL_INTERVAL_MS,
            OPERATION_POLL_MAX_ATTEMPTS: network.OPERATION_POLL_MAX_ATTEMPTS,
            shouldContinueOperationPolling: network.shouldContinueOperationPolling,
            fetch: async url => url.includes('/operations/')
                ? { ok: true, json: async () => ({ operationId, ...operation }) }
                : { ok: false },
            setTimeout: () => { scheduled += 1; return scheduled; },
            loadTopology: async () => {},
            showToast: message => { toasts.push(message); },
            i18n: {},
        },
    );
    const state = { operationId, kind: 'topology.deploy' };
    await runOperationPollStep(state, 0, 0);
    assert.equal(scheduled, 0);
    assert.match(toasts[0], /не подтверждена/i);
    operation = { status: 'succeeded', clientReadiness: 'unverified' };
    await runOperationPollStep(state, network.OPERATION_POLL_MAX_ATTEMPTS, 0);
    assert.equal(scheduled, 0);
    assert.match(toasts[1], /не подтверждена/i);
});
