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

test('classic synchronous UI completion says link applied, keeps readiness unverified, and never polls invented IDs', () => {
    const result = { status: 'succeeded', executionMode: 'classic', topologyRevision: 7 };
    assert.match(network.deployResultMessage(result), /Связь применена/i);
    assert.doesNotMatch(network.deployResultMessage(result), /topology already|цепь готова/i);
    assert.match(network.deployResultMessage(result), /готовность клиента не подтверждена/i);
    const handler = source.match(/    function handleLinkAutoDeploy\(snapshot, optedIn\) \{[\s\S]*?(?=\n    async function onAddLinkSubmit)/)?.[0];
    const toasts = [];
    const polls = [];
    const context = { i18n: {}, deployResultMessage: network.deployResultMessage,
        isCompletedClassicDeploymentResult: network.isCompletedClassicDeploymentResult,
        responseJob: vm.runInNewContext(source.match(/    function responseJob\([\s\S]*?(?=\n    async function handleDraftMutationResponse)/)[0] + '\nresponseJob', { i18n: {} }),
        TRACKED_OPERATION_STATUSES: ['queued', 'preparing', 'committing', 'rolling_back', 'succeeded'],
        showToast: (message, type) => toasts.push({ message, type }),
        startOperationPolling: op => polls.push(op), startIntentPolling: op => polls.push(op),
        describeTopologyError: () => 'blocked' };
    const handle = vm.runInNewContext(handler + '\nhandleLinkAutoDeploy', context);
    handle({ topologyRevision: 7, autoDeployResult: result }, true);
    assert.equal(toasts.length, 1); assert.notEqual(toasts[0].type, 'error');
    assert.match(toasts[0].message, /Связь применена/i);
    assert.match(toasts[0].message, /готовность клиента не подтверждена/i);
    assert.deepEqual(polls, []);
    for (const bad of [{ ...result, status: 'queued' }, { ...result, topologyRevision: 6 },
        { ...result, operationId: 'fake' }, { ...result, executionMode: 'native' }]) {
        handle({ topologyRevision: 7, autoDeployResult: bad }, true);
        assert.equal(toasts.at(-1).type, 'error');
    }
    for (const code of ['CLASSIC_DEPLOY_UNCERTAIN', 'CLASSIC_DEPLOY_FENCE_LOST']) {
        handle({ autoDeployError: { code } }, true);
        assert.match(toasts.at(-1).message, /применение не подтверждено/i);
        assert.doesNotMatch(toasts.at(-1).message, /не запущен/i);
    }
    const before = toasts.length;
    handle({ topologyRevision: 7, autoDeployResult: result }, false);
    assert.equal(toasts.length, before + 1);
    assert.match(toasts.at(-1).message, /сохранены.*не запускался/i);
    assert.deepEqual(polls, [], 'save-only feedback must never start deployment polling');
    handle({ autoDeployOperation: { status: 'queued', operationId: 'real-native' } }, true);
    assert.equal(polls.length, 1);
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
    const projection = source.match(/        for \(const e of edges\) \{[\s\S]*?\n        \}/)[0];
    const elements = [];
    vm.runInNewContext(projection, { elements,
        rebuild: false,
        edges: [{ data: { linkId: 'link', source: 'p', target: 'b', clientReadiness: scopedProof } }],
        visibleNodeIds: new Set(['p', 'b']), confirmedDeletions: new Set(), listedLinkIds: new Set(['link']),
        _allLinks: [{ _id: 'link', clientReadiness: undefined }], linkProgress: new Map(), buildEdgeLabel: () => '' });
    assert.equal(elements[0].data.clientReadiness, undefined, 'fresh inventory must override stale green edge proof');
});

test('rebuild map expires reverse evidence and rejects an old green graph after a cut', () => {
    const projection = source.match(/        for \(const e of edges\) \{[\s\S]*?\n        \}/)[0];
    const stamp = 100_000;
    const edgeData = { linkId: 'link', source: 'p', target: 'b', mode: 'reverse', status: 'online',
        observationExpiresAt: stamp + 90_000 };
    const run = (edge, link, now = stamp, rebuild = true) => {
        const elements = [];
        vm.runInNewContext(projection, { elements, rebuild,
            expireReverseStatus: row => network.expireReverseStatus(row, now),
            edges: [{ data: edge }], visibleNodeIds: new Set(['p', 'b']), confirmedDeletions: new Set(),
            listedLinkIds: new Set(['link']), _allLinks: [{ _id: 'link', ...link }],
            linkProgress: new Map(), buildEdgeLabel: () => '' });
        return elements[0].data;
    };
    const list = { status: 'online', tunnelState: 'connected', observationExpiresAt: stamp + 40_000 };
    assert.equal(run(edgeData, list).status, 'online');
    assert.equal(run(edgeData, list).observationExpiresAt, list.observationExpiresAt);
    assert.equal(run(edgeData, list, list.observationExpiresAt).status, 'deployed');
    assert.equal(run(edgeData, { status: 'deployed' }).status, 'deployed');
    assert.equal(run(edgeData, { ...list, observationExpiresAt: undefined }).tunnelState, 'unknown');
    assert.equal(run({ ...edgeData, observationExpiresAt: undefined }, list).status, 'deployed');
    assert.equal(run({ ...edgeData, mode: 'forward' }, {}).status, 'online');
    assert.equal(run({ ...edgeData, isInternetEdge: true }, {}).status, 'online');
    assert.equal(run({ ...edgeData, observationExpiresAt: undefined }, {}, stamp, false).status, 'online');
});

test('an already open rebuild map and drawer expire without a refresh', () => {
    const display = source.match(/    function expireReverseDisplay\(\) \{[\s\S]*?\n    \}/)[0];
    let now = 100_000, scheduled;
    const row = { status: 'online', tunnelState: 'connected', observationExpiresAt: now + 5000 };
    const edge = { length: 1, data: key => typeof key === 'string' ? row[key] : Object.assign(row, key) };
    const badge = { dataset: { reverseLink: 'fixture', reverseExpires: String(row.observationExpiresAt),
        reverseFallback: '● deployed' }, classList: new Set(['online']), textContent: '● online' };
    badge.classList.remove = badge.classList.delete.bind(badge.classList);
    vm.runInNewContext(display + '\nexpireReverseDisplay();', {
        Date: { now: () => now }, clearTimeout: () => {}, observationTimer: undefined, _allLinks: [{ ...row }],
        setTimeout: (fn, ms) => { scheduled = { fn, ms }; },
        cy: { edges: () => [edge], getElementById: id => id === 'link-fixture' ? edge : { length: 0 } },
        document: { getElementById: () => ({ querySelectorAll: () => [badge] }) },
        expireReverseStatus: network.expireReverseStatus,
    });
    assert.equal(row.status, 'online');
    assert.equal(scheduled.ms, 5000);
    now += scheduled.ms;
    scheduled.fn();
    assert.equal(row.status, 'deployed');
    assert.equal(row.tunnelState, 'unknown');
    assert.equal(badge.textContent, '● deployed');
    assert.equal(badge.classList.has('online'), false);
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
    const pollSource = source.match(/    const operationPolls = new Map\(\);[\s\S]*?(?=\n    window\._cascadeDeploy =)/)?.[0];
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
        linkProgress: new Map(), deleteTombstones: new Map(), listedLinkIds: new Set(), confirmedDeletions: new Set(),
        progressMessage: () => '',
        showToast: (message, type) => { toasts.push({ message, type }); },
        i18n: {},
    };
    const { runOperationPollStep, operationPolls } = vm.runInNewContext(
        pollSource + '\n({ runOperationPollStep, operationPolls })', context,
    );
    const state = { operationId, kind: 'link.apply' };
    operationPolls.set(operationId, state);
    await runOperationPollStep(state, 0, 0);
    assert.equal(timers.length, 1);
    assert.equal(topologyLoads, 1, 'refreshing topology is not readiness confirmation');
    assert.deepEqual(toasts, []);

    operation = { status: 'succeeded', clientReadiness: 'verified' };
    await runOperationPollStep(state, 1, 0);
    assert.equal(timers.length, 1);
    assert.equal(topologyLoads, 2);
    assert.equal(toasts.length, 1);
    assert.doesNotMatch(toasts[0].message, /не подтверждена/i);
});

test('operation poll stops on degraded proof or exhausted budget without ready toast', async () => {
    const pollSource = source.match(/    const operationPolls = new Map\(\);[\s\S]*?(?=\n    window\._cascadeDeploy =)/)?.[0];
    const toasts = [];
    let scheduled = 0;
    let operation = { status: 'succeeded', clientReadiness: 'unverified', clientProofState: 'degraded' };
    const operationId = 'a'.repeat(24);
    const { runOperationPollStep, operationPolls } = vm.runInNewContext(
        pollSource + '\n({ runOperationPollStep, operationPolls })', {
            OPERATION_POLL_INTERVAL_MS: network.OPERATION_POLL_INTERVAL_MS,
            OPERATION_POLL_MAX_ATTEMPTS: network.OPERATION_POLL_MAX_ATTEMPTS,
            shouldContinueOperationPolling: network.shouldContinueOperationPolling,
            fetch: async url => url.includes('/operations/')
                ? { ok: true, json: async () => ({ operationId, ...operation }) }
                : { ok: false },
            setTimeout: () => { scheduled += 1; return scheduled; },
            loadTopology: async () => {},
            clearTimeout: () => {},
            linkProgress: new Map(), deleteTombstones: new Map(), listedLinkIds: new Set(), confirmedDeletions: new Set(),
            progressMessage: () => '',
            showToast: message => { toasts.push(message); },
            i18n: {},
        },
    );
    const state = { operationId, kind: 'topology.deploy' };
    operationPolls.set(operationId, state);
    await runOperationPollStep(state, 0, 0);
    assert.equal(scheduled, 0);
    assert.match(toasts[0], /не подтверждена/i);
    operation = { status: 'succeeded', clientReadiness: 'unverified' };
    operationPolls.set(operationId, state);
    await runOperationPollStep(state, network.OPERATION_POLL_MAX_ATTEMPTS, 0);
    assert.equal(scheduled, 0);
    assert.match(toasts[1], /не подтверждена/i);
});
