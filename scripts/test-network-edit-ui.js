const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '..', 'public/js/network.js'), 'utf8');
const LINK_ID = '507f1f77bcf86cd799439011';
const OP_ID = '507f1f77bcf86cd799439022';
const snapshot = (extra = {}) => ({ topologyRevision: 7, deployedRevision: 6, links: [], ...extra });

function browserHarness({ persistedAutoDeploy = true, operation = null } = {}) {
    const requests = [];
    const toasts = [];
    const timers = [];
    const elements = {};
    const element = (id, value = '') => elements[id] = {
        value, textContent: '', innerHTML: '', style: {}, disabled: false, checked: false,
        classList: { add() {}, remove() {} }, querySelectorAll: () => [],
    };
    const form = element('addLinkForm');
    for (const [name, value] of Object.entries({
        name: 'Existing link', mode: 'reverse', portalNodeId: 'portal', bridgeNodeId: 'bridge',
        tunnelPort: '10086', tunnelProtocol: 'vless', tunnelTransport: 'tcp', tunnelSecurity: 'none',
        muxConcurrency: '8', priority: '100', tunnelDomain: '', realitySni: '', realityPrivateKey: '',
        realityPublicKey: '', realityShortIds: '', realityDest: '', realityFingerprint: 'chrome',
    })) form[name] = { value };
    form.autoDeploy = { checked: true };
    form.muxEnabled = { checked: false };
    const submit = { disabled: false, innerHTML: '' };
    form.querySelector = selector => selector === '[type="submit"]' ? submit : null;
    form.reset = () => { form.autoDeploy.checked = true; };
    for (const id of ['addLinkModal', 'selectPortal', 'selectBridge', 'linkModalTitle',
        'linkModalSubmit', 'linkAutoDeployLabel', 'linkIdInput', 'geoRoutingEnabled', 'geoRoutingFields',
        'geoRoutingDomains', 'geoRoutingGeoip', 'realitySection', 'tunnelDomainGroup',
        'modeHint', 'modeSwitcher']) element(id);
    form.linkId = elements.linkIdInput;
    const document = {
        readyState: 'loading', addEventListener() {},
        getElementById: id => elements[id] || null,
        querySelector: selector => selector === '#addLinkForm [name="realityFingerprint"]'
            ? form.realityFingerprint : null,
        createElement: () => ({ value: '', textContent: '' }),
    };
    form.realityFingerprint.options = [{ value: 'chrome' }];
    form.realityFingerprint.appendChild = () => {};
    const json = body => ({ ok: true, status: 200, async json() { return body; } });
    const fetch = async (url, options) => {
        requests.push({ url, method: options?.method || 'GET', body: options?.body && JSON.parse(options.body) });
        if (url === '/api/nodes') return json([{ _id: 'portal', name: 'Portal', ip: '1.2.3.4' }]);
        if (url === '/api/cascade/links' && !options) return json(snapshot());
        if (url === '/api/cascade/links/' + LINK_ID && !options) return json({
            name: 'Existing link', portalNode: 'portal', bridgeNode: 'bridge', autoDeploy: persistedAutoDeploy,
        });
        if (url === '/api/cascade/topology/deploy') return json({
            operationId: OP_ID, status: 'queued', kind: 'link.apply', topologyRevision: 7,
        });
        if (url === '/api/cascade/topology/operations/' + OP_ID) return json({
            operationId: OP_ID, status: 'succeeded', kind: 'link.apply', topologyRevision: 7,
        });
        if (options?.method === 'PUT' || options?.method === 'POST') return json(snapshot(operation
            ? { autoDeployOperation: operation } : {}));
        throw Error('Unexpected request: ' + url);
    };
    const window = { _networkI18n: { save: 'Save', saveAndDeploy: 'Save & Deploy',
        deployAfterEdit: 'Deploy this link after saving', autoDeploy: 'Auto Deploy', createLink: 'Create' },
    showToast: (...args) => toasts.push(args) };
    // Expose the real browser handlers while skipping graph bootstrapping; all
    // form reads, fetch payloads, response handling and timers remain real.
    const instrumented = source.replace('    // ==================== START ====================',
        '    loadTopology = async function () {}; refreshStatuses = async function () {}; window.__ui = { openAddLinkModal, openEditLinkModal, onAddLinkSubmit, updateLinkSubmitIntent, deployTopology };\n    // ==================== START ====================');
    assert.notEqual(instrumented, source, 'browser probe insertion must find the boot boundary');
    vm.runInNewContext(instrumented, {
        window, document, fetch, cytoscape: () => {},
        setTimeout: (fn, delay) => { timers.push({ fn, delay }); return timers.length; },
        clearTimeout: () => {}, console,
    });
    return { ui: window.__ui, form, elements, requests, toasts, timers };
}

async function save(harness) {
    await harness.ui.onAddLinkSubmit({ target: harness.form, preventDefault() {} });
    return harness.requests.find(r => r.method === 'PUT' || r.method === 'POST');
}

test('ordinary edit of a persisted autoDeploy link has no activation intent', async () => {
    const h = browserHarness({ persistedAutoDeploy: true });
    await h.ui.openEditLinkModal(LINK_ID);
    assert.equal(h.form.autoDeploy.checked, false);
    assert.equal(h.elements.linkAutoDeployLabel.textContent, 'Deploy this link after saving');
    assert.equal(h.elements.linkModalSubmit.textContent, 'Save');
    const request = await save(h);
    assert.equal(request.method, 'PUT');
    assert.equal(request.url, '/api/cascade/links/' + LINK_ID);
    assert.equal(Object.hasOwn(request.body, 'autoDeploy'), false);
    assert.equal(h.timers.length, 0);
});

test('explicit edit-and-deploy PUT consumes scoped operation without claiming readiness', async () => {
    const h = browserHarness({ operation: { operationId: OP_ID, status: 'queued', kind: 'link.apply' } });
    await h.ui.openEditLinkModal(LINK_ID);
    h.form.autoDeploy.checked = true;
    h.ui.updateLinkSubmitIntent();
    assert.equal(h.elements.linkModalSubmit.textContent, 'Save & Deploy');
    const request = await save(h);
    assert.equal(request.body.autoDeploy, true);
    assert.equal(h.timers.length, 1, 'queue response must start operation polling');
    assert(h.timers[0].delay > 0);
    assert(h.toasts.some(([message]) => /queued|очеред/i.test(message)));
    assert(!h.toasts.some(([message]) => /ready|готова/i.test(message)));
    assert(!h.requests.some(r => r.url === '/api/cascade/topology/deploy'));
    h.timers[0].fn();
    await new Promise(resolve => setImmediate(resolve));
    assert(h.requests.some(r => r.url === '/api/cascade/topology/operations/' + OP_ID));
    assert(h.toasts.some(([message]) => /полной цепочки.*не подтверждена/i.test(message)));
});

test('create retains checkbox opt-in and never starts unscoped deploy', async () => {
    const h = browserHarness({ operation: { operationId: OP_ID, status: 'queued', kind: 'link.apply' } });
    await h.ui.openAddLinkModal();
    assert.equal(h.form.autoDeploy.checked, true);
    assert.equal(h.elements.linkAutoDeployLabel.textContent, 'Auto Deploy');
    const request = await save(h);
    assert.equal(request.method, 'POST');
    assert.equal(request.body.autoDeploy, true);
    assert.equal(h.timers.length, 1);
    assert(!h.requests.some(r => r.url === '/api/cascade/topology/deploy'));
});

test('explicit edit opt-in with blocked API response reports failure, never ready', async () => {
    const h = browserHarness();
    await h.ui.openEditLinkModal(LINK_ID);
    h.form.autoDeploy.checked = true;
    const request = await save(h);
    assert.equal(request.body.autoDeploy, true);
    assert.equal(h.timers.length, 0);
    assert(h.toasts.some(([, type]) => type === 'error'));
    assert(!h.toasts.some(([message]) => /ready|готова/i.test(message)));
});

test('switching from edit to create clears edit intent while retaining create opt-in', async () => {
    const h = browserHarness();
    await h.ui.openEditLinkModal(LINK_ID);
    h.form.autoDeploy.checked = false;
    await h.ui.openAddLinkModal();
    assert.equal(h.form.autoDeploy.checked, true);
    assert.equal(h.elements.linkAutoDeployLabel.textContent, 'Auto Deploy');
    assert.equal(h.elements.linkModalSubmit.textContent, 'Create');
});

test('dedicated link deploy still sends the linkId, never unscoped', async () => {
    const h = browserHarness();
    await h.ui.openAddLinkModal();
    await h.ui.deployTopology(LINK_ID);
    const deploy = h.requests.find(r => r.url === '/api/cascade/topology/deploy');
    assert.equal(deploy.method, 'POST');
    assert.equal(deploy.body.linkId, LINK_ID);
    assert.equal(deploy.body.expectedTopologyRevision, 7);
    assert.equal(h.timers.length, 1);
});
