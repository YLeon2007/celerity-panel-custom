const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '..', 'public/js/network.js'), 'utf8');
const LINK_ID = '507f1f77bcf86cd799439011';
const OP_ID = '507f1f77bcf86cd799439022';
const snapshot = (extra = {}) => ({ topologyRevision: 7, deployedRevision: 6, links: [], ...extra });

function browserHarness({ persistedAutoDeploy = true, operation = null, job = null,
    links = [], deployResponse = null, confirmResult = true, autoDeployError = null } = {}) {
    const requests = [];
    const toasts = [];
    const timers = [];
    const confirmations = [];
    let reloads = 0;
    const edges = links.map(link => ({
        values: { ...link, linkId: link._id, source: 'portal', target: 'bridge', mode: 'reverse' },
        data(key, value) {
            if (key === undefined) return this.values;
            if (arguments.length > 1) this.values[key] = value;
            return this.values[key];
        },
    }));
    function collection(items) {
        return { length: items.length, toArray: () => items,
            filter: predicate => collection(items.filter(predicate)),
            data: (...args) => items[0]?.data(...args) };
    }
    const graph = { edges: () => collection(edges), getElementById: () => ({ length: 0 }),
        elements: () => ({ unselect() {} }) };
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
        'modeHint', 'modeSwitcher', 'nodeInfoTitleText', 'nodeInfoBody', 'nodeInfoModal']) element(id);
    elements.nodeInfoBody.querySelector = () => null;
    elements.nodeInfoBody.appendChild = () => {};
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
        requests.push({ url, method: options?.method || 'GET', headers: options?.headers, body: options?.body && JSON.parse(options.body) });
        if (url === '/api/nodes') return json([{ _id: 'portal', name: 'Portal', ip: '1.2.3.4' }]);
        if (url === '/api/cascade/links' && !options) return json(snapshot({ links }));
        if (url === '/api/cascade/links/' + LINK_ID && !options) return json({
            name: 'Existing link', portalNode: 'portal', bridgeNode: 'bridge', autoDeploy: persistedAutoDeploy,
        });
        if (url === '/api/cascade/topology/deploy' && deployResponse) return {
            ok: false, status: deployResponse.status, async json() { return deployResponse.body; },
        };
        if (url === '/api/cascade/topology/deploy') return json({
            operationId: OP_ID, status: 'queued', kind: 'link.apply', topologyRevision: 7,
        });
        if (url === '/api/cascade/topology/operations/' + OP_ID) return json({
            operationId: OP_ID, status: 'succeeded', kind: 'link.apply', topologyRevision: 7,
        });
        if (job && url === '/api/cascade/links/auto-deploy-jobs/' + job.jobId) return json({ autoDeployJob: { ...job, status: 'admitted', operationId: OP_ID, topologyRevision: 8 } });
        if (job && options?.method === 'POST' && url === '/api/cascade/links') return { ok: true, status: 202, async json() { return { autoDeployJob: job, acceptedTopologyRevision: 7 }; } };
        if (options?.method === 'PUT' || options?.method === 'POST') return json(snapshot({
            ...(operation ? { autoDeployOperation: operation } : {}),
            ...(autoDeployError ? { autoDeployError, autoDeployStatus: 'blocked' } : {}),
        }));
        throw Error('Unexpected request: ' + url);
    };
    const window = { crypto: { randomUUID: require('node:crypto').randomUUID }, _networkI18n: { save: 'Save', saveAndDeploy: 'Save & Deploy',
        deployAfterEdit: 'Deploy this link after saving', autoDeploy: 'Auto Deploy', createLink: 'Create',
        syncChain: 'Sync Chain', syncingChain: 'Syncing entire chain...',
        confirmDeployChain: 'Deploy entire chain? This will sync all connected nodes in the correct order.' },
    showToast: (...args) => toasts.push(args) };
    // Expose the real browser handlers while skipping graph bootstrapping; all
    // form reads, fetch payloads, response handling and timers remain real.
    const instrumented = source.replace('    // ==================== START ====================',
        '    cy = window.__graph; applyLinkSnapshot(window.__snapshot); loadTopology = window.__reload; refreshStatuses = async function () {}; window.__ui = { openAddLinkModal, openEditLinkModal, onAddLinkSubmit, updateLinkSubmitIntent, deployTopology, onEdgeTap };\n    // ==================== START ====================');
    assert.notEqual(instrumented, source, 'browser probe insertion must find the boot boundary');
    window.__graph = graph;
    window.__snapshot = snapshot({ links });
    window.__reload = async () => { reloads += 1; };
    vm.runInNewContext(instrumented, {
        window, document, fetch, cytoscape: () => {},
        confirm: message => { confirmations.push(message); return confirmResult; },
        setTimeout: (fn, delay) => { timers.push({ fn, delay }); return timers.length; },
        clearTimeout: () => {}, console,
    });
    return { ui: window.__ui, window, form, elements, requests, toasts, timers, confirmations,
        get reloads() { return reloads; },
        renderEdge: (index = 0) => window.__ui.onEdgeTap({ target: edges[index] }) };
}

async function save(harness) {
    await harness.ui.onAddLinkSubmit({ target: harness.form, preventDefault() {} });
    return harness.requests.find(r => r.method === 'PUT' || r.method === 'POST');
}

test('accepted create intent polls its job without claiming a created link, saved draft or readiness', async () => {
    const job = { jobId: '507f1f77bcf86cd799439099', status: 'waiting', acceptanceRevision: 7 };
    const h = browserHarness({ job });
    await h.ui.openAddLinkModal();
    const request = await save(h);
    assert.match(request.headers['Idempotency-Key'], /^[a-f0-9-]{36}$/);
    assert.equal(h.timers.length, 1, JSON.stringify(h.toasts));
    assert(h.toasts.some(([message]) => /принят|accepted/i.test(message) && message.includes(job.jobId)));
    assert(!h.toasts.some(([message]) => /saved|сохранен|ready|готова/i.test(message)));
    await h.timers[0].fn();
    assert(h.requests.some(row => row.url.endsWith('/auto-deploy-jobs/' + job.jobId)));
    assert(!h.requests.some(row => row.url === '/api/cascade/topology/deploy'));
});

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
    assert.equal(h.timers.length, 2, 'applied topology must keep polling for client proof');
    assert(!h.toasts.some(([message]) => /готовность подтверждена|ready/i.test(message)));
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

test('unconfirmed domain anchor directs the user to separate Deploy without any mutation', async () => {
    for (const status of ['pending', 'offline', 'error', 'syncing', undefined]) {
        const h = browserHarness({ links: [{ _id: LINK_ID, status, active: true }] });
        h.renderEdge();
        assert.match(h.elements.nodeInfoBody.innerHTML, /сначала выполните отдельный Deploy/);
        await h.window._cascadeDeployChain(LINK_ID);
        assert.equal(h.requests.length, 0, `must not submit ${status} anchor`);
        assert.equal(h.confirmations.length, 0);
        assert.equal(h.timers.length, 0);
        assert(h.toasts.some(([message, type]) => type === 'error'
            && /сначала выполните отдельный Deploy/.test(message)));
    }
});

test('typed 409 busy response offers a manual retry after the current operation, never replays', async () => {
    for (const code of ['TOPOLOGY_DEPLOY_BUSY', 'TOPOLOGY_OPERATION_BUSY', 'TOPOLOGY_DEPLOYMENT_BUSY', 'OPERATION_IN_PROGRESS']) {
        const h = browserHarness({ links: [{ _id: LINK_ID, status: 'deployed', active: true }],
            deployResponse: { status: 409, body: { error: { code, message: 'secret=do-not-display' } } } });
        await h.window._cascadeDeployChain(LINK_ID);
        assert.equal(h.requests.filter(r => r.url === '/api/cascade/topology/deploy').length, 1);
        assert(h.reloads > 0, 'conflict must refresh the snapshot');
        assert.equal(h.timers.length, 0, 'busy is not an accepted operation and must not schedule retry');
        assert(h.toasts.some(([message, type]) => type === 'error' && message.includes(code)
            && /дождитесь завершения/i.test(message) && /повторите вручную/i.test(message)));
        assert(!h.toasts.some(([message]) => message.includes('do-not-display')));
    }
});

test('blocked auto-deploy surfaces typed busy guidance after saving without retrying', async () => {
    for (const mode of ['create', 'edit']) {
        const h = browserHarness({ autoDeployError: { code: 'TOPOLOGY_DEPLOY_BUSY',
            message: 'secret=do-not-display', retryable: true } });
        if (mode === 'edit') await h.ui.openEditLinkModal(LINK_ID);
        else await h.ui.openAddLinkModal();
        h.form.autoDeploy.checked = true;
        await save(h);
        assert.equal(h.requests.filter(r => ['PUT', 'POST'].includes(r.method)).length, 1);
        assert(!h.requests.some(r => r.url === '/api/cascade/topology/deploy'));
        assert.equal(h.timers.length, 0, 'retryable hint must not schedule an automatic deploy');
        assert(h.toasts.some(([message, type]) => type === 'error' && message.includes('TOPOLOGY_DEPLOY_BUSY')
            && /дождитесь завершения/i.test(message) && /повторите вручную/i.test(message)));
        assert(!h.toasts.some(([message]) => message.includes('do-not-display')));
    }
});

test('domain Sync explains confirmed-only scope despite legacy chain translations', async () => {
    const h = browserHarness({ links: [
        { _id: LINK_ID, status: 'deployed', active: true },
        { _id: '507f1f77bcf86cd799439033', status: 'pending', active: true },
    ] });
    h.renderEdge();
    const html = h.elements.nodeInfoBody.innerHTML;
    assert.match(html, /Sync применённого домена/);
    assert.match(html, /Только подтверждённые применённые связи/);
    assert.match(html, /[Оо]жидающие связи не включаются/);
    assert.doesNotMatch(html, /Sync Chain/);
    await h.window._cascadeDeployChain(LINK_ID);
    assert.equal(h.confirmations.length, 1);
    assert.match(h.confirmations[0], /подтверждённые применённые связи/);
    assert.match(h.confirmations[0], /[Оо]жидающие связи не включаются/);
    assert.doesNotMatch(h.confirmations[0], /entire chain|all connected/);
    const deploys = h.requests.filter(r => r.url === '/api/cascade/topology/deploy');
    assert.equal(deploys.length, 1);
    assert.deepEqual(deploys[0].body, { expectedTopologyRevision: 7, domainLinkId: LINK_ID });
    assert.equal(h.timers.length, 1, 'accepted scoped operation still starts identity-bound polling');
});

test('all API-confirmed anchor states remain eligible for scoped Sync', async () => {
    for (const status of ['deployed', 'online', 'staged']) {
        const h = browserHarness({ links: [{ _id: LINK_ID, status, active: true }] });
        await h.window._cascadeDeployChain(LINK_ID);
        assert.equal(h.requests.length, 1);
        assert.deepEqual(h.requests[0].body, { expectedTopologyRevision: 7, domainLinkId: LINK_ID });
    }
});

test('missing, disabled or newly unconfirmed anchors cannot submit domain Sync', async () => {
    for (const links of [[], [{ _id: LINK_ID, status: 'deployed', active: false }]]) {
        const h = browserHarness({ links });
        await h.window._cascadeDeployChain(LINK_ID);
        assert.equal(h.requests.length, 0);
        assert.equal(h.confirmations.length, 0);
        assert(h.toasts.some(([, type]) => type === 'error'));
    }
    const links = [{ _id: LINK_ID, status: 'deployed', active: true }];
    const h = browserHarness({ links });
    h.renderEdge();
    links[0].status = 'pending';
    await h.window._cascadeDeployChain(LINK_ID);
    assert.equal(h.requests.length, 0, 'click must check the latest snapshot, not the drawn edge color');
});

test('cancelled domain Sync does not mutate while Full Sync requires its own explicit confirmation', async () => {
    const h = browserHarness({ links: [{ _id: LINK_ID, status: 'deployed', active: true }], confirmResult: false });
    await h.window._cascadeDeployChain(LINK_ID);
    await h.window._cascadeDeployFull();
    assert.equal(h.requests.length, 0);
    assert.equal(h.confirmations.length, 2);
    assert.match(h.confirmations[1], /всю топологию/);
    const full = browserHarness();
    await full.window._cascadeDeployFull();
    assert.deepEqual(full.requests[0].body, { expectedTopologyRevision: 7 });
    assert.equal(full.confirmations.length, 1);
});

test('server-side unconfirmed rejection stays actionable without expanding scope', async () => {
    const h = browserHarness({ links: [{ _id: LINK_ID, status: 'deployed', active: true }],
        deployResponse: { status: 422, body: { error: { code: 'INVALID_TOPOLOGY_DEPLOYMENT' },
            errors: [{ code: 'SCOPE_LINK_UNCONFIRMED' }] } } });
    await h.window._cascadeDeployChain(LINK_ID);
    assert.equal(h.requests.length, 1);
    assert.equal(h.requests[0].body.domainLinkId, LINK_ID);
    assert.equal(h.timers.length, 0);
    assert(h.toasts.some(([message]) => /сначала выполните отдельный Deploy/.test(message)));
});

test('dedicated link deploy still sends the linkId, never unscoped', async () => {
    const h = browserHarness({ links: [{ _id: LINK_ID, status: 'pending', active: true }] });
    await h.window._cascadeDeploy(LINK_ID);
    assert.equal(h.confirmations.length, 1);
    const deploy = h.requests.find(r => r.url === '/api/cascade/topology/deploy');
    assert.equal(deploy.method, 'POST');
    assert.equal(deploy.body.linkId, LINK_ID);
    assert.equal(deploy.body.expectedTopologyRevision, 7);
    assert.equal(h.timers.length, 1);
});
