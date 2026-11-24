'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { IncomingMessage, ServerResponse } = require('node:http');
const { Socket } = require('node:net');
const { i18nMiddleware } = require('../../middleware/i18n');
const { routerForRebuild } = require('../../routes/cascadeRebuild');
const { createRebuildService } = require('../rebuildService');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
const generator = require('../configGenerator');
const Link = require('../../models/cascadeLinkModel');
test.after(() => require.cache[require.resolve('../sshPoolService')]?.exports.closeAll());

const id = i => String(i).padStart(24, '0');
const [source, target, anchor, hy, exit, downstream] = [1, 2, 3, 4, 5, 6].map(id);
const port = 40123;
function fixture(t, mode = 'forward') {
    t.mock.method(generator, 'buildPanelInlineCertificate', () => null);
    const inventory = [source, target, exit].map((_id, i) => ({ _id, active: true, type: 'xray',
        cascadeRole: i === 0 ? 'portal' : i === 1 ? 'relay' : 'bridge', ip: `192.0.2.${i + 1}`,
        name: i === 0 ? 'Portal A' : i === 1 ? 'Мост 乙' : 'Exit', xrayVersion: '26.6.1',
        xray: { security: 'none', apiPort: 61000 } }));
    const hyCard = { _id: hy, type: 'hysteria', active: false, name: 'Hysteria', port: 30123,
        ip: `192.0.2.${mode === 'reverse' ? 1 : 2}`, portRange: '40000-40122', portConfigs: [] };
    inventory.push(hyCard);
    const edge = (_id, portalNode, bridgeNode, extra) => ({ _id, active: true, mode,
        portalNode, bridgeNode, tunnelPort: port, tunnelSecurity: 'none', tunnelEncryption: 'none',
        tunnelUuid: `00000000-0000-4000-8000-${_id.slice(-12)}`, ...extra });
    const rows = [edge(anchor, source, target, { tunnelTransport: 'kcp' }),
        edge(downstream, target, exit, { tunnelPort: port + 1 })];
    const operations = [], reads = [], connections = [], states = [];
    const query = (fn, hook = () => {}) => ({
        select(fields) { this.fields = fields; return this; },
        read() { return this; }, readConcern() { return this; },
        async lean() {
            hook(this.fields);
            const rows = structuredClone(fn());
            if (!this.fields || this.fields.startsWith('+')) return rows;
            const keys = this.fields.split(' ').map(field => field.replace(/^\+/, ''));
            return rows.map(row => Object.fromEntries(keys.filter(k => Object.hasOwn(row, k)).map(k => [k, row[k]])));
        },
    });
    let onProfileRead;
    const nodeRows = inventory.filter(n => n.type === 'xray');
    const standalone = new Map(composeRebuildProfiles({ nodes: nodeRows, links: [] })
        .map(p => [`${p.nodeId}:${p.profile}`, p.config]));
    const Node = { find: filter => query(() => inventory.filter(row => (!filter._id || filter._id.$in.includes(row._id))
        && (!filter.type || row.type === filter.type) && (!filter.active || row.active)), fields => reads.push(fields)) };
    const service = createRebuildService({
        Node,
        Link: { find: filter => query(() => filter._id ? rows.filter(l => filter._id.$in.includes(l._id)) : rows),
            db: { transaction: async () => assert.fail('unexpected transaction') },
            updateOne: async () => assert.fail('unexpected link write') },
        State: { find: filter => query(() => states.filter(row => filter.node.$in.includes(row.node))) },
        sync: { _getUsersForNode: async () => [] },
        env: { C3_REBUILD_ENABLED: 'true' }, locks: { run: fn => fn(async () => {}) },
        assertNoRelayAccountIntent: async () => {},
        connect: node => {
            connections.push(node._id);
            return { close() {}, requireSupportedCore: async () => '26.11.9',
                read: async profile => { onProfileRead?.(); return structuredClone(standalone.get(`${node._id}:${profile}`)); },
                stagePair: async () => { operations.push('stage'); throw Error('stage must never be reached'); },
                putPair: async () => { operations.push('put'); throw Error('put must never be reached'); } };
        },
    });
    const app = express();
    app.use(express.json(), i18nMiddleware, (req, res, next) => {
        req.apiKey = { scopes: ['nodes:write'] }; next();
    });
    app.use('/api/cascade', routerForRebuild({ service, Node, Link }));
    function request(path, input, lang = 'en', method = 'POST') {
        const body = JSON.stringify(input);
        return new Promise(resolve => {
            const req = new IncomingMessage(new Socket());
            Object.assign(req, { url: `/api/cascade${path}`, method, complete: true,
                headers: { 'accept-language': lang, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) } });
            req.push(body); req.push(null);
            const res = new ServerResponse(req);
            res.end = bytes => resolve({ status: res.statusCode, body: JSON.parse(bytes) });
            app(req, res);
        });
    }
    return { inventory, hyCard, rows, states, reads, operations, connections, request, onRead(fn) { onProfileRead = fn; },
        preview: (linkId = anchor, lang, remove) => request('/rebuild/preview', { linkId, remove, xrayVersion: '99.9.9' }, lang),
        apply: (expectedPreview, lang) => request('/topology/deploy', { linkId: anchor, expectedPreview }, lang) };
}
const expectDenied = (reply, code) => {
    assert.equal(reply.status, 409);
    assert.deepEqual(Object.keys(reply.body), ['error']);
    assert.equal(reply.body.error.code, code);
    assert.ok(reply.body.error.message);
    return reply.body.error;
};

test('mounted Preview reports every failed endpoint of desired sibling links, never exposes malformed input or a token', async t => {
    const f = fixture(t);
    delete f.inventory[0].xrayVersion;
    f.inventory[0].name = '<script>fixture()</script>';
    f.inventory[1].xrayVersion = '26.3.27';
    const error = expectDenied(await f.preview(downstream, 'ru-RU'), 'REBUILD_KCP_XRAY_VERSION_UNSUPPORTED');
    assert.deepEqual(error.issues.map(i => [i.nodeId, i.nodeName, i.version, i.reason]), [
        [source, source, null, 'unknown'], [target, 'Мост 乙', '26.3.27', 'too_old'],
    ]);
    assert.match(error.message, /Нода Мост 乙: Xray 26\.3\.27, для mKCP нужен 26\.6\.1\+/);
    for (const malformed of ['Xray 99.9.9', '26.6.1-rc.1', '26.6.1\n', '26.06.1', ' 27.1.1', 27, null, '26.13.1']) {
        f.inventory[0].xrayVersion = malformed;
        const refusal = expectDenied(await f.preview(anchor, 'zh-CN'), 'REBUILD_KCP_XRAY_VERSION_UNSUPPORTED');
        assert.equal(refusal.issues[0].version, null);
        assert.match(refusal.message, /节点.*需要 Xray 26\.6\.1/);
    }
    assert.deepEqual(f.connections, []);
    assert.deepEqual(f.operations, []);
});

test('Apply recomputes and binds the stored versions even when the generated profiles do not change', async t => {
    const f = fixture(t);
    const { status, body } = await f.preview();
    assert.equal(status, 200);
    assert.equal(body.allowed, true);
    assert.match(body.previewId, /^[a-f0-9]{128}$/);
    f.connections.length = 0;
    f.inventory[0].xrayVersion = '26.6.0';
    assert.equal(expectDenied(await f.apply(body.previewId), 'REBUILD_KCP_XRAY_VERSION_UNSUPPORTED').issues[0].version, '26.6.0');
    assert.deepEqual(f.connections, []);
    f.inventory[0].xrayVersion = '26.6.2';
    const stale = expectDenied(await f.apply(body.previewId), 'REBUILD_PREVIEW_CHANGED');
    assert.match(stale.message, /Run Preview again/);
    assert.deepEqual(f.operations, []);
});

test('in-flight health drift is reread before staging, and removing an unsupported mKCP link is not gated', async t => {
    const f = fixture(t);
    const initial = await f.preview();
    assert.equal(initial.status, 200);
    assert.equal(initial.body.allowed, true);
    f.onRead(() => { f.inventory[1].xrayVersion = '26.3.27'; });
    expectDenied(await f.apply(initial.body.previewId), 'REBUILD_KCP_XRAY_VERSION_UNSUPPORTED');
    assert.deepEqual(f.operations, []);
    f.onRead(undefined);
    const remove = await f.preview(anchor, 'en', true);
    assert.equal(remove.status, 200);
    assert.equal(remove.body.allowed, true);
});

for (const mode of ['forward', 'reverse']) test(`${mode} UDP ownership: same-host Hysteria only, primary/alternate/range, checked again on Apply`, async t => {
    const f = fixture(t, mode);
    f.hyCard.portConfigs = [{ port, enabled: false, portRange: '40000-40200' }];
    const preview = await f.preview();
    assert.equal(preview.status, 200);
    assert.ok(preview.body.allowed);
    f.connections.length = 0;
    f.hyCard.portRange = '40123-40124';
    const reply = expectDenied(await f.apply(preview.body.previewId, 'ru'), 'REBUILD_KCP_UDP_PORT_CONFLICT');
    assert.deepEqual(reply.issues.map(i => [i.nodeId, i.port, i.ownerId, i.reason]),
        [[mode === 'reverse' ? source : target, port, hy, 'hysteria_hop_range']]);
    assert.deepEqual(f.connections, []);
    f.hyCard.portRange = '';
    f.hyCard.portConfigs[0].enabled = true;
    assert.equal(expectDenied(await f.preview(), 'REBUILD_KCP_UDP_PORT_CONFLICT').issues[0].reason, 'hysteria_port');
    f.hyCard.portConfigs = [];
    f.hyCard.port = port;
    expectDenied(await f.preview(), 'REBUILD_KCP_UDP_PORT_CONFLICT');
    f.hyCard.ip = f.inventory[mode === 'reverse' ? 1 : 0].ip;
    assert.equal((await f.preview()).status, 200);
    assert.deepEqual(f.operations, []);
});


test('a working mKCP field drifting after the desired snapshot cannot stage any profile', async t => {
    const f = fixture(t);
    const preview = await f.preview();
    assert.equal(preview.status, 200);
    f.onRead(() => { f.rows[0].kcpMtu = 1300; });
    const result = await f.apply(preview.body.previewId);
    assert.deepEqual(result, { status: 409, body: { error: { code: 'REBUILD_LINK_CHANGED' } } });
    assert.deepEqual(f.operations, []);
});

test('mKCP cannot use an installed relay’s reserved L2TP or TPROXY UDP port', async t => {
    const f = fixture(t);
    f.states.push({ node: target, status: 'installed', desiredState: 'installed', tproxyPort: port });
    for (const reserved of [port, 500, 4500, 1701]) {
        f.rows[0].tunnelPort = reserved;
        const error = expectDenied(await f.preview(), 'REBUILD_KCP_UDP_PORT_CONFLICT');
        assert.deepEqual(error.issues.map(x => [x.nodeId, x.port, x.reason]), [[target, reserved, 'l2tp_reserved']]);
    }
    assert.deepEqual(f.connections, []);
});


const listenerCode = 'REBUILD_L2TP_KCP_LISTENER_UNSUPPORTED';
const directState = node => ({ node, status: 'installed', desiredState: 'installed', tproxyPort: 41000,
    rebuildInstallToken: '00000000-0000-4000-8000-000000000001' });

for (const mode of ['forward', 'reverse']) test(`${mode}: refuse an installed DIRECT mKCP listener before draft save, Preview or Apply`, async t => {
    const f = fixture(t, mode);
    if (mode === 'reverse') {
        delete f.rows[0].tunnelTransport;
        f.rows[1].tunnelTransport = 'kcp';
    }
    const link = f.rows[mode === 'reverse' ? 1 : 0];
    const initial = await f.preview(); // uninstalled relay is still allowed to use mKCP
    assert.equal(initial.body.allowed, true);
    f.connections.length = 0;
    f.states.push(directState(target));
    const save = t.mock.method(Link.prototype, 'save', async () => assert.fail('unexpected draft write'));
    const draft = { name: 'fixture mKCP', mode, tunnelTransport: 'kcp', tunnelSecurity: 'none', autoDeploy: true,
        portalNodeId: link.portalNode, bridgeNodeId: link.bridgeNode, tunnelPort: link.tunnelPort };
    const ru = expectDenied(await f.request('/links', draft, 'ru-RU'), listenerCode);
    assert.match(ru.message, /Мост 乙.*mKCP.*L2TP/);
    t.mock.method(Link, 'findById', () => ({ select: async () => new Link({ ...link, name: 'saved fixture' }) }));
    expectDenied(await f.request(`/links/${link._id}`, { kcpTti: 40 }, 'en', 'PUT'), listenerCode);
    const en = expectDenied(await f.preview(anchor, 'en'), listenerCode);
    assert.match(en.message, /Мост 乙.*L2TP.*mKCP listener/);
    assert.equal(en.issues[0].nodeId, target);
    expectDenied(await f.apply(initial.body.previewId), listenerCode);
    assert.deepEqual([f.connections, f.operations, save.mock.callCount()], [[], [], 0]);
});

test('Apply rechecks DIRECT listener ownership before staging', async t => {
    const f = fixture(t);
    const initial = await f.preview();
    assert.equal(initial.body.allowed, true);
    f.onRead(() => { if (!f.states.length) f.states.push(directState(target)); });
    expectDenied(await f.apply(initial.body.previewId), listenerCode);
    assert.deepEqual(f.operations, []);
});

test('mKCP draft remains allowed when the installed relay only dials or the listener has no DIRECT layout', async t => {
    const f = fixture(t);
    const save = t.mock.method(Link.prototype, 'save', async () => {});
    f.states.push(directState(target));
    const draft = { name: 'fixture mKCP', mode: 'forward', tunnelTransport: 'kcp', tunnelSecurity: 'none',
        portalNodeId: target, bridgeNodeId: exit, tunnelPort: port + 1 };
    assert.equal((await f.request('/links', draft)).body.status, 'saved');
    delete f.states[0].rebuildInstallToken;
    f.states[0].routingMode = 'route-group';
    assert.equal((await f.request('/links', { ...draft, portalNodeId: source, bridgeNodeId: target })).body.status, 'saved');
    assert.equal(save.mock.callCount(), 2);
    assert.deepEqual(f.connections, []);
});

test('an unsupported mKCP draft POST never saves or begins its auto-deploy Preview', async t => {
    const f = fixture(t);
    const save = t.mock.method(Link.prototype, 'save', async () => assert.fail('unexpected draft write'));
    f.inventory[1].xrayVersion = '26.3.27';
    const result = await f.request('/links', { name: 'fixture mKCP', portalNodeId: source, bridgeNodeId: target,
        tunnelPort: port, tunnelTransport: 'kcp', tunnelSecurity: 'none', autoDeploy: true, xrayVersion: '26.11.9' }, 'ru');
    assert.match(expectDenied(result, 'REBUILD_KCP_XRAY_VERSION_UNSUPPORTED').message, /Xray 26\.3\.27/);
    assert.equal(save.mock.callCount(), 0);
    assert.deepEqual(f.connections, []);
});
