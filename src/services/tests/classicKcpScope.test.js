'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { inspectTunnelPort, preflightTunnelPort } = require('../classicScopedPortPreflight');
const { createClassicScopedCascadeDeploymentService } = require('../classicScopedCascadeDeploymentService');
const { TopologyDraftWriteService } = require('../../modules/relay-l2tp/services/topologyDraftWriteService');
const { describeTopologyError } = require('../../../public/js/network');
const { t: translate } = require('../../middleware/i18n');
const refusal = { code: 'CLASSIC_KCP_REBUILD_ONLY' };
const fixture = { port: 10086, node: { active: true, ip: '192.0.2.1', ssh: { password: 'fixture' } } };

test('explicit UDP transport is rejected before constructing SSH', async () => {
    let constructed = 0;
    class SSH {
        constructor() { constructed++; }
        connect() { throw Error('unexpected SSH connect'); }
        disconnect() {}
    }
    await assert.rejects(preflightTunnelPort({ ...fixture, tunnelTransport: 'kcp' }, { NodeSSH: SSH }), refusal);
    assert.equal(constructed, 0);
});

test('a retained mKCP link is not eligible for TCP attribution, even with a TCP override', async () => {
    let reads = 0;
    await assert.rejects(inspectTunnelPort({ ...fixture, tunnelTransport: 'tcp', target: {tunnelTransport: 'kcp'} },
        async () => { reads++; return ''; }), refusal);
    assert.equal(reads, 0);
});

test('a known UDP-only config inbound does not occupy the TCP port; the TCP socket can still be taken', async () => {
    for (const occupied of [false, true]) {
        const commands = [];
        const work = inspectTunnelPort(fixture, async command => {
            commands.push(command);
            if (command.startsWith('ss ')) return occupied ? 'LISTEN 0 128 *:10086 *:*' : '';
            return JSON.stringify({ inbounds: [{ port: '10085-10086', streamSettings: { network: 'kcp' } }] });
        });
        if (occupied) await assert.rejects(work, { code: 'TUNNEL_PORT_IN_USE' });
        else await work;
        assert.match(commands.at(-1), /^ss -H -ltnp /);
    }
});

for (const retained of [false, true]) test(`scoped classic refuses ${retained ? 'a confirmed mKCP sibling' : 'an mKCP target'} before lock, owner lookup or SSH`, async () => {
    const source = 'a'.repeat(24), target = 'b'.repeat(24), linkId = 'c'.repeat(24), siblingId = 'd'.repeat(24);
    const selected = { _id: linkId, portalNode: source, bridgeNode: target, mode: 'reverse', active: true,
        status: 'pending', tunnelTransport: retained ? 'tcp' : 'kcp' };
    const sibling = { ...selected, _id: siblingId, portalNode: 'e'.repeat(24), status: 'offline', tunnelTransport: 'kcp' };
    const db = { transaction: work => work({}) };
    const query = value => ({ setOptions() { return this; }, select() { return this; }, session() { return this; }, lean: async () => value });
    const forbidden = () => assert.fail('ownership, lock and SSH must not run');
    const service = createClassicScopedCascadeDeploymentService({
        // Pure authorization inputs; no process settings or real endpoints.
        env: { PANEL_DOMAIN: 'lm1.infograd.online', L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
            L2TP_PRODUCTION_EXECUTION_ENABLED: 'true', CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true',
            TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false', CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: linkId },
        CascadeTopologyState: { db, findById: () => query({ revision: 1 }) },
        CascadeLink: { db, find: filter => query(filter._id ? [selected] : [selected, ...(retained ? [sibling] : [])]) },
        HyNode: { db, find: filter => filter ? query([{ _id: source, cascadeRole: 'portal' }, { _id: target, cascadeRole: 'bridge' }]) : forbidden() },
        TopologyOperation: { db }, TopologyCreateIntent: { db }, TopologyIntentQueueState: { db },
        NodeOperationLock: { db }, RelayL2tpState: { db }, CascadeRouteGroup: { db },
        topologyManagesNodeConfig: forbidden, lockService: { acquire: forbidden }, NodeSSH: forbidden,
        logger: { warn() {} },
    });
    await assert.rejects(service.queue({ expectedTopologyRevision: 1,
        scope: { kind: 'link.apply', linkId, linkIds: [linkId, ...(retained ? [siblingId] : [])] } }), refusal);
});

test('classic partial edits and conversion cannot overwrite a retained Rebuild transport', async () => {
    const id = 'a'.repeat(24);
    const service = new TopologyDraftWriteService({ repository: { commitDraft: ({prepare}) =>
        prepare({ links: [{ _id: id, tunnelTransport: 'kcp' }] }) } });
    await assert.rejects(service.updateLink({ expectedTopologyRevision: 1, linkId: id, changes: { name: 'fixture' } }), refusal);
    await assert.rejects(service.updateLink({ expectedTopologyRevision: 1, linkId: id, changes: { tunnelTransport: 'tcp' } }), refusal);
});

test('classic refusal is localized by the shared view error renderer', () => {
    const previous = global.window;
    try {
        for (const [lang, pattern] of [['en', /supported only in Rebuild/], ['ru', /доступен только в Rebuild/]]) {
            const classicKcpRebuildOnly = translate('network.classicKcpRebuildOnly', lang);
            global.window = { _networkI18n: { classicKcpRebuildOnly } };
            assert.match(classicKcpRebuildOnly, pattern);
            assert.equal(describeTopologyError({ error: refusal }), classicKcpRebuildOnly);
        }
    } finally { if (previous === undefined) delete global.window; else global.window = previous; }
});
