'use strict';
process.env.PANEL_DOMAIN ||= 'test.infograd.online';
process.env.ACME_EMAIL ||= 'test@example.invalid';
process.env.ENCRYPTION_KEY ||= '0123456789abcdef0123456789abcdef';
process.env.SESSION_SECRET ||= 'classic-import-local-test';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readClassicAppliedTopologies } = require('../services/classicBaselineImport');
const generator = require('../../../services/configGenerator');
const id = n => n.toString(16).padStart(24, '0');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

function fixture() {
    const rows = ['portal', 'bridge'].map((cascadeRole, i) => ({ _id: id(i + 1), cascadeRole,
        type: 'xray', active: true, ip: `192.0.2.${i + 1}`, port: 24443,
        xray: { inboundTag: 'client-in', security: 'none', transport: 'tcp', extraInbounds: [] } }));
    const link = { _id: id(10), portalNode: rows[0]._id, bridgeNode: rows[1]._id,
        mode: 'reverse', active: true, status: 'online', tunnelPort: 25000,
        tunnelUuid: '11111111-1111-4111-8111-111111111111', tunnelSecurity: 'none',
        tunnelTransport: 'tcp', tunnelDomain: 'classic.test.invalid', priority: 1 };
    const populated = { ...link, portalNode: rows[0], bridgeNode: rows[1] };
    const portal = JSON.parse(generator.generateXrayConfig(rows[0], []));
    generator.applyReversePortal(portal, [populated], ['client-in']);
    const profiles = { [id(1)]: JSON.stringify(portal, null, 2),
        [id(2)]: generator.generateCombinedBridgeConfig([populated]) };
    const nodes = rows.map(row => ({ nodeId: row._id,
        targetProfile: row.cascadeRole === 'portal' ? 'xray-main' : 'xray-bridge',
        originalSnapshot: { configSha256: sha(profiles[row._id]) } }));
    const query = value => ({ select() { return this; }, read() { return this; },
        readConcern() { return this; }, maxTimeMS() { return this; }, lean: async () => structuredClone(value) });
    const dependencies = { nodes, readProfile: async node => profiles[node],
        HyNode: { find: () => query(rows) }, CascadeLink: { find: () => query([link]) },
        CascadeRouteGroup: { find: () => query([]) } };
    return { dependencies, profiles, nodes };
}

test('startup classic import checks both actual profiles and keeps private descriptors for public adoption', async () => {
    const f = fixture();
    const result = await readClassicAppliedTopologies(f.dependencies);
    assert.deepEqual(Object.keys(result), [id(1), id(2)]);
    assert.deepEqual(result[id(1)], result[id(2)]);
    assert.equal(result[id(1)].links[0].status, undefined);
    for (const node of result[id(1)].nodes) assert.equal(node.profileConfig, f.profiles[node.id]);
    assert.equal(result[id(1)].links[0].tunnelUuid, '11111111-1111-4111-8111-111111111111');
});

test('startup import recognizes the scoped classic bootstrap guard order without changing actual bytes', async () => {
    const f = fixture();
    const delta = JSON.parse(f.profiles[id(2)]);
    const bridge = JSON.parse(require('../../../services/classicPortalBridgeBootstrap').IDLE_BYTES);
    bridge.reverse = delta.reverse;
    bridge.outbounds = delta.outbounds;
    // Same seed-tail / insert-before-private sequence as the real scoped writer.
    bridge.routing.rules.push(...delta.routing.rules.filter(row => !row.domain && !row.inboundTag));
    const index = bridge.routing.rules.findIndex(row => !row.inboundTag && row.ip?.includes('geoip:private'));
    bridge.routing.rules.splice(index < 0 ? bridge.routing.rules.length : index, 0,
        ...delta.routing.rules.filter(row => row.domain || row.inboundTag));
    f.profiles[id(2)] = JSON.stringify(bridge);
    f.nodes[1].originalSnapshot.configSha256 = sha(f.profiles[id(2)]);
    const result = await readClassicAppliedTopologies(f.dependencies);
    assert.equal(result[id(2)].nodes[1].profileConfig, f.profiles[id(2)]);
    assert.deepEqual(JSON.parse(result[id(2)].nodes[1].profileConfig).routing.rules, bridge.routing.rules);
});

test('startup import names the mismatching peer and does not normalize an honestly observed profile', async () => {
    const f = fixture();
    const b = JSON.parse(f.profiles[id(2)]);
    b.routing.rules.unshift(b.routing.rules.splice(1, 1)[0]);
    f.profiles[id(2)] = JSON.stringify(b);
    f.nodes[1].originalSnapshot.configSha256 = sha(f.profiles[id(2)]);
    await assert.rejects(readClassicAppliedTopologies(f.dependencies), error => {
        assert.equal(error.code, 'CLASSIC_BASELINE_IMPORT_REFUSED');
        assert.equal(error.nodeId, id(2));
        assert.equal(error.profile, 'xray-bridge');
        assert.equal(error.causeCode, 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH');
        assert.match(error.message, /фактический профиль не совпадает/);
        assert(!error.message.includes('11111111-1111'));
        return true;
    });
    await assert.rejects(readClassicAppliedTopologies({ ...f.dependencies,
        readProfile: async () => '{}',
    }), { code: 'CLASSIC_BASELINE_IMPORT_REFUSED', causeCode: 'CONFIG_LEGACY_IMPORT_READBACK_MISMATCH' });
});

test('startup import leaves the proven empty-profile bootstrap unchanged', async () => {
    assert.equal(await readClassicAppliedTopologies({ nodes: [{ originalSnapshot: { configSha256: sha('{}') } }] }), undefined);
});
