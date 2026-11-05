'use strict';
// PHASE A ONLY: local observed-artifact adoption, not installed-owner join,
// selected admission, native lifecycle, real Mongo/SSH/PPP or PROD evidence.
const test = require('node:test');
const assert = require('node:assert/strict');
const { isDeepStrictEqual: same } = require('node:util');
const { installedGroupFixture, id, sha, copy, key, profileFor } = require('./helpers/cascadeLegacyInstalledGroupFixture');
const { legacyProfileArtifacts } = require('../../../services/topologyConfigTransfer');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
for (const context of [TEST, PROD]) test(`phase A ${context.target}: public adoption recognizes observed reverse G2 installed ingress independently on all three profiles`, async () => {
    const f = installedGroupFixture(context), original = copy(f.topology);
    const protectedHash = sha(JSON.stringify({ physical: [...f.physical], inventory: f.inventory }));
    const results = [];
    for (const node of f.topology.nodes) results.push(await f.adopt(node));
    for (const [index, owner] of results.entries()) {
        const node = f.topology.nodes[index], observed = f.physical.get(key(node.id, profileFor(node)));
        assert.equal(owner.owner, 'topology');
        assert.equal(owner.profile, profileFor(node));
        assert.equal(owner.originalSnapshot.configSha256, sha(observed.config));
        assert.equal(owner.originalSnapshot.unitSha256, sha(observed.unit));
        assert.equal(owner.adoptionReceipt.toGeneration, owner.generation);
        assert.notEqual(owner.adoptionReceipt.fromGeneration, owner.generation);
        assert.equal(owner.lastSettledOperation, undefined);
        assert.equal(owner.profileTargetPin, undefined, 'reverse import must not mint forward placement authority');
        assert.ok(same(owner.legacyAppliedTopology, original), 'public confirmation returns complete private accepted descriptors');
        const ordinary = await f.Owner.findOne({ node: node.id, profile: profileFor(node) }).lean();
        assert.equal(ordinary.legacyAppliedTopology, undefined, 'actual Mongoose default query hides private descriptor');
        const explicit = await f.Owner.findOne({ node: node.id, profile: profileFor(node) }).select('+legacyAppliedTopology').lean();
        assert.ok(same(explicit.legacyAppliedTopology, original), 'actual explicit query reload preserves descriptor');
        const confirmation = f.events.find(event => event.method === 'findOne' && event.filter.owner === 'topology'
            && String(event.filter.node) === node.id);
        assert.notEqual(confirmation.options.projection?.legacyAppliedTopology, 0);
        assert.equal(confirmation.options.readPreference.mode, 'primary');
        assert.deepEqual(confirmation.options.readConcern, { level: 'majority' });
        assert.equal(confirmation.options.maxTimeMS, 5000);
        assert.equal(confirmation.held, true);
    }
    const relay = legacyProfileArtifacts(f.topology, id(2)), path = original.groups[0].paths[0];
    assert.deepEqual(relay.inbounds.filter(row => row.tag === path.cascadePathIngress.tag), [{
        tag: path.cascadePathIngress.tag, listen: '127.0.0.1', port: path.cascadePathIngress.port,
        protocol: 'socks', settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' } }]);
    assert.deepEqual(relay.routing.rules.filter(row => row.inboundTag?.includes(path.cascadePathIngress.tag)), [{
        type: 'field', inboundTag: [path.cascadePathIngress.tag], outboundTag: `portal-down-${original.links[1].id.slice(-8)}` }]);
    assert.equal(protectedHash, sha(JSON.stringify({ physical: [...f.physical], inventory: f.inventory })));
    assert.equal(f.events.filter(event => event.method === 'findOneAndUpdate').length, 3);
    assert.deepEqual(f.calls, []);
    assert.equal(f.data.TopologyOperation, undefined, 'adoption creates no successful topology history');
    assert.equal(f.held(), false);
});

function rejectedWithoutCAS(f) {
    assert.equal(f.events.filter(event => event.method === 'findOneAndUpdate').length, 0);
    assert.ok(f.data.TopologyConfigOwner.every(row => row.owner === 'classic' && row.adoptionReceipt === undefined
        && row.legacyAppliedTopology === undefined));
    assert.deepEqual(f.calls, []);
}
const ingress = config => config.inbounds.find(row => row.tag.startsWith('cascade-'));
for (const [name, change] of [
    ['missing cascade listener', c => { c.inbounds = c.inbounds.filter(row => !row.tag.startsWith('cascade-')); }],
    ['altered listen', c => { ingress(c).listen = '0.0.0.0'; }],
    ['altered port', c => { ingress(c).port++; }],
    ['altered auth', c => { ingress(c).settings.auth = 'password'; }],
    ['altered UDP', c => { ingress(c).settings.udp = false; }],
    ['altered SOCKS IP', c => { ingress(c).settings.ip = '192.0.2.1'; }],
    ['altered protocol', c => { ingress(c).protocol = 'http'; }],
    ['empty SOCKS settings', c => { ingress(c).settings = {}; }],
    ['duplicate listener', c => { c.inbounds.push(copy(ingress(c))); }],
    ['duplicate tag on different port', c => { c.inbounds.push({ ...copy(ingress(c)), port: 19999 }); }],
    ['duplicate port under unrelated tag', c => { c.inbounds.push({ ...copy(ingress(c)), tag: 'foreign-listener' }); }],
    ['unknown second cascade ingress', c => { c.inbounds.push({ ...copy(ingress(c)), tag: 'cascade-unrepresented', port: 29999 }); }],
    ['missing ingress route', c => { c.routing.rules = c.routing.rules.filter(row => !row.inboundTag?.includes(ingress(c).tag)); }],
    ['altered ingress egress', c => { c.routing.rules.find(row => row.inboundTag?.includes(ingress(c).tag)).outboundTag = 'unrelated-out'; }],
    ['reordered canonical rules', c => { const index = c.routing.rules.findIndex(row => row.inboundTag?.includes(ingress(c).tag));
        [c.routing.rules[index - 1], c.routing.rules[index]] = [c.routing.rules[index], c.routing.rules[index - 1]]; }],
    ['missing global private guard', c => { c.routing.rules = c.routing.rules.filter(row => row.ip?.[0] !== 'geoip:private'); }],
    ['extra global direct escape', c => { c.routing.rules.unshift({ type: 'field', outboundTag: 'unrelated-out' }); }],
    ['extra empty-scope direct escape', c => { c.routing.rules.unshift({ type: 'field', inboundTag: [], outboundTag: 'unrelated-out' }); }],
    ['extra global domain direct escape', c => { c.routing.rules.unshift({ type: 'field', domain: ['full:escape.invalid'], outboundTag: 'unrelated-out' }); }],
    ['extra global balancer escape', c => { c.routing.rules.unshift({ type: 'field', balancerTag: 'unrepresented-balancer' }); }],
    ['extra K-scoped direct escape', c => { c.routing.rules.unshift({ type: 'field', inboundTag: [ingress(c).tag], outboundTag: 'unrelated-out' }); }],
    ['extra K-scoped balancer escape', c => { c.routing.rules.unshift({ type: 'field', inboundTag: [ingress(c).tag], balancerTag: 'unrepresented-balancer' }); }],
    ['extra mixed K and unrelated scope escape', c => { c.routing.rules.unshift({ type: 'field', inboundTag: ['unrelated-client', ingress(c).tag], outboundTag: 'unrelated-out' }); }],
]) test(`phase A exact R artifacts: refuses ${name} despite matching own readback SHA`, async () => {
    const f = installedGroupFixture(), proposed = copy(f.topology), relay = proposed.nodes[1];
    const config = JSON.parse(relay.profileConfig); change(config);
    relay.profileConfig = JSON.stringify(config);
    f.physical.get(key(relay.id, profileFor(relay))).config = relay.profileConfig;
    const protectedHash = sha(JSON.stringify({ physical: [...f.physical], inventory: f.inventory }));
    await assert.rejects(f.adopt(relay, proposed), { code: 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH' });
    rejectedWithoutCAS(f);
    assert.equal(protectedHash, sha(JSON.stringify({ physical: [...f.physical], inventory: f.inventory })));
});

for (const [name, change, code = 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'] of [
    ['full portal path instead of R suffix', t => { t.groups[0].paths[0].linkIds = t.links.map(link => link.id); }],
    ['upstream-only path', t => { t.groups[0].paths[0].linkIds = [t.links[0].id]; }],
    ['reversed full path', t => { t.groups[0].paths[0].linkIds = t.links.map(link => link.id).reverse(); }],
    ['duplicate path membership', t => { t.groups[0].paths[0].linkIds.push(t.links[1].id); }],
    ['foreign path membership', t => { t.groups[0].paths[0].linkIds = [id(99)]; }, 'CONFIG_LEGACY_IMPORT_INVALID'],
    ['disabled path', t => { t.groups[0].paths[0].enabled = false; }],
    ['implicit enabled default', t => { delete t.groups[0].paths[0].enabled; }],
    ['empty path', t => { t.groups[0].paths[0].linkIds = []; }],
    ['no paths', t => { t.groups[0].paths = []; }],
    ['second path', t => { t.groups[0].paths.push(copy(t.groups[0].paths[0])); }],
    ['second group', t => { t.groups.push({ ...copy(t.groups[0]), _id: id(61) }); }],
    ['duplicate group', t => { t.groups.push(copy(t.groups[0])); }, 'CONFIG_LEGACY_IMPORT_INVALID'],
    ['forward group', t => { t.groups[0].mode = 'forward'; }],
    ['unsupported strategy', t => { t.groups[0].strategy = 'random'; }],
    ['zero priority', t => { t.groups[0].paths[0].priority = 0; }],
    ['negative priority', t => { t.groups[0].paths[0].priority = -1; }],
    ['nonfinite priority', t => { t.groups[0].paths[0].priority = Infinity; }, 'CONFIG_LEGACY_IMPORT_INVALID'],
    ['string priority', t => { t.groups[0].paths[0].priority = '4'; }],
    ['unsafe path key', t => { t.groups[0].paths[0].pathKey = '../legacy-main'; }],
    ['empty path key', t => { t.groups[0].paths[0].pathKey = ''; }],
    ['overlong path key', t => { t.groups[0].paths[0].pathKey = 'a'.repeat(65); }],
    ['wrong ingress tag', t => { t.groups[0].paths[0].cascadePathIngress.tag += '-wrong'; }],
    ['wrong ingress port', t => { t.groups[0].paths[0].cascadePathIngress.port++; }],
    ['string ingress port', t => { t.groups[0].paths[0].cascadePathIngress.port = String(t.groups[0].paths[0].cascadePathIngress.port); }],
    ['missing ingress descriptor', t => { delete t.groups[0].paths[0].cascadePathIngress; }],
    ['noncanonical group display field', t => { t.groups[0].name = 'not-routing-authority'; }],
    ['geo route', t => { t.links[1].geoRouting = { enabled: true, domains: ['example.invalid'] }; }],
    ['mixed link mode', t => { t.links[1].mode = 'forward'; }],
    ['all-forward grouped layout', t => { for (const link of t.links) link.mode = 'forward'; }],
    ['TLS tunnel', t => { t.links[0].tunnelSecurity = 'tls'; }],
    ['REALITY grouped tunnel', t => { t.links[0].tunnelSecurity = 'reality'; }],
    ['unsupported tunnel protocol', t => { t.links[0].tunnelProtocol = 'vmess'; }],
    ['unsupported tunnel transport', t => { t.links[0].tunnelTransport = 'ws'; }],
    ['TLS grouped client', t => { t.nodes[0].xray.security = 'tls'; }],
    ['REALITY grouped client', t => { t.nodes[0].xray.security = 'reality'; }],
    ['unsupported client protocol', t => { t.nodes[1].xray.protocol = 'vmess'; }],
    ['unsupported client transport', t => { t.nodes[1].xray.transport = 'ws'; }],
    ['REALITY extra client', t => { t.nodes[0].xray.extraInbounds.push({ inboundTag: 'extra', security: 'reality' }); }],
    ['missing relay node/non-G2', t => { t.nodes.splice(1, 1); }, 'CONFIG_LEGACY_IMPORT_INVALID'],
    ['extra unrepresented node', t => { t.nodes.push({ ...copy(t.nodes[2]), id: id(4) }); }],
    ['fan-in link', t => { t.links.push({ ...copy(t.links[0]), id: id(12) }); }],
    ['fan-out link', t => { t.links.push({ ...copy(t.links[1]), id: id(12) }); }],
    ['malformed group ID', t => { t.groups[0]._id += '0'; }, 'CONFIG_LEGACY_IMPORT_INVALID'],
    ['malformed node ID', t => { t.nodes[0].id += '0'; }, 'CONFIG_LEGACY_IMPORT_INVALID'],
    ['duplicate link ID', t => { t.links[1].id = t.links[0].id; }, 'CONFIG_LEGACY_IMPORT_INVALID'],
    ['string tunnel port', t => { t.links[1].tunnelPort = String(t.links[1].tunnelPort); }, 'CONFIG_LEGACY_IMPORT_INVALID'],
]) test(`phase A bounded descriptor: refuses ${name} before maintenance or adoption CAS`, async () => {
    const f = installedGroupFixture(), proposed = copy(f.topology), relay = proposed.nodes[1];
    change(proposed);
    await assert.rejects(f.adopt(relay, proposed), { code });
    rejectedWithoutCAS(f);
    assert.ok(!f.events.some(event => event.held), 'unsupported inventory must fail before maintenance');
});

for (const index of [0, 1, 2]) {
    test(`phase A independent ${['P MAIN', 'R SIDECAR', 'B SIDECAR'][index]}: raw bytes cannot borrow another profile SHA`, async () => {
        const f = installedGroupFixture(), proposed = copy(f.topology), node = proposed.nodes[index];
        node.profileConfig += '\n'; // Equivalent JSON, different original bytes.
        await assert.rejects(f.adopt(node, proposed), { code: 'CONFIG_LEGACY_IMPORT_READBACK_MISMATCH' });
        rejectedWithoutCAS(f);
    });
    test(`phase A independent ${['P MAIN', 'R SIDECAR', 'B SIDECAR'][index]}: honest hash still requires exact tunnel artifacts`, async () => {
        const f = installedGroupFixture(), proposed = copy(f.topology), node = proposed.nodes[index];
        const config = JSON.parse(node.profileConfig);
        if (index === 0) config.inbounds.find(row => row.tag.startsWith('bridge-conn-')).settings.clients[0].id = '55555555-5555-4555-8555-555555555555';
        else config.outbounds.find(row => row.protocol === 'vless').settings.vnext[0].users[0].id = '55555555-5555-4555-8555-555555555555';
        node.profileConfig = JSON.stringify(config); f.physical.get(key(node.id, profileFor(node))).config = node.profileConfig;
        await assert.rejects(f.adopt(node, proposed), { code: 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH' });
        rejectedWithoutCAS(f);
    });
    test(`phase A independent ${['P MAIN', 'R SIDECAR', 'B SIDECAR'][index]}: opposite nonempty role profile cannot qualify`, async () => {
        const f = installedGroupFixture(), node = f.topology.nodes[index];
        await assert.rejects(f.adopt(node, f.topology, profileFor(node) === 'xray-main' ? 'xray-bridge' : 'xray-main'),
            { code: 'CONFIG_LEGACY_IMPORT_READBACK_MISMATCH' });
        rejectedWithoutCAS(f);
    });
}

test('phase A own SHA certifies only its own profile; a peer still needs independent public adoption', async () => {
    const f = installedGroupFixture(), proposed = copy(f.topology);
    proposed.nodes[2].profileConfig += '\n';
    const portal = await f.adopt(proposed.nodes[0], proposed);
    assert.equal(portal.owner, 'topology', 'P does not pretend to have observed B');
    assert.ok(same(portal.legacyAppliedTopology, proposed));
    await assert.rejects(f.adopt(proposed.nodes[2], proposed), { code: 'CONFIG_LEGACY_IMPORT_READBACK_MISMATCH' });
    assert.equal(f.data.TopologyConfigOwner.filter(row => row.owner === 'topology').length, 1);
    assert.equal(f.data.TopologyConfigOwner.filter(row => row.owner === 'classic').length, 1);
});

test('phase A publicly adopts all six nonempty profiles without changing MAIN PPP, users, sync facts or pending inventory', async () => {
    const f = installedGroupFixture(), before = sha(JSON.stringify({ physical: [...f.physical], inventory: f.inventory }));
    const main = JSON.parse(f.physical.get(key(id(2), 'xray-main')).config), groupId = f.group._id;
    assert.ok(main.routing.rules.some(row => row.inboundTag?.includes(`relay-l2tp-${groupId}`)
        && row.ip?.length === 1 && row.ip[0] === 'geoip:private' && row.outboundTag === 'block'), 'real L2TP fragment scoped private refusal present');
    assert.ok(main.outbounds.some(row => row.tag === f.topology.groups[0].paths[0].cascadePathIngress.tag
        && row.settings.servers[0].port === f.topology.groups[0].paths[0].cascadePathIngress.port));
    for (const node of f.topology.nodes) {
        await f.adopt(node);
        const other = profileFor(node) === 'xray-main' ? 'xray-bridge' : 'xray-main';
        const adopted = await f.adopt(node, null, other);
        assert.equal(adopted.legacyAppliedTopology, undefined, 'independent profile stays ordinary public adoption');
        assert.equal(adopted.originalSnapshot.configSha256, sha(f.physical.get(key(node.id, other)).config));
    }
    assert.equal(f.data.TopologyConfigOwner.length, 6);
    assert.equal(f.events.filter(event => event.method === 'findOneAndUpdate').length, 6);
    assert.equal(before, sha(JSON.stringify({ physical: [...f.physical], inventory: f.inventory })));
    assert.equal(f.inventory.label, 'MODELED_PREEXISTING_LEGACY_INVENTORY');
    assert.ok(f.data.TopologyConfigOwner.every(row => row.lastSettledOperation === undefined));
});

test('phase A private descriptor survives strict schema/BSON; actual default and explicit driver projections differ', async () => {
    const f = installedGroupFixture(), node = f.topology.nodes[1], adopted = await f.adopt(node);
    const document = new f.Owner(adopted); await document.validate();
    const { bson } = require('./helpers/cascadeLegacyInstalledGroupFixture');
    const reloaded = f.Owner.hydrate(bson(document.toObject()));
    assert.ok(same(reloaded.legacyAppliedTopology, f.topology));
    assert.equal(f.Owner.schema.path('legacyAppliedTopology').options.select, false);
    assert.equal(new f.Owner({}).legacyAppliedTopology, undefined);
    const offset = f.events.length;
    assert.equal((await f.Owner.findOne({ node: node.id }).lean()).legacyAppliedTopology, undefined);
    assert.ok(same((await f.Owner.findOne({ node: node.id }).select('+legacyAppliedTopology').lean()).legacyAppliedTopology, f.topology));
    const reads = f.events.slice(offset).filter(event => event.method === 'findOne');
    assert.equal(reads[0].options.projection.legacyAppliedTopology, 0);
    assert.notEqual(reads[1].options.projection?.legacyAppliedTopology, 0);
});

test('phase A public grouped R accepts unrelated explicitly scoped routes before canonical ingress', async () => {
    const f = installedGroupFixture(), proposed = copy(f.topology), relay = proposed.nodes[1];
    const config = JSON.parse(relay.profileConfig);
    config.routing.rules.unshift({ type: 'field', inboundTag: ['unrelated-client'], domain: ['full:unrelated.invalid'], outboundTag: 'unrelated-out' });
    relay.profileConfig = JSON.stringify(config); f.physical.get(key(relay.id, profileFor(relay))).config = relay.profileConfig;
    const before = sha(JSON.stringify([...f.physical]));
    assert.equal((await f.adopt(relay, proposed)).owner, 'topology');
    assert.equal(before, sha(JSON.stringify([...f.physical])));
});

test('phase A fourth generator argument is not interchangeable with classic ingress composition order', async () => {
    const { generator } = require('./helpers/cascadeLegacyInstalledGroupFixture');
    const f = installedGroupFixture(), proposed = copy(f.topology), relay = proposed.nodes[1], path = proposed.groups[0].paths[0];
    const [u, d] = f.populated;
    const config = JSON.parse(generator.generateRelayConfig(u, u.portalNode, [d], [{ pathKey: path.pathKey,
        port: path.cascadePathIngress.port, egressTag: `portal-down-${d.id.slice(-8)}` }]));
    require('../../../services/classicL2tpConfigComposition').finishClassicConfigRouting(config);
    relay.profileConfig = JSON.stringify(config); f.physical.get(key(relay.id, profileFor(relay))).config = relay.profileConfig;
    await assert.rejects(f.adopt(relay, proposed), { code: 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH' });
    rejectedWithoutCAS(f);
});

test('phase A groupless manual client TLS remains accepted through the public transfer without certificate IO', async () => {
    const { generator } = require('./helpers/cascadeLegacyInstalledGroupFixture');
    const f = installedGroupFixture(), proposed = copy(f.topology), portal = proposed.nodes[0], relay = proposed.nodes[1];
    proposed.groups = [];
    Object.assign(portal.xray, { security: 'tls', tlsSource: 'manual', manualCert: 'synthetic-fixture-certificate', manualKey: 'synthetic-fixture-private-key' });
    const config = JSON.parse(generator.generateXrayConfig({ ...portal, _id: portal.id }, []));
    generator.applyReversePortal(config, [f.populated[0]], ['client-in']);
    portal.profileConfig = JSON.stringify(config);
    relay.profileConfig = generator.generateRelayConfig(f.populated[0], f.populated[0].portalNode, [f.populated[1]]);
    for (const node of proposed.nodes) f.physical.get(key(node.id, profileFor(node))).config = node.profileConfig;
    for (const node of proposed.nodes) {
        const adopted = await f.adopt(node, proposed);
        assert.ok(same(adopted.legacyAppliedTopology, proposed), 'groupless TLS descriptor retained verbatim');
    }
});

for (const index of [0, 1, 2]) test(`phase A readback-only drift at member ${index} cannot inherit desired profile bytes`, async () => {
    const f = installedGroupFixture(), node = f.topology.nodes[index];
    f.physical.get(key(node.id, profileFor(node))).config += '\n';
    await assert.rejects(f.adopt(node), { code: 'CONFIG_LEGACY_IMPORT_READBACK_MISMATCH' });
    rejectedWithoutCAS(f);
});

test('phase A caller mutation after adoption starts cannot replace the copied accepted group', async () => {
    const f = installedGroupFixture(), node = f.topology.nodes[1], classic = await f.initialize(node);
    const proposed = copy(f.topology), before = copy(proposed);
    const pending = f.transfer.adopt({ node: node.id, profile: classic.profile, generation: classic.generation,
        proofRef: 'modeled-frozen-inventory', legacyTopology: proposed });
    proposed.groups[0].paths[0].priority++;
    assert.ok(same((await pending).legacyAppliedTopology, before));
});

for (const index of [0, 2]) test(`phase A grouped ${index === 0 ? 'P' : 'B'}: refuses an unrepresented cascade listener`, async () => {
    const f = installedGroupFixture(), proposed = copy(f.topology), node = proposed.nodes[index];
    const config = JSON.parse(node.profileConfig);
    config.inbounds.push({ tag: 'cascade-foreign', listen: '127.0.0.1', port: 19999, protocol: 'socks',
        settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' } });
    node.profileConfig = JSON.stringify(config); f.physical.get(key(node.id, profileFor(node))).config = node.profileConfig;
    await assert.rejects(f.adopt(node, proposed), { code: 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH' });
    rejectedWithoutCAS(f);
});

// Fixture regression only: unchanged public restoration, not worker rollback or
// physical/Mongo acceptance. Positive owners always come from initialize/adopt.
for (const context of [TEST, PROD]) test(`fixture BSON ${context.target}: public unchanged R handback preserves original private history`, async () => {
    const f = installedGroupFixture(context), node = f.topology.nodes[1];
    const protectedHash = sha(JSON.stringify({ physical: [...f.physical], inventory: f.inventory }));
    const adopted = await f.adopt(node), start = f.events.length;
    const returned = await f.transfer.handback({ node: node.id, profile: profileFor(node), generation: adopted.generation,
        proofRef: 'modeled-unchanged-original-restoration' });
    assert.equal(returned.owner, 'classic');
    assert.notEqual(returned.generation, adopted.generation);
    assert.equal(returned.handbackReceipt.fromGeneration, adopted.generation);
    assert.equal(returned.handbackReceipt.toGeneration, returned.generation);
    const durable = await f.Owner.findOne({ node: node.id, profile: profileFor(node) }).select('+legacyAppliedTopology').lean();
    assert.deepEqual(durable.adoptionReceipt, adopted.adoptionReceipt);
    assert.deepEqual(durable.originalSnapshot, adopted.originalSnapshot);
    assert.deepEqual(durable.nodeIdentity, adopted.nodeIdentity);
    assert.deepEqual(durable.legacyAppliedTopology, adopted.legacyAppliedTopology);
    assert.deepEqual(durable.legacyAppliedTopology, f.topology);
    assert.equal(durable.lastSettledOperation, undefined);
    assert.equal(returned.legacyAppliedTopology, undefined, 'public default handback projection stays private');
    const cas = f.events.slice(start).filter(event => event.method === 'findOneAndUpdate');
    assert.equal(cas.length, 1);
    assert.equal(cas[0].held, true);
    assert.equal(cas[0].filter.generation, adopted.generation);
    assert.deepEqual(cas[0].filter.adoptionReceipt, adopted.adoptionReceipt);
    assert.deepEqual(cas[0].filter.originalSnapshot, adopted.originalSnapshot);
    const confirmation = f.events.slice(start).find(event => event.method === 'findOne' && event.filter.owner === 'classic');
    assert.equal(confirmation.held, true);
    assert.equal(confirmation.options.readPreference.mode, 'primary');
    assert.deepEqual(confirmation.options.readConcern, { level: 'majority' });
    assert.equal(protectedHash, sha(JSON.stringify({ physical: [...f.physical], inventory: f.inventory })));
    assert.equal(f.connection.readyState, 0);
    assert.equal(f.data.TopologyOperation, undefined);
    assert.deepEqual(f.calls, []);
    assert.equal(f.held(), false);
});

test('fixture BSON: cast embedded receipt matches by value in findOne and find without ignoring receipt or generation', async () => {
    const f = installedGroupFixture(), node = f.topology.nodes[1], adopted = await f.adopt(node);
    const before = sha(JSON.stringify(f.data)), start = f.events.length;
    const filter = { node: node.id, profile: profileFor(node), generation: adopted.generation,
        executionContext: adopted.executionContext, nodeIdentity: adopted.nodeIdentity,
        originalSnapshot: adopted.originalSnapshot, adoptionReceipt: { ...adopted.adoptionReceipt,
            verifiedAt: new Date(adopted.adoptionReceipt.verifiedAt.getTime()) } };
    assert.equal((await f.Owner.findOne(filter).lean())?.generation, adopted.generation);
    assert.equal((await f.Owner.find(filter).lean()).length, 1);
    for (const bad of [
        { ...filter, adoptionReceipt: { ...filter.adoptionReceipt, proofId: 'mismatching-proof' } },
        { ...filter, adoptionReceipt: { ...filter.adoptionReceipt, verifiedAt: new Date(filter.adoptionReceipt.verifiedAt.getTime() + 1) } },
        { ...filter, adoptionReceipt: { ...filter.adoptionReceipt, oldPid: filter.adoptionReceipt.oldPid + 1 } },
        { ...filter, generation: adopted.adoptionReceipt.fromGeneration },
        { ...filter, node: id(99) },
    ]) {
        assert.equal(await f.Owner.findOne(bad).lean(), null);
        assert.deepEqual(await f.Owner.find(bad).lean(), []);
    }
    assert.equal(before, sha(JSON.stringify(f.data)));
    assert.ok(f.events.slice(start).every(event => ['find', 'findOne'].includes(event.method)));
});

for (const [name, change] of [
    ['receipt proof', row => { row.adoptionReceipt.proofId = 'modeled-competing-proof'; }],
    ['receipt date', row => { row.adoptionReceipt.verifiedAt = new Date(row.adoptionReceipt.verifiedAt.getTime() + 1); }],
    ['generation', row => { row.generation = row.adoptionReceipt.fromGeneration; }],
]) test(`fixture BSON public handback: retains competing ${name} at the actual CAS boundary`, async () => {
    const f = installedGroupFixture(), node = f.topology.nodes[1], adopted = await f.adopt(node);
    const driver = f.Owner.collection.collection, original = driver.findOneAndUpdate;
    const protectedHash = sha(JSON.stringify({ physical: [...f.physical], inventory: f.inventory }));
    let calls = 0, competingHash;
    driver.findOneAndUpdate = async function(...args) {
        calls++;
        // Deliberate modeled race on the publicly adopted row, never a seeded
        // positive owner. A stale read must not overwrite the competing value.
        change(f.data.TopologyConfigOwner[0]);
        competingHash = sha(JSON.stringify(f.data));
        return original.apply(this, args);
    };
    try {
        await assert.rejects(f.transfer.handback({ node: node.id, profile: profileFor(node), generation: adopted.generation,
            proofRef: 'modeled-stale-original-restoration' }), { code: 'CONFIG_OWNERSHIP_CONFLICT' });
    } finally { driver.findOneAndUpdate = original; }
    assert.equal(calls, 1, 'refusal must reach the actual receipt/generation CAS');
    assert.equal(competingHash, sha(JSON.stringify(f.data)));
    assert.equal(f.data.TopologyConfigOwner[0].owner, 'topology');
    assert.equal(f.data.TopologyConfigOwner[0].handbackReceipt, undefined);
    assert.equal(protectedHash, sha(JSON.stringify({ physical: [...f.physical], inventory: f.inventory })));
    assert.deepEqual(f.calls, []);
    assert.equal(f.held(), false);
});

test('fixture BSON: native-boundary operators, ObjectId, null and undefined retain bounded driver semantics', async () => {
    const f = installedGroupFixture(), node = f.topology.nodes[1], adopted = await f.adopt(node);
    const driver = f.Owner.collection.collection, oid = new f.Owner.base.Types.ObjectId(node.id);
    const filter = { $and: [{ node: { $in: [oid] } }, { 'adoptionReceipt.oldPid': { $gte: adopted.adoptionReceipt.oldPid } }],
        generation: { $ne: adopted.adoptionReceipt.fromGeneration } };
    const options = { session: f.session, projection: { node: 1, generation: 1, _id: 0 } };
    const projected = await driver.findOne(filter, options);
    assert.deepEqual(Object.keys(projected).sort(), ['generation', 'node']);
    assert.ok(projected.node instanceof f.Owner.base.Types.ObjectId);
    assert.equal(projected.generation, adopted.generation);
    assert.ok(f.events.at(-1).options.session === f.session);
    assert.equal(await driver.findOne({ ...filter, node: new f.Owner.base.Types.ObjectId(id(99)) }), null);
    assert.ok(await driver.findOne({ node: oid, lastSettledOperation: null }), 'native null equality includes missing');
    assert.ok(await driver.findOne({ node: oid, lastSettledOperation: undefined }), 'driver defaults undefined to null');
    assert.equal(await driver.findOne({ node: oid, generation: null }), null);
    assert.equal(await driver.findOne({ node: oid, generation: undefined }), null, 'undefined is not an omitted guard by default');
    assert.ok(await driver.findOne({ node: oid, generation: undefined }, { ignoreUndefined: true }), 'explicit native omission remains opt-in');
    assert.equal(await driver.findOne({ node: oid, generation: null }, { ignoreUndefined: true }), null);
    assert.equal(await driver.findOne({ node: oid, generation: { $in: [adopted.adoptionReceipt.fromGeneration] } }), null);
});

test('phase A adoption never resolves transport, runs commands or accesses network', async () => {
    const f = installedGroupFixture(), net = require('node:net'), child = require('node:child_process');
    const guards = [[net.Socket.prototype, 'connect'], ...['spawn', 'spawnSync', 'exec', 'execFile', 'execFileSync', 'execSync', 'fork'].map(name => [child, name])];
    const originals = guards.map(([object, name]) => object[name]), attempts = [];
    guards.forEach(([object, name]) => { object[name] = () => { attempts.push(name); throw Error('PHASE_A_FORBIDDEN_IO'); }; });
    try { for (const node of f.topology.nodes) await f.adopt(node); assert.deepEqual(attempts, []); }
    finally { guards.forEach(([object, name], index) => { object[name] = originals[index]; }); }
});
