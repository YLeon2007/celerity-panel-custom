'use strict';
// Phase B only: public phase-A adoption -> real selected reader/query schemas.
// Initial installed/users/sync and physical authority remain MODELED PREEXISTING
// LEGACY INVENTORY. No Mongo, worker settlement, transport, MAIN/PPP readiness.
const test = require('node:test');
const assert = require('node:assert/strict');
const { installedGroupFixture, id, sha, copy, bson } = require('./helpers/cascadeLegacyInstalledGroupFixture');
const { Types } = require('mongoose');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
const { selectedAdmissionFingerprint } = require('../repositories/topologyOperationRepository');

const PUBLICATION = 'TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED';
const AMBIGUOUS = 'TOPOLOGY_INSTALLED_ROUTE_OWNER_AMBIGUOUS';
const oid = value => new Types.ObjectId(value);
class ModeledSession {}
function selectedFixture() {
    const f = installedGroupFixture();
    // Like an actual ClientSession, retain identity through Mongoose option
    // cloning. A plain object would be copied before reaching the driver seam.
    Object.setPrototypeOf(f.session, ModeledSession.prototype);
    // Compose the frozen A adapter: real schema/query casting, actual filter and
    // projection over BSON rows. Do not hydrate/default missing installed epochs.
    const HyNode = f.model('HyNode', require('../../../models/hyNodeModel'), f.inventory.nodes.map(row => ({ ...copy(row), _id: oid(row._id) })));
    const CascadeLink = f.model('CascadeLink', require('../../../models/cascadeLinkModel'), f.inventory.links.map(row => ({
        ...copy(row), _id: oid(row._id), portalNode: oid(row.portalNode), bridgeNode: oid(row.bridgeNode) })));
    const CascadeRouteGroup = f.model('CascadeRouteGroup', require('../models/cascadeRouteGroupModel'), f.inventory.groups.map(row => ({
        ...copy(row), _id: oid(row._id), paths: row.paths.map(path => ({ ...copy(path), linkIds: path.linkIds.map(oid) })) })));
    const RelayL2tpState = f.model('RelayL2tpState', require('../models/relayL2tpStateModel'), f.inventory.states.map(row => ({
        ...copy(row), _id: oid(row._id), node: oid(row.node), routeGroup: oid(row.routeGroup) })));
    const CascadeTopologyState = f.model('CascadeTopologyState', require('../models/cascadeTopologyStateModel'), [{
        _id: 'singleton', revision: 7, deployedRevision: 0, topologyAdmissionCount: 0, remoteAdmissionCount: 0 }]);
    const TopologyOperation = f.model('TopologyOperation', require('../models/topologyOperationModel'));
    const NodeOperationLock = f.model('NodeOperationLock', require('../models/nodeOperationLockModel'));
    const models = { HyNode, CascadeLink, CascadeRouteGroup, RelayL2tpState, CascadeTopologyState, TopologyOperation, NodeOperationLock,
        TopologyConfigOwner: f.Owner };
    const draft = new TopologyDraftRepository(models);
    const deployment = new TopologyDeploymentRepository({ ...models, snapshotReader: draft });
    const read = async ({ snapshot, kind = 'link.apply', linkId = id(11), session = f.session } = {}) => deployment.readSelected({
        snapshot: snapshot ?? await draft.readDraft(session), scope: { kind, linkId }, executionContext: f.context, session });
    const adoptAll = async () => { for (const node of f.topology.nodes) await f.adopt(node); };
    const protectedHash = () => sha(JSON.stringify({ physical: [...f.physical], inventory: f.inventory, data: f.data }));
    return { ...f, models, draft, deployment, read, adoptAll, protectedHash };
}
function unchangedReadOnly(f, start, protectedHash) {
    assert.equal(f.protectedHash(), protectedHash, 'selected refusal/read must preserve all inventory, private owners and profile bytes');
    assert.ok(f.events.slice(start).every(event => ['find', 'findOne'].includes(event.method)), 'no admission, lock, owner or publication writes');
    assert.deepEqual(f.calls, [], 'no node dispatch');
    assert.equal(f.data.TopologyOperation.length, 0, 'no fabricated settlement');
    assert.equal(f.data.NodeOperationLock.length, 0);
    assert.ok(f.data.TopologyConfigOwner.every(row => row.lastSettledOperation === undefined));
}
async function rejected(f, code, options) {
    const start = f.events.length, protectedHash = f.protectedHash();
    await assert.rejects(f.read(options), { code });
    unchangedReadOnly(f, start, protectedHash);
}
test('phase B public imported G2: selected baseline and installed path retain exact accepted suffix and epochs', async () => {
    const f = selectedFixture(); await f.adoptAll();
    const start = f.events.length, protectedHash = f.protectedHash();
    const selected = await f.read();
    assert.deepEqual(selected.baselineTopology, f.topology);
    assert.deepEqual(selected.installedPath, { groupId: id(60), pathKey: 'legacy-main', ownerNodeId: id(2),
        ownerTopologyRevision: 7, ownerCredentialRevision: 41, oldPathLinkIds: [id(11)], newPathLinkIds: [id(11)],
        groupBefore: f.topology.groups[0], kind: 'link.apply' });
    assert.deepEqual(selected.effectiveTopology.groups, f.topology.groups);
    assert.deepEqual(selected.resourceNodeIds, f.topology.nodes.map(node => node.id));
    assert.deepEqual(await f.read(), selected, 'same-session repeat has exact equality');
    const joins = f.events.slice(start).filter(event => event.name === 'RelayL2tpState' && event.method === 'find' && event.filter.routeGroup?._bsontype === 'ObjectId');
    assert.equal(joins.length, 2, 'each read performs the same-session owner join, not only the installed-only snapshot query');
    for (const event of joins) {
        assert.equal(String(event.filter.routeGroup), id(60));
        assert.ok(event.options.session === f.session);
        assert.deepEqual(event.options.projection, Object.fromEntries('node routeGroup status desiredState activePathKey appliedTopologyRevision secretRevision'.split(' ').map(key => [key, 1])));
    }
    unchangedReadOnly(f, start, protectedHash);
});
test('phase B causal current-group priority drift cannot overwrite the public imported group', async () => {
    const f = selectedFixture(); await f.adoptAll();
    f.data.CascadeRouteGroup[0].paths[0].priority++;
    await rejected(f, PUBLICATION);
});
test('phase B causal missing installed reference cannot bypass the initial imported installed branch', async () => {
    const f = selectedFixture(); await f.adoptAll();
    f.data.RelayL2tpState.length = 0;
    assert.deepEqual((await f.draft.readDraft(f.session)).installedRouteOwners, []);
    await rejected(f, PUBLICATION);
});
test('phase B causal configured pending peer on the same group is ambiguous before selected admission', async () => {
    const f = selectedFixture(); await f.adoptAll();
    f.data.RelayL2tpState.push({ ...bson(f.data.RelayL2tpState[0]), _id: oid(id(71)), node: oid(id(4)), status: 'queued' });
    assert.equal((await f.draft.readDraft(f.session)).installedRouteOwners.length, 1, 'installed-only snapshot omits the configured peer');
    await rejected(f, AMBIGUOUS);
});

for (const [name, change] of [
    ['mode', group => { group.mode = 'forward'; }],
    ['strategy', group => { group.strategy = 'round-robin'; }],
    ['path key', group => { group.paths[0].pathKey = 'other-path'; }],
    ['enabled', group => { group.paths[0].enabled = false; }],
    ['empty membership', group => { group.paths[0].linkIds = []; }],
    ['upstream membership', group => { group.paths[0].linkIds = [oid(id(10))]; }],
    ['full portal-path membership', group => { group.paths[0].linkIds = [oid(id(10)), oid(id(11))]; }],
    ['extra path', group => { group.paths.push({ ...bson(group.paths[0]), pathKey: 'extra-path' }); }],
]) test(`phase B exact imported group: refuses current ${name} drift before overwrite`, async () => {
    const f = selectedFixture(); await f.adoptAll(); change(f.data.CascadeRouteGroup[0]);
    await rejected(f, PUBLICATION);
});
for (const duplicate of [false, true]) test(`phase B exact imported group: refuses ${duplicate ? 'duplicate current G' : 'missing current G'}`, async () => {
    const f = selectedFixture(); await f.adoptAll();
    if (duplicate) f.data.CascadeRouteGroup.push(bson(f.data.CascadeRouteGroup[0]));
    else f.data.CascadeRouteGroup.shift();
    await rejected(f, PUBLICATION);
});
for (const [name, change] of [
    ['not configured installed', row => { row.desiredState = 'absent'; }],
    ['not installed status', row => { row.status = 'degraded'; }],
    ['wrong owner node', row => { row.node = oid(id(4)); }],
    ['wrong group', row => { row.routeGroup = oid(id(61)); }],
    ['wrong active path', row => { row.activePathKey = 'foreign-path'; }],
    ['missing active path', row => { delete row.activePathKey; }],
    ['missing topology epoch', row => { delete row.appliedTopologyRevision; }],
    ['negative topology epoch', row => { row.appliedTopologyRevision = -1; }],
    ['fractional topology epoch', row => { row.appliedTopologyRevision = 1.5; }],
    ['unsafe topology epoch', row => { row.appliedTopologyRevision = Number.MAX_SAFE_INTEGER + 1; }],
    ['string topology epoch', row => { row.appliedTopologyRevision = '7'; }],
    ['missing credential epoch', row => { delete row.secretRevision; }],
    ['zero credential epoch', row => { row.secretRevision = 0; }],
    ['negative credential epoch', row => { row.secretRevision = -1; }],
    ['fractional credential epoch', row => { row.secretRevision = 1.5; }],
    ['unsafe credential epoch', row => { row.secretRevision = Number.MAX_SAFE_INTEGER + 1; }],
    ['string credential epoch', row => { row.secretRevision = '41'; }],
]) test(`phase B exact installed state: refuses ${name} without inferred defaults`, async () => {
    const f = selectedFixture(); await f.adoptAll(); change(f.data.RelayL2tpState[0]);
    await rejected(f, PUBLICATION);
});
for (const [name, change] of [
    ['missing installed projection', snapshot => { snapshot.installedRouteOwners = []; }],
    ['wrong projected owner', snapshot => { snapshot.installedRouteOwners[0].nodeId = id(4); }],
    ['wrong projected group', snapshot => { snapshot.installedRouteOwners[0].groupId = id(61); }],
    ['wrong projected path', snapshot => { snapshot.installedRouteOwners[0].pathKey = 'foreign-path'; }],
    ['changed projected topology epoch', snapshot => { snapshot.installedRouteOwners[0].ownerTopologyRevision++; }],
    ['changed projected credential epoch', snapshot => { snapshot.installedRouteOwners[0].ownerCredentialRevision++; }],
    ['missing projected topology epoch', snapshot => { delete snapshot.installedRouteOwners[0].ownerTopologyRevision; }],
    ['missing projected credential epoch', snapshot => { delete snapshot.installedRouteOwners[0].ownerCredentialRevision; }],
]) test(`phase B exact snapshot join: refuses ${name}`, async () => {
    const f = selectedFixture(); await f.adoptAll();
    const snapshot = await f.draft.readDraft(f.session); change(snapshot);
    await rejected(f, PUBLICATION, { snapshot });
});
for (const [status, desiredState] of [['degraded', 'installed'], ['installed', 'installed'], ['queued', 'absent']]) {
    test(`phase B same-group reference: ${status}/${desiredState} peer remains ambiguous`, async () => {
        const f = selectedFixture(); await f.adoptAll();
        f.data.RelayL2tpState.push({ ...bson(f.data.RelayL2tpState[0]), _id: oid(id(71)), node: oid(id(4)), status, desiredState });
        await rejected(f, AMBIGUOUS);
    });
}
test('phase B same-group projected second owner outside the component is not silently filtered away', async () => {
    const f = selectedFixture(); await f.adoptAll(); const snapshot = await f.draft.readDraft(f.session);
    snapshot.installedRouteOwners.push({ ...snapshot.installedRouteOwners[0], nodeId: oid(id(4)) });
    await rejected(f, AMBIGUOUS, { snapshot });
});
test('phase B unrelated groups and dormant absent references do not block or migrate with the selected import', async () => {
    const f = selectedFixture(); await f.adoptAll();
    f.data.RelayL2tpState.push({ ...bson(f.data.RelayL2tpState[0]), _id: oid(id(71)), node: oid(id(4)), routeGroup: oid(id(61)) },
        { ...bson(f.data.RelayL2tpState[0]), _id: oid(id(72)), node: oid(id(5)), status: 'not_installed', desiredState: 'absent' });
    const start = f.events.length, protectedHash = f.protectedHash();
    const rows = await f.models.RelayL2tpState.find({ routeGroup: id(60) }).select('node routeGroup status desiredState').session(f.session).lean();
    assert.equal(rows.length, 2, 'actual filter excludes unrelated installed group');
    for (const row of rows) assert.deepEqual(Object.keys(row).sort(), ['_id', 'desiredState', 'node', 'routeGroup', 'status']);
    const selected = await f.read();
    assert.deepEqual(selected.baselineTopology.groups, f.topology.groups);
    assert.deepEqual(selected.effectiveTopology.groups, f.topology.groups);
    unchangedReadOnly(f, start, protectedHash);
});
test('phase B initial import does not freeze epochs at adoption or rotate credentials', async () => {
    const f = selectedFixture(); await f.adoptAll();
    f.data.RelayL2tpState[0].appliedTopologyRevision = 0;
    f.data.RelayL2tpState[0].secretRevision = 42; // Modeled independently current epoch before admission; not readiness.
    const start = f.events.length, protectedHash = f.protectedHash();
    const selected = await f.read();
    assert.equal(selected.installedPath.ownerTopologyRevision, 0);
    assert.equal(selected.installedPath.ownerCredentialRevision, 42);
    assert.deepEqual(selected.installedPath.groupBefore, f.topology.groups[0]);
    unchangedReadOnly(f, start, protectedHash);
});
test('phase B selected explicit request never imports a save-only neighbor edit or pending/inactive peers', async () => {
    const f = selectedFixture(); await f.adoptAll();
    f.data.CascadeLink[0].tunnelPort++;
    f.data.CascadeLink[0].tunnelUuid = '66666666-6666-4666-8666-666666666666';
    const start = f.events.length, protectedHash = f.protectedHash();
    const selected = await f.read();
    assert.deepEqual(selected.baselineTopology, f.topology);
    assert.deepEqual(selected.effectiveTopology.links.find(link => link.id === id(10)), f.topology.links[0]);
    assert.deepEqual(selected.effectiveTopology.links.map(link => link.id), [id(10), id(11)]);
    assert.equal(f.data.CascadeLink[2].status, 'pending'); assert.equal(f.data.CascadeLink[3].active, false);
    unchangedReadOnly(f, start, protectedHash);
});
for (const [linkId, newPathLinkIds] of [[id(11), []], [id(10), [id(11)]]]) {
    test(`phase B delete reader ${linkId}: proposes only the owned suffix without publishing it`, async () => {
        const f = selectedFixture(); await f.adoptAll(); const start = f.events.length, protectedHash = f.protectedHash();
        const selected = await f.read({ kind: 'link.delete', linkId });
        assert.equal(selected.installedPath.kind, 'link.delete');
        assert.deepEqual(selected.installedPath.groupBefore, f.topology.groups[0]);
        assert.deepEqual(selected.installedPath.oldPathLinkIds, [id(11)]);
        assert.deepEqual(selected.installedPath.newPathLinkIds, newPathLinkIds);
        assert.deepEqual(selected.effectiveTopology.groups[0].paths[0].linkIds, newPathLinkIds);
        unchangedReadOnly(f, start, protectedHash);
    });
}
test('phase B incomplete public adoption cannot reach the installed owner join', async () => {
    const f = selectedFixture();
    for (const node of f.topology.nodes.slice(0, 2)) await f.adopt(node);
    await rejected(f, 'TOPOLOGY_CONFIG_OWNER_REQUIRED');
    assert.ok(!f.events.some(event => event.name === 'RelayL2tpState' && event.filter.routeGroup?._bsontype === 'ObjectId'));
});
test('phase B a private accepted peer-group mismatch is refused before installed publication', async () => {
    const f = selectedFixture(); await f.adoptAll();
    f.data.TopologyConfigOwner[2].legacyAppliedTopology.groups[0].paths[0].priority++;
    await rejected(f, 'TOPOLOGY_LEGACY_IMPORT_MISMATCH');
});
test('phase B owner epochs drifting after the same-session snapshot cannot be admitted from stale installed projection', async () => {
    const f = selectedFixture(); await f.adoptAll();
    const snapshot = await f.draft.readDraft(f.session);
    f.data.RelayL2tpState[0].secretRevision++;
    await rejected(f, PUBLICATION, { snapshot });
});

// Actual descriptor materialization supplies an admission-shaped fingerprint;
// this is never persisted as a succeeded operation or used as settlement proof.
async function admissionEnvelope(f) {
    const selected = await f.read();
    const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
    const { compileTopology } = require('../domain/topologyCompiler');
    const plan = await new TopologyOperationPlanMaterializer(f.models).materialize({
        target: f.context.target, hostIdentity: f.context.hostIdentity, operationKind: 'link.apply',
        pinnedSnapshot: { revision: 7, topology: selected.effectiveTopology, compiled: compileTopology(selected.effectiveTopology) },
        baselineTopology: selected.baselineTopology, effectiveTopology: selected.effectiveTopology,
        installedPath: selected.installedPath, selectedOwnerPins: selected.selectedOwnerPins });
    const operation = { ...selected, _id: id(100), executionContext: f.context, admissionScope: 'selected', kind: 'link.apply',
        linkId: id(11), linkIds: selected.effectiveTopology.links.map(link => link.id),
        // The ordinary coordinator projects this exact candidate digest too.
        nodes: plan.nodes.map(node => ({ ...node, candidateHash: node.candidate.sha256 })) };
    operation.admissionFingerprint = selectedAdmissionFingerprint(operation);
    return operation;
}
test('phase B verifySelected rereads exact public imported group and owner in the caller admission session', async () => {
    const f = selectedFixture(); await f.adoptAll(); const operation = await admissionEnvelope(f);
    const start = f.events.length, protectedHash = f.protectedHash();
    const fresh = await f.deployment.verifySelected(operation, f.session);
    assert.deepEqual(fresh.installedPath, operation.installedPath);
    assert.ok(f.events.slice(start).filter(event => ['find', 'findOne'].includes(event.method)).every(event => event.options.session === f.session));
    unchangedReadOnly(f, start, protectedHash);
});
for (const [name, change, code] of [
    ['current group drift', f => { f.data.CascadeRouteGroup[0].paths[0].priority++; }, PUBLICATION],
    ['current epoch drift', f => { f.data.RelayL2tpState[0].secretRevision++; }, 'TOPOLOGY_SELECTED_PIN_CHANGED'],
    ['new configured peer', f => { f.data.RelayL2tpState.push({ ...bson(f.data.RelayL2tpState[0]), _id: oid(id(71)), node: oid(id(4)), status: 'queued' }); }, AMBIGUOUS],
]) test(`phase B verifySelected refuses ${name} between admission reads before dispatch`, async () => {
    const f = selectedFixture(); await f.adoptAll(); const operation = await admissionEnvelope(f); change(f);
    const start = f.events.length, protectedHash = f.protectedHash();
    await assert.rejects(f.deployment.verifySelected(operation, f.session), { code });
    unchangedReadOnly(f, start, protectedHash);
});
