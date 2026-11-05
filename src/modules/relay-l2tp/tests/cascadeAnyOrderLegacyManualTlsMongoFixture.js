'use strict';
// Dedicated data adaptation of the accepted real-Mongo C harness. No product,
// model, worker, finalizer, query or module-loader replacement. Only its existing
// fake-root/physical maintenance/SSH/Xray/systemd seams remain MODELED.
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { nativeFixture, mongoFixture, context, sha, evidence } = require('./cascadeAnyOrderLegacyForwardNativeFixture');
const { generator, copy, targets, id } = require('./cascadeAnyOrderLegacyForwardFixture');
// Reuse only the pre-existing synthetic TEST inputs, never a live certificate.
const { TEST_CERT, TEST_KEY } = require('./cascadeAnyOrderLegacyManualTlsFixture');
const { NODE_METADATA_SELECT } = require('../services/topologyOperationPlanMaterializer');
const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TopologyIntentService, linkDesiredVersion } = require('../services/topologyIntentService');
const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
const { prepareIntentLink } = require('../../../routes/cascadeLinks');
const oldBackend = Object.freeze({ instanceId: 'MODELED-classic', pid: 42, processStartTime: 'MODELED-start', processTree: 'stopped', dispatch: 'disabled' });
async function manualTlsMongoFixture(t, mongo, variant = 'primary') {
    assert.ok(['primary', 'extra'].includes(variant));
    const f = await nativeFixture(t, mongo, { mode: 'reverse', security: variant === 'extra' ? 'reality' : 'none' });
    const { models, hosts } = f;
    // All data adaptation happens before initialize/adopt/preEnroll/queue. The
    // actual native fixture still owns store, lifecycle, worker and runner IO.
    assert.equal(await models.TopologyConfigOwner.countDocuments(), 0);
    assert.equal(await models.TopologyOperation.countDocuments(), 0);
    const portal = f.nodes[0];
    portal.port = 443; portal.domain = 'manual-tls-TEST-only.invalid';
    Object.assign(portal.xray, { tlsSource: 'manual', manualCert: TEST_CERT, manualKey: TEST_KEY,
        alpn: ['http/1.1', 'h2'], flow: 'xtls-rprx-vision', security: variant === 'primary' ? 'tls' : 'none' });
    if (variant === 'extra') portal.xray.extraInbounds = [{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', inboundTag: 'tls-extra', port: 24444,
        security: 'tls', transport: 'tcp', alpn: ['h2', 'http/1.1'], flow: 'xtls-rprx-vision' }];
    await models.HyNode.updateOne({ _id: portal.id }, { $set: { port: portal.port, domain: portal.domain, xray: portal.xray } }, { runValidators: true });
    f.link.name = 'original installed link';
    const populated = { ...copy(f.link), _id: f.link.id,
        portalNode: { ...copy(portal), _id: portal.id }, bridgeNode: { ...copy(f.nodes[1]), _id: f.nodes[1].id } };
    const config = JSON.parse(generator.generateXrayConfig({ ...portal, _id: portal.id }, [
        { xrayUuid: '88888888-8888-4888-8888-888888888888', userId: 'portal-existing@invalid' },
    ]));
    const old = JSON.parse(portal.profileConfig);
    config.inbounds.push(copy(old.inbounds.find(row => row.tag === 'unrelated-ingress')));
    config.outbounds.push(copy(old.outbounds.find(row => row.tag === 'unrelated-out')));
    config.routing.rules.push(copy(old.routing.rules.find(row => row.outboundTag === 'unrelated-out')));
    config.policy = copy(old.policy);
    generator.applyReversePortal(config, [populated], ['client-in', ...(variant === 'extra' ? ['tls-extra'] : [])]);
    portal.profileConfig = JSON.stringify(config, null, 2) + '\n';
    const portalHost = hosts.get(portal.id);
    portalHost.put(targets[portalHost.profile].configPath, portal.profileConfig);
    portalHost.original[portalHost.profile] = f.readProfile(portalHost, portalHost.profile);
    for (const [number, fields] of [[90, { status: 'pending' }], [91, { active: false, status: 'online' }]]) {
        const { id: ignored, source, target, ...link } = f.link;
        await models.CascadeLink.create({ ...link, _id: id(number), name: `TEST-unselected-${number}`,
            portalNode: source, bridgeNode: target, tunnelPort: 25900 + number, ...fields });
    }
    const stats = { maintenanceCalls: 0, adoptionCAS: 0 };
    const commandListener = event => {
        if (event.commandName === 'findAndModify' && event.command.findAndModify === models.TopologyConfigOwner.collection.name
            && event.command.update?.$set?.owner === 'topology') stats.adoptionCAS++;
    };
    mongo.connection.getClient().on('commandStarted', commandListener);
    t.after(() => mongo.connection.getClient().off('commandStarted', commandListener));
    const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: models.TopologyConfigOwner,
        async withVerifiedMaintenance({ binding, proofRef }, work) {
            assert.equal(proofRef, 'MODELED-exact-original-manual-TLS'); stats.maintenanceCalls++;
            const host = hosts.get(binding.node); assert.ok(host); assert.deepEqual(binding.nodeIdentity, host.identity);
            const actual = f.readProfile(host, binding.profile);
            return work({ authority: 'external-maintenance-v1', status: 'verified', binding: copy(binding), proofId: randomUUID(),
                maintenanceId: host.maintenance, maintenance: 'held', allWriters: 'drained', oldBackend,
                readback: { source: 'node-readback', configSha256: sha(actual.config), unitSha256: sha(actual.unit),
                    serviceActive: actual.active, serviceEnabled: actual.enabled } });
        } });
    const initialize = (node, profile = hosts.get(node).profile) => transfer.initializeClassic({ node, profile, nodeIdentity: hosts.get(node).identity });
    const adoptOne = async (node, snapshot = f.topology, profile = hosts.get(node).profile) => {
        const classic = await initialize(node, profile);
        return transfer.adopt({ node, profile, generation: classic.generation, proofRef: 'MODELED-exact-original-manual-TLS',
            ...(snapshot === null ? {} : { legacyTopology: snapshot }) });
    };
    const adopt = async () => {
        for (const host of hosts.values()) {
            await adoptOne(host.node.id);
            await adoptOne(host.node.id, null, host.profile === 'xray-main' ? 'xray-bridge' : 'xray-main');
        }
    };
    const draft = new TopologyDraftRepository(models), deployment = new TopologyDeploymentRepository({ ...models, snapshotReader: draft });
    const dependencies = { ...models, executionContext: context, prepareLink: prepareIntentLink,
        deleteIntentWriter: models.CascadeLink.createDeleteIntentWriter({ CascadeLink: models.CascadeLink }),
        intentDraftWriter: draft.createIntentDraftWriter({ selectedTopologyRepository: deployment }),
        intentOperationAdmission: { db: mongo.connection, queue: input => f.coordinator.queueIntent(input) },
        resolveIntentResources: input => f.coordinator.resolveIntentResourcesForQueue(input) };
    const service = new TopologyIntentService(dependencies), consumer = new TopologyIntentConsumer(dependencies);
    const applyRequest = async (requestKey = randomUUID(), linkId = f.link.id) => ({ kind: 'link.apply', requestKey, linkId,
        expectedTopologyRevision: await f.revision(), desiredVersion: linkDesiredVersion(await models.CascadeLink.findById(linkId).lean()) });
    const drain = async job => {
        const claimed = await consumer.claim(); assert.equal(String(claimed._id), job.jobId);
        const queued = await consumer.consumeVersioned(claimed);
        const result = await f.worker.run(queued.operationId);
        assert.equal(result.status, 'succeeded', JSON.stringify(result));
        assert.equal(await consumer.settle(await models.TopologyCreateIntent.findById(job.jobId).lean()), true);
        assert.equal((await service.get(job.jobId)).status, 'succeeded');
        return f.operation(queued.operationId);
    };
    const apply = async () => drain(await service.acceptVersioned(await applyRequest()));
    const assertOriginalFiles = () => {
        for (const host of hosts.values()) for (const profile of Object.keys(targets)) {
            assert.deepEqual(f.readProfile(host, profile), host.original[profile], 'adoption must not mutate either profile');
        }
    };
    return { ...f, variant, transfer, initialize, adoptOne, adopt, stats, service, applyRequest, drain, apply, assertOriginalFiles };
}
module.exports = { manualTlsMongoFixture, mongoFixture, TEST_CERT, TEST_KEY, NODE_METADATA_SELECT, context, sha, evidence, copy, id };
