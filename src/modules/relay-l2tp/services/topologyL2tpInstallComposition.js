'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const fail = code => { throw Object.assign(new Error(code), { code }); };
const id = value => String(value?._id ?? value);
const hash = content => createHash('sha256').update(content).digest('hex');

// This grants MAIN L2TP/CHAP execution only. It never grants a classic writer
// access to the independently topology-owned SIDECAR or changes its owner.
function validateTopologyL2tpWrite({ owner, mainOwners, scope, operation, admission,
    gate, settled, plan, executionContext, normalization = false }) {
    const refuse = () => fail('TOPOLOGY_L2TP_WRITE_UNAVAILABLE');
    if (normalization && (!same(operation?.plan, plan)
        || !same(plan?.steps?.map(row => row.type), ['backup', 'compose_xray_fragment', 'validate_xray', 'activate_xray']))) refuse();
    if (!plan || !scope || !operation || !admission || !owner || !settled || !gate
        || !Array.isArray(mainOwners) || mainOwners.some(row => row.owner === 'topology'
            || row.lastSettledOperation !== undefined || row.handbackReceipt !== undefined)
        || owner.owner !== 'topology' || owner.profile !== 'xray-bridge'
        || id(owner.node) !== plan.relayId || owner.handbackReceipt !== undefined
        || !same(owner.executionContext, executionContext) || !same(operation.executionContext, executionContext)
        || !same(settled.executionContext, executionContext)
        || id(operation) !== scope.operationId || id(operation) !== plan.operationId
        || id(operation.node) !== plan.relayId || operation.status !== 'running'
        || !(normalization ? operation.kind === 'repair' : ['install', 'sync_users'].includes(operation.kind))
        || operation.leaseOwner !== scope.owner || operation.admissionId !== admission._id
        || admission.nodeId !== plan.relayId || admission.phase !== 'running'
        || (normalization ? scope.standaloneAdmissionId !== admission._id
            || admission.kind !== 'standalone_preflight' || admission.ownerGeneration !== 1
            || Object.hasOwn(admission, 'operationId') || Object.hasOwn(admission, 'leaseOwner')
            : admission.operationId !== plan.operationId || admission.kind !== operation.kind
                || admission.leaseOwner !== scope.owner || admission.ownerGeneration !== operation.ownerGeneration)
        || gate.topologyAdmissionCount !== 0 || !(gate.remoteAdmissionCount > 0)
        || gate.remoteDrain !== undefined || gate.replacementReservation !== undefined
        || (operation.kind === 'install' || normalization) && gate.revision !== plan.topologyRevision
        || id(settled) !== owner.lastSettledOperation || settled.status !== 'succeeded'
        || settled.heldTopologyAdmission !== false || settled.v2Terminal?.state !== 'proven') refuse();
    const entries = settled.nodes?.filter(row => id(row.node) === plan.relayId && row.targetProfile === 'xray-bridge');
    const bindings = settled.v2Terminal.bindings?.filter(row => row.nodeId === plan.relayId);
    const proofs = settled.v2Terminal.proofs?.filter(row => row.nodeId === plan.relayId);
    const fences = settled.v2Terminal.ownerFences?.filter(row => row.node === plan.relayId && row.profile === 'xray-bridge');
    if (entries?.length !== 1 || entries[0].state !== 'committed' || bindings?.length !== 1
        || proofs?.length !== 1 || fences?.length !== 1 || fences[0].generation !== owner.generation
        || bindings[0].generation !== owner.lastSettledGeneration
        || bindings[0].commandIds?.close !== owner.lastSettledCloseId
        || proofs[0].commandId !== owner.lastSettledCloseId
        || proofs[0].terminalOutcome !== 'verified' || proofs[0].completion !== 'completed') refuse();
    return true;
}

// MAIN always hands PPP to the stable (group,path) endpoint. Reverse portals,
// tunnel credentials and geo/default policy belong to the SIDECAR process.
function composeTopologyL2tpMainFragment({ fragment, topologyConfig, groupId, pathKey }) {
    const { routeToIngress } = require('./topologyAttachIngressGate');
    const { cascadePathIngressPort, cascadePathIngressTag } = require('../domain/cascadePathIngress');
    const port = cascadePathIngressPort(groupId, pathKey), tag = cascadePathIngressTag(pathKey);
    if (!routeToIngress({ bytes: Buffer.from(JSON.stringify(topologyConfig)) }, tag, port, { owned: true })
        || fragment.outbounds?.length !== 1 || fragment.outbounds[0].tag !== tag
        || fragment.outbounds[0].protocol !== 'socks'
        || !same(fragment.outbounds[0].settings?.servers, [{ address: '127.0.0.1', port }])) {
        fail('TOPOLOGY_L2TP_PATH_UNAVAILABLE');
    }
    return structuredClone(fragment);
}

function createTopologyL2tpInstallComposition({ env, HyNode, readConfig, models } = {}) {
    const dependencies = () => models ?? {
        Owner: require('../../../models/topologyConfigOwnerModel'),
        Operation: require('../models/l2tpOperationModel'), Admission: require('../models/remoteAdmissionModel'),
        State: require('../models/cascadeTopologyStateModel'), TopologyOperation: require('../models/topologyOperationModel'),
        Group: require('../models/cascadeRouteGroupModel'),
    };
    async function authorize(nodeId, request) {
        const { assertHeldL2tpNodeConfigWrite } = require('../../../services/classicNodeConfigWrite');
        const scope = await assertHeldL2tpNodeConfigWrite(nodeId);
        if (!request?.plan || !scope.operationId) fail('CLASSIC_CONFIG_WRITE_OWNER_VETO');
        const m = dependencies();
        const options = { readPreference: 'primary', readConcern: { level: 'majority' }, maxTimeMS: 5000 };
        const read = query => query.setOptions(options).lean();
        const [owners, operation, gate] = await Promise.all([
            read(m.Owner.find({ node: nodeId })), read(m.Operation.findById(scope.operationId)), read(m.State.findById('singleton')),
        ]);
        const owner = owners.find(row => row.profile === 'xray-bridge');
        const [admission, settled] = await Promise.all([
            read(m.Admission.findById(operation?.admissionId)),
            read(m.TopologyOperation.findById(owner?.lastSettledOperation).select('+effectiveTopology')),
        ]);
        const executionContext = { target: operation?.executionContext?.target, hostIdentity: env.PANEL_DOMAIN };
        validateTopologyL2tpWrite({ owner, mainOwners: owners.filter(row => row.profile === 'xray-main'), scope,
            operation, admission, gate, settled, plan: request.plan, executionContext,
            normalization: request.normalization === true });
        await assertHeldL2tpNodeConfigWrite(nodeId);
        return { owner, settled, operation };
    }
    async function prepare(plan, { normalization = false } = {}) {
        const { settled } = await authorize(plan.relayId, { plan, normalization });
        const entry = settled.nodes.find(row => id(row.node) === plan.relayId && row.targetProfile === 'xray-bridge');
        const live = await readConfig(plan.relayId, 'xray-bridge');
        if (hash(live) !== entry.candidateHash) fail('TOPOLOGY_L2TP_PATH_UNAVAILABLE');
        const m = dependencies();
        const group = await m.Group.findById(plan.routeGroupId).lean();
        const path = group?.paths?.find(row => row.pathKey === plan.selectedPathKey && row.enabled !== false);
        if (!path?.linkIds?.length) fail('TOPOLOGY_L2TP_PATH_UNAVAILABLE');
        let config;
        if (settled.effectiveTopology === undefined) {
            // Full reconcile persists the canonical per-node candidate, not the
            // selected-operation effectiveTopology. It is usable only at the
            // exact still-held revision and for its explicitly settled links.
            // The owner/V2 close proof above and live byte hash remain mandatory.
            if (settled.kind !== 'domain.reconcile' || settled.topologyRevision !== plan.topologyRevision
                || !Array.isArray(settled.linkIds) || path.linkIds.some(link => !settled.linkIds.includes(id(link)))
                || !Array.isArray(entry.candidate?.bytes)
                || entry.candidate.sha256 !== entry.candidateHash
                || hash(Buffer.from(entry.candidate.bytes)) !== entry.candidateHash) fail('TOPOLOGY_L2TP_PATH_UNAVAILABLE');
            config = JSON.parse(Buffer.from(entry.candidate.bytes).toString('utf8'));
        } else {
            const before = structuredClone(settled.effectiveTopology), after = structuredClone(before);
            if (!before?.links?.some(row => row.id === id(path.linkIds[0])
                && row.source === plan.relayId && row.target === plan.nextHopNodeId
                && ['forward', 'reverse'].includes(row.mode))
                || path.linkIds.some(link => !before.links.some(row => row.id === id(link)))) fail('TOPOLOGY_L2TP_PATH_UNAVAILABLE');
            for (const node of before.nodes) {
                const row = settled.nodes.find(row => id(row.node) === node.id);
                if (row) node.profileConfig = Buffer.from(row.candidate.bytes).toString('utf8');
            }
            after.groups = [{ _id: plan.routeGroupId, mode: group.mode, strategy: group.strategy,
                paths: [{ pathKey: plan.selectedPathKey, linkIds: path.linkIds.map(id), priority: path.priority, enabled: true }] }];
            const { composeFrozenTopologyDeploymentPlan } = require('./frozenTopologyDeploymentPlanComposer');
            const { compileConfiguredTopology } = require('../domain/primaryReservePolicy');
            const generated = composeFrozenTopologyDeploymentPlan({ baselineTopology: before, snapshot: after,
                compiledTopology: compileConfiguredTopology(after) });
            const candidate = generated.nodes.find(row => row.node === plan.relayId);
            config = JSON.parse(Buffer.from(candidate.candidate.bytes).toString('utf8'));
        }
        const tag = `cascade-${plan.selectedPathKey}`;
        const rules = config.routing.rules.filter(row => row.inboundTag?.includes(tag));
        const fallback = rules.at(-1);
        if (!fallback || Object.keys(fallback).some(key => !['type', 'inboundTag', 'outboundTag'].includes(key))) fail('TOPOLOGY_L2TP_PATH_UNAVAILABLE');
        // Generated bytes are expectations, never evidence that a live listener
        // exists. Check the actual committed/read-back ingress and its policy.
        const original = JSON.parse(live);
        const { routeToIngress } = require('./topologyAttachIngressGate');
        const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
        if (!routeToIngress({ bytes: Buffer.from(live) }, tag,
            cascadePathIngressPort(plan.routeGroupId, plan.selectedPathKey), { owned: true })
            || !same(original.inbounds?.filter(row => row.tag === tag), config.inbounds.filter(row => row.tag === tag))
            || !same(original.routing?.rules?.filter(row => row.inboundTag?.includes(tag)), rules)) {
            fail('TOPOLOGY_L2TP_PATH_UNAVAILABLE');
        }
        for (const rule of rules) {
            const expected = config.outbounds.find(row => row.tag === rule.outboundTag);
            const portal = config.reverse?.portals?.find(row => row.tag === rule.outboundTag);
            if (expected ? !original.outbounds?.some(row => same(row, expected))
                : !portal || !original.reverse?.portals?.some(row => same(row, portal))) fail('TOPOLOGY_L2TP_PATH_UNAVAILABLE');
        }
        await authorize(plan.relayId, { plan, normalization });
        return { topologyConfig: original, groupId: plan.routeGroupId, pathKey: plan.selectedPathKey };
    }
    return { authorize, prepare };
}
module.exports = { validateTopologyL2tpWrite, composeTopologyL2tpMainFragment, createTopologyL2tpInstallComposition };
