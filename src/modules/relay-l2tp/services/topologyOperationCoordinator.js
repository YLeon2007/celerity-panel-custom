'use strict';

const { createHash, randomUUID } = require('node:crypto');
const { compileConfiguredTopology: compileTopology, primaryReservePolicies } = require('../domain/primaryReservePolicy');
const {
    projectGroups,
    projectLinks,
    projectNodes,
} = require('../domain/topologyDraft');
const { validateTopology } = require('../domain/topologyValidator');
const { computeTopologyDomains } = require('../domain/topologyDomains');
const { deriveReplacementTopology, deriveAttachTopology } = require('../domain/topologyReplacement');
const { validNodeRef } = require('./topologyNodeRef');
const { durableSelectedTopology, selectedAdmissionFingerprint } = require('../repositories/topologyOperationRepository');
const {
    TEST_TOPOLOGY_EXECUTION_CONTEXT,
    matchesTopologyOperationExecutionContext,
    matchesTopologyExecutionContext,
    topologyExecutionContext,
} = require('../domain/topologyExecutionContext');

const ACTIVE_OPERATION_STATUSES = new Set([
    'queued',
    'preparing',
    'committing',
    'rolling_back',
]);
const OPERATION_STATUSES = new Set([
    ...ACTIVE_OPERATION_STATUSES,
    'succeeded',
    'failed',
    'rolled_back',
]);
const NODE_STATES = new Set(['pending', 'prepared', 'committed', 'failed', 'rolled_back']);
const SAFE_VALIDATION_ERROR_FIELDS = Object.freeze([
    'code',
    'path',
    'groupId',
    'pathKey',
    'linkId',
    'nodeId',
    'sourceNodeId',
    'targetNodeId',
    'groupMode',
    'linkMode',
    'modes',
]);

class TopologyOperationCoordinatorError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'TopologyOperationCoordinatorError';
        this.code = code;
        Object.assign(this, details);
    }
}

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    Object.values(value).forEach(deepFreeze);
    return Object.freeze(value);
}

function entityId(value) {
    const id = value !== null && typeof value === 'object'
        ? value._id ?? value.id ?? value.node
        : value;
    return id === null || id === undefined ? '' : String(id);
}

function idFromIdempotencyKey(idempotencyKey) {
    return createHash('sha256').update(idempotencyKey).digest('hex').slice(0, 24);
}

const SCOPED_OPERATION_KINDS = new Set(['link.apply', 'link.delete', 'domain.reconcile', 'link.replace']);
const { nodeActivation: normalizeNodeActivation, overlayNodeSecurity } = require('./topologyNodeActivation');
// Legacy global-admission scope filter only. These statuses do not establish
// selected applied-descriptor authority; that requires a verified settled
// snapshot, never a reread of a status-labelled desired record.
const CONFIRMED_BASELINE_LINK_STATUSES = new Set(['deployed', 'online', 'staged']);

function normalizeOperationScope(scope) {
    if (scope === undefined) return null;
    if (!scope || typeof scope !== 'object' || Array.isArray(scope)
        || !Object.keys(scope).every(key => (scope.kind === 'link.replace'
            ? ['kind', 'linkId', 'linkIds', 'oldLinkId', 'groupId', 'pathKey']
            : ['kind', 'linkId', 'linkIds', 'nodeActivation']).includes(key))
        || !SCOPED_OPERATION_KINDS.has(scope.kind)
        || typeof scope.linkId !== 'string' || scope.linkId.length === 0
        || !Array.isArray(scope.linkIds) || scope.linkIds.length === 0
        || scope.linkIds.some(linkId => typeof linkId !== 'string' || linkId.length === 0)
        || new Set(scope.linkIds).size !== scope.linkIds.length
        || !scope.linkIds.includes(scope.linkId)
        || (scope.kind === 'link.replace' && (
            !['oldLinkId', 'groupId', 'pathKey'].every(key =>
                typeof scope[key] === 'string' && scope[key].length > 0)
            || scope.oldLinkId === scope.linkId
            || scope.linkIds.includes(scope.oldLinkId)))) {
        throw new TopologyOperationCoordinatorError(
            'INVALID_REQUEST',
            'A scoped topology operation requires kind, a linkId contained in unique linkIds',
        );
    }
    return {
        kind: scope.kind,
        ...(scope.nodeActivation !== undefined ? { nodeActivation: scope.kind === 'link.apply'
            ? normalizeNodeActivation(scope.nodeActivation) : (() => { throw new TopologyOperationCoordinatorError('INVALID_REQUEST', 'Node activation requires explicit apply'); })() } : {}),
        linkId: scope.linkId,
        linkIds: [...scope.linkIds].sort((left, right) => left.localeCompare(right, 'en')),
        ...(scope.kind === 'link.replace' ? {
            oldLinkId: scope.oldLinkId, groupId: scope.groupId, pathKey: scope.pathKey,
        } : {}),
    };
}

function assertQueueInput(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)
        || !Object.hasOwn(input, 'expectedTopologyRevision')
        || !Object.keys(input).every(key => ['expectedTopologyRevision', 'scope'].includes(key))) {
        throw new TopologyOperationCoordinatorError(
            'INVALID_REQUEST',
            'Only expectedTopologyRevision and an optional scope are accepted',
        );
    }
    if (!Number.isSafeInteger(input.expectedTopologyRevision)
        || input.expectedTopologyRevision < 0) {
        throw new TopologyOperationCoordinatorError(
            'INVALID_TOPOLOGY_REVISION',
            'expectedTopologyRevision must be a non-negative safe integer',
            { expectedTopologyRevision: input.expectedTopologyRevision },
        );
    }
    return normalizeOperationScope(input.scope);
}

function sanitizeValidationErrors(errors) {
    return (Array.isArray(errors) ? errors : []).map(error => {
        const projected = {};
        for (const field of SAFE_VALIDATION_ERROR_FIELDS) {
            if (error?.[field] !== undefined) projected[field] = error[field];
        }
        return projected;
    });
}

function safeQueueError(error, operationId, expectedTopologyRevision) {
    if (error instanceof TopologyOperationCoordinatorError) return error;
    if (error?.code === 'TOPOLOGY_ADMISSION_UNAVAILABLE') {
        // The compare-and-swap did not acquire the admission slot; nothing
        // was committed for this attempt. Do not classify ambiguous Mongo
        // commit failures or arbitrary transaction errors as retryable.
        return new TopologyOperationCoordinatorError(
            'TOPOLOGY_DEPLOY_BUSY',
            'Another topology deployment owns the slot; retry after it finishes',
            { operationId, expectedTopologyRevision, retryable: true },
        );
    }
    if (error?.code === 'TOPOLOGY_REPLACEMENT_RESERVED') {
        return new TopologyOperationCoordinatorError(
            'TOPOLOGY_REPLACEMENT_RESERVED',
            'A topology replacement owns the deployment pin fence',
            { operationId, expectedTopologyRevision },
        );
    }
    if (error?.code === 'STALE_TOPOLOGY_REVISION') {
        return new TopologyOperationCoordinatorError(
            'STALE_TOPOLOGY_REVISION',
            'The topology revision changed before the operation could be pinned',
            {
                operationId,
                expectedTopologyRevision,
                topologyRevision: Number.isSafeInteger(error.topologyRevision)
                    ? error.topologyRevision
                    : null,
            },
        );
    }
    if (error?.name === 'TopologyReplacementError') {
        return new TopologyOperationCoordinatorError(
            'INVALID_TOPOLOGY_DEPLOYMENT',
            'The pinned replacement is not a complete installed path',
            { operationId, causeCode: error.code },
        );
    }
    // Plan validation failures (incomplete chain, bad roles, unsupported
    // metadata) are client-visible 422s, not opaque 500 queue failures.
    if (error?.name === 'FrozenTopologyDeploymentPlanError') {
        return new TopologyOperationCoordinatorError(
            'INVALID_TOPOLOGY_DEPLOYMENT',
            error.message || 'The pinned topology is invalid',
            {
                operationId,
                expectedTopologyRevision,
                causeCode: error?.code,
            },
        );
    }
    return new TopologyOperationCoordinatorError(
        'TOPOLOGY_OPERATION_QUEUE_FAILED',
        'The topology operation could not be queued',
        {
            operationId,
            expectedTopologyRevision,
        },
    );
}

function projectTopology(snapshot) {
    return {
        nodes: projectNodes(snapshot.nodes)
            .sort((left, right) => left.id.localeCompare(right.id, 'en')),
        links: projectLinks(snapshot.links)
            .sort((left, right) => left.id.localeCompare(right.id, 'en')),
        groups: projectGroups(snapshot.groups)
            .sort((left, right) => left._id.localeCompare(right._id, 'en')),
    };
}

// Selected-applied seam. Its caller must have verified every baseline
// descriptor against the exact settled owner pointers in the same admission
// snapshot. An absent/legacy baseline is not permission to hydrate desired.
// Admission, claim, worker revalidation and settlement all consume these pins.
function selectEffectiveTopology({ verifiedBaselineTopology, desiredTopology, scope } = {}) {
    if (verifiedBaselineTopology === undefined) {
        throw new TopologyOperationCoordinatorError('APPLIED_BASELINE_REQUIRED',
            'A verified applied snapshot is required for selected topology');
    }
    if (!['link.apply', 'link.delete'].includes(scope?.kind) || typeof scope.linkId !== 'string') {
        throw new TopologyOperationCoordinatorError('INVALID_REQUEST',
            'Selected topology requires one explicit apply/delete mutation');
    }
    const applied = durableSelectedTopology(verifiedBaselineTopology);
    const desired = durableSelectedTopology(desiredTopology);
    const activation = scope.nodeActivation === undefined ? undefined : normalizeNodeActivation(scope.nodeActivation);
    const requested = (activation ? applied : desired).links.find(link => link.id === scope.linkId);
    if (!requested) {
        throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT',
            'The requested desired link is missing', { causeCode: 'SCOPE_LINK_MISSING', linkId: scope.linkId });
    }
    const old = applied.links.find(link => link.id === requested.id);
    if (activation && (requested.source !== activation.nodeId && requested.target !== activation.nodeId)) {
        throw new TopologyOperationCoordinatorError('INVALID_REQUEST', 'Node must belong to the applied anchor');
    }
    const resources = new Set([requested.source, requested.target,
        ...(old ? [old.source, old.target] : [])]);
    const included = new Set();
    const groups = new Set();
    let expanded;
    do {
        expanded = false;
        for (const link of applied.links) {
            if (!resources.has(link.source) && !resources.has(link.target) && !included.has(link.id)) continue;
            if (!included.has(link.id)) expanded = true;
            included.add(link.id);
            resources.add(link.source);
            resources.add(link.target);
        }
        for (const group of applied.groups) {
            const linkIds = group.paths.flatMap(path => path.linkIds);
            if (!linkIds.some(id => included.has(id) || id === requested.id)) continue;
            groups.add(group._id);
            for (const id of linkIds) {
                if (!included.has(id)) expanded = true;
                included.add(id);
            }
        }
    } while (expanded);
    const baselineTopology = {
        nodes: applied.nodes.filter(node => resources.has(node.id)),
        links: applied.links.filter(link => included.has(link.id)),
        groups: applied.groups.filter(group => groups.has(group._id)),
    };
    if (scope.kind === 'link.delete') {
        // Endpoints without a settled edge have already passed the adopted
        // empty-profile proof. Still take the ordinary cleanup/readback path;
        // a mutable pending status is never a DB-only deletion shortcut.
        for (const id of resources) if (!baselineTopology.nodes.some(node => node.id === id)) {
            baselineTopology.nodes.push(desired.nodes.find(node => node.id === id));
        }
        baselineTopology.nodes.sort((a, b) => a.id.localeCompare(b.id, 'en'));
    }
    const links = [...baselineTopology.links.filter(link => link.id !== requested.id),
        ...(scope.kind === 'link.delete' ? [] : [requested])]
        .sort((left, right) => left.id.localeCompare(right.id, 'en'));
    const linkedNodes = new Set(links.flatMap(link => [link.source, link.target]));
    const appliedNodes = new Map(applied.nodes.map(node => [node.id, node]));
    const desiredNodes = new Map(desired.nodes.map(node => [node.id, node]));
    const nodes = [...linkedNodes].sort((left, right) => left.localeCompare(right, 'en'))
        .map(id => activation?.nodeId === id ? overlayNodeSecurity(appliedNodes.get(id), desiredNodes.get(id), activation)
            : appliedNodes.get(id) || desiredNodes.get(id));
    const effectiveTopology = { nodes, links, groups: baselineTopology.groups };
    // A selected apply can consume an explicit saved primary/reserve policy
    // only when every referenced transport is already applied or this exact
    // requested link. No neighboring desired-only transport joins admission.
    for (const group of desired.groups) {
        if (activation) break;
        if (!group.paths.some(path => path.linkIds.includes(requested.id))
            || group.paths.some(path => path.linkIds.some(id => !links.some(link => link.id === id)))) continue;
        if (primaryReservePolicies({ ...effectiveTopology, groups: [group] }).length) {
            effectiveTopology.groups = [...effectiveTopology.groups.filter(row => row._id !== group._id), group];
        }
    }
    const policies = primaryReservePolicies(effectiveTopology);
    const standby = new Set(policies.flatMap(policy => policy.candidates
        .filter(candidate => candidate !== policy.selected).map(candidate => candidate.link.id)));
    const defaults = new Map();
    let ambiguous = false;
    for (const link of links.filter(link => link.geoRouting?.enabled !== true && !standby.has(link.id))) {
        if (defaults.has(link.source)) ambiguous = true;
        defaults.set(link.source, link.target);
    }
    const roles = new Map(nodes.map(node => [node.id, node.role]));
    const portals = nodes.filter(node => node.role === 'portal');
    const complete = portals.some(portal => {
        const seen = new Set();
        let id = portal.id;
        while (id && !seen.has(id)) {
            if (roles.get(id) === 'bridge') return true;
            seen.add(id);
            id = defaults.get(id);
        }
        return false;
    });
    return deepFreeze({ baselineTopology, effectiveTopology,
        resourceNodeIds: [...resources].sort((left, right) => left.localeCompare(right, 'en')),
        affectedGroupIds: [...groups].sort((left, right) => left.localeCompare(right, 'en')),
        routeState: ambiguous ? 'policy_ambiguous' : portals.length === 0 ? 'no_portal_input'
            : complete ? 'complete' : 'no_bridge_exit' });
}

// Scoped reconcile: the effective graph is exactly the requested link plus the
// links the caller proved deployed. Anything else — in particular preexisting
// pending links — must stay out of the plan, even on shared relays.
function applyScopeToTopology(topology, scope, operationId, rawLinks = []) {
    const wanted = new Set(scope.linkIds);
    const available = new Set(topology.links.map(link => link.id));
    const rawById = new Map(rawLinks.map(link => [entityId(link._id ?? link.id), link]));
    if (scope.kind === 'domain.reconcile') {
        const anchor = rawById.get(scope.linkId);
        if (!CONFIRMED_BASELINE_LINK_STATUSES.has(anchor?.status)) {
            throw new TopologyOperationCoordinatorError(
                'INVALID_TOPOLOGY_DEPLOYMENT',
                'A domain Sync requires a confirmed applied anchor',
                { operationId, causeCode: 'SCOPE_LINK_UNCONFIRMED' },
            );
        }
        // Recompute membership from the pinned revision, not the route's
        // earlier read. Pending links do not join components; omitted or
        // foreign confirmed links make caller-supplied scope ambiguous.
        const confirmed = topology.links.filter(link =>
            CONFIRMED_BASELINE_LINK_STATUSES.has(rawById.get(link.id)?.status));
        const domain = computeTopologyDomains({ nodes: topology.nodes, links: confirmed })
            .find(component => component.linkIds.includes(scope.linkId));
        if (!domain || domain.linkIds.length !== wanted.size
            || domain.linkIds.some(linkId => !wanted.has(linkId))) {
            throw new TopologyOperationCoordinatorError(
                'INVALID_TOPOLOGY_DEPLOYMENT',
                'The selected domain scope does not match the pinned topology',
                { operationId, causeCode: 'SCOPE_DOMAIN_AMBIGUOUS' },
            );
        }
    }
    for (const linkId of wanted) {
        if (!available.has(linkId)) {
            throw new TopologyOperationCoordinatorError(
                'INVALID_TOPOLOGY_DEPLOYMENT',
                'A scoped link is missing from the pinned topology',
                { operationId, causeCode: 'SCOPE_LINK_MISSING', linkId },
            );
        }
        // A request may activate only its own explicit link. Every other
        // member must already be confirmed deployed; never trust caller-supplied
        // linkIds to pull an old active/pending edge into a new candidate.
        if (linkId !== scope.linkId) {
            const status = rawById.get(linkId)?.status;
            if (!CONFIRMED_BASELINE_LINK_STATUSES.has(status)) {
                throw new TopologyOperationCoordinatorError(
                    'INVALID_TOPOLOGY_DEPLOYMENT',
                    'A scoped baseline link is not confirmed deployed',
                    { operationId, causeCode: 'SCOPE_LINK_UNCONFIRMED', linkId },
                );
            }
        }
    }
    const links = topology.links.filter(link => wanted.has(link.id));
    const nodeIds = new Set(links.flatMap(link => [link.source, link.target]));
    const nodes = topology.nodes.filter(node => nodeIds.has(node.id));
    const groups = [];
    for (const group of topology.groups) {
        const referenced = new Set(
            (group.paths || []).flatMap(path => path.linkIds || []),
        );
        const inside = [...referenced].filter(linkId => wanted.has(linkId));
        if (inside.length === 0) continue;
        if (inside.length !== referenced.size) {
            throw new TopologyOperationCoordinatorError(
                'INVALID_TOPOLOGY_DEPLOYMENT',
                'A route group straddles the scoped component boundary',
                { operationId, causeCode: 'SCOPE_GROUP_CONFLICT', groupId: group._id },
            );
        }
        groups.push(group);
    }
    return { nodes, links, groups };
}

// Select attach only from the transactional owner projection. A pending
// foreign draft cannot join the scoped graph or impersonate the owned suffix.
function deriveScopedAttach(snapshot, scope, scopedTopology, operationId) {
    if (scope?.kind !== 'link.apply'
        || !Array.isArray(snapshot.installedRouteGroupIds)
        || !Array.isArray(snapshot.installedRouteOwners)
        || !Array.isArray(snapshot.activeRouteGroupIds)) return null;
    const requested = scopedTopology.links.find(link => link.id === scope.linkId);
    const roles = new Map(scopedTopology.nodes.map(node => [node.id, node.role]));
    if (!requested || roles.get(requested.target) !== 'bridge') return null;
    const installed = new Set(snapshot.installedRouteGroupIds.map(entityId));
    const active = new Set(snapshot.activeRouteGroupIds.map(entityId));
    const candidates = snapshot.groups.filter(group => installed.has(entityId(group))
        && active.has(entityId(group)) && Array.isArray(group.paths)
        && (group.paths.length === 0 || group.paths.some(path => path?.linkIds?.length === 0)));
    const scopedNodes = new Set(scopedTopology.nodes.map(node => node.id));
    const owners = candidates.flatMap(group => snapshot.installedRouteOwners
        .filter(owner => entityId(owner.groupId) === entityId(group)
            && scopedNodes.has(entityId(owner.nodeId)))
        .map(owner => ({ group, owner })));
    if (owners.length === 0 && candidates.length === 0) return null;
    if (owners.length !== 1 || typeof owners[0].owner.pathKey !== 'string'
        || !owners[0].owner.pathKey
        || !Number.isSafeInteger(owners[0].owner.ownerTopologyRevision)
        || owners[0].owner.ownerTopologyRevision < 0
        || !Number.isSafeInteger(owners[0].owner.ownerCredentialRevision)
        || owners[0].owner.ownerCredentialRevision < 0) {
        throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT',
            'The installed owner identity is ambiguous',
            { operationId, causeCode: 'ATTACH_OWNER_AMBIGUOUS' });
    }
    const { group, owner } = owners[0];
    const eligible = { ...snapshot, links: snapshot.links.filter(link =>
        link.status !== 'pending' || entityId(link) === scope.linkId) };
    const result = deriveAttachTopology(eligible, {
        groupId: entityId(group), pathKey: owner.pathKey, linkId: scope.linkId,
    });
    if (result.topology.links.length !== scope.linkIds.length
        || result.topology.links.some(link => !scope.linkIds.includes(link.id))) {
        throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT',
            'Attach scope differs from its pinned graph',
            { operationId, causeCode: 'SCOPE_DOMAIN_AMBIGUOUS' });
    }
    const newPathLinkIds = result.topology.groups[0].paths
        .find(path => path.pathKey === owner.pathKey).linkIds;
    return { ...result, groupId: entityId(group), pathKey: owner.pathKey,
        ownerTopologyRevision: owner.ownerTopologyRevision,
        ownerCredentialRevision: owner.ownerCredentialRevision,
        newPathLinkIds: [...newPathLinkIds] };
}

function nodeIdsByRef(topology, plan, resourceNodeIds) {
    // New materializers preserve the composer's exact physical-node identity.
    // Do not derive a second ordering for suffixes, geo leaves or fan-in. The
    // legacy walker below is only for older plans with no binding metadata.
    if (plan?.nodes?.some(node => Object.hasOwn(node, 'node'))) {
        const rolesById = new Map(topology.nodes.map(node => [node.id, node.role]));
        const refs = new Map();
        const ids = new Set();
        for (const node of plan.nodes) {
            const id = entityId(node.node);
            if (!id || rolesById.get(id) !== node.role || !validNodeRef(node.role, node.nodeRef)
                || refs.has(node.nodeRef) || ids.has(id)) {
                throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT',
                    'Invalid materialized node identity');
            }
            refs.set(node.nodeRef, id);
            ids.add(id);
        }
        for (const role of ['portal', 'relay']) {
            const members = plan.nodes.filter(node => node.role === role);
            const expected = members.map((_, index) => role === 'portal' && members.length === 1
                ? 'portal' : `${role}-${index + 1}`);
            if (expected.some(ref => !refs.has(ref))) {
                throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT',
                    'Invalid materialized node reference set');
            }
        }
        const linked = new Set(resourceNodeIds || topology.links.flatMap(link => [link.source, link.target]));
        if (linked.size !== ids.size || [...linked].some(id => !ids.has(id))) {
            throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT',
                'Incomplete materialized node identity');
        }
        return refs;
    }
    const nodes = new Map(topology.nodes.map(node => [node.id, node]));
    const outgoing = new Map();
    const incoming = new Set();
    const geoTargets = new Set();
    for (const link of topology.links) {
        if (!nodes.has(link.source) || !nodes.has(link.target)) {
            throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT', 'Invalid node ref endpoint');
        }
        if (link.geo === true) {
            if (geoTargets.has(link.target)) {
                throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT', 'Ambiguous geo node ref');
            }
            geoTargets.add(link.target);
        } else {
            if (outgoing.has(link.source)) {
                throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT', 'Ambiguous node ref path');
            }
            outgoing.set(link.source, link.target);
            incoming.add(link.target);
        }
    }
    // Mirror the composer's ordering: portal sources sorted by id, then
    // relays in first-seen portal-path order, then the shared default sink.
    const portals = topology.nodes.filter(node => node.role === 'portal' && outgoing.has(node.id) && !incoming.has(node.id))
        .sort((left, right) => left.id.localeCompare(right.id, 'en'));
    const paths = portals.map(portal => {
        const path = [];
        const seen = new Set();
        let id = portal.id;
        while (id) {
            if (seen.has(id)) {
                throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT', 'Invalid cyclic node ref path');
            }
            seen.add(id);
            path.push(id);
            id = outgoing.get(id);
        }
        return path;
    });
    const fanIn = portals.length > 1;
    // Match the composer: shared sink last, including a staged relay sink.
    // PPP readiness also relies on the staged terminal's highest relay ref.
    const sinkId = fanIn ? paths[0].at(-1) : null;
    const ordered = fanIn
        ? [...portals.map(portal => portal.id),
            ...paths.flatMap(path => path.slice(1).filter(id => id !== sinkId)), sinkId]
        : (paths[0] || []);
    const visited = new Set();
    const result = new Map();
    let portalIndex = 0;
    let relayIndex = 0;
    for (const id of ordered) {
        if (visited.has(id)) continue;
        visited.add(id);
        const role = nodes.get(id).role;
        const ref = role === 'portal' ? (fanIn ? `portal-${++portalIndex}` : 'portal')
            : role === 'relay' ? `relay-${++relayIndex}` : 'bridge';
        if (result.has(ref)) {
            throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT', 'Ambiguous node ref role');
        }
        result.set(ref, id);
    }
    // Composer numbers geo bridge leaves by sorted id, starting at 2.
    const geoBridges = topology.nodes.filter(node => geoTargets.has(node.id) && !visited.has(node.id))
        .sort((left, right) => left.id.localeCompare(right.id, 'en'));
    geoBridges.forEach((node, index) => result.set(`bridge-${index + 2}`, node.id));
    return result;
}

function operationPlan({ operationId, topologyRevision, priorDeployedRevision, topology, plan, resourceNodeIds }) {
    const idsByRef = nodeIdsByRef(topology, plan, resourceNodeIds);
    const seenRefs = new Set();
    const seenIds = new Set();
    const rolesById = new Map(topology.nodes.map(node => [node.id, node.role]));
    const nodes = plan.nodes.map(node => {
        const nodeId = idsByRef.get(node.nodeRef);
        const candidateHash = node.candidateHash ?? node.candidate?.sha256;
        if (!nodeId || (entityId(node.node) && entityId(node.node) !== nodeId)
            || rolesById.get(nodeId) !== node.role
            || seenRefs.has(node.nodeRef) || seenIds.has(nodeId)
            || typeof candidateHash !== 'string' || candidateHash.length === 0) {
            throw new TopologyOperationCoordinatorError(
                'INVALID_TOPOLOGY_DEPLOYMENT',
                'The frozen topology operation plan is invalid',
                { operationId },
            );
        }
        seenRefs.add(node.nodeRef);
        seenIds.add(nodeId);
        return {
            ...node,
            node: nodeId,
            candidateHash,
        };
    });
    return deepFreeze({
        operationId,
        topologyRevision,
        priorDeployedRevision,
        nodes,
    });
}

function projectTopologyOperationStatus(operation = {}) {
    const operationId = entityId(operation.operationId ?? operation._id ?? operation.id);
    const topologyRevision = operation.topologyRevision;
    const status = operation.status;
    const projected = {};
    if (operationId) projected.operationId = operationId;
    if (Number.isSafeInteger(topologyRevision) && topologyRevision >= 0) {
        projected.topologyRevision = topologyRevision;
    }
    if (OPERATION_STATUSES.has(status)) projected.status = status;
    if (Array.isArray(operation.nodes)) {
        projected.nodes = operation.nodes.map(node => ({
            nodeId: entityId(node?.node),
            state: node?.state,
        })).filter(node => node.nodeId && NODE_STATES.has(node.state))
            .sort((left, right) => left.nodeId.localeCompare(right.nodeId, 'en'));
    }
    return projected;
}

class TopologyOperationCoordinator {
    #executionContext;

    constructor({
        // Retain the fixed TEST-only seam for existing server-side callers
        // (the intent consumer now requires an explicit context). Runtime always
        // supplies its validated context; request input cannot override it.
        executionContext = TEST_TOPOLOGY_EXECUTION_CONTEXT,
        topologyRepository,
        planMaterializer,
        operationRepository,
        operationWorker,
        intentDraftWriter,
        validator = validateTopology,
        compiler = compileTopology,
        idFactory = idFromIdempotencyKey,
        onWorkerError = () => {},
    } = {}) {
        if (!topologyRepository || typeof topologyRepository.admitTopology !== 'function') {
            throw new TypeError('Topology operation coordinator requires topologyRepository.admitTopology');
        }
        if (!planMaterializer || typeof planMaterializer.materialize !== 'function') {
            throw new TypeError('Topology operation coordinator requires planMaterializer.materialize');
        }
        if (!operationRepository || typeof operationRepository.createFrozen !== 'function') {
            throw new TypeError('Topology operation coordinator requires operationRepository.createFrozen');
        }
        if (operationWorker !== undefined && typeof operationWorker?.run !== 'function') {
            throw new TypeError('Topology operation coordinator requires operationWorker.run');
        }
        if (typeof validator !== 'function' || typeof compiler !== 'function'
            || typeof idFactory !== 'function' || typeof onWorkerError !== 'function') {
            throw new TypeError('Topology operation coordinator requires callable policies');
        }
        this.#executionContext = topologyExecutionContext(
            executionContext?.target, executionContext?.hostIdentity,
        );
        if (!this.#executionContext) {
            throw new TypeError('Topology operation coordinator requires an exact server execution context');
        }
        this.topologyRepository = topologyRepository;
        this.planMaterializer = planMaterializer;
        this.operationRepository = operationRepository;
        this.operationWorker = operationWorker;
        // Forward the complete same-session capability, including atomic edits.
        this.intentDraftWriter = intentDraftWriter;
        this.validator = validator;
        this.compiler = compiler;
        this.idFactory = idFactory;
        this.onWorkerError = onWorkerError;
        this.operationsByIdempotencyKey = new Map();
    }

    projectStatus(operation) {
        return projectTopologyOperationStatus(operation);
    }

    async queue(input) {
        const scope = assertQueueInput(input);
        const { expectedTopologyRevision } = input;
        // A scoped reconcile gets its own idempotency key so it can never be
        // collapsed with (or satisfied by) a legacy full-sync operation.
        const idempotencyKey = scope
            ? `topology:${this.#executionContext.target}:revision-${expectedTopologyRevision}:${scope.kind}:${scope.linkId}`
                + (scope.kind === 'link.replace'
                    ? `:${createHash('sha256').update(JSON.stringify({
                        groupId: scope.groupId, pathKey: scope.pathKey,
                        oldLinkId: scope.oldLinkId, linkIds: scope.linkIds,
                    })).digest('hex')}` : '')
                + (scope.nodeActivation ? `:node-${scope.nodeActivation.nodeId}:${scope.nodeActivation.targetProfile}` : '')
            : `topology:${this.#executionContext.target}:revision-${expectedTopologyRevision}`;
        const existing = this.operationsByIdempotencyKey.get(idempotencyKey);
        if (existing) {
            const settled = await existing.then(operation => operation, () => null);
            if (!settled) {
                this.operationsByIdempotencyKey.delete(idempotencyKey);
            } else if (typeof this.operationRepository.findPublicById === 'function') {
                const persisted = await this.operationRepository.findPublicById(settled.operationId);
                // A live or successful operation satisfies the idempotency key.
                // A terminally failed one (failed/rolled_back) must not block a
                // retry of the same revision — re-queue with a fresh run id.
                if (persisted && persisted.status !== 'failed' && persisted.status !== 'rolled_back') {
                    return existing;
                }
                this.operationsByIdempotencyKey.delete(idempotencyKey);
            } else {
                return existing;
            }
        }

        const queued = this.queueOnce({ expectedTopologyRevision, scope,
            // The in-process cache separates activation from link apply; the
            // persisted key keeps the existing bounded producer grammar. The
            // immutable marker/descriptors are in the admission fingerprint.
            idempotencyKey: scope?.nodeActivation ? idempotencyKey.split(':node-')[0] : idempotencyKey });
        this.operationsByIdempotencyKey.set(idempotencyKey, queued);
        try {
            return await queued;
        } catch (error) {
            this.operationsByIdempotencyKey.delete(idempotencyKey);
            throw error;
        }
    }

    // Transaction-aware v2 intent seam. No worker starts until its caller's
    // outer intent+operation transaction commits; recovery performs handoff.
    get db() { return this.topologyRepository.db; }

    async resolveIntentResourcesForQueue({ kind, link, desiredVersion, nodeActivation, session }) {
        if (!['link.create', 'link.apply', 'link.delete'].includes(kind)) throw new TopologyOperationCoordinatorError('INVALID_REQUEST', 'Unknown mutation');
        const selected = await this.topologyRepository.readSelected({
            snapshot: await this.topologyRepository.snapshotReader.readDraft(session),
            scope: { kind: kind === 'link.delete' ? kind : 'link.apply', linkId: String(link._id), ...(nodeActivation ? { nodeActivation } : {}) }, desiredVersion, session, executionContext: this.#executionContext,
        });
        return selected.resourceNodeIds;
    }

    // Read-only diagnostic for an explicitly selected, never-admitted TEST
    // intent. This does not reserve admission or create/run an operation.
    async inspectUnadmittedPreparation({ linkId, desiredVersion, session }) {
        if (this.#executionContext.target !== 'test') throw new TopologyOperationCoordinatorError('TOPOLOGY_INTENT_RECONCILIATION_UNPROVEN', 'TEST-only preparation readback');
        const snapshot = await this.topologyRepository.snapshotReader.readDraft(session);
        const selected = await this.topologyRepository.readSelected({ snapshot,
            scope: { kind: 'link.apply', linkId }, desiredVersion, session, executionContext: this.#executionContext });
        const topology = selected.effectiveTopology;
        const compiled = this.compiler({ ...topology, healthByPathKey: {} });
        if (this.validator(topology)?.valid !== true || compiled?.valid !== true) return { status: 'unproven' };
        try {
            await this.planMaterializer.materialize({ ...this.#executionContext, operationKind: 'link.apply', session,
                baselineTopology: selected.baselineTopology, effectiveTopology: selected.effectiveTopology,
                installedPath: selected.installedPath, selectedOwnerPins: selected.selectedOwnerPins,
                pinnedSnapshot: deepFreeze({ revision: snapshot.revision, topology, compiled }) });
            return { status: 'valid', revision: snapshot.revision, resourceNodeIds: selected.resourceNodeIds };
        } catch (error) {
            const { FrozenTopologyDeploymentPlanError } = require('./frozenTopologyDeploymentPlanComposer');
            if (!(error instanceof FrozenTopologyDeploymentPlanError) || error.code !== 'MULTIPLE_DEFAULT_EGRESS') throw error;
            return { status: 'refused', code: 'INVALID_TOPOLOGY_DEPLOYMENT', causeCode: error.code,
                revision: snapshot.revision, resourceNodeIds: selected.resourceNodeIds };
        }
    }

    async queueIntent({ session, executionContext, intentId, mutation, expectedTopologyRevision, resourceNodeIds }) {
        if (!session?.inTransaction?.() || !matchesTopologyExecutionContext(executionContext, this.#executionContext)
            || !['link.apply', 'link.delete'].includes(mutation?.kind)) {
            throw new TopologyOperationCoordinatorError('TOPOLOGY_INTENT_ADMISSION_UNAVAILABLE', 'Selected mutation transaction required');
        }
        if (mutation.kind === 'link.delete') {
            const replay = await this.operationRepository.findSelectedDeleteByJobId(String(intentId), session);
            if (replay) {
                if (!matchesTopologyOperationExecutionContext(replay, this.#executionContext)
                    || replay.admissionScope !== 'selected' || replay.kind !== mutation.kind
                    || replay.linkId !== mutation.linkId || replay.desiredVersion !== mutation.desiredVersion
                    || JSON.stringify(replay.resourceNodeIds) !== JSON.stringify(resourceNodeIds)
                    || replay.admissionFingerprint !== selectedAdmissionFingerprint(replay)) {
                    throw new TopologyOperationCoordinatorError('TOPOLOGY_INTENT_BINDING_INVALID', 'Delete job identity changed');
                }
                return Object.freeze({ operationId: String(replay._id), topologyRevision: replay.topologyRevision,
                    status: replay.status, kind: replay.kind, linkId: replay.linkId, linkIds: replay.linkIds });
            }
            if (this.topologyRepository.selectedEnabled) {
                // Pure desired-row deletion needs the SAME verified applied
                // baseline and availability fences as admission. Pending status
                // alone is never proof; do not initialize/rewrite node profiles
                // when this link is absent from that authoritative baseline.
                const repository = this.topologyRepository;
                const snapshot = await repository.snapshotReader.readDraft(session);
                if (snapshot.revision !== expectedTopologyRevision) throw new TopologyOperationCoordinatorError(
                    'STALE_TOPOLOGY_REVISION', 'The topology changed before desired-only deletion');
                const selected = await repository.readSelected({ snapshot,
                    scope: { kind: 'link.delete', linkId: mutation.linkId }, executionContext: this.#executionContext,
                    session, desiredVersion: mutation.desiredVersion, deleteJobId: String(intentId) });
                const same = require('node:util').isDeepStrictEqual;
                if (!selected.installedPath && !selected.baselineTopology.links.some(link => link.id === mutation.linkId)
                    && same(selected.baselineTopology.links, selected.effectiveTopology.links)
                    && same(selected.baselineTopology.groups, selected.effectiveTopology.groups)) {
                    if (JSON.stringify(selected.resourceNodeIds) !== JSON.stringify(resourceNodeIds)) throw new TopologyOperationCoordinatorError(
                        'TOPOLOGY_INTENT_RESOURCE_SCOPE_CHANGED', 'Selected resources changed');
                    const count = await repository.assertSelectedAvailable(selected.resourceNodeIds, session);
                    const removed = await repository.snapshotReader.CascadeLink.deleteOne({ _id: mutation.linkId,
                        'lifecycle.state': 'deleting', 'lifecycle.deleteJobId': String(intentId),
                        'lifecycle.desiredVersion': mutation.desiredVersion }, { session });
                    if (removed.deletedCount !== 1) throw new TopologyOperationCoordinatorError(
                        'TOPOLOGY_INTENT_FENCE_LOST', 'Delete marker changed');
                    const state = await repository.CascadeTopologyState.findOneAndUpdate({ _id: 'singleton', revision: expectedTopologyRevision,
                        topologyAdmissionCount: count.topologyAdmissionCount, remoteAdmissionCount: count.remoteAdmissionCount,
                        replacementReservation: { $exists: false }, remoteDrain: { $exists: false } },
                    { $inc: { stateTransitionRevision: 1 } }, { session, new: true, runValidators: true }).lean();
                    if (!state) throw new TopologyOperationCoordinatorError('TOPOLOGY_INTENT_FENCE_LOST', 'Delete state changed');
                    return Object.freeze({ desiredOnly: true, status: 'succeeded', kind: 'link.delete', linkId: mutation.linkId,
                        deleteJobId: String(intentId), topologyRevision: expectedTopologyRevision });
                }
            }
        }
        return this.queueOnce({ expectedTopologyRevision, scope: { kind: mutation.kind, linkId: mutation.linkId, linkIds: [mutation.linkId],
            ...(mutation.nodeActivation ? { nodeActivation: normalizeNodeActivation(mutation.nodeActivation) } : {}) },
            ...(mutation.kind === 'link.delete' ? { deleteJobId: String(intentId) } : {}),
            desiredVersion: mutation.desiredVersion, resourceNodeIds, session,
            idempotencyKey: `topology:${this.#executionContext.target}:revision-${expectedTopologyRevision}:${mutation.kind}:${mutation.linkId}` });
    }

    deploy(input) {
        return this.queue(input);
    }

    async prepareL2tpIngress({ nodeId, routeGroupId }) {
        const snapshot = await this.topologyRepository.snapshotReader.readDraft();
        const group = snapshot.groups.find(row => entityId(row) === String(routeGroupId));
        const links = snapshot.links;
        const paths = group?.paths?.filter(path => path.enabled !== false && path.linkIds?.length
            && links.some(link => entityId(link) === String(path.linkIds[0]) && entityId(link.portalNode) === String(nodeId)));
        if (paths?.length !== 1) throw new TopologyOperationCoordinatorError('TOPOLOGY_L2TP_PATH_UNAVAILABLE', 'Exact relay path required');
        const linkId = String(paths[0].linkIds[0]);
        const selected = await this.topologyRepository.readSelected({ snapshot, scope: { kind: 'link.apply', linkId },
            executionContext: this.#executionContext });
        const scope = { kind: 'domain.reconcile', linkId, linkIds: selected.baselineTopology.links.map(row => row.id).sort() };
        // New desired operation, never replay a previous succeeded operation.
        const queued = await this.queueOnce({ expectedTopologyRevision: snapshot.revision, scope,
            idempotencyKey: `topology:${this.#executionContext.target}:revision-${snapshot.revision}:domain.reconcile:${linkId}` });
        for (let i = 0; i < 240; i++) {
            const current = await this.operationRepository.findPublicById(queued.operationId);
            if (current?.status === 'succeeded') return { operationId: queued.operationId, status: 'succeeded' };
            if (current && !ACTIVE_OPERATION_STATUSES.has(current.status)) {
                throw new TopologyOperationCoordinatorError('TOPOLOGY_L2TP_INGRESS_FAILED', 'Ingress preparation did not succeed', { operationId: queued.operationId });
            }
            await new Promise(resolve => setTimeout(resolve, 500));
        }
        throw new TopologyOperationCoordinatorError('TOPOLOGY_L2TP_INGRESS_PENDING', 'Ingress preparation remains pending', { operationId: queued.operationId });
    }

    async queueOnce({ expectedTopologyRevision, scope, idempotencyKey, session: joinedSession, desiredVersion, resourceNodeIds, deleteJobId }) {
        // Unique run suffix: node-side runner state is keyed by operation id,
        // so a re-queued revision must never reuse a previous operation id.
        const runIdempotencyKey = `${idempotencyKey}:host-${this.#executionContext.hostIdentity}:${randomUUID()}`;
        let operationId = entityId(this.idFactory(runIdempotencyKey));
        if (!operationId) {
            throw new TopologyOperationCoordinatorError(
                'TOPOLOGY_OPERATION_QUEUE_FAILED',
                'The topology operation could not be queued',
            );
        }
        let pinned;
        let scopedIdentity;
        let selectedIdentity = {};
        let admissionFingerprint;
        let admittedPriorDeployedRevision;
        let effectiveRunIdempotencyKey = runIdempotencyKey;
        try {
            pinned = await this.topologyRepository.admitTopology({
                expectedRevision: expectedTopologyRevision,
                ...(joinedSession ? { session: joinedSession } : {}),
                prepare: async (snapshot, session) => {
                    // Legacy full-sync finalization marks every active link
                    // deployed. Never let it silently claim an unrelated
                    // pending draft alongside already deployed links.
                    if (!scope) {
                        const active = snapshot.links.filter(link => link.active !== false);
                        const hasPending = active.some(link => link.status === 'pending');
                        const hasConfirmed = active.some(link => link.status === 'deployed'
                            || link.status === 'online' || link.status === 'staged'
                            || link.status == null);
                        if (hasPending && hasConfirmed) {
                            throw new TopologyOperationCoordinatorError(
                                'INVALID_TOPOLOGY_DEPLOYMENT',
                                'Mixed pending and deployed links require an explicit scoped operation',
                                { operationId, causeCode: 'UNCONFIRMED_LINK_IN_FULL_DEPLOY' },
                            );
                        }
                    }
                    const selected = scope?.kind === 'domain.reconcile' && this.topologyRepository.selectedEnabled
                        ? await this.topologyRepository.readIngressPreparation({ snapshot, scope,
                            executionContext: this.#executionContext, session, desiredVersion })
                        : ['link.apply', 'link.delete'].includes(scope?.kind) && this.topologyRepository.selectedEnabled
                            ? await this.topologyRepository.readSelected({ snapshot, scope,
                                executionContext: this.#executionContext, session, desiredVersion, deleteJobId }) : null;
                    if (scope?.kind === 'link.delete' && (!selected || !deleteJobId)) throw new TopologyOperationCoordinatorError('INVALID_REQUEST', 'Delete requires an admitted tombstone job');
                    // A retained cleanup owns these physical resources even if
                    // its old edge makes a successor candidate structurally
                    // impossible. Wait for that exact owner before composition.
                    if (selected) await this.topologyRepository.assertSelectedAvailable(selected.resourceNodeIds, session);
                    const projected = projectTopology(snapshot);
                    // Scoped reconcile: plan only the caller-declared
                    // component (deployed links + the requested link). This
                    // selects the scope of coordination only — it never marks
                    // a link physically applied by itself.
                    const replacement = scope?.kind === 'link.replace'
                        ? deriveReplacementTopology(snapshot, {
                            groupId: scope.groupId, pathKey: scope.pathKey,
                            oldLinkId: scope.oldLinkId, newLinkId: scope.linkId,
                        }) : null;
                    const scopedTopology = selected ? selected.effectiveTopology : scope && !replacement
                        ? applyScopeToTopology(projected, scope, operationId, snapshot.links) : null;
                    // Installed cutover remains in the explicit attach protocol; a
                    // selected apply must not impersonate an installed owner path.
                    const attach = !selected && scopedTopology
                        ? deriveScopedAttach(snapshot, scope, scopedTopology, operationId) : null;
                    if (attach) {
                        const attachIdentity = createHash('sha256').update(JSON.stringify({
                            groupId: attach.groupId, pathKey: attach.pathKey,
                            ownerNodeId: attach.ownerNodeId,
                            ownerTopologyRevision: attach.ownerTopologyRevision,
                            ownerCredentialRevision: attach.ownerCredentialRevision,
                            linkIds: scope.linkIds,
                            newPathLinkIds: attach.newPathLinkIds,
                        })).digest('hex');
                        effectiveRunIdempotencyKey = `topology:${this.#executionContext.target}:revision-${expectedTopologyRevision}:link.attach:${scope.linkId}:${attachIdentity}:host-${this.#executionContext.hostIdentity}:${runIdempotencyKey.slice(-36)}`;
                        operationId = entityId(this.idFactory(effectiveRunIdempotencyKey));
                        if (!operationId) {
                            throw new TopologyOperationCoordinatorError('TOPOLOGY_OPERATION_QUEUE_FAILED',
                                'The topology operation could not be queued');
                        }
                    }
                    const topology = replacement ? replacement.topology
                        : attach ? attach.topology : scopedTopology || projected;
                    if (scope?.kind === 'link.replace'
                        && (topology.links.length !== scope.linkIds.length
                            || topology.links.some(link => !scope.linkIds.includes(link.id)))) {
                        throw new TopologyOperationCoordinatorError(
                            'INVALID_TOPOLOGY_DEPLOYMENT', 'Replacement scope differs from its pinned graph',
                            { operationId, causeCode: 'SCOPE_DOMAIN_AMBIGUOUS' },
                        );
                    }
                    if (selected && resourceNodeIds && JSON.stringify(resourceNodeIds) !== JSON.stringify(selected.resourceNodeIds)) {
                        throw new TopologyOperationCoordinatorError('TOPOLOGY_INTENT_RESOURCE_SCOPE_CHANGED', 'Selected resources changed');
                    }
                    const validation = this.validator(topology);
                    if (validation?.valid !== true) {
                        throw new TopologyOperationCoordinatorError(
                            'INVALID_TOPOLOGY_DEPLOYMENT',
                            'The pinned topology is invalid',
                            { operationId, errors: sanitizeValidationErrors(validation?.errors) },
                        );
                    }
                    const compiled = this.compiler({ ...topology, healthByPathKey: {} });
                    if (compiled?.valid !== true) {
                        throw new TopologyOperationCoordinatorError(
                            'INVALID_TOPOLOGY_DEPLOYMENT',
                            'The pinned topology could not be compiled',
                            { operationId, errors: sanitizeValidationErrors(compiled?.errors) },
                        );
                    }
                    const frozenPlan = await this.planMaterializer.materialize({
                        ...this.#executionContext,
                        operationKind: attach ? 'link.attach' : scope?.kind,
                        ...(selected ? { baselineTopology: selected.baselineTopology, effectiveTopology: selected.effectiveTopology,
                            installedPath: selected.installedPath, selectedOwnerPins: selected.selectedOwnerPins } : {}),
                        session,
                        pinnedSnapshot: deepFreeze({
                            revision: snapshot.revision,
                            topology,
                            compiled,
                        }),
                    });
                    if (selected && (frozenPlan.nodes.length !== selected.resourceNodeIds.length
                        || selected.resourceNodeIds.some(id => !frozenPlan.nodes.some(node => String(node.node) === id)))) {
                        throw new TopologyOperationCoordinatorError('TOPOLOGY_SELECTED_CLEANUP_PLAN_REQUIRED', 'The materializer must cover the full before/after node union');
                    }
                    return { topology, frozenPlan,
                        ...(selected ? { ...selected, admissionScope: 'selected' } : {}),
                        ...(attach ? { attach: {
                            groupId: attach.groupId, pathKey: attach.pathKey,
                            ownerNodeId: attach.ownerNodeId,
                            ownerTopologyRevision: attach.ownerTopologyRevision,
                            ownerCredentialRevision: attach.ownerCredentialRevision,
                            newPathLinkIds: [...attach.newPathLinkIds],
                        } } : {}),
                        ...(replacement ? { oldPathLinkIds: replacement.oldPathLinkIds,
                            ownerNodeId: replacement.ownerNodeId } : {}) };
                },
                admit: async (admitted, session) => {
                    admittedPriorDeployedRevision = admitted.deployedRevision;
                    const plan = operationPlan({
                        operationId,
                        topologyRevision: admitted.revision,
                        priorDeployedRevision: admitted.deployedRevision,
                        ...(admitted.admissionScope === 'selected' ? { resourceNodeIds: admitted.resourceNodeIds } : {}),
                        // Binding checks include removed profiles, not just the
                        // effective linked nodes. This union is never compiled.
                        topology: admitted.admissionScope === 'selected' ? {
                            nodes: admitted.resourceNodeIds.map(id => admitted.effectiveTopology.nodes.find(node => node.id === id)
                                || admitted.baselineTopology.nodes.find(node => node.id === id)),
                            links: [...admitted.baselineTopology.links, ...admitted.effectiveTopology.links],
                        } : admitted.topology,
                        plan: admitted.frozenPlan,
                    });
                    selectedIdentity = admitted.admissionScope === 'selected' ? { admissionScope: 'selected',
                        ...(scope.nodeActivation ? { nodeActivation: scope.nodeActivation } : {}),
                        baselineTopology: admitted.baselineTopology, effectiveTopology: admitted.effectiveTopology,
                        resourceNodeIds: admitted.resourceNodeIds, desiredVersion: admitted.desiredVersion,
                        selectedOwnerPins: admitted.selectedOwnerPins, routeState: admitted.routeState,
                        ...(scope.kind === 'link.delete' ? { deleteJobId } : {}),
                        ...(admitted.installedPath ? { installedPath: admitted.installedPath } : {}) }
                        : admitted.frozenPlan.fullTopology !== undefined ? { fullTopology: admitted.frozenPlan.fullTopology } : {};
                    scopedIdentity = scope
                        ? { kind: admitted.attach ? 'link.attach' : scope.kind,
                            linkId: scope.linkId, linkIds: admitted.admissionScope === 'selected'
                                ? admitted.effectiveTopology.links.map(link => link.id).sort() : [...scope.linkIds],

                            ...(scope.kind === 'link.apply' && !admitted.attach
                                ? { staged: admitted.frozenPlan.staged === true } : {}),
                            ...(scope.kind === 'link.replace' ? {
                                oldLinkId: scope.oldLinkId,
                                groupId: scope.groupId,
                                pathKey: scope.pathKey,
                                ownerNodeId: admitted.ownerNodeId,
                                oldPathLinkIds: [...admitted.oldPathLinkIds],
                            } : {}),
                            ...(admitted.attach ? { ...admitted.attach } : {}) }
                        : {};
                    admissionFingerprint = createHash('sha256').update(JSON.stringify({
                        operationId,
                        topologyRevision: admitted.revision,
                        priorDeployedRevision: admitted.deployedRevision,
                        nodes: plan.nodes,
                        executionContext: this.#executionContext,
                        idempotencyKey: effectiveRunIdempotencyKey,
                        ...scopedIdentity, ...selectedIdentity,
                    })).digest('hex');
                    if (selectedIdentity.admissionScope === 'selected' || selectedIdentity.fullTopology !== undefined) admissionFingerprint = selectedAdmissionFingerprint({
                        operationId, executionContext: this.#executionContext, idempotencyKey: effectiveRunIdempotencyKey,
                        topologyRevision: admitted.revision, priorDeployedRevision: admitted.deployedRevision, nodes: plan.nodes,
                        ...scopedIdentity, ...selectedIdentity,
                    });
                    await this.operationRepository.createFrozen({
                        executionContext: this.#executionContext,
                        operationId,
                        idempotencyKey: effectiveRunIdempotencyKey,
                        topologyRevision: admitted.revision,
                        priorDeployedRevision: admitted.deployedRevision,
                        nodes: plan.nodes,
                        ...scopedIdentity, ...selectedIdentity,
                        heldTopologyAdmission: true,
                        admissionFingerprint,
                        session,
                    });
                },
            });
        } catch (error) {
            if (admissionFingerprint
                && error?.hasErrorLabel?.('UnknownTransactionCommitResult') === true
                && typeof this.operationRepository.findAdmissionById === 'function') {
                try {
                    const found = await this.operationRepository.findAdmissionById(operationId);
                    if (found && String(found._id) === operationId
                        && matchesTopologyOperationExecutionContext(found, this.#executionContext)
                        && found.idempotencyKey === effectiveRunIdempotencyKey
                        && found.topologyRevision === expectedTopologyRevision
                        && found.heldTopologyAdmission === true
                        && found.admissionFingerprint === admissionFingerprint
                        && found.priorDeployedRevision === admittedPriorDeployedRevision
                        && OPERATION_STATUSES.has(found.status)) {
                        // A confirmed commit is left to the gated recovery scan;
                        // never start a worker on an ambiguous response path.
                        return Object.freeze({ operationId,
                            topologyRevision: found.topologyRevision,
                            status: found.status, ...scopedIdentity });
                    }
                } catch {
                    // An unavailable readback cannot establish a safe commit.
                }
            }
            throw safeQueueError(error, operationId, expectedTopologyRevision);
        }
        if (this.operationWorker && !joinedSession) {
            Promise.resolve(this.operationWorker.run(operationId)).catch(() => {
                this.onWorkerError({ operationId });
            });
        }
        return Object.freeze({
            operationId,
            topologyRevision: pinned.revision,
            status: 'queued',
            ...scopedIdentity,
        });
    }
}

module.exports = {
    ACTIVE_OPERATION_STATUSES,
    OPERATION_STATUSES,
    TopologyOperationCoordinator,
    TopologyOperationCoordinatorError,
    assertQueueInput,
    deepFreeze,
    idFromIdempotencyKey,
    nodeIdsByRef,
    selectEffectiveTopology,
    projectTopologyOperationStatus,
};
