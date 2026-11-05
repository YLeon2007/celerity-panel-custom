'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const { validTerminalReceipt, UUID } = require('../models/topologyExecutionBindingContract');
const { durableSelectedTopology, selectedAdmissionFingerprint } = require('./topologyOperationRepository');
const { matchesTopologyExecutionContext, topologyExecutionContext } = require('../domain/topologyExecutionContext');
const { linkDesiredVersion } = require('../services/topologyIntentService');
const { verifyImportedProfileTargetPin, resolveTopologyProfileTarget, assertSelectedProfileTargets } = require('../services/topologyProfileTarget');
const TOPOLOGY_STATE_SELECT = 'revision deployedRevision';
const SELECTED_FIELDS = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +deleteJobId +installedPath';
const plain = value => JSON.parse(JSON.stringify(value));
const ownerPin = row => plain(Object.fromEntries(['node', 'profile', 'executionContext', 'owner', 'generation',
    'nodeIdentity', 'originalSnapshot', 'adoptionReceipt', 'handbackReceipt', 'lastSettledOperation',
    'lastSettledGeneration', 'lastSettledRevision', 'lastSettledCloseId', 'profileTargetPin'].filter(key => row[key] !== undefined).map(key => [key, row[key]])));
const OWNER_TARGET_SELECT = '+legacyAppliedTopology +profileTargetPin';
const hasTargetPin = row => row && Object.hasOwn(row, 'profileTargetPin');
function selectedError(code = 'APPLIED_BASELINE_REQUIRED') {
    return new TopologyDeploymentRepositoryError(code, 'The selected applied baseline could not be verified');
}
// An exact adopted readback of {} (optionally newline terminated) proves no
// managed cascade graph, unlike an absent pointer or a desired status. This is
// deliberately narrower than importing an arbitrary classic configuration.
const EMPTY_CONFIG_HASHES = new Set(['{}', '{}\n'].map(bytes => createHash('sha256').update(bytes).digest('hex')));

class TopologyDeploymentRepositoryError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'TopologyDeploymentRepositoryError';
        this.code = code;
        Object.assign(this, details);
    }
}

function staleRevision(expectedRevision, actualRevision) {
    return new TopologyDeploymentRepositoryError(
        'STALE_TOPOLOGY_REVISION',
        'The topology revision changed before deployment could be fenced',
        {
            expectedTopologyRevision: expectedRevision,
            topologyRevision: actualRevision,
        },
    );
}

function defaultTransactionRunner(CascadeTopologyState) {
    const connection = CascadeTopologyState?.db;
    if (!connection || typeof connection.transaction !== 'function') return null;
    return work => connection.transaction(work);
}

function withSession(query, session) {
    return session === undefined ? query : query.session(session);
}

function componentAt(snapshot, nodeId) {
    const nodes = new Set(snapshot.nodes.some(node => node.id === nodeId) ? [nodeId] : []);
    const links = new Set(), groups = new Set();
    let expanded;
    do {
        expanded = false;
        for (const link of snapshot.links) {
            if (!nodes.has(link.source) && !nodes.has(link.target) && !links.has(link.id)) continue;
            if (!links.has(link.id)) expanded = true;
            links.add(link.id); nodes.add(link.source); nodes.add(link.target);
        }
        for (const group of snapshot.groups) {
            const members = group.paths.flatMap(path => path.linkIds);
            if (!members.some(id => links.has(id))) continue;
            groups.add(group._id);
            for (const id of members) { if (!links.has(id)) expanded = true; links.add(id); }
        }
    } while (expanded);
    return { nodes: snapshot.nodes.filter(node => nodes.has(node.id)), links: snapshot.links.filter(link => links.has(link.id)),
        groups: snapshot.groups.filter(group => groups.has(group._id)) };
}

class TopologyDeploymentRepository {
    constructor({ snapshotReader, CascadeTopologyState, TopologyOperation, TopologyConfigOwner, NodeOperationLock, RemoteAdmission, transactionRunner } = {}) {
        if (!snapshotReader || typeof snapshotReader.readDraft !== 'function') {
            throw new TypeError('Topology deployment repository requires snapshotReader.readDraft');
        }
        if (!CascadeTopologyState
            || typeof CascadeTopologyState.findOneAndUpdate !== 'function') {
            throw new TypeError('Topology deployment repository requires CascadeTopologyState');
        }
        const runTransaction = transactionRunner
            ?? defaultTransactionRunner(CascadeTopologyState);
        if (typeof runTransaction !== 'function') {
            throw new TypeError('Topology deployment repository requires a transaction runner');
        }
        this.snapshotReader = snapshotReader;
        this.CascadeTopologyState = CascadeTopologyState;
        this.transactionRunner = runTransaction;
        this.TopologyOperation = TopologyOperation;
        this.TopologyConfigOwner = TopologyConfigOwner;
        this.NodeOperationLock = NodeOperationLock;
        this.RemoteAdmission = RemoteAdmission;
        this.db = CascadeTopologyState.db;
        this.selectedEnabled = Boolean(TopologyConfigOwner && NodeOperationLock);
        this.usesDefaultRunner = transactionRunner === undefined;
    }

    async readSelected({ snapshot, scope, executionContext, session, desiredVersion, deleteJobId }) {
        executionContext = topologyExecutionContext(executionContext?.target, executionContext?.hostIdentity);
        if (!executionContext || !this.selectedEnabled || !['link.apply', 'link.delete'].includes(scope?.kind)) throw selectedError();
        const { NODE_METADATA_SELECT, LINK_METADATA_SELECT } = require('../services/topologyOperationPlanMaterializer');
        const nodeRows = await withSession(this.snapshotReader.HyNode.find({ type: 'xray', active: true, cascadeRole: { $in: ['portal', 'relay', 'bridge'] } })
            .select(NODE_METADATA_SELECT), session).lean();
        const linkRows = await withSession(this.snapshotReader.CascadeLink.find({ _id: scope.linkId,
            ...(scope.kind === 'link.apply' ? { active: true } : {}) })
            .select(`${LINK_METADATA_SELECT} tunnelUuid active name priority lifecycle`), session).lean();
        const target = linkRows.find(row => String(row._id) === scope.linkId);
        if (!target) throw selectedError('CASCADE_LINK_NOT_FOUND');
        const version = linkDesiredVersion(target);
        if (desiredVersion !== undefined && desiredVersion !== version) throw selectedError('TOPOLOGY_INTENT_DESIRED_VERSION_CONFLICT');
        if (scope.kind === 'link.apply' && target.lifecycle?.state === 'deleting') throw selectedError('CASCADE_LINK_DELETING');
        if (deleteJobId !== undefined && (scope.kind !== 'link.delete' || target.lifecycle?.state !== 'deleting'
            || String(target.lifecycle.deleteJobId) !== deleteJobId || target.lifecycle.desiredVersion !== version)) throw selectedError('TOPOLOGY_DELETE_TOMBSTONE_CHANGED');
        const desiredTopology = durableSelectedTopology({
            nodes: nodeRows.map(row => {
                const { _id, cascadeRole, ...fields } = plain(row);
                delete fields.__v; delete fields.createdAt; delete fields.updatedAt;
                return { ...fields, id: String(_id), role: cascadeRole };
            }),
            links: linkRows.map(row => {
                const { _id, portalNode, bridgeNode, status, lifecycle, ...fields } = plain(row);
                delete fields.__v; delete fields.createdAt; delete fields.updatedAt;
                return { ...fields, id: String(_id), source: String(portalNode), target: String(bridgeNode) };
            }),
            groups: [], // Only settled policies may be preserved by a link apply.
        });
        const catalog = await withSession(this.TopologyConfigOwner.find({}).select(OWNER_TARGET_SELECT), session).lean();
        const resources = new Set([String(target.portalNode), String(target.bridgeNode)]);
        for (const row of catalog) {
            if (row.lastSettledOperation !== undefined || !Array.isArray(row.legacyAppliedTopology?.links)) continue;
            const old = row.legacyAppliedTopology.links.find(link => link.id === scope.linkId);
            if (old) { resources.add(old.source); resources.add(old.target); }
        }
        // Endpoint edits must also clean the OLD applied profiles. Discover the
        // old selected link through adoption evidence or settlement pointers;
        // the loop below verifies every discovered owner/component in full.
        const pointers = [...new Set(catalog.map(row => row.lastSettledOperation).filter(Boolean))];
        if (pointers.length) {
            const prior = await withSession(this.TopologyOperation.find({ _id: { $in: pointers },
                'effectiveTopology.links.id': scope.linkId }).select(SELECTED_FIELDS), session).lean();
            for (const source of prior) {
                const old = source.effectiveTopology.links.find(link => link.id === scope.linkId);
                resources.add(old.source); resources.add(old.target);
            }
        }
        const baseline = { nodes: [], links: [], groups: [] };
        const visited = new Set();
        const owners = new Map();
        const settledProfiles = new Map();
        const initialImportedGroups = new Map();
        const add = topology => {
            for (const kind of ['nodes', 'links', 'groups']) for (const value of topology[kind]) {
                const key = kind === 'groups' ? '_id' : 'id';
                const existing = baseline[kind].find(row => row[key] === value[key]);
                if (existing && !same(existing, value)) throw selectedError();
                if (!existing) baseline[kind].push(value);
            }
            topology.nodes.forEach(node => resources.add(node.id));
        };
        while ([...resources].some(node => !visited.has(node))) {
            const node = [...resources].find(id => !visited.has(id));
            visited.add(node);
            const metadata = desiredTopology.nodes.find(row => row.id === node);
            if (!metadata) throw selectedError('TOPOLOGY_SELECTED_NODE_CHANGED');
            // A non-default profile is selected only from an independently
            // verified imported owner root, never from desired/role/tags. An
            // independent generic SIDECAR is not a competing applied source.
            const nodeOwners = catalog.filter(row => String(row.node) === node);
            const importedOwners = nodeOwners.filter(hasTargetPin);
            const sources = nodeOwners.filter(row => row.legacyAppliedTopology !== undefined
                || row.lastSettledOperation !== undefined || hasTargetPin(row));
            if (sources.length > 1) throw selectedError('TOPOLOGY_PROFILE_TARGET_AMBIGUOUS');
            let profile = metadata.role === 'portal' ? 'xray-main' : 'xray-bridge';
            if (importedOwners.length > 1) throw selectedError('TOPOLOGY_PROFILE_TARGET_AMBIGUOUS');
            // A raw forward descriptor without its saved pin is not an older
            // compatible native source and must not fall back to SIDECAR.
            if (nodeOwners.some(row => !hasTargetPin(row)
                && row.legacyAppliedTopology?.links?.some(link => link.mode === 'forward'))) {
                throw selectedError('TOPOLOGY_LEGACY_IMPORT_MISMATCH');
            }
            if (importedOwners.length) {
                const imported = importedOwners[0];
                try {
                    const pin = verifyImportedProfileTargetPin({ owner: imported,
                        profileTargetPin: imported.profileTargetPin, executionContext });
                    profile = resolveTopologyProfileTarget({ nodeId: node, role: metadata.role,
                        targetProfile: pin.targetProfile, profileTargetPin: pin }).targetProfile;
                } catch { throw selectedError('TOPOLOGY_LEGACY_IMPORT_MISMATCH'); }
                // Keep both original endpoints selected even after a settled
                // delete has no remaining links/tags. Never rewrite this root.
                imported.legacyAppliedTopology.nodes.forEach(peer => resources.add(peer.id));
            }
            const matches = catalog.filter(row => String(row.node) === node && row.profile === profile);
            const owner = matches[0];
            if (matches.length !== 1 || owner.owner !== 'topology'
                || !matchesTopologyExecutionContext(owner.executionContext, executionContext)
                || !/^[a-f0-9]{32}$/.test(owner.nodeIdentity?.machineId)
                || !/^[a-f0-9]{64}$/.test(owner.nodeIdentity?.sshHostKeySha256)
                || !UUID.test(owner.generation) || !owner.originalSnapshot || owner.adoptionReceipt?.toGeneration !== owner.generation
                || !UUID.test(owner.adoptionReceipt?.proofId) || !UUID.test(owner.adoptionReceipt?.maintenanceId)
                || !Number.isFinite(new Date(owner.adoptionReceipt?.verifiedAt).getTime())
                || owner.handbackReceipt !== undefined) throw selectedError('TOPOLOGY_CONFIG_OWNER_REQUIRED');
            // A physical alias cannot receive a separate admission slot. Until
            // multi-ID profile composition is supported, refuse that alias rather
            // than locking just one mutable node name and racing another writer.
            if (catalog.some(other => String(other.node) !== node
                && (other.nodeIdentity?.machineId === owner.nodeIdentity.machineId
                    || other.nodeIdentity?.sshHostKeySha256 === owner.nodeIdentity.sshHostKeySha256))) {
                throw selectedError('TOPOLOGY_PHYSICAL_NODE_ALIAS');
            }
            owners.set(node, owner);
            if (owner.lastSettledOperation === undefined) {
                if (owner.lastSettledGeneration !== undefined || owner.lastSettledRevision !== undefined
                    || owner.lastSettledCloseId !== undefined) throw selectedError();
                if (owner.legacyAppliedTopology !== undefined) {
                    try {
                        const imported = require('../../../services/topologyConfigTransfer').verifyLegacyAppliedProfile(
                            owner.legacyAppliedTopology, { node, profile, originalSnapshot: owner.originalSnapshot });
                        if (!same(imported, owner.legacyAppliedTopology)) throw selectedError();
                        add(imported);
                        for (const group of imported.groups) {
                            // The verified bounded G2 import carries the R -> B
                            // suffix, not the portal path or mutable desired policy.
                            const path = group.paths[0];
                            const suffix = imported.links.find(link => link.id === path.linkIds[0]);
                            initialImportedGroups.set(group._id, { group, pathKey: path.pathKey, ownerNodeId: suffix.source });
                        }
                    } catch { throw selectedError('TOPOLOGY_LEGACY_IMPORT_MISMATCH'); }
                } else if (!EMPTY_CONFIG_HASHES.has(owner.originalSnapshot.configSha256)) throw selectedError();
                // A real adoption readback proves the imported profile (or {})
                // without manufacturing a terminal operation or tunnel proof.
                continue;
            }
            const operation = await withSession(this.TopologyOperation.findById(owner.lastSettledOperation)
                .select(SELECTED_FIELDS), session).lean();
            if (!operation || operation.status !== 'succeeded' || operation.heldTopologyAdmission !== false
                || operation.admissionScope !== 'selected'
                || !matchesTopologyExecutionContext(operation.executionContext, executionContext)
                || owner.lastSettledRevision !== operation.topologyRevision
                || operation.admissionFingerprint !== selectedAdmissionFingerprint(operation)
                || !operation.selectedOwnerPins?.some(pin => pin.node === node && pin.profile === profile
                    && pin.generation === owner.generation && same(pin.nodeIdentity, plain(owner.nodeIdentity))
                    && same(pin.originalSnapshot, plain(owner.originalSnapshot))
                    && same(pin.adoptionReceipt, plain(owner.adoptionReceipt))
                    && same(pin.profileTargetPin, owner.profileTargetPin))) throw selectedError();
            try { assertSelectedProfileTargets(operation); } catch { throw selectedError('TOPOLOGY_SELECTED_PIN_CHANGED'); }
            const entries = operation.nodes?.filter(item => String(item.node) === node && item.targetProfile === profile);
            const entry = entries?.[0];
            if (entries?.length !== 1 || entry.state !== 'committed' || entry.role !== metadata.role
                || !same(entry.profileTargetPin, owner.profileTargetPin)
                || !UUID.test(owner.lastSettledGeneration)) throw selectedError();
            let currentProfile;
            try {
                currentProfile = require('../services/topologyXrayCandidate')
                    .projectCanonicalXrayCandidate(entry.candidate, entry.candidateHash).content;
            } catch { throw selectedError(); }
            if (operation.v2Terminal) {
                const bindings = operation.v2Terminal.bindings?.filter(item => item.nodeId === node);
                const binding = bindings?.[0];
                const proofs = operation.v2Terminal.proofs?.filter(item => item.commandId === owner.lastSettledCloseId);
                const proof = proofs?.[0];
                if (operation.v2Terminal.state !== 'proven' || bindings?.length !== 1 || proofs?.length !== 1
                    || binding.operationId !== String(operation._id) || binding.targetProfile !== profile
                    || binding.candidateHash !== `sha256:${entry.candidateHash}` || binding.backupId !== entry.backupId
                    || binding.executionContext !== executionContext.hostIdentity || binding.owner !== operation.leaseOwner
                    || binding.attempt !== operation.attempts || binding.topologyRevision !== operation.topologyRevision
                    || binding.priorDeployedRevision !== operation.priorDeployedRevision
                    || binding.generation !== owner.lastSettledGeneration
                    || binding.commandIds?.close !== owner.lastSettledCloseId
                    || !same(binding.profileTargetPin, owner.profileTargetPin)
                    || !validTerminalReceipt(proof, binding) || proof.terminalOutcome !== 'verified') throw selectedError();
            } else if (hasTargetPin(owner) || executionContext.target !== 'test') throw selectedError();
            const settled = durableSelectedTopology(operation.effectiveTopology);
            const component = componentAt(settled, node);
            // A cleaned detached endpoint is absent from effectiveTopology but
            // its verified candidate remains the current physical profile. Keep
            // its pinned prior metadata, not a new desired-profile guess.
            if (!component.nodes.length) {
                const prior = durableSelectedTopology(operation.baselineTopology).nodes.find(item => item.id === node);
                if (!prior) throw selectedError();
                component.nodes.push(prior);
            }
            add(component);
            settledProfiles.set(node, currentProfile);
        }
        for (const kind of ['nodes', 'links', 'groups']) baseline[kind].sort((a, b) =>
            String(a.id ?? a._id).localeCompare(String(b.id ?? b._id), 'en'));
        // Every node in a published component must still point to the same
        // snapshot. A stale partial pointer is not a source of old descriptors.
        for (const node of baseline.nodes) {
            const owner = owners.get(node.id);
            if (hasTargetPin(owner) && owner.legacyAppliedTopology.nodes.some(member => {
                const peer = owners.get(member.id);
                return !hasTargetPin(peer) || !same(peer.legacyAppliedTopology, owner.legacyAppliedTopology)
                    || peer.profileTargetPin.descriptorSha256 !== owner.profileTargetPin.descriptorSha256
                    || peer.lastSettledOperation !== owner.lastSettledOperation;
            })) throw selectedError('TOPOLOGY_LEGACY_IMPORT_INCOMPLETE');
            if (owner.lastSettledOperation === undefined) {
                const imported = owner.legacyAppliedTopology;
                if (!imported || imported.nodes.some(member => {
                    const peer = owners.get(member.id);
                    return !peer || peer.lastSettledOperation !== undefined || !same(peer.legacyAppliedTopology, imported);
                })) throw selectedError('TOPOLOGY_LEGACY_IMPORT_INCOMPLETE');
                continue;
            }
            const source = await withSession(this.TopologyOperation.findById(owner.lastSettledOperation).select(SELECTED_FIELDS), session).lean();
            const component = componentAt(durableSelectedTopology(source.effectiveTopology), node.id);
            if (component.nodes.some(member => owners.get(member.id)?.lastSettledOperation !== owner.lastSettledOperation)) throw selectedError();
        }
        // Apply current bytes only after each component member's independent
        // owner/settlement/terminal checks above. Imported originals remain
        // immutable historical handback evidence, never current readback.
        for (const node of baseline.nodes) if (settledProfiles.has(node.id)) node.profileConfig = settledProfiles.get(node.id);
        let selected = require('../services/topologyOperationCoordinator').selectEffectiveTopology({
            verifiedBaselineTopology: baseline, desiredTopology, scope,
        });
        const installed = (snapshot?.installedRouteOwners || []).filter(owner => selected.resourceNodeIds.includes(String(owner.nodeId))
            || initialImportedGroups.has(String(owner.groupId)));
        let importedGroup;
        if (initialImportedGroups.size) {
            // Only initial imported provenance needs this join. After genuine
            // settlement the checked committed candidate above is authoritative;
            // historical import policy must not veto empty-path/recreate work.
            if (initialImportedGroups.size !== 1) throw selectedError('TOPOLOGY_INSTALLED_ROUTE_OWNER_AMBIGUOUS');
            const imported = [...initialImportedGroups.values()][0];
            const states = await withSession(this.snapshotReader.RelayL2tpState.find({ routeGroup: imported.group._id })
                .select('node routeGroup status desiredState activePathKey appliedTopologyRevision secretRevision'), session).lean();
            const { ACTIVE_RELAY_STATUSES } = require('./topologyDraftRepository');
            const references = states.filter(row => row.desiredState === 'installed' || ACTIVE_RELAY_STATUSES.includes(row.status));
            if (references.length > 1 || installed.length > 1) throw selectedError('TOPOLOGY_INSTALLED_ROUTE_OWNER_AMBIGUOUS');
            const state = references[0], owner = installed[0];
            if (references.length !== 1 || installed.length !== 1
                || state.status !== 'installed' || state.desiredState !== 'installed'
                || String(state.node) !== imported.ownerNodeId || String(state.routeGroup) !== imported.group._id
                || state.activePathKey !== imported.pathKey
                || !Number.isSafeInteger(state.appliedTopologyRevision) || state.appliedTopologyRevision < 0
                || !Number.isSafeInteger(state.secretRevision) || state.secretRevision < 1
                || String(owner.nodeId) !== imported.ownerNodeId || String(owner.groupId) !== imported.group._id
                || owner.pathKey !== imported.pathKey || owner.ownerTopologyRevision !== state.appliedTopologyRevision
                || owner.ownerCredentialRevision !== state.secretRevision) throw selectedError('TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED');
            const groups = require('../domain/topologyDraft').projectGroups(snapshot.groups)
                .filter(group => group._id === imported.group._id);
            if (groups.length !== 1 || !same(groups[0], imported.group)) throw selectedError('TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED');
            importedGroup = imported.group;
        }
        if (installed.length) {
            if (installed.length !== 1) throw selectedError('TOPOLOGY_INSTALLED_ROUTE_OWNER_AMBIGUOUS');
            const owner = installed[0];
            if (!owner.pathKey || !Number.isSafeInteger(owner.ownerTopologyRevision)
                || !Number.isSafeInteger(owner.ownerCredentialRevision) || owner.ownerCredentialRevision < 1) throw selectedError('TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED');
            const group = importedGroup || require('../domain/topologyDraft').projectGroups(snapshot.groups)
                .find(row => row._id === String(owner.groupId));
            if (!group || new Set(group.paths.map(path => path.pathKey)).size !== group.paths.length) throw selectedError('TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED');
            const oldPath = group.paths.find(path => path.pathKey === owner.pathKey);
            if (oldPath?.enabled === false) throw selectedError('TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED');
            const oldPathLinkIds = oldPath?.linkIds || [];
            const effective = plain(selected.effectiveTopology), before = plain(selected.baselineTopology);
            const ownerNode = effective.nodes.find(node => node.id === String(owner.nodeId))
                || before.nodes.find(node => node.id === String(owner.nodeId));
            if (!ownerNode || ownerNode.role !== 'relay') throw selectedError('TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED');
            if (!effective.nodes.some(node => node.id === ownerNode.id)) effective.nodes.push(ownerNode);
            // All nonempty members must come from the verified applied graph,
            // never mutable desired. Empty owned/peer paths carry no edge authority.
            if (group.paths.some(path => path.linkIds.some(id => !baseline.links.some(link => link.id === id)))) throw selectedError();
            let cursor = String(owner.nodeId);
            const visited = new Set(), path = [];
            while (!visited.has(cursor)) {
                visited.add(cursor);
                const outgoing = effective.links.filter(link => link.source === cursor && link.geoRouting?.enabled !== true && link.geo !== true);
                if (outgoing.length !== 1) break;
                path.push(outgoing[0].id); cursor = outgoing[0].target;
            }
            const complete = (effective.nodes.find(node => node.id === cursor) || baseline.nodes.find(node => node.id === cursor))?.role === 'bridge';
            const newPathLinkIds = complete ? path : [];
            // An explicit APPLY can extend a valid incomplete prefix too. Keep
            // its installed path empty/blocked until a real bridge suffix exists;
            // frozen candidate + MAIN/PPP proofs still precede publication.
            const proposed = plain(group);
            const owned = proposed.paths.find(path => path.pathKey === owner.pathKey);
            if (owned) owned.linkIds = newPathLinkIds;
            else proposed.paths.push({ pathKey: owner.pathKey, linkIds: newPathLinkIds, priority: 1, enabled: true });
            before.groups = [...before.groups.filter(row => row._id !== group._id), group];
            effective.groups = [...effective.groups.filter(row => row._id !== group._id), proposed];
            selected = { ...selected, baselineTopology: before, effectiveTopology: effective,
                installedPath: { groupId: group._id, pathKey: owner.pathKey, ownerNodeId: String(owner.nodeId),
                    ownerTopologyRevision: owner.ownerTopologyRevision, ownerCredentialRevision: owner.ownerCredentialRevision,
                    oldPathLinkIds, newPathLinkIds, groupBefore: group,
                    kind: scope.kind === 'link.apply' && oldPathLinkIds.length === 0 ? 'link.attach' : scope.kind },
                routeState: complete ? selected.routeState : 'no_bridge_exit' };
        }
        const selectedOwnerPins = [...owners.values()].filter(owner => selected.resourceNodeIds.includes(String(owner.node)))
            .sort((a, b) => String(a.node).localeCompare(String(b.node), 'en')).map(ownerPin);
        try {
            assertSelectedProfileTargets({ ...selected, executionContext, admissionScope: 'selected', kind: scope.kind,
                linkId: scope.linkId, linkIds: selected.effectiveTopology.links.map(link => link.id), selectedOwnerPins,
                nodes: selectedOwnerPins.filter(hasTargetPin).map(owner => ({ node: owner.node, role: owner.profileTargetPin.role,
                    targetProfile: owner.profile, profileTargetPin: owner.profileTargetPin })) });
        } catch { throw selectedError('TOPOLOGY_SELECTED_PIN_CHANGED'); }
        return { ...selected, desiredVersion: version, selectedOwnerPins };
    }

    async isSelectedCurrent(operation) {
        if (!Array.isArray(operation.selectedOwnerPins) || !operation.selectedOwnerPins.length) return false;
        if (operation.selectedOwnerPins.some(hasTargetPin) || operation.nodes?.some(hasTargetPin)) {
            return Boolean(await require('../services/topologySelectedProofState').readSettledSelectedOperation(this, operation));
        }
        for (const pin of operation.selectedOwnerPins) {
            const owner = await this.TopologyConfigOwner.findOne({ node: pin.node, profile: pin.profile }).select(OWNER_TARGET_SELECT).lean();
            if (!owner || hasTargetPin(owner) || owner.lastSettledOperation !== String(operation._id) || owner.owner !== 'topology'
                || owner.generation !== pin.generation || !same(plain(owner.nodeIdentity), pin.nodeIdentity)) return false;
        }
        const link = await this.snapshotReader.CascadeLink.findById(operation.linkId).lean();
        return Boolean(link && linkDesiredVersion(link) === operation.desiredVersion);
    }

    async verifySelected(operation, session) {
        if (operation.admissionFingerprint !== selectedAdmissionFingerprint(operation)) throw selectedError('TOPOLOGY_SELECTED_FINGERPRINT_CHANGED');
        const fresh = await this.readSelected({ snapshot: await this.snapshotReader.readDraft(session),
            scope: { kind: operation.kind === 'link.delete' ? 'link.delete' : 'link.apply', linkId: operation.linkId }, executionContext: operation.executionContext,
            desiredVersion: operation.desiredVersion, deleteJobId: operation.deleteJobId, session });
        for (const key of ['baselineTopology', 'effectiveTopology', 'resourceNodeIds', 'selectedOwnerPins', 'desiredVersion', 'installedPath']) {
            if (!same(fresh[key], operation[key])) throw selectedError('TOPOLOGY_SELECTED_PIN_CHANGED');
        }
        return fresh;
    }

    async assertSelectedAvailable(resourceNodeIds, session, exceptOperationId, { desiredOnly = false } = {}) {
        const state = await withSession(this.CascadeTopologyState.findById('singleton'), session).lean();
        const held = await withSession(this.TopologyOperation.find({ heldTopologyAdmission: true }).select(SELECTED_FIELDS), session).lean();
        if (!Number.isSafeInteger(state?.topologyAdmissionCount) || state.topologyAdmissionCount !== held.length
            || !Number.isSafeInteger(state.remoteAdmissionCount) || state.remoteAdmissionCount < 0
            || state.remoteDrain || state.replacementReservation
            || held.some(row => row.admissionScope !== 'selected' || !Array.isArray(row.resourceNodeIds) || !row.resourceNodeIds.length)) throw selectedError('TOPOLOGY_ADMISSION_UNAVAILABLE');
        if (!desiredOnly && held.some(row => String(row._id) !== exceptOperationId
            && row.resourceNodeIds?.some(node => resourceNodeIds.includes(node)))) throw selectedError('TOPOLOGY_ADMISSION_UNAVAILABLE');
        if (state.remoteAdmissionCount > 0) {
            if (!this.RemoteAdmission || this.RemoteAdmission.db !== this.db) throw selectedError('TOPOLOGY_ADMISSION_UNAVAILABLE');
            const remote = await withSession(this.RemoteAdmission.find({ phase: { $in: ['running', 'queued', 'recovery_required'] } }), session).lean();
            if (remote.length !== state.remoteAdmissionCount || remote.some(row => typeof row.nodeId !== 'string' || !row.nodeId || resourceNodeIds.includes(row.nodeId))) throw selectedError('TOPOLOGY_ADMISSION_UNAVAILABLE');
        }
        if (this.NodeOperationLock && await withSession(this.NodeOperationLock.exists({ node: { $in: resourceNodeIds },
            ...(desiredOnly ? { operationId: { $nin: held.map(row => String(row._id)) } }
                : exceptOperationId ? { operationId: { $ne: exceptOperationId } } : {}) }), session)) throw selectedError('NODE_OPERATION_LOCK_CONFLICT');
        return { topologyAdmissionCount: state.topologyAdmissionCount, remoteAdmissionCount: state.remoteAdmissionCount };
    }

    // Admission is separate from the legacy pin API: a caller cannot accidentally
    // acknowledge a pin without committing its frozen operation in the same tx.
    async admitTopology({ expectedRevision, prepare, admit, session: joinedSession }) {
        if (typeof prepare !== 'function' || typeof admit !== 'function') {
            throw new TypeError('Topology admission requires prepare and admit callbacks');
        }
        const connection = this.CascadeTopologyState.db;
        const participatingModels = [this.TopologyOperation,
            ...(this.selectedEnabled ? [this.TopologyConfigOwner, this.NodeOperationLock] : []),
            this.snapshotReader.HyNode, this.snapshotReader.CascadeLink,
            this.snapshotReader.CascadeRouteGroup, this.snapshotReader.RelayL2tpState];
        if (this.usesDefaultRunner && (!connection
            || participatingModels.some(model => model?.db !== connection))) {
            throw new TypeError('Topology admission requires models on one transactional connection');
        }
        if (connection && participatingModels.some(model => model?.db !== connection)) {
            throw new TypeError('Topology admission requires models on one transactional connection');
        }
        const run = joinedSession ? work => work(joinedSession) : this.transactionRunner;
        return run(async session => {
            if (!session || typeof session.inTransaction !== 'function'
                || session.inTransaction() !== true
                || (typeof connection?.getClient === 'function' && session.client !== connection.getClient())) {
                throw new TypeError('Topology admission requires an active Mongo transaction');
            }
            const snapshot = await this.snapshotReader.readDraft(session);
            if (snapshot.revision !== expectedRevision) {
                throw staleRevision(expectedRevision, snapshot.revision);
            }
            if (snapshot.replacementReservation) {
                throw new TopologyDeploymentRepositoryError(
                    'TOPOLOGY_REPLACEMENT_RESERVED',
                    'A topology replacement owns the deployment fence',
                );
            }
            const prepared = await prepare(snapshot, session);
            const selectedCount = prepared.admissionScope === 'selected'
                ? await this.assertSelectedAvailable(prepared.resourceNodeIds, session) : { topologyAdmissionCount: 0, remoteAdmissionCount: 0 };
            // Never upsert or infer that either missing legacy counter is zero.
            // This shared singleton write conflicts with remote admission, drain
            // and replacement acquisition; only explicitly quiescent state admits.
            const state = await withSession(this.CascadeTopologyState.findOneAndUpdate(
                {
                    _id: 'singleton',
                    revision: expectedRevision,
                    replacementReservation: { $exists: false },
                    remoteDrain: { $exists: false },
                    remoteAdmissionCount: selectedCount.remoteAdmissionCount,
                    topologyAdmissionCount: selectedCount.topologyAdmissionCount,
                },
                { $inc: { topologyAdmissionCount: 1 } },
                { new: true, runValidators: true, session, timestamps: false, upsert: false },
            ).select(TOPOLOGY_STATE_SELECT), session).lean();
            if (!state) {
                throw new TopologyDeploymentRepositoryError(
                    'TOPOLOGY_ADMISSION_UNAVAILABLE',
                    'Topology admission is unavailable or the topology fence changed',
                );
            }
            const pinned = {
                revision: state.revision,
                deployedRevision: state.deployedRevision ?? 0,
                ...prepared,
            };
            await admit(pinned, session);
            return pinned;
        });
    }

    async pinTopology({ expectedRevision, prepare }) {
        if (typeof prepare !== 'function') {
            throw new TypeError('Topology deployment pin requires a prepare function');
        }
        try {
            return await this.transactionRunner(async session => {
                const snapshot = await this.snapshotReader.readDraft(session);
                if (snapshot.revision !== expectedRevision) {
                    throw staleRevision(expectedRevision, snapshot.revision);
                }
                if (snapshot.replacementReservation) {
                    throw new TopologyDeploymentRepositoryError(
                        'TOPOLOGY_REPLACEMENT_RESERVED',
                        'A topology replacement owns the deployment pin fence',
                    );
                }
                const prepared = await prepare(snapshot);
                const update = { $set: { revision: expectedRevision } };
                if (expectedRevision === 0) update.$setOnInsert = { deployedRevision: 0 };
                const state = await withSession(
                    this.CascadeTopologyState.findOneAndUpdate(
                        {
                            _id: 'singleton',
                            revision: expectedRevision,
                            replacementReservation: { $exists: false },
                        },
                        update,
                        {
                            new: true,
                            runValidators: true,
                            session,
                            timestamps: false,
                            upsert: expectedRevision === 0,
                        },
                    ).select(TOPOLOGY_STATE_SELECT),
                    session,
                ).lean();
                if (!state) throw staleRevision(expectedRevision, null);
                return {
                    revision: state.revision,
                    deployedRevision: state.deployedRevision ?? 0,
                    ...prepared,
                };
            });
        } catch (error) {
            if (expectedRevision === 0 && (error?.code === 11000 || error?.code === 11001)) {
                throw staleRevision(expectedRevision, null);
            }
            throw error;
        }
    }

    async markDeployed({ expectedRevision, expectedDeployedRevision }) {
        const state = await this.CascadeTopologyState.findOneAndUpdate(
            {
                _id: 'singleton',
                revision: expectedRevision,
                deployedRevision: expectedDeployedRevision,
            },
            { $set: { deployedRevision: expectedRevision } },
            {
                new: true,
                runValidators: true,
                timestamps: false,
            },
        )
            .select(TOPOLOGY_STATE_SELECT)
            .lean();
        if (!state) throw staleRevision(expectedRevision, null);
        return {
            revision: state.revision,
            deployedRevision: state.deployedRevision,
        };
    }
}

module.exports = {
    TOPOLOGY_STATE_SELECT,
    TopologyDeploymentRepository,
    TopologyDeploymentRepositoryError,
    staleRevision,
};
