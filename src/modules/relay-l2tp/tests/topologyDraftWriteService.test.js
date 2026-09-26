'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    createTopologyDraftWriteService,
    TopologyDraftWriteService,
} = require('../services/topologyDraftWriteService');

function validSnapshot() {
    return {
        revision: 7,
        deployedRevision: 5,
        nodes: [
            { _id: 'portal-1', cascadeRole: 'portal' },
            { _id: 'relay-1', cascadeRole: 'relay' },
            { _id: 'bridge-1', cascadeRole: 'bridge' },
        ],
        links: [{
            _id: 'link-1',
            portalNode: 'portal-1',
            bridgeNode: 'relay-1',
            mode: 'forward',
            active: true,
        }],
        groups: [{
            _id: 'group-1',
            name: 'primary',
            mode: 'forward',
            strategy: 'priority-failover',
            paths: [{
                pathKey: 'primary',
                linkIds: ['link-1', 'link-2'],
                priority: 1,
            }],
        }],
        activeRouteGroupIds: [],
    };
}

test('validates and compiles the latest link update before committing one draft revision', async () => {
    const snapshot = validSnapshot();
    snapshot.links.push({
        _id: 'link-2',
        portalNode: 'wrong-relay',
        bridgeNode: 'bridge-1',
        mode: 'forward',
        active: true,
    });
    let compilerInput;
    let preparedMutation;
    const repository = {
        async commitDraft({ expectedRevision, prepare }) {
            assert.equal(expectedRevision, 7);
            preparedMutation = (await prepare(snapshot)).mutation;
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({
        repository,
        compiler(candidate) {
            compilerInput = candidate;
            return { valid: true, errors: [], relays: [] };
        },
    });

    const result = await service.updateLink({
        expectedTopologyRevision: 7,
        linkId: 'link-2',
        changes: { portalNode: 'relay-1' },
    });

    assert.deepEqual(result, { revision: 8, deployedRevision: 5 });
    assert.deepEqual(preparedMutation, {
        kind: 'link.update',
        id: 'link-2',
        changes: { portalNode: 'relay-1' },
    });
    assert.equal(
        compilerInput.links.find(link => link.id === 'link-2').source,
        'relay-1',
    );
});

test('validates the full candidate graph before updating a link', async () => {
    let persisted = false;
    const snapshot = validSnapshot();
    snapshot.links.push({
        _id: 'link-2',
        portalNode: 'relay-1',
        bridgeNode: 'bridge-1',
        mode: 'forward',
        active: true,
    });
    const repository = {
        async commitDraft({ prepare }) {
            await prepare(snapshot);
            persisted = true;
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({ repository });

    await assert.rejects(
        service.updateLink({
            expectedTopologyRevision: 7,
            linkId: 'link-1',
            changes: { bridgeNode: 'bridge-1' },
        }),
        error => {
            assert.equal(error.code, 'INVALID_TOPOLOGY_DRAFT');
            assert.ok(error.errors.some(candidate => candidate.code === 'DISCONTINUOUS_PATH'));
            return true;
        },
    );
    assert.equal(persisted, false);
});

test('heals a stale route path with a missing link instead of blocking link mutations', async () => {
    let preparedMutation;
    let compiledCandidate;
    const snapshot = validSnapshot();
    snapshot.groups[0].paths[0].linkIds = ['link-1', 'missing-link'];
    const repository = {
        async commitDraft({ prepare }) {
            preparedMutation = (await prepare(snapshot)).mutation;
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({
        repository,
        compiler(candidate) {
            compiledCandidate = candidate;
            return { valid: true, errors: [], relays: [] };
        },
    });

    const result = await service.createLink({
        expectedTopologyRevision: 7,
        link: {
            _id: 'link-2',
            portalNode: 'relay-1',
            bridgeNode: 'bridge-1',
            mode: 'forward',
            active: true,
        },
    });

    assert.deepEqual(result, { revision: 8, deployedRevision: 5 });
    assert.deepEqual(
        preparedMutation.groupUpdates,
        [{ id: 'group-1', paths: [] }],
        'the path referencing an unknown link must be dropped and persisted',
    );
    assert.deepEqual(
        compiledCandidate.groups.find(group => group._id === 'group-1' || group.id === 'group-1').paths,
        [],
        'the healed candidate must not contain the stale path',
    );
});

test('deletes a link referenced by a route group, stripping its paths', async () => {
    let preparedCandidate;
    const repository = {
        async commitDraft({ prepare }) {
            await prepare(validSnapshot());
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({
        repository,
        validator: candidate => {
            preparedCandidate = candidate;
            return { valid: true, errors: [] };
        },
        compiler: () => ({ valid: true, errors: [] }),
    });

    const result = await service.deleteLink({
        expectedTopologyRevision: 7,
        linkId: 'link-1',
    });

    assert.deepEqual(result, { revision: 8, deployedRevision: 5 });
    assert.equal(preparedCandidate.links.length, 0);
    assert.equal(
        preparedCandidate.groups.length,
        0,
        'group left without paths must be dropped',
    );
});

test('keeps an active route group when link deletion empties its paths', async () => {
    const snapshot = validSnapshot();
    snapshot.activeRouteGroupIds = ['group-1'];
    let preparedCandidate;
    const repository = {
        async commitDraft({ prepare }) {
            await prepare(snapshot);
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({
        repository,
        validator: candidate => {
            preparedCandidate = candidate;
            return { valid: true, errors: [] };
        },
        compiler: () => ({ valid: true, errors: [] }),
    });

    await service.deleteLink({
        expectedTopologyRevision: 7,
        linkId: 'link-1',
    });

    assert.equal(preparedCandidate.groups.length, 1);
    assert.deepEqual(preparedCandidate.groups[0].paths, []);
});

test('link mutations never trigger automatic node role changes', async () => {
    // Roles are pure operator state: create, update and delete of cascade
    // links must all commit without any role recalculation hook firing.
    const repository = {
        async commitDraft({ prepare }) {
            await prepare(validSnapshot());
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({
        repository,
        validator: () => ({ valid: true, errors: [] }),
        compiler: () => ({ valid: true, errors: [] }),
        // Legacy option: even if a caller still passes a role recalculator,
        // the service must never invoke it.
        recalculateRoles: async () => {
            throw new Error('automatic role recalculation is forbidden');
        },
    });

    await service.createLink({
        expectedTopologyRevision: 7,
        link: {
            _id: 'link-new',
            portalNode: 'relay-1',
            bridgeNode: 'bridge-1',
            mode: 'forward',
            active: true,
        },
    });
    await service.updateLink({ expectedTopologyRevision: 8, linkId: 'link-1', changes: { name: 'l1b' } });
    await service.deleteLink({ expectedTopologyRevision: 8, linkId: 'link-1' });
    await service.deleteRouteGroup({ expectedTopologyRevision: 8, routeGroupId: 'group-1' });
});

test('write service exposes no automatic role recalculation API', () => {
    const exported = require('../services/topologyDraftWriteService');
    assert.equal('recalculateNodeRoles' in exported, false,
        'graph-based role inference must not be part of the write service');
});

test('deletes an unreferenced link as a validated draft mutation', async () => {
    const snapshot = validSnapshot();
    snapshot.groups = [];
    let preparedMutation;
    const repository = {
        async commitDraft({ prepare }) {
            preparedMutation = (await prepare(snapshot)).mutation;
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({ repository });

    const result = await service.deleteLink({
        expectedTopologyRevision: 7,
        linkId: 'link-1',
    });

    assert.deepEqual(result, { revision: 8, deployedRevision: 5 });
    assert.deepEqual(preparedMutation, {
        kind: 'link.delete',
        id: 'link-1',
        groupUpdates: [],
        groupDeletes: [],
    });
});

test('rejects deleting a route group referenced by active relay state', async () => {
    const snapshot = validSnapshot();
    snapshot.activeRouteGroupIds = ['group-1'];
    let persisted = false;
    const repository = {
        async commitDraft({ prepare }) {
            await prepare(snapshot);
            persisted = true;
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({ repository });

    await assert.rejects(
        service.deleteRouteGroup({
            expectedTopologyRevision: 7,
            routeGroupId: 'group-1',
        }),
        error => {
            assert.equal(error.name, 'TopologyDraftWriteError');
            assert.equal(error.code, 'CASCADE_ROUTE_GROUP_IN_USE');
            assert.equal(error.routeGroupId, 'group-1');
            return true;
        },
    );
    assert.equal(persisted, false);
});

test('deletes an unreferenced route group as a validated draft mutation', async () => {
    let preparedMutation;
    const repository = {
        async commitDraft({ prepare }) {
            preparedMutation = (await prepare(validSnapshot())).mutation;
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({ repository });

    const result = await service.deleteRouteGroup({
        expectedTopologyRevision: 7,
        routeGroupId: 'group-1',
    });

    assert.deepEqual(result, { revision: 8, deployedRevision: 5 });
    assert.deepEqual(preparedMutation, { kind: 'group.delete', id: 'group-1' });
});

test('updates a route group through candidate validation and compilation', async () => {
    const snapshot = validSnapshot();
    snapshot.links.push({
        _id: 'link-2',
        portalNode: 'relay-1',
        bridgeNode: 'bridge-1',
        mode: 'forward',
        active: true,
    });
    let preparedMutation;
    const repository = {
        async commitDraft({ prepare }) {
            preparedMutation = (await prepare(snapshot)).mutation;
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({ repository });

    const result = await service.updateRouteGroup({
        expectedTopologyRevision: 7,
        routeGroupId: 'group-1',
        changes: {
            name: 'updated primary',
            paths: [{ pathKey: 'primary', linkIds: ['link-1'], priority: 5 }],
        },
    });

    assert.deepEqual(result, { revision: 8, deployedRevision: 5 });
    assert.deepEqual(preparedMutation, {
        kind: 'group.update',
        id: 'group-1',
        changes: {
            name: 'updated primary',
            paths: [{ pathKey: 'primary', linkIds: ['link-1'], priority: 5 }],
        },
    });
});

test('preserves disabled route paths through draft validation and compilation', async () => {
    const snapshot = validSnapshot();
    snapshot.groups[0].paths[0].enabled = false;
    let validatorCandidate;
    let compilerCandidate;
    const repository = {
        async commitDraft({ prepare }) {
            await prepare(snapshot);
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({
        repository,
        validator(candidate) {
            validatorCandidate = candidate;
            return { valid: true, errors: [] };
        },
        compiler(candidate) {
            compilerCandidate = candidate;
            return { valid: true, errors: [], relays: [] };
        },
    });

    await service.updateRouteGroup({
        expectedTopologyRevision: 7,
        routeGroupId: 'group-1',
        changes: { name: 'updated primary' },
    });

    assert.equal(validatorCandidate.groups[0].paths[0].enabled, false);
    assert.equal(compilerCandidate.groups[0].paths[0].enabled, false);
});

test('rejects a candidate that the compiler cannot materialize before persistence', async () => {
    const snapshot = validSnapshot();
    snapshot.groups = [];
    let persisted = false;
    const repository = {
        async commitDraft({ prepare }) {
            await prepare(snapshot);
            persisted = true;
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({
        repository,
        compiler() {
            return {
                valid: false,
                errors: [{ code: 'UNCOMPILABLE_ROUTE_GROUP', groupId: 'group-2' }],
                relays: [],
            };
        },
    });

    await assert.rejects(
        service.createRouteGroup({
            expectedTopologyRevision: 7,
            routeGroup: {
                _id: 'group-2',
                name: 'portal to relay',
                mode: 'forward',
                strategy: 'priority-failover',
                paths: [{ pathKey: 'primary', linkIds: ['link-1'], priority: 1 }],
            },
        }),
        error => {
            assert.equal(error.name, 'TopologyDraftWriteError');
            assert.equal(error.code, 'INVALID_TOPOLOGY_DRAFT');
            assert.deepEqual(error.errors, [{
                code: 'UNCOMPILABLE_ROUTE_GROUP',
                groupId: 'group-2',
            }]);
            return true;
        },
    );
    assert.equal(persisted, false);
});

test('creates a validated route-group draft without invoking deployment', async () => {
    const snapshot = validSnapshot();
    snapshot.groups = [];
    let deploymentCalls = 0;
    const repository = {
        async commitDraft({ prepare }) {
            const prepared = await prepare(snapshot);
            assert.equal(prepared.mutation.kind, 'group.create');
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({
        repository,
        deployTopology() {
            deploymentCalls += 1;
        },
    });

    const result = await service.createRouteGroup({
        expectedTopologyRevision: 7,
        routeGroup: {
            _id: 'group-2',
            name: 'portal to relay',
            mode: 'forward',
            strategy: 'priority-failover',
            paths: [{ pathKey: 'primary', linkIds: ['link-1'], priority: 1 }],
        },
    });

    assert.deepEqual(result, { revision: 8, deployedRevision: 5 });
    assert.equal(deploymentCalls, 0);
});

test('creates a validated draft link and returns the one-step revision snapshot', async () => {
    let commits = 0;
    const repository = {
        async commitDraft({ expectedRevision, prepare }) {
            assert.equal(expectedRevision, 7);
            const prepared = await prepare(validSnapshot());
            assert.deepEqual(prepared.mutation, {
                kind: 'link.create',
                document: {
                    _id: 'link-2',
                    name: 'relay to bridge',
                    portalNode: 'relay-1',
                    bridgeNode: 'bridge-1',
                    mode: 'forward',
                    active: true,
                },
            });
            commits += 1;
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const service = new TopologyDraftWriteService({ repository });

    const result = await service.createLink({
        expectedTopologyRevision: 7,
        link: {
            _id: 'link-2',
            name: 'relay to bridge',
            portalNode: 'relay-1',
            bridgeNode: 'bridge-1',
            mode: 'forward',
            active: true,
        },
    });

    assert.equal(commits, 1);
    assert.deepEqual(result, { revision: 8, deployedRevision: 5 });
});

test('factory wires the topology models into an API-ready draft write service', () => {
    const dependencies = {
        HyNode: { modelName: 'HyNode' },
        CascadeLink: { modelName: 'CascadeLink' },
        CascadeRouteGroup: { modelName: 'CascadeRouteGroup' },
        CascadeTopologyState: { modelName: 'CascadeTopologyState' },
        RelayL2tpState: { modelName: 'RelayL2tpState' },
        transactionRunner: async work => work({ id: 'factory-session' }),
    };
    let repositoryDependencies;
    class FakeRepository {
        constructor(candidateDependencies) {
            repositoryDependencies = candidateDependencies;
        }

        async commitDraft() {}
    }
    const validator = () => ({ valid: true, errors: [] });
    const compiler = () => ({ valid: true, errors: [], relays: [] });

    const service = createTopologyDraftWriteService({
        ...dependencies,
        Repository: FakeRepository,
        validator,
        compiler,
    });

    assert.ok(service instanceof TopologyDraftWriteService);
    assert.deepEqual(repositoryDependencies, dependencies);
    assert.strictEqual(service.validator, validator);
    assert.strictEqual(service.compiler, compiler);
    for (const methodName of [
        'createLink',
        'updateLink',
        'deleteLink',
        'createRouteGroup',
        'updateRouteGroup',
        'deleteRouteGroup',
    ]) {
        assert.equal(typeof service[methodName], 'function');
    }
});
