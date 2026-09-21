'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const mongoose = require('mongoose');

const CascadeRouteGroup = require('../models/cascadeRouteGroupModel');
const CascadeTopologyState = require('../models/cascadeTopologyStateModel');

function objectId() {
    return new mongoose.Types.ObjectId();
}

function assertValidationKind(document, path, kind) {
    const error = document.validateSync();
    assert.ok(error, `${path} should be invalid`);
    assert.equal(error.errors[path]?.kind, kind);
}

function routeGroup(overrides = {}) {
    return new CascadeRouteGroup({
        name: 'primary routes',
        mode: 'reverse',
        strategy: 'priority-failover',
        paths: [{
            pathKey: 'primary',
            linkIds: [objectId()],
            priority: 1,
        }],
        ...overrides,
    });
}

test('route group requires a nonempty name', () => {
    assert.equal(routeGroup().validateSync(), undefined);

    for (const name of [undefined, '', '   ']) {
        const error = routeGroup({ name }).validateSync();
        assert.equal(error.errors.name.kind, 'required');
    }
});

test('route group mode is required and limited to reverse or forward', () => {
    for (const mode of ['reverse', 'forward']) {
        assert.equal(routeGroup({ mode }).validateSync(), undefined);
    }

    assertValidationKind(routeGroup({ mode: undefined }), 'mode', 'required');
    assertValidationKind(routeGroup({ mode: 'direct' }), 'mode', 'enum');
});

test('route group strategy is required and limited to priority-failover', () => {
    assert.equal(routeGroup({ strategy: 'priority-failover' }).validateSync(), undefined);
    assertValidationKind(routeGroup({ strategy: undefined }), 'strategy', 'required');
    assertValidationKind(routeGroup({ strategy: 'round-robin' }), 'strategy', 'enum');
});

test('each route group path requires a nonempty pathKey', () => {
    for (const pathKey of [undefined, '', '   ']) {
        assertValidationKind(routeGroup({
            paths: [{ pathKey, linkIds: [objectId()], priority: 1 }],
        }), 'paths.0.pathKey', 'required');
    }
});

test('pathKey values are unique within a route group', () => {
    assertValidationKind(routeGroup({
        paths: [
            { pathKey: 'duplicate', linkIds: [objectId()], priority: 1 },
            { pathKey: 'duplicate', linkIds: [objectId()], priority: 2 },
        ],
    }), 'paths', 'user defined');

    assert.equal(routeGroup({
        paths: [
            { pathKey: 'primary', linkIds: [objectId()], priority: 1 },
            { pathKey: 'secondary', linkIds: [objectId()], priority: 2 },
        ],
    }).validateSync(), undefined);
});

test('each route group path requires nonempty ordered linkIds', () => {
    for (const linkIds of [undefined, []]) {
        const error = routeGroup({
            paths: [{ pathKey: 'primary', linkIds, priority: 1 }],
        }).validateSync();
        assert.ok(error, 'linkIds should be invalid');
        assert.ok(error.errors['paths.0.linkIds']);
    }

    const linkIds = [objectId(), objectId(), objectId()];
    const group = routeGroup({
        paths: [{ pathKey: 'primary', linkIds, priority: 1 }],
    });
    assert.equal(group.validateSync(), undefined);
    assert.deepEqual(group.paths[0].linkIds.map(String), linkIds.map(String));
});

test('each route group path requires a positive finite numeric priority', () => {
    for (const priority of [undefined, 0, -1, Number.POSITIVE_INFINITY, Number.NaN, 'invalid']) {
        const error = routeGroup({
            paths: [{ pathKey: 'primary', linkIds: [objectId()], priority }],
        }).validateSync();
        assert.ok(error, `priority ${String(priority)} should be invalid`);
        assert.ok(error.errors['paths.0.priority']);
    }

    for (const priority of [0.5, 1, 100]) {
        assert.equal(routeGroup({
            paths: [{ pathKey: 'primary', linkIds: [objectId()], priority }],
        }).validateSync(), undefined);
    }
});

test('topology state uses a fixed singleton document identity', () => {
    const state = new CascadeTopologyState();
    assert.equal(state._id, 'singleton');
    assert.equal(state.validateSync(), undefined);

    assertValidationKind(
        new CascadeTopologyState({ _id: 'another-state' }),
        '_id',
        'enum',
    );
});

test('topology state revision rejects negative values', () => {
    assertValidationKind(
        new CascadeTopologyState({ revision: -1 }),
        'revision',
        'min',
    );
});

test('topology state deployed revision rejects negative values', () => {
    assertValidationKind(
        new CascadeTopologyState({ deployedRevision: -1 }),
        'deployedRevision',
        'min',
    );
});
