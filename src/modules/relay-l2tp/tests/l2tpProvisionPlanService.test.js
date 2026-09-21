'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { buildInstallPlan } = require('../services/l2tpProvisionPlanService');

function installInput(overrides = {}) {
    return {
        operationId: 'operation-17',
        topologyRevision: 17,
        relay: { id: 'relay-1', role: 'relay' },
        routeGroup: { id: 'group-a' },
        relayGroupPlan: {
            groupId: 'group-a',
            candidates: [
                { pathKey: 'secondary', healthy: true, nextHopNodeId: 'relay-3' },
                { pathKey: 'primary', healthy: true, nextHopNodeId: 'relay-2' },
            ],
            decision: {
                decision: 'select',
                groupId: 'group-a',
                pathKey: 'primary',
                nextHopNodeId: 'relay-2',
            },
        },
        desired: {
            desiredState: 'installed',
            routeGroup: 'group-a',
            psk: 'install-psk-secret',
            users: [{ login: 'alice', password: 'user-password-secret' }],
        },
        ...overrides,
    };
}

test('builds the deterministic ordered install operation plan', () => {
    const input = installInput();
    const first = buildInstallPlan(input);
    const reordered = installInput();
    reordered.relayGroupPlan.candidates.reverse();
    const second = buildInstallPlan(reordered);

    assert.deepEqual(first, second);
    assert.deepEqual(first, {
        ok: true,
        operationId: 'operation-17',
        topologyRevision: 17,
        relayId: 'relay-1',
        routeGroupId: 'group-a',
        selectedPathKey: 'primary',
        nextHopNodeId: 'relay-2',
        steps: [
            { type: 'preflight' },
            { type: 'backup' },
            { type: 'stage_managed_files' },
            { type: 'compose_xray_fragment' },
            { type: 'validate_xray' },
            { type: 'validate_nft' },
            { type: 'activate_xray' },
            { type: 'apply_firewall_policy' },
            { type: 'start_l2tp' },
            { type: 'sync_users' },
            { type: 'verify' },
            { type: 'commit' },
        ],
    });
});

test('rejects a non-installed desired state before creating steps', () => {
    assert.throws(
        () => buildInstallPlan(installInput({
            desired: {
                desiredState: 'absent',
                routeGroup: 'group-a',
                psk: 'must-not-leak',
            },
        })),
        error => {
            assert.equal(error.name, 'L2tpProvisionPlanError');
            assert.equal(error.code, 'DESIRED_STATE_NOT_INSTALLED');
            assert.equal(error.desiredState, 'absent');
            assert.equal(Object.hasOwn(error, 'steps'), false);
            assert.doesNotMatch(error.message, /must-not-leak/);
            return true;
        },
    );
});

test('rejects a non-relay target before creating steps', () => {
    assert.throws(
        () => buildInstallPlan(installInput({
            relay: { id: 'bridge-1', role: 'bridge' },
        })),
        error => {
            assert.equal(error.name, 'L2tpProvisionPlanError');
            assert.equal(error.code, 'NODE_NOT_RELAY');
            assert.equal(error.relayId, 'bridge-1');
            assert.equal(error.role, 'bridge');
            assert.equal(Object.hasOwn(error, 'steps'), false);
            return true;
        },
    );
});

test('rejects a desired route-group mismatch before creating steps', () => {
    assert.throws(
        () => buildInstallPlan(installInput({
            desired: {
                desiredState: 'installed',
                routeGroup: 'group-b',
                psk: 'must-not-leak',
            },
        })),
        error => {
            assert.equal(error.name, 'L2tpProvisionPlanError');
            assert.equal(error.code, 'ROUTE_GROUP_MISMATCH');
            assert.equal(error.selectedRouteGroupId, 'group-b');
            assert.equal(error.routeGroupId, 'group-a');
            assert.equal(Object.hasOwn(error, 'steps'), false);
            assert.doesNotMatch(JSON.stringify(error), /must-not-leak/);
            return true;
        },
    );
});

test('rejects a compiled relay plan for a different route group before creating steps', () => {
    const input = installInput();
    input.relayGroupPlan.groupId = 'group-b';
    input.relayGroupPlan.decision.groupId = 'group-b';

    assert.throws(
        () => buildInstallPlan(input),
        error => {
            assert.equal(error.name, 'L2tpProvisionPlanError');
            assert.equal(error.code, 'ROUTE_GROUP_MISMATCH');
            assert.equal(error.routeGroupId, 'group-a');
            assert.equal(error.compiledRouteGroupId, 'group-b');
            assert.equal(Object.hasOwn(error, 'steps'), false);
            return true;
        },
    );
});

test('rejects a missing selected route group before creating steps', () => {
    const input = installInput({
        routeGroup: null,
        desired: {
            desiredState: 'installed',
            routeGroup: null,
        },
    });
    input.relayGroupPlan.groupId = null;
    delete input.relayGroupPlan.decision.groupId;

    assert.throws(
        () => buildInstallPlan(input),
        error => {
            assert.equal(error.name, 'L2tpProvisionPlanError');
            assert.equal(error.code, 'ROUTE_GROUP_MISMATCH');
            assert.equal(error.selectedRouteGroupId, null);
            assert.equal(error.routeGroupId, null);
            assert.equal(Object.hasOwn(error, 'steps'), false);
            return true;
        },
    );
});

test('returns a fail-closed plan without steps when the selected route group has no healthy path', () => {
    const input = installInput();
    input.relayGroupPlan.candidates.forEach(candidate => { candidate.healthy = false; });
    input.relayGroupPlan.decision = { decision: 'block', error: { code: 'NO_HEALTHY_PATH' } };

    assert.deepEqual(buildInstallPlan(input), {
        ok: false,
        operationId: 'operation-17',
        topologyRevision: 17,
        relayId: 'relay-1',
        routeGroupId: 'group-a',
        error: { code: 'NO_HEALTHY_PATH' },
        steps: [],
    });
});
