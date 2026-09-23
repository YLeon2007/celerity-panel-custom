'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
const { projectGroups } = require('../domain/topologyDraft');

test('preserves enabled path state while projecting topology draft groups', () => {
    assert.deepEqual(projectGroups([{
        _id: 'group-1',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [
            { pathKey: 'disabled', linkIds: ['link-1'], priority: 1, enabled: false },
            { pathKey: 'enabled', linkIds: ['link-2'], priority: 2, enabled: true },
        ],
    }]), [{
        _id: 'group-1',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [
            {
                pathKey: 'disabled',
                linkIds: ['link-1'],
                priority: 1,
                enabled: false,
                cascadePathIngress: { tag: 'cascade-disabled', port: 18468 },
            },
            {
                pathKey: 'enabled',
                linkIds: ['link-2'],
                priority: 2,
                enabled: true,
                cascadePathIngress: { tag: 'cascade-enabled', port: 18652 },
            },
        ],
    }]);
});

test('projects deterministic cascade path ingress handles for every path', () => {
    const groups = [{
        _id: 'group-1',
        mode: 'reverse',
        strategy: 'priority-failover',
        paths: [
            { pathKey: 'backup', linkIds: ['link-2'], priority: 2 },
            { pathKey: 'primary', linkIds: ['link-1'], priority: 1 },
        ],
    }];

    const [projected] = projectGroups(groups);
    const [backup, primary] = projected.paths;

    assert.deepEqual(primary.cascadePathIngress, {
        tag: 'cascade-primary',
        port: cascadePathIngressPort('group-1', 'primary'),
    });
    assert.deepEqual(backup.cascadePathIngress, {
        tag: 'cascade-backup',
        port: cascadePathIngressPort('group-1', 'backup'),
    });
    assert.deepEqual(projectGroups(groups), projectGroups(groups));
});

test('omits ingress projection for paths without usable identities', () => {
    const [group] = projectGroups([{
        mode: 'reverse',
        strategy: 'priority-failover',
        paths: [
            { pathKey: 'primary', linkIds: ['link-1'], priority: 1 },
            { linkIds: ['link-2'], priority: 2 },
        ],
    }]);

    assert.equal(group._id, null);
    assert.equal(group.paths[0].cascadePathIngress, undefined);
    assert.equal(group.paths[1].cascadePathIngress, undefined);
});

test('does not project secret or hostile group fields alongside ingress handles', () => {
    const hostile = 'HOSTILE; rm -rf /';
    const [group] = projectGroups([{
        _id: 'group-1',
        mode: 'reverse',
        strategy: 'priority-failover',
        secret: 'group-secret-canary',
        command: hostile,
        paths: [{
            pathKey: 'primary',
            linkIds: ['link-1'],
            priority: 1,
            password: 'path-secret-canary',
        }],
    }]);

    const serialized = JSON.stringify(group);
    assert.doesNotMatch(serialized, /secret-canary|HOSTILE/);
    assert.deepEqual(Object.keys(group.paths[0]).sort(), [
        'cascadePathIngress',
        'enabled',
        'linkIds',
        'pathKey',
        'priority',
    ]);
});
