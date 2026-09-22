'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

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
            { pathKey: 'disabled', linkIds: ['link-1'], priority: 1, enabled: false },
            { pathKey: 'enabled', linkIds: ['link-2'], priority: 2, enabled: true },
        ],
    }]);
});
