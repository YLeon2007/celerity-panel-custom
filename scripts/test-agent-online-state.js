const assert = require('assert');
const {
    extractAgentOnlineUserIds,
    mergeNodeOnlineContributions,
} = require('../src/utils/agentOnlineState');

const payload = {
    users: {
        leon: {
            online: true,
            lastSeenAt: '2026-07-03T15:58:12.000Z',
            source: 'xray-log',
            clientIp: '95.105.78.83',
        },
        lilya: {
            online: false,
            lastSeenAt: '2026-07-03T15:57:00.000Z',
            source: 'timeout',
        },
        empty: null,
    },
};

assert.deepStrictEqual(extractAgentOnlineUserIds(payload), ['leon']);
assert.deepStrictEqual(extractAgentOnlineUserIds({ users: {} }), []);
assert.deepStrictEqual(extractAgentOnlineUserIds(null), []);

{
    const contributions = new Map([
        ['de', new Set(['leon'])],
        ['fi', new Set(['lilya'])],
    ]);
    const merged = mergeNodeOnlineContributions(contributions, ['de', 'fi']);
    assert.deepStrictEqual([...merged.userIds].sort(), ['leon', 'lilya']);

    // A successful empty /online response for one node must replace that node,
    // not preserve old users for an extra panel-side timeout.
    contributions.set('de', new Set());
    const afterEmptyDe = mergeNodeOnlineContributions(contributions, ['de', 'fi']);
    assert.deepStrictEqual([...afterEmptyDe.userIds].sort(), ['lilya']);

    // Removed/inactive node contributions must be pruned.
    const afterPrune = mergeNodeOnlineContributions(contributions, ['de']);
    assert.deepStrictEqual([...afterPrune.contributions.keys()], ['de']);
}

console.log('test-agent-online-state: OK');
