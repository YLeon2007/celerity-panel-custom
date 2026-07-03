const assert = require('assert');
const { extractAgentOnlineUserIds } = require('../src/utils/agentOnlineState');

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

console.log('test-agent-online-state: OK');
