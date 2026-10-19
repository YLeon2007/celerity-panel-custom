'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
const service = require('../cascadeService');
const HyNode = require('../../models/hyNodeModel');
const CascadeLink = require('../../models/cascadeLinkModel');
const Settings = require('../../models/settingsModel');
const sshPool = require('../sshPoolService');
test.after(() => sshPool.closeAll());

const exits = [
    { _id: '507f1f77bcf86cd799439011', name: 'bridge A', cascadeRole: 'bridge', status: 'online', mapPosition: { x: 710, y: 28 } },
    { _id: '507f1f77bcf86cd799439012', name: 'bridge B', cascadeRole: 'bridge', status: 'online', mapPosition: { x: 710, y: 164 } },
];
function stubGraph(t, setting) {
    t.mock.method(HyNode, 'find', () => ({ select: () => ({ lean: async () => exits }) }));
    t.mock.method(CascadeLink, 'find', () => ({ populate: () => ({ populate: () => ({ lean: async () => [] }) }) }));
    t.mock.method(Settings, 'findById', () => ({ select: () => ({ lean: async () => setting }) }));
}

test('fresh map places virtual Internet next to positioned exits, not at origin', async t => {
    stubGraph(t, null);
    const result = await service.getTopology();
    assert.deepEqual(result.nodes.find(n => n.data.id === 'internet').position, { x: 870, y: 96 });
});

test('saved virtual Internet position wins over exit-derived default', async t => {
    stubGraph(t, { networkMap: { internetPosition: { x: 910, y: 51 } } });
    const result = await service.getTopology();
    assert.deepEqual(result.nodes.find(n => n.data.id === 'internet').position, { x: 910, y: 51 });
});

test('saving the map persists the Internet icon separately from physical nodes', async t => {
    let savedSettings, savedNodes;
    t.mock.method(HyNode, 'bulkWrite', async ops => { savedNodes = ops; });
    t.mock.method(Settings, 'findByIdAndUpdate', async (...args) => { savedSettings = args; });
    await service.savePositions([
        { id: exits[0]._id, x: 710, y: 28 },
        { id: 'internet', x: 930, y: 85 },
    ]);
    assert.equal(savedNodes.length, 1);
    assert.equal(savedNodes[0].updateOne.filter._id, exits[0]._id);
    assert.deepEqual(savedSettings[1].$set['networkMap.internetPosition'], { x: 930, y: 85 });
    assert.equal(savedSettings[0], 'settings');
});

test('non-finite virtual Internet coordinates are ignored', async t => {
    let saved = false;
    t.mock.method(Settings, 'findByIdAndUpdate', async () => { saved = true; });
    await service.savePositions([{ id: 'internet', x: Infinity, y: 2 }]);
    assert.equal(saved, false);
});
