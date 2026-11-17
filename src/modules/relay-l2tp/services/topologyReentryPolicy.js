'use strict';
// A temporary product restriction, NOT execution authority. Reads never grant
// adoption and never change aliases, operations, users, counters or ownership.
const CODE = 'TOPOLOGY_BUSINESS_REENTRY_BLOCKED';
const MESSAGE = 'Повторное включение any-order после бизнес-операций и возврата управления classic временно недоступно. Схема classic продолжает работать; история и пользователи сохранены.';
const ALLOWED = Object.freeze({ blocked: false });
const BLOCKED = Object.freeze({ blocked: true, code: CODE, message: MESSAGE });
const SETTLED = ['lastSettledOperation', 'lastSettledGeneration', 'lastSettledRevision', 'lastSettledCloseId'];
const read = query => query.read('primary').readConcern('majority').maxTimeMS(5000).lean();
function unavailable() {
    return Object.assign(new Error('Проверка истории повторного включения недоступна.'), { code: 'TOPOLOGY_REENTRY_POLICY_UNAVAILABLE' });
}
function businessReentryError() { return Object.assign(new Error(MESSAGE), { code: CODE }); }
async function readOwnerReentryRestriction(owner, { TopologyOperation, TopologyExecutionBinding } = {}) {
    // Operations in the FIRST active epoch must remain usable. A classic row
    // without public handback is also not evidence of a completed native cycle.
    if (owner?.owner !== 'classic' || !owner.handbackReceipt) return ALLOWED;
    if (SETTLED.some(key => Object.hasOwn(owner, key))) return BLOCKED;
    const node = String(owner.node);
    if (!/^[a-f0-9]{24}$/.test(node) || !TopologyOperation?.findOne || !TopologyExecutionBinding?.findOne) throw unavailable();
    // Same immutable history and node/resource union already checked by entry.
    // Terminal does not mean erasable; accepted but unsettled work also vetoes.
    for (const [Model, filter] of [
        [TopologyExecutionBinding, { nodeId: node }],
        [TopologyOperation, { $or: [{ 'nodes.node': node }, { resourceNodeIds: node }] }],
    ]) if (await read(Model.findOne(filter).select('_id'))) return BLOCKED;
    return ALLOWED;
}
async function assertOwnerReentryAllowed(owner, models) {
    if ((await readOwnerReentryRestriction(owner, models)).blocked) throw businessReentryError();
}
async function readBusinessReentryRestriction({ executionContext, nodeIds,
    TopologyConfigOwner = require('../../../models/topologyConfigOwnerModel'),
    TopologyOperation = require('../models/topologyOperationModel'),
    TopologyExecutionBinding = require('../models/topologyExecutionBindingModel'),
} = {}) {
    const { TOPOLOGY_EXECUTION_CONTEXTS, matchesTopologyExecutionContext } = require('../domain/topologyExecutionContext');
    if (!TOPOLOGY_EXECUTION_CONTEXTS.some(context => matchesTopologyExecutionContext(context, executionContext))) throw unavailable();
    const filter = { executionContext, owner: 'classic', handbackReceipt: { $exists: true },
        ...(nodeIds === undefined ? {} : { node: { $in: nodeIds } }) };
    const owners = await read(TopologyConfigOwner.find(filter).select('node owner handbackReceipt lastSettledOperation lastSettledGeneration lastSettledRevision lastSettledCloseId'));
    for (const owner of owners) if ((await readOwnerReentryRestriction(owner, { TopologyOperation, TopologyExecutionBinding })).blocked) return BLOCKED;
    return ALLOWED;
}
module.exports = { CODE, MESSAGE, businessReentryError, readOwnerReentryRestriction, assertOwnerReentryAllowed, readBusinessReentryRestriction };
