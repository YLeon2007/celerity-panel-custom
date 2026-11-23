'use strict';

const { publicProgress } = require('../../services/rebuildInstallProgress');
const path = '/rebuild/relays/:id/l2tp/install/progress';

async function readProgress(id) {
    const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
    return State.findOne({ node: id, status: { $in: ['installing', 'installed'] }, desiredState: 'installed' })
        .select('status installProgress -_id').read('primary').readConcern('majority')
        .setOptions({ timeoutMS: 1500, maxTimeMS: 1200 }).lean();
}

function handler(read = readProgress) {
    return async (req, res) => {
        if (req.method !== 'GET') return res.set('Allow', 'GET').status(405).end();
        if (req.session?.authenticated !== true || !req.sessionID) return res.status(403).end();
        const id = req.params.id;
        if (typeof id !== 'string' || !/^[a-f0-9]{24}(?![\s\S])/.test(id) || req.url.includes('?')) return res.status(400).end();
        try {
            return res.json({ nodeId: id, installProgress: publicProgress(await read(id)) });
        } catch { return res.status(503).end(); }
    };
}
module.exports = { path, handler };
