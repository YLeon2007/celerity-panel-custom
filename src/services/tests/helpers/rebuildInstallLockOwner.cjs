'use strict';
// Isolated Mongo fixture only. Model the relay, not lock acquisition, reservation or cleanup.
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const { createRebuildService } = require('../../rebuildService');
(async () => {
    const [name, cut] = process.argv.slice(2), port = process.env.C3_DIRECTORY_FIXTURE_PORT;
    assert.match(name, /^c3_directory_fixture_[a-f0-9]{16}$/);
    assert.match(port, /^\d{4,5}$/);
    assert.deepEqual(Object.keys(require('node:os').networkInterfaces()), ['lo']);
    assert.ok(['unknown', 'crash', 'apply', 'refused'].includes(cut));
    await mongoose.connect(`mongodb://127.0.0.1:${port}/?directConnection=true`, { dbName: name, serverSelectionTimeoutMS: 2000 });
    try {
        const [relay] = JSON.parse(process.env.C3_REBUILD_L2TP_RELAYS_JSON);
        let dispatched = false;
        const service = createRebuildService({ cache: {}, sync: {}, createRelayDirect: () => ({
            preflight: async () => ({ machineId: relay.machineId, ppp: cut !== 'refused', unitsLoaded: true, masked: false }),
            prepare: async () => ({ backupId: 'fixture-install' }),
            install: async (_, verify) => {
                await verify(); dispatched = true;
                if (cut === 'crash') process.exit(0); // After dispatch, before retain or finally.
                throw Error('fixture lost reply');
            },
            close: async () => {},
        }) });
        if (cut === 'apply') await service.locks.run(async verify => { await verify(); process.exit(0); });
        await assert.rejects(service.installRelay(relay.nodeId), cut === 'refused'
            ? { code: 'REBUILD_L2TP_HOST_NOT_READY', outcome: 'refused' }
            : { code: 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN', outcome: 'unknown', retryAllowed: false });
        assert.equal(dispatched, cut === 'unknown');
    } finally { await mongoose.disconnect(); }
})().catch(() => { process.exitCode = 1; });
