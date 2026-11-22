'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { performance } = require('node:perf_hooks');

const [phase, fixturePath, mongoPort, agentURL] = process.argv.slice(2);
const { portal, bridge, link, subscriber, wrong, other } = JSON.parse(readFileSync(fixturePath, 'utf8'));
const lo = '127.0.0.1';

function compose() {
    const { composeRebuildProfiles } = require('../../src/modules/relay-l2tp/services/rebuildTopologyComposer');
    const profiles = tunnel => composeRebuildProfiles({
        nodes: [portal, bridge], links: [tunnel], dialerVersions: new Map([[bridge._id, '26.11.9']]),
        usersByNode: { [portal._id]: [subscriber] },
    });
    const current = profiles(link);
    // Pre-proof receiver: a short legacy fixture ID has the same tag suffix,
    // but the composer cannot assign the full-ID account name to it.
    const old = profiles({ ...link, _id: link._id.slice(-8) });
    const receiver = files => files.find(p => p.nodeId === portal._id && p.profile === 'main').config;
    const dial = files => files.find(p => p.nodeId === bridge._id && p.profile === 'bridge').config.outbounds
        .find(o => o.settings?.reverse);
    assert.equal(dial(current).streamSettings.realitySettings.fingerprint, 'chrome');
    console.log(JSON.stringify({ receiver: receiver(current), old: receiver(old), dial: dial(current),
        wrong: dial(profiles({ ...link, tunnelUuid: wrong })), other: dial(profiles({ ...link, tunnelUuid: other })) }));
}

async function sample() {
    const { hostname, port } = new URL(agentURL);
    assert.match(agentURL, /^http:\/\/127\.0\.0\.1:[1-9]\d*$/);
    assert.match(mongoPort, /^[1-9]\d{0,4}$/);
    assert.ok(Number(mongoPort) <= 65535);
    // Do not load any .env or open the panel's file logs in this fixture.
    process.env.DOTENV_CONFIG_PATH = '/dev/null';
    const noop = () => {};
    require.cache[require.resolve('../../src/utils/logger')] = {
        loaded: true, exports: { info: noop, warn: noop, error: noop, debug: noop },
    };
    const mongoose = require('mongoose');
    const Link = require('../../src/models/cascadeLinkModel');
    const Node = require('../../src/models/hyNodeModel');
    const sync = require('../../src/services/syncService');
    // Importing syncService creates an idle pool timer; no SSH client is used.
    clearInterval(require('../../src/services/sshPoolService').cleanupTimer);
    const { createReverseObserver, observationSelect, projectReverseHealth } = require('../../src/services/rebuildReverseLinkHealth');
    const read = () => Link.findById(link._id).select(observationSelect).lean();
    await mongoose.connect(`mongodb://${lo}:${mongoPort}/reverse_evidence?directConnection=true`, {
        serverSelectionTimeoutMS: 5_000, autoIndex: false,
    });
    try {
        if (phase === 'connected') {
            await Node.create({ ...portal, xray: { ...portal.xray, agentToken: 'fixture-only', agentTls: false, agentPort: Number(port) } });
            await Link.create({ ...link, status: 'deployed', rebuildApplyEpoch: 'a'.repeat(32), rebuildApplied: {
                listener: portal._id, mode: link.mode, protocol: link.tunnelProtocol, port: link.tunnelPort, uuid: link.tunnelUuid,
            } });
        } else {
            // Only the HTTP fixture is recreated per phase, not the applied link/receipt.
            await Node.updateOne({ _id: portal._id }, { $set: { 'xray.agentPort': Number(port) } });
        }
        const before = await read();
        assert.equal(projectReverseHealth(before).status, phase === 'cut' ? 'online' : 'deployed');
        assert.equal(before.rebuildReverseObservation?.established, { connected: undefined, cut: true, reconnected: false }[phase]);
        let elapsed;
        const observer = createReverseObserver({ Link, Node, request: async (node, path, timeout) => {
            assert.equal(node.ip, hostname);
            assert.equal(node.xray.agentPort, Number(port));
            assert.equal(timeout, 15_000);
            const start = performance.now();
            const response = await sync.readRebuildReverseObservation(node, path, timeout);
            elapsed = performance.now() - start;
            return response;
        } });
        const established = phase !== 'cut';
        assert.equal(await observer.manual(link._id), established);
        // All three requests, including cut with the retained handler, must actually sample.
        assert.ok(elapsed >= 11_000 && elapsed < 15_000, `unexpected ${phase} HTTP sample: ${elapsed}ms`);
        const stored = await read();
        const proof = stored.rebuildReverseObservation;
        assert.equal(proof.established, established);
        assert.equal(+stored.updatedAt, +before.updatedAt, 'health must not change the apply generation');
        const view = projectReverseHealth(stored);
        assert.equal(stored.status, 'deployed');
        assert.equal(view.status, established ? 'online' : 'deployed');
        assert.deepEqual(view.lastHealthCheck, established ? proof.observedAt : null);
        assert.equal(view.latencyMs, null);
        assert.equal(Object.hasOwn(view, 'rebuildReverseObservation'), false);
        if (established) assert.equal(projectReverseHealth(stored, view.observationExpiresAt).status, 'deployed');
        console.log(`PANEL ${phase}: persisted=${proof.established} projected=${view.status} sample=${Math.round(elapsed)}ms timeout=15000ms`);
    } finally {
        await mongoose.disconnect();
    }
}

if (phase === 'compose') compose();
else if (['connected', 'cut', 'reconnected'].includes(phase)) sample().catch(error => { console.error(error); process.exitCode = 1; });
else throw new Error('unexpected fixture phase');
