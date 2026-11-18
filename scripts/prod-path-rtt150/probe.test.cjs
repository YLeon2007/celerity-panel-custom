'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { makeLink, classify, loopbackConfig } = require('./probe.cjs');

test('RTT model brackets the effect with equal one-way delays and does not retry it', async () => {
    const events = [];
    const link = makeLink(150, async n => events.push(n));
    assert.equal(await link.call('guard', () => { events.push('effect'); return 17; }), 17);
    await assert.rejects(link.call('runner', () => { events.push('failed effect'); throw Error('lost reply'); }), /lost reply/);
    assert.deepEqual(events, [75, 'effect', 75, 75, 'failed effect', 75]);
    assert.deepEqual(link.counts(), { guard: 1, runner: 1 });
});

test('ACK, closing, timeout, late or missing client proof never pass the strict gate', () => {
    const success = { startupMs: 123, ackMs: 456, status: 'succeeded', proofs: 2, lockCount: 0,
        heldAdmission: false, admissionCount: 0, remoteAdmissionCount: 0,
        exactCandidates: true, dataPlaneMs: 299876.9, combinedMs: 299999.9 };
    assert.equal(classify(success), 'local-e2e-under-5m');
    for (const bad of [{ status: 'queued' }, { status: 'closing' }, { status: 'timed_out' }, { proofs: 1 },
        { lockCount: 1 }, { admissionCount: 1 }, { remoteAdmissionCount: 1 }, { heldAdmission: true }, { exactCandidates: false },
        { startupMs: 300000 }, { dataPlaneMs: 300000 }, { combinedMs: 300000 }, { combinedMs: undefined }]) {
        assert.notEqual(classify({ ...success, ...bad }), 'local-e2e-under-5m');
    }
    assert.equal(classify({ startupMs: 1, ackMs: 2 }), 'unproven');
    assert.equal(classify({ ...success, dataPlaneMs: undefined }), 'unproven');
    assert.equal(classify({ ...success, combinedMs: 300000 }), 'local-e2e-over-budget');
    assert.equal(classify({ ...success, combinedMs: 300001 }), 'local-e2e-over-budget');
    assert.equal(classify({ ...success, combinedMs: 1 }), 'unproven');
});

test('Xray launch projection confines declared listeners; outbound domains and special profiles refuse', () => {
    const config = { inbounds: [{ listen: '0.0.0.0', port: 40000, protocol: 'vless' }], outbounds: [{ protocol: 'freedom' }] };
    assert.equal(loopbackConfig(config).inbounds[0].listen, '127.0.0.1');
    assert.equal(config.inbounds[0].listen, '0.0.0.0');
    for (const unsafe of [{ dns: {} }, { inbounds: [{ protocol: 'vless', listen: '::' }] },
        { inbounds: [{ protocol: 'http', listen: '127.0.0.1' }] },
        { outbounds: [{ protocol: 'vless', settings: { vnext: [{ address: 'portal.invalid' }] } }] },
        { outbounds: [{ protocol: 'freedom', settings: { redirect: '192.0.2.1:1' } }] }]) {
        assert.throws(() => loopbackConfig({ ...config, ...unsafe }), /unsafe Xray/);
    }
});
