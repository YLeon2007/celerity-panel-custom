'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { withFreshOperationalRestoration } = require('../heldRestorationChannel');
const { spawn } = require('node:child_process');
test('JS fresh bridge sends one terminal request and accepts natural finite exit', async () => {
    const python = "import json,sys\nfor line in sys.stdin:\n r=json.loads(line); op=r['op']; print(json.dumps({**{k:v for k,v in r.items() if k!='proof'},'op':'checked' if op=='check' else op+'-ack',**({} if op=='check' else {'commitSha256':'a'*64})}),flush=True)\n if op=='fresh-handback': break\n";
    const inputs = { pins: [], config: {}, assertPins() {} };
    const result = await withFreshOperationalRestoration(inputs, async scope => {
        assert.equal(typeof scope.freshHandback, 'function');
        return scope.freshHandback({ proof: 'terminal' });
    }, { openBridge: () => spawn('/usr/bin/python3', ['-B', '-c', python], { stdio: ['pipe', 'pipe', 'pipe'] }) });
    assert.equal(result, 'a'.repeat(64));
});

test('JS fresh bridge maps lost terminal reply to committed unknown without replay', async () => {
    const python = "import json,sys\nfor line in sys.stdin:\n r=json.loads(line); op=r['op']\n if op=='fresh-handback': sys.exit(0)\n print(json.dumps({**r,'op':'checked'}),flush=True)\n";
    const inputs = { pins: [], config: {}, assertPins() {} };
    let service;
    let error;
    try {
        await withFreshOperationalRestoration(inputs, async scope => {
            service = scope;
            await scope.freshHandback({ proof: 'terminal' });
        }, { openBridge: () => spawn('/usr/bin/python3', ['-B', '-c', python], { stdio: ['pipe', 'pipe', 'pipe'] }) });
        assert.fail('terminal loss unexpectedly succeeded');
    } catch (caught) { error = caught; }
    assert.equal(error.code, 'COMMITTED_ACTIVATION_UNKNOWN');
    await assert.rejects(service.freshHandback({ proof: 'replay' }));
});
