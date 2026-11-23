'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
const test = require('node:test');

test('DIRECT runtime reattestation: modeled host with real file and lock guards', () => {
    const result = spawnSync('/usr/bin/python3', ['-I', '-B', join(__dirname, 'rebuildRelayDirectReattestHost.py'), '-v'],
        { cwd: join(__dirname, '../../..'), env: {}, encoding: 'utf8', timeout: 15000 });
    assert.equal(result.status, 0, result.stderr || result.error?.message);
});
