'use strict';

const assert = require('node:assert/strict');

// Adapt payload-only fakes to the pinned exec capability. Each receiver needs
// its own immediately preceding, stdin-free observation on the same instance.
module.exports = (PayloadSSH, machineId) => class extends PayloadSSH {
    async connectDirectOnce(timeout) {
        assert.equal(this.usePool, false);
        assert.ok(Number.isSafeInteger(timeout) && timeout > 0);
        assert.equal(this.connectedOnce, undefined);
        this.connectedOnce = true;
        await this.connect();
        let observed = false;
        return (command, options, verify) => {
            if (command === '/usr/bin/head -c 34 /etc/machine-id') {
                assert.equal(Object.hasOwn(options, 'stdin'), false);
                assert.equal(verify, undefined);
                assert.equal(options.maxOutputBytes, 34);
                assert.ok(Number.isSafeInteger(options.timeout) && options.timeout > 0);
                observed = true;
                return { code: 0, stdout: `${machineId}\n`, stderr: '' };
            }
            assert.equal(observed, true, 'fresh attestation before opening the receiver');
            observed = false;
            assert.equal(typeof verify, 'function');
            return this.exec(command, options, verify);
        };
    }
};
