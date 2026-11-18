'use strict';

const Module = require('node:module');

// Keep the pure suites independent of key derivation and panel settings.
const load = Module._load;
let composer;
try {
    Module._load = function (request, ...args) {
        if (request === '../../../services/rebuildLinkKeys') {
            return { tunnelSettings: link => link._rebuildVless };
        }
        return load.call(this, request, ...args);
    };
    composer = require('../../services/rebuildTopologyComposer');
} finally {
    Module._load = load;
}

const syntheticTunnelSettings = n => ({ decryption: `fixture-decryption-${n}`, encryption: `fixture-encryption-${n}` });

module.exports = { ...composer, syntheticTunnelSettings };