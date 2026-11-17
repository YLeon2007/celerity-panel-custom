'use strict';
// Executes the actual classic generator with inert dependency adapters: no
// logger, panel settings, DB, SSH or service is opened by this pure byte test.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
function readSource(file) {
    const parts = path.resolve(file).split('/').filter(Boolean);
    const directoryFlags = 0o10000000 | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
    let parent = fs.openSync('/', directoryFlags);
    try {
        for (const part of parts.slice(0, -1)) {
            const next = fs.openSync(`/proc/self/fd/${parent}/${part}`, directoryFlags);
            fs.closeSync(parent); parent = next;
        }
        const fd = fs.openSync(`/proc/self/fd/${parent}/${parts.at(-1)}`,
            fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NOATIME);
        try { return fs.readFileSync(fd, 'utf8'); } finally { fs.closeSync(fd); }
    } finally { fs.closeSync(parent); }
}
const root = path.resolve(__dirname, '../../..');
const generatorSource = readSource(path.join(root, 'src/services/configGenerator.js'));
const bootstrapSource = readSource(path.join(root, 'src/modules/relay-l2tp/services/topologyRunnerBootstrapper.js'));
const exportsObject = { exports: {} };
const imports = {
    yaml: {}, fs, path,
    '../utils/logger': {}, '../../config': {},
    '../modules/relay-l2tp/services/xrayConfigComposer': { composeXrayConfig() { throw Error('not used by unit generator'); } },
};
vm.runInNewContext(generatorSource, {
    module: exportsObject,
    require(name) { assert.ok(Object.hasOwn(imports, name), `unexpected dependency ${name}`); return imports[name]; },
    __dirname: path.join(root, 'src/services'), Buffer, process: { env: {} },
}, { filename: 'actual-configGenerator.js' });
const declaration = bootstrapSource.match(/const BRIDGE_UNIT_SOURCE = (\[[\s\S]*?\]\.join\('\\n'\));/);
assert.ok(declaration, 'actual bootstrap canonical unit declaration');
const canonical = vm.runInNewContext(declaration[1]);
test('classic bridge unit is byte-for-byte compatible with native bootstrap', () => {
    assert.equal(exportsObject.exports.generateBridgeSystemdService(), canonical);
});
test('classic bridge unit preserves canonical two final linefeeds', () => {
    const actual = exportsObject.exports.generateBridgeSystemdService();
    assert.equal(Buffer.byteLength(actual), 427);
    assert.equal(actual.match(/\n+$/)[0], '\n\n');
});
