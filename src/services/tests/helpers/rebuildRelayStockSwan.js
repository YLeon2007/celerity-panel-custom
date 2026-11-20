'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { join } = require('node:path');

const profile = '/etc/strongswan.d/celerity-rebuild-l2tp.conf';

function seed(root) {
    const from = process.env.C3_FIXTURE_SWAN_ETC;
    assert.ok(from && from !== '/etc' && from.startsWith('/'), 'require separately mounted stock settings fixture');
    const leaves = [];
    function copy(relative) {
        const source = join(from, relative), target = join(root, 'etc', relative);
        const st = fs.lstatSync(source);
        if (st.isDirectory()) {
            fs.mkdirSync(target, { mode: 0o755 });
            for (const name of fs.readdirSync(source).sort()) copy(join(relative, name));
        } else {
            assert.ok(st.isFile(), 'stock settings must be ordinary files');
            fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL);
            fs.chmodSync(target, st.mode & 0o777);
            leaves.push('/etc/' + relative);
        }
    }
    copy('strongswan.conf');
    copy('strongswan.d');
    assert.equal(leaves.length, 25);
    assert.ok(!leaves.includes(profile));
    return leaves;
}

module.exports = { seed, profile };