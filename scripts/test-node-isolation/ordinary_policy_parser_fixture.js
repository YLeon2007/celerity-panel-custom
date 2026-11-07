'use strict';
// Exercise the shipped public parser unchanged. Only root/private filesystem
// ownership and fixed-path placement are modeled; bytes, hashes and parser run.
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const api = require('../../src/services/heldRestorationChannel');
const files = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const rawPolicy = fs.readFileSync(files['/etc/c3-test-fresh-classic.json']);
const original = Object.fromEntries(['lstatSync', 'openSync', 'fstatSync'].map(k => [k, fs[k]]));
const uid = process.getuid, owned = new Set(), ancestors = new Set(['/']);
for (const file of Object.keys(files)) {
    for (let p = path.dirname(file); p !== '/'; p = path.dirname(p)) ancestors.add(p);
}
const rootOwned = s => new Proxy(s, { get: (s, key) => key === 'uid' || key === 'gid' ? 0 : Reflect.get(s, key) });
try {
    process.getuid = () => 0;
    fs.lstatSync = file => {
        if (Object.hasOwn(files, file)) return rootOwned(original.lstatSync(files[file]));
        if (ancestors.has(file)) return rootOwned(original.lstatSync(path.dirname(process.argv[2])));
        throw new Error('unmodeled root path: ' + file);
    };
    fs.openSync = (file, ...args) => {
        if (!Object.hasOwn(files, file)) throw new Error('unmodeled root read: ' + file);
        const fd = original.openSync(files[file], ...args); owned.add(fd); return fd;
    };
    fs.fstatSync = fd => { if (!owned.has(fd)) throw new Error('unmodeled descriptor'); return rootOwned(original.fstatSync(fd)); };
    const inputs = api.freshOperationalInputs(); inputs.assertPins();
    process.stdout.write(JSON.stringify({ accepted: true, policySha256: createHash('sha256').update(rawPolicy).digest('hex') }) + '\n');
} catch (error) {
    process.stdout.write(JSON.stringify({ accepted: false, error: error.message }) + '\n');
} finally {
    Object.assign(fs, original); process.getuid = uid;
}
