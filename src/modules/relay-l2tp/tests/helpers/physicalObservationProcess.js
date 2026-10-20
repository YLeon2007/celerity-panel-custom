'use strict';
// Explicit SIMULATED physical observation process; real bounded NDJSON channel.
const readline = require('node:readline');
const value = JSON.parse(process.argv[2]);
readline.createInterface({ input: process.stdin }).on('line', line => {
    const request = JSON.parse(line);
    if (value.fixtureBehavior === 'silent') return;
    if (value.fixtureBehavior === 'wrong-nonce') request.nonce = '0'.repeat(64);
    if (value.fixtureBehavior === 'malformed') { process.stdout.write('not-json\n'); return; }
    if (process.argv[3]) {
        const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
        const root = process.argv[3];
        const installed = path.join(root, 'usr/local/bin/celerity-topology-node-runner');
        const mode = fs.statSync(installed).mode & 0o777;
        value.installation = { runner: { path: '/usr/local/bin/celerity-topology-node-runner',
            sha256: 'sha256:' + crypto.createHash('sha256').update(fs.readFileSync(installed)).digest('hex'),
            mode: mode.toString(8).padStart(4, '0'), owner: 'root', regularFile: fs.lstatSync(installed).isFile(),
            symlink: fs.lstatSync(installed).isSymbolicLink(), writableByRunner: Boolean(mode & 0o022) },
        profile: { targetProfile: 'xray-main', configDirectoryReady: fs.statSync(path.join(root, 'usr/local/etc/xray')).isDirectory(),
            bridgeUnitSha256: null, bridgeUnitDropIns: null } };
        const journalPath = path.join(root, 'var/lib/celerity/topology/fences/xray-main/journal.json');
        if (fs.existsSync(journalPath)) {
            const journal = JSON.parse(fs.readFileSync(journalPath));
            value.runnerState = { head: journal.head, journal: 'present', legacyState: 'not-applicable', terminal: null };
            if (request.predecessor) {
                const b = request.predecessor.binding;
                const receipt = journal.generations[b.generation].commands[b.commandIds.close].receipt;
                value.runnerState.terminal = { ...receipt, command: 'status' };
            }
        }
    }
    process.stdout.write(JSON.stringify({ nonce: request.nonce, observation: value }) + '\n');
});
