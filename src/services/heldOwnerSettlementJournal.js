'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const STATE = '/var/lib/c3-test-node-isolation';
function need(ok) { if (!ok) throw new Error('OWNER_SETTLEMENT_JOURNAL_UNKNOWN_RETAINED'); }
// This journal never authorizes handback. It is a private durable no-replay
// record of partial progress; its existence ALWAYS refuses a new invocation.
class HeldOwnerSettlementJournal {
    #directory; #file; #expected; #uid; #poisoned = false;
    constructor({ directory = STATE, uid = 0, fixtureRoot } = {}) {
        this.#directory = directory; this.#uid = uid;
        need(!fixtureRoot || (uid !== 0 && uid === process.getuid() && directory.startsWith(fixtureRoot + '/')));
        need(path.isAbsolute(directory) && path.normalize(directory) === directory);
        for (let current = directory; ; current = path.dirname(current)) {
            const st = fs.lstatSync(current);
            need(st.isDirectory() && !st.isSymbolicLink() && [0, uid].includes(st.uid) && !(st.mode & 0o022));
            if (current === '/' || current === fixtureRoot) break;
        }
        const st = fs.lstatSync(directory); need(st.uid === uid && (st.mode & 0o777) === 0o700);
        this.#file = path.join(directory, 'owner-settlement.json');
    }
    #syncDirectory() {
        const fd = fs.openSync(this.#directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
        try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    }
    #read() {
        const fd = fs.openSync(this.#file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        try {
            const st = fs.fstatSync(fd);
            need(st.isFile() && st.uid === this.#uid && st.nlink === 1 && (st.mode & 0o777) === 0o600 && st.size <= 65536);
            return JSON.parse(fs.readFileSync(fd, 'utf8'));
        } finally { fs.closeSync(fd); }
    }
    #write(value, initial = false) {
        need(!this.#poisoned);
        try {
            if (!initial) { need(same(this.#read(), this.#expected)); need(!fs.existsSync(this.#file + '.next')); }
            const target = initial ? this.#file : this.#file + '.next';
            const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
            try { fs.writeFileSync(fd, JSON.stringify(value) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
            if (!initial) fs.renameSync(target, this.#file);
            this.#syncDirectory();
            this.#expected = structuredClone(value);
            need(same(this.#read(), value));
        } catch (error) { this.#poisoned = true; throw error; }
    }
    start(plan) {
        need(!this.#expected && !fs.existsSync(this.#file + '.next'));
        this.#write({ version: 1, id: randomUUID(), plan, phase: 'settling-held', inFlightNode: null, settled: [] }, true);
    }
    beforeNode(nodeId) {
        need(this.#expected?.phase === 'settling-held' && this.#expected.inFlightNode === null
            && !this.#expected.settled.some(n => n.nodeId === nodeId));
        this.#write({ ...this.#expected, inFlightNode: nodeId });
    }
    afterNode(nodeId, generation) {
        need(this.#expected?.inFlightNode === nodeId);
        this.#write({ ...this.#expected, inFlightNode: null, settled: [...this.#expected.settled, { nodeId, generation }] });
    }
    committed(commitSha256) {
        need(this.#expected?.phase === 'settled-held' && typeof commitSha256 === 'string' && /^[a-f0-9]{64}$/.test(commitSha256));
        this.#write({ ...this.#expected, phase: 'irreversibly-committed', commitSha256 });
    }
    complete() {
        need(this.#expected?.phase === 'settling-held' && this.#expected.inFlightNode === null && this.#expected.settled.length === 5);
        this.#write({ ...this.#expected, phase: 'settled-held' });
    }
}
module.exports = { HeldOwnerSettlementJournal };
