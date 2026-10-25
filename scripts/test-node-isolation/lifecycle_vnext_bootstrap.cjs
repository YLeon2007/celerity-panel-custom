'use strict';
// Versioned LOCAL invocation admission, before importing index.js/dependencies/DDL.
// Not writer-generation or terminal handback authority. No deploy/normal D path.
const fs = require('node:fs');
const crypto = require('node:crypto');
try {
    const readFd = Number(process.env.C3_VNEXT_CAPSULE_FD);
    const ackFd = Number(process.env.C3_VNEXT_ACK_FD);
    if (!Number.isInteger(readFd) || !Number.isInteger(ackFd) || readFd < 3 || ackFd < 3 || readFd === ackFd
        || !fs.fstatSync(readFd).isFIFO() || !fs.fstatSync(ackFd).isFIFO()) throw Error('FD_REQUIRED');
    const bytes = Buffer.alloc(4097);
    const count = fs.readSync(readFd, bytes, 0, bytes.length, null);
    fs.closeSync(readFd);
    if (count === 0 || count > 4096) throw Error('CAPSULE_SIZE');
    const c = JSON.parse(bytes.subarray(0, count).toString('utf8'));
    if (c.schema !== 'c3-local-temporary-invocation/1' || !['F', 'R'].includes(c.role)
        || !/^[0-9a-f]{32}$/.test(c.invocation) || !/^[0-9a-f]{64}$/.test(c.indexSha256)
        || c.bootId !== fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim()
        || !/^[0-9]+$/.test(c.deadlineNs) || process.hrtime.bigint() >= BigInt(c.deadlineNs)
        || c.index !== process.cwd() + '/index.js' || !process.env.C3_SETTINGS
        || crypto.createHash('sha256').update(fs.readFileSync(c.index)).digest('hex') !== c.indexSha256) {
        throw Error('CAPSULE_REFUSED');
    }
    delete process.env.C3_VNEXT_CAPSULE_FD;
    delete process.env.C3_VNEXT_ACK_FD;
    // No lifecycle owner/control/peer FDs enter Node. These two one-use admission
    // pipes are closed before normal async app work; PDEATHSIG persists over exec.
    require(c.index);
    fs.writeSync(ackFd, 'LOCAL_TEMPORARY_ADMITTED\n');
    fs.closeSync(ackFd);
} catch (_) {
    fs.writeSync(2, 'VNEXT_BOOTSTRAP_REFUSED\n');
    process.exit(1);
}
