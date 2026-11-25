'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createHash, createCipheriv, createDecipheriv, randomBytes, randomUUID } = require('node:crypto');
const { O_RDONLY, O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW, O_DIRECTORY, O_NONBLOCK } = fs.constants;

const MAX_BYTES = 8 * 1024 * 1024;
const IV_BYTES = 12, TAG_BYTES = 16, OVERHEAD = IV_BYTES + TAG_BYTES;
const stat = { bigint: true };
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![\s\S])/;
const SHA = /^[0-9a-f]{64}(?![\s\S])/;
const LABEL = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}(?![\s\S])/;
const valid = (pattern, value) => typeof value === 'string' && pattern.test(value);
const hash = data => createHash('sha256').update(data).digest('hex');
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const unchanged = (a, b) => same(a, b) && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
const owner = (row, mode) => row.uid === BigInt(process.geteuid()) && (row.mode & 0o7777n) === mode;
const privateFile = row => row.isFile() && owner(row, 0o600n) && row.nlink === 1n;
const refused = () => Object.assign(new Error('REBUILD_CUTOVER_ARTIFACT_UNPROVED'), { code: 'REBUILD_CUTOVER_ARTIFACT_UNPROVED' });
const need = condition => { if (!condition) throw refused(); };

function associatedData({ plan, step }, side, id) {
    need(valid(LABEL, plan.scope) && valid(UUID, plan.operationId) && valid(UUID, plan.fenceId)
        && valid(SHA, plan.planDigest) && valid(LABEL, step.id) && valid(UUID, id)
        && ['before', 'desired', 'confirmed'].includes(side));
    return Buffer.from(JSON.stringify(['rebuild-cutover-artifact-v1', plan.scope, plan.operationId,
        plan.fenceId, plan.planDigest, step.id, side, id]));
}

// A private, already provisioned durable directory and a trusted 256-bit key
// are mandatory. This stores exact caller-supplied bytes; it does not assert
// that a live/boot observation was complete or authorize any remote effect.
function createCutoverArtifactStore({ directory, key } = {}) {
    need(typeof directory === 'string' && path.isAbsolute(directory) && path.resolve(directory) === directory
        && Buffer.isBuffer(key) && key.length === 32);
    const secret = Buffer.from(key);
    let identity;
    function verifyDir(fd) {
        const dir = fs.fstatSync(fd, stat), named = fs.lstatSync(directory, stat);
        need(dir.isDirectory() && owner(dir, 0o700n) && same(dir, named) && (!identity || same(dir, identity)));
        identity ??= dir;
    }
    function useDir(fn) {
        try {
            const fd = fs.openSync(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            try { verifyDir(fd); const result = fn(fd); verifyDir(fd); return result; }
            finally { fs.closeSync(fd); }
        } catch { throw refused(); }
    }
    const at = (fd, id) => `/proc/self/fd/${fd}/${id}.sealed`;
    function readPacket(file, written) {
        const reader = fs.openSync(file, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
        try {
            const before = fs.fstatSync(reader, stat);
            need(privateFile(before) && before.size >= OVERHEAD && before.size <= MAX_BYTES + OVERHEAD
                && (!written || unchanged(before, written)));
            const bytes = Buffer.alloc(Number(before.size));
            for (let offset = 0; offset < bytes.length;) {
                const got = fs.readSync(reader, bytes, offset, bytes.length - offset, offset);
                need(got > 0);
                offset += got;
            }
            const after = fs.fstatSync(reader, stat), named = fs.lstatSync(file, stat);
            need(privateFile(after) && privateFile(named) && unchanged(before, after) && unchanged(after, named));
            return bytes;
        } finally { fs.closeSync(reader); }
    }
    useDir(() => {});
    return Object.freeze({
        seal(ctx, side, bytes) {
            return useDir(dir => {
                need(Buffer.isBuffer(bytes) && bytes.length <= MAX_BYTES);
                const id = randomUUID(), iv = randomBytes(IV_BYTES);
                const cipher = createCipheriv('aes-256-gcm', secret, iv);
                cipher.setAAD(associatedData(ctx, side, id));
                const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
                const packet = Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
                const file = at(dir, id);
                const fd = fs.openSync(file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600);
                let written;
                try {
                    fs.writeFileSync(fd, packet);
                    fs.fsyncSync(fd);
                    written = fs.fstatSync(fd, stat);
                    need(privateFile(written) && written.size === BigInt(packet.length));
                } finally { fs.closeSync(fd); }
                fs.fsyncSync(dir);
                need(readPacket(file, written).equals(packet));
                return { id, sha256: hash(packet) };
            });
        },
        read(ctx, side, pin) {
            return useDir(dir => {
                const { id, sha256 } = pin;
                need(valid(SHA, sha256));
                const aad = associatedData(ctx, side, id);
                const packet = readPacket(at(dir, id));
                need(hash(packet) === sha256);
                const decoder = createDecipheriv('aes-256-gcm', secret, packet.subarray(0, IV_BYTES));
                decoder.setAAD(aad);
                decoder.setAuthTag(packet.subarray(IV_BYTES, OVERHEAD));
                return Buffer.concat([decoder.update(packet.subarray(OVERHEAD)), decoder.final()]);
            });
        },
    });
}

module.exports = { createCutoverArtifactStore };
