'use strict';

const fs = require('node:fs');
const { createHash, randomFillSync } = require('node:crypto');
const { join } = require('node:path');

const SEED_BYTES = 64, PUBLIC_BYTES = 1184, MEMORY_BYTES = 4 * 1024 * 1024;
const WASM_SHA256 = '3877680a811f50bd948dd0ad9bfb83214df267fc3e4376f22aad5edcfd9790a0';
let compiled;

function load() {
    if (!compiled) {
        const bytes = fs.readFileSync(join(__dirname, 'mlkem768', 'mlkem768.wasm'));
        if (createHash('sha256').update(bytes).digest('hex') !== WASM_SHA256) {
            throw new Error('ML-KEM portable artifact mismatch');
        }
        compiled = new WebAssembly.Module(bytes);
    }
    return compiled;
}

// Closed WASI imports for the pinned Go runtime, not Node's general WASI host.
// Only a clock, empty argv/env and RNG for Go runtime initialization are backed.
function runtimeImports(getMemory) {
    const view = () => new DataView(getMemory().buffer);
    const empty = (count, size) => {
        const data = view();
        data.setUint32(count, 0, true);
        data.setUint32(size, 0, true);
        return 0;
    };
    const deny = () => { throw new Error('ML-KEM portable runtime import denied'); };
    const badFd = () => 8; // WASI ERRNO_BADF: there are no descriptors, including stdio.
    return { wasi_snapshot_preview1: {
        args_sizes_get: empty, environ_sizes_get: empty,
        args_get: deny, environ_get: deny,
        clock_time_get: (clock, _precision, address) => {
            if (clock !== 0 && clock !== 1) return deny();
            const time = clock === 0 ? BigInt(Date.now()) * 1000000n : process.hrtime.bigint();
            view().setBigUint64(address, time, true);
            return 0;
        },
        random_get: (address, size) => {
            randomFillSync(new Uint8Array(getMemory().buffer, address, size));
            return 0;
        },
        fd_prestat_get: badFd, fd_prestat_dir_name: badFd,
        fd_fdstat_get: badFd, fd_fdstat_set_flags: badFd, fd_close: badFd,
        fd_write: deny, proc_exit: deny, poll_oneoff: deny, sched_yield: deny,
    } };
}

module.exports = function deriveMLKEM768(seed) {
    if (!Buffer.isBuffer(seed) || seed.length !== SEED_BYTES) throw new Error('Invalid ML-KEM seed size');
    let memory;
    try {
        const { exports } = new WebAssembly.Instance(load(), runtimeImports(() => memory));
        memory = exports.memory;
        if (memory.buffer.byteLength !== MEMORY_BYTES) throw new Error('Unexpected ML-KEM memory size');
        exports._initialize();
        const scratch = new Uint8Array(memory.buffer, exports.buffer(), SEED_BYTES + PUBLIC_BYTES);
        scratch.set(seed);
        if (exports.derive() !== PUBLIC_BYTES) throw new Error('Invalid ML-KEM public key size');
        return Buffer.from(scratch.buffer, scratch.byteOffset + SEED_BYTES, PUBLIC_BYTES).toString('base64url');
    } finally {
        // Discard the whole instance per call, including Go stack/heap copies of the expanded key.
        if (memory) new Uint8Array(memory.buffer).fill(0);
    }
};
