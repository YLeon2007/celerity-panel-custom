'use strict';

const assert = require('node:assert/strict');
const { readlinkSync, mkdtempSync, openSync, closeSync, readFileSync, rmSync } = require('node:fs');
const { spawn, execFileSync } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');

const PORT = '27198';
const SET = 'isolated_retire_join';
const endpoint = `127.0.0.1:${PORT}`;
const uri = `mongodb://${endpoint}/?directConnection=true`;

function guard(parent) {
    assert.match(parent ?? '', /^net:\[\d+\]$/);
    assert.notEqual(readlinkSync('/proc/self/ns/net'), parent);
    const ip = (...args) => JSON.parse(execFileSync('/tools/ip', ['-j', ...args], { timeout: 1000 }));
    const links = ip('address');
    assert.deepEqual(links.map(link => link.ifname), ['lo']);
    assert.ok(links[0].flags.includes('UP'));
    assert.deepEqual(ip('-4', 'route', 'show'), []);
    assert.deepEqual(ip('-6', 'route', 'show'), []);
}

function child(exe, args, opts) {
    const proc = spawn(exe, args, opts);
    const exited = new Promise(resolve => {
        proc.once('error', error => resolve({ error }));
        proc.once('close', (code, signal) => resolve({ code, signal }));
    });
    return { proc, exited };
}

async function primary(mongod) {
    const { MongoClient } = require('mongoose').mongo;
    let initiated = false, lastError;
    const until = performance.now() + 15_000;
    while (performance.now() < until) {
        if (mongod.exitCode !== null || mongod.signalCode !== null) throw new Error('mongod exited before primary');
        // An early selection failure can close the driver's topology; use a
        // fresh client to poll readiness, not to retry the initiate command.
        const client = new MongoClient(uri, { connectTimeoutMS: 400, serverSelectionTimeoutMS: 600 });
        try {
            const admin = client.db('admin');
            const hello = await admin.command({ hello: 1 }).catch(error => { lastError = error; return null; });
            if (hello?.isWritablePrimary && hello.setName === SET) {
                assert.deepEqual(hello.hosts, [endpoint]);
                return;
            }
            if (hello && !initiated) {
                await admin.command({ replSetInitiate: { _id: SET, members: [{ _id: 0, host: endpoint }] } }, { timeoutMS: 5000 });
                initiated = true;
            }
        } finally {
            await client.close();
        }
        await delay(100);
    }
    throw new Error('fixture replica set did not become primary', { cause: lastError });
}

async function stop({ proc, exited }) {
    proc.kill('SIGTERM');
    const escalate = setTimeout(() => proc.kill('SIGKILL'), 8000);
    try { return await exited; }
    finally { clearTimeout(escalate); }
}

async function main() {
    guard(process.env.PARENT_NETNS);
    const mode = process.env.FIXTURE_MODE;
    assert.ok(['graph', 'public'].includes(mode));
    const scratch = mkdtempSync('/tmp/retire-');
    const log = `${scratch}/mongod.log`;
    const fd = openSync(log, 'wx');
    const mongo = child('/tools/mongod', ['--dbpath', scratch, '--bind_ip', '127.0.0.1', '--port', PORT,
        '--replSet', SET, '--nounixsocket', '--wiredTigerCacheSizeGB', '0.25', '--oplogSize', '32',
        '--setParameter', 'diagnosticDataCollectionEnabled=false'], { stdio: ['ignore', fd, fd] });
    closeSync(fd);
    let witnessedPrimary = false;
    try {
        await primary(mongo.proc);
        witnessedPrimary = true;
        console.log(`fixture=${SET} native primary at ${endpoint} in a fresh loopback-only netns`);
        const suite = child('/tools/node', ['--test', '--test-reporter=tap', '/app/scripts/integration.cjs'], {
            stdio: 'inherit', env: { ...process.env, C3_RETIRE_FIXTURE_PORT: PORT },
        });
        const terminate = setTimeout(() => suite.proc.kill('SIGTERM'), 65_000);
        const kill = setTimeout(() => suite.proc.kill('SIGKILL'), 70_000);
        try { assert.deepEqual(await suite.exited, { code: 0, signal: null }, 'test process exit'); }
        finally { clearTimeout(terminate); clearTimeout(kill); }
    } finally {
        const result = await stop(mongo);
        console.log('mongod original child wait:', JSON.stringify(result));
        if (!witnessedPrimary || result.code !== 0) console.error(readFileSync(log, 'utf8').split('\n').slice(-15).join('\n'));
        rmSync(scratch, { recursive: true });
        if (witnessedPrimary) assert.deepEqual(result, { code: 0, signal: null }, 'native Mongo shutdown');
    }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { guard, PORT, SET, uri };
