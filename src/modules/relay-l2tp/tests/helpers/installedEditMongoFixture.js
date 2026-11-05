'use strict';
// Dedicated real replica-set fixture. Never accepts a URI or attaches to an
// existing process. All destructive commands target this freshly named DB only.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const syncFs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID, createHash } = require('node:crypto');
const mongoose = require('mongoose');
const sha = value => createHash('sha256').update(value).digest('hex');
const startTicks = async pid => (await fs.readFile(`/proc/${pid}/stat`, 'utf8')).split(') ').at(-1).split(' ')[19];
const portClosed = port => new Promise(resolve => {
    const socket = net.connect({ host: '127.0.0.1', port });
    socket.setTimeout(1000, () => { socket.destroy(); resolve(false); });
    socket.once('connect', () => { socket.destroy(); resolve(false); });
    socket.once('error', error => resolve(error.code === 'ECONNREFUSED'));
});
function fixture() {
    let child, directory, connection, database, port, models, evidence;
    const commands = [], lifecycle = {}, sessions = [];
    const guarded = () => {
        assert.match(database, /^c3_installed_edit_[a-f0-9]{32}$/);
        assert.equal(connection.name, database);
        assert.equal(connection.host, '127.0.0.1'); assert.equal(connection.port, port);
    };
    const save = async () => {
        if (evidence) {
            await fs.writeFile(path.join(evidence, 'commands.json'), JSON.stringify(commands, null, 2));
            await fs.writeFile(path.join(evidence, 'fixture-lifecycle.json'), JSON.stringify(lifecycle, null, 2));
        }
    };
    async function until(work, milliseconds = 15000) {
        const deadline = Date.now() + milliseconds; let error;
        while (Date.now() < deadline) {
            try { return await work(); } catch (e) { error = e; }
            if (child.exitCode !== null) throw Error(`owned mongod exited ${child.exitCode}: ${error?.message}`);
            await new Promise(resolve => setTimeout(resolve, 50));
        }
        throw error || Error('owned fixture deadline exceeded');
    }
    return {
        commands, sessions, lifecycle, guarded,
        get models() { return models; }, get connection() { return connection; },
        async start() {
            assert.ok(process.env.C3_MONGOD, 'existing local C3_MONGOD required; never skip Mongo proof');
            const scratch = await fs.realpath(process.env.TMPDIR);
            assert.ok(scratch.startsWith('/home/leon/.hermes/cache/scratch/'));
            assert.equal(syncFs.existsSync(path.resolve(__dirname, '../../../../..', '.env')), false);
            directory = await fs.mkdtemp(path.join(scratch, 'installed-edit-'));
            evidence = process.env.C3_INSTALLED_EDIT_MONGO_EVIDENCE;
            if (evidence) await fs.mkdir(evidence, { recursive: true });
            port = await new Promise(resolve => { const server = net.createServer();
                server.listen(0, '127.0.0.1', () => { const p = server.address().port; server.close(() => resolve(p)); }); });
            database = `c3_installed_edit_${randomUUID().replaceAll('-', '')}`;
            const replicaSet = `c3_edit_${process.pid}`;
            const logpath = path.join(evidence || directory, 'mongod.log');
            child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
                '--replSet', replicaSet, '--wiredTigerCacheSizeGB', '0.25', '--oplogSize', '32', '--logpath', logpath],
            { stdio: ['ignore', 'ignore', 'pipe'] });
            let stderr = ''; child.stderr.on('data', data => { stderr += data; });
            Object.assign(lifecycle, { pid: child.pid, startTicks: await startTicks(child.pid), port, directory, database,
                replicaSet, logpath, binary: process.env.C3_MONGOD, binarySha256: sha(await fs.readFile(process.env.C3_MONGOD)),
                startedAt: new Date().toISOString() });
            await save();
            const direct = new mongoose.mongo.MongoClient(`mongodb://127.0.0.1:${port}/admin?directConnection=true`, {
                serverSelectionTimeoutMS: 200, connectTimeoutMS: 500 });
            try {
                await until(() => direct.connect());
                await direct.db('admin').command({ replSetInitiate: { _id: replicaSet,
                    members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
                await until(async () => assert.equal((await direct.db('admin').command({ hello: 1 })).isWritablePrimary, true));
                lifecycle.replicaSetId = String((await direct.db('local').collection('system.replset').findOne({})).settings.replicaSetId);
            } catch (error) { error.message += `; owned mongod stderr: ${stderr}`; throw error; }
            finally { await direct.close(); }
            await mongoose.connect(`mongodb://127.0.0.1:${port}/${database}?replicaSet=${replicaSet}&appName=c3-installed-edit`, {
                monitorCommands: true, serverSelectionTimeoutMS: 5000, maxPoolSize: 4 });
            connection = mongoose.connection; guarded();
            connection.getClient().on('commandStarted', event => {
                const c = event.command, name = event.commandName;
                if (!['find', 'findAndModify', 'insert', 'update', 'delete', 'commitTransaction', 'abortTransaction'].includes(name)) return;
                // Only metadata/predicate field names are retained, no secret/config bytes.
                commands.push({ name, databaseName: event.databaseName, collection: c[name],
                    lsid: c.lsid ? mongoose.mongo.BSON.EJSON.stringify(c.lsid) : null,
                    txnNumber: c.txnNumber?.toString(), autocommit: c.autocommit, startTransaction: c.startTransaction,
                    readConcern: c.readConcern, writeConcern: c.writeConcern, projection: c.projection,
                    updateFields: c.updates?.map(row => Object.keys(row.u.$set || {})),
                    filterFields: Object.keys(c.filter || {}), readPreference: c.$readPreference });
            });
            models = { ...require('../..').registerModels(), HyNode: require('../../../../models/hyNodeModel'),
                CascadeLink: require('../../../../models/cascadeLinkModel') };
            for (const model of Object.values(models)) { assert.ok(model.db === connection); await model.init(); }
            await save();
        },
        async reset() {
            guarded();
            // Immutable model hooks intentionally stay enabled; administrative
            // raw cleanup is confined to this exact scratch database.
            for (const model of Object.values(models)) await model.collection.deleteMany({});
        },
        async stop() {
            const errors = [];
            if (connection?.readyState === 1) {
                try { guarded(); await connection.dropDatabase();
                    lifecycle.databaseAbsent = !(await connection.getClient().db('admin').admin().listDatabases())
                        .databases.some(row => row.name === database);
                    assert.equal(lifecycle.databaseAbsent, true);
                } catch (error) { errors.push(error.message); }
            }
            require.cache[require.resolve('../../../../services/sshPoolService')]?.exports.closeAll();
            try { await mongoose.disconnect(); } catch (error) { errors.push(error.message); }
            if (child && child.exitCode === null) {
                try {
                    assert.equal(await startTicks(child.pid), lifecycle.startTicks, 'signal only the exact owned child');
                    const exit = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM');
                    await Promise.race([exit, new Promise((_, reject) => {
                        const timer = setTimeout(() => reject(Error('owned mongod did not terminate')), 15000); timer.unref();
                    })]);
                } catch (error) { errors.push(error.message); }
            }
            lifecycle.exitCode = child?.exitCode; lifecycle.signalCode = child?.signalCode;
            lifecycle.processExited = child ? child.exitCode !== null || child.signalCode !== null : false;
            lifecycle.pidAbsent = child ? !syncFs.existsSync(`/proc/${child.pid}`) : false;
            if (directory && lifecycle.processExited && lifecycle.pidAbsent) {
                await fs.rm(directory, { recursive: true, force: true }); lifecycle.directoryAbsent = !syncFs.existsSync(directory);
            }
            if (port) lifecycle.portClosed = await portClosed(port);
            lifecycle.cleanupErrors = errors; lifecycle.finishedAt = new Date().toISOString(); await save();
            assert.deepEqual(errors, []); assert.equal(lifecycle.databaseAbsent, true);
            assert.equal(lifecycle.processExited, true); assert.equal(lifecycle.pidAbsent, true);
            assert.equal(lifecycle.directoryAbsent, true); assert.equal(lifecycle.portClosed, true);
        },
    };
}
module.exports = { fixture, sha };
