'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { createL2tpStartupLifecycle } = require('../createL2tpStartupLifecycle');

function createEnabledHostDependencies() {
    return {
        HyNode: { findById() {} },
        NodeSSH: class FakeNodeSSH {},
        NodeTransport: class FakeNodeTransport {},
        preflightRunner: async () => ({ ok: true, checks: [] }),
        operationMaterializer: async () => ({ persistedPlan: {}, remoteArtifacts: [] }),
        secretBox: {
            encrypt() {},
            decrypt() {},
        },
        secretKey: 'test-only-secret-key',
        clock: { now: () => new Date('2026-09-22T12:00:00.000Z') },
        workerId: 'test-l2tp-worker',
        leaseMs: 30_000,
        workerLifecycle: {
            intervalMs: 1_000,
            timer: {
                setInterval() { return {}; },
                clearInterval() {},
            },
            logger: { error() {} },
        },
    };
}

test('false or missing enable flag constructs a dormant host and startup never starts it', () => {
    for (const config of [undefined, { enabled: false }]) {
        const calls = [];
        const host = {
            start() {
                calls.push('start');
            },
            async stop() {
                calls.push('stop');
            },
        };

        const lifecycle = createL2tpStartupLifecycle({
            config,
            createPanelHost(dependencies) {
                calls.push({ kind: 'create', dependencies });
                return host;
            },
        });

        assert.deepEqual(calls, [{
            kind: 'create',
            dependencies: { workerLifecycle: { enabled: false } },
        }]);
        assert.deepEqual(lifecycle.start(), {
            enabled: false,
            started: false,
            running: false,
            stopped: false,
        });
        assert.equal(calls.some(call => call === 'start'), false);
    }
});

test('rejects string enable flags instead of treating environment-like values as truthy', () => {
    let hostConstructions = 0;

    for (const enabled of ['true', 'false', '1', '0']) {
        assert.throws(
            () => createL2tpStartupLifecycle({
                config: { enabled },
                createPanelHost() {
                    hostConstructions += 1;
                    return { start() {}, async stop() {} };
                },
            }),
            /enabled must be a boolean/i,
        );
    }

    assert.equal(hostConstructions, 0);
});

test('enabled bootstrap rejects every missing execution dependency before host construction', () => {
    const dependencyNames = Object.keys(createEnabledHostDependencies());
    let hostConstructions = 0;

    for (const dependencyName of dependencyNames) {
        const hostDependencies = createEnabledHostDependencies();
        delete hostDependencies[dependencyName];

        assert.throws(
            () => createL2tpStartupLifecycle({
                config: { enabled: true },
                hostDependencies,
                createPanelHost() {
                    hostConstructions += 1;
                    return { start() {}, async stop() {} };
                },
            }),
            new RegExp(dependencyName, 'i'),
            dependencyName,
        );
    }

    assert.equal(hostConstructions, 0);
});

test('enabled bootstrap rejects undefined and incomplete execution dependencies', () => {
    const baseDependencies = createEnabledHostDependencies();
    let hostConstructions = 0;

    for (const dependencyName of Object.keys(baseDependencies)) {
        const hostDependencies = createEnabledHostDependencies();
        hostDependencies[dependencyName] = undefined;
        assert.throws(
            () => createL2tpStartupLifecycle({
                config: { enabled: true },
                hostDependencies,
                createPanelHost() {
                    hostConstructions += 1;
                    return { start() {}, async stop() {} };
                },
            }),
            new RegExp(dependencyName, 'i'),
            dependencyName,
        );
    }

    for (const dependencyName of ['intervalMs', 'timer', 'logger']) {
        const hostDependencies = createEnabledHostDependencies();
        delete hostDependencies.workerLifecycle[dependencyName];
        assert.throws(
            () => createL2tpStartupLifecycle({
                config: { enabled: true },
                hostDependencies,
                createPanelHost() {
                    hostConstructions += 1;
                    return { start() {}, async stop() {} };
                },
            }),
            new RegExp(dependencyName, 'i'),
            `workerLifecycle.${dependencyName}`,
        );
    }

    assert.equal(hostConstructions, 0);
});

test('enabled bootstrap validates execution dependency contracts before host construction', () => {
    const invalidDependencies = [
        ['HyNode', {}],
        ['NodeSSH', {}],
        ['NodeTransport', {}],
        ['preflightRunner', {}],
        ['operationMaterializer', {}],
        ['secretBox', {}],
        ['secretKey', ''],
        ['clock', {}],
        ['workerId', ''],
        ['leaseMs', 0],
        ['workerLifecycle.intervalMs', '1000'],
        ['workerLifecycle.timer', {}],
        ['workerLifecycle.logger', {}],
    ];
    let hostConstructions = 0;

    for (const [dependencyName, invalidValue] of invalidDependencies) {
        const hostDependencies = createEnabledHostDependencies();
        const [parentName, childName] = dependencyName.split('.');
        if (childName) {
            hostDependencies[parentName][childName] = invalidValue;
        } else {
            hostDependencies[parentName] = invalidValue;
        }

        assert.throws(
            () => createL2tpStartupLifecycle({
                config: { enabled: true },
                hostDependencies,
                createPanelHost() {
                    hostConstructions += 1;
                    return { start() {}, async stop() {} };
                },
            }),
            new RegExp(dependencyName.replace('.', '\\.'), 'i'),
            dependencyName,
        );
    }

    assert.equal(hostConstructions, 0);
});

test('enabled lifecycle starts and stops its host once with safe idempotent state', async () => {
    const hostDependencies = createEnabledHostDependencies();
    const calls = [];
    let finishStop;
    const host = {
        start() {
            calls.push('start');
            return { running: true, secretKey: 'must-not-escape' };
        },
        stop() {
            calls.push('stop');
            return new Promise(resolve => { finishStop = resolve; });
        },
    };
    let constructedWith;
    const lifecycle = createL2tpStartupLifecycle({
        config: { enabled: true },
        hostDependencies,
        createPanelHost(dependencies) {
            constructedWith = dependencies;
            return host;
        },
    });

    assert.deepEqual(calls, []);
    assert.strictEqual(constructedWith.NodeTransport, hostDependencies.NodeTransport);
    assert.deepEqual(constructedWith.workerLifecycle, {
        ...hostDependencies.workerLifecycle,
        enabled: true,
    });
    assert.equal(Object.hasOwn(hostDependencies.workerLifecycle, 'enabled'), false);

    const runningState = {
        enabled: true,
        started: true,
        running: true,
        stopped: false,
    };
    assert.deepEqual(lifecycle.start(), runningState);
    assert.deepEqual(lifecycle.start(), runningState);
    assert.deepEqual(calls, ['start']);
    assert.doesNotMatch(JSON.stringify(runningState), /must-not-escape/);

    let firstStopped = false;
    let secondStopped = false;
    const firstStop = lifecycle.stop().then(state => {
        firstStopped = true;
        return state;
    });
    const secondStop = lifecycle.stop().then(state => {
        secondStopped = true;
        return state;
    });
    await Promise.resolve();

    assert.deepEqual(calls, ['start', 'stop']);
    assert.equal(firstStopped, false);
    assert.equal(secondStopped, false);

    finishStop({ stopped: true, secretKey: 'must-not-escape' });
    const stoppedState = {
        enabled: true,
        started: true,
        running: false,
        stopped: true,
    };
    assert.deepEqual(await firstStop, stoppedState);
    assert.deepEqual(await secondStop, stoppedState);
    assert.deepEqual(await lifecycle.stop(), stoppedState);
    assert.deepEqual(lifecycle.start(), stoppedState);
    assert.deepEqual(calls, ['start', 'stop']);
    assert.doesNotMatch(JSON.stringify(stoppedState), /must-not-escape/);
});
