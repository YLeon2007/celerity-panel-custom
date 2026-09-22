'use strict';

const REQUIRED_ENABLED_DEPENDENCIES = Object.freeze([
    'HyNode',
    'NodeSSH',
    'NodeTransport',
    'createPreflightRunner',
    'createCandidateService',
    'candidateNodeResolver',
    'candidateUserResolver',
    'configGenerator',
    'fragmentProvider',
    'operationMaterializer',
    'secretBox',
    'secretKey',
    'clock',
    'workerId',
    'leaseMs',
    'workerLifecycle',
]);

function lifecycleState({ enabled, started, stopped }) {
    return {
        enabled,
        started,
        running: enabled && started && !stopped,
        stopped,
    };
}

function readEnabled(config) {
    if (config === undefined) return false;
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
        throw new TypeError('L2TP startup config must be an object');
    }
    if (config.enabled === undefined) return false;
    if (typeof config.enabled !== 'boolean') {
        throw new TypeError('L2TP startup config enabled must be a boolean');
    }
    return config.enabled;
}

function assertEnabledDependencies(hostDependencies) {
    for (const dependencyName of REQUIRED_ENABLED_DEPENDENCIES) {
        if (
            !Object.hasOwn(hostDependencies, dependencyName)
            || hostDependencies[dependencyName] === undefined
            || hostDependencies[dependencyName] === null
        ) {
            throw new TypeError(
                `L2TP enabled startup requires explicit ${dependencyName}`,
            );
        }
    }

    for (const dependencyName of ['intervalMs', 'timer', 'logger']) {
        if (
            !Object.hasOwn(hostDependencies.workerLifecycle, dependencyName)
            || hostDependencies.workerLifecycle[dependencyName] === undefined
            || hostDependencies.workerLifecycle[dependencyName] === null
        ) {
            throw new TypeError(
                `L2TP enabled startup requires explicit workerLifecycle.${dependencyName}`,
            );
        }
    }

    if (typeof hostDependencies.HyNode.findById !== 'function') {
        throw new TypeError('L2TP enabled startup requires HyNode.findById');
    }
    for (const dependencyName of [
        'NodeSSH',
        'NodeTransport',
        'createPreflightRunner',
        'createCandidateService',
        'candidateNodeResolver',
        'candidateUserResolver',
        'configGenerator',
        'fragmentProvider',
        'operationMaterializer',
    ]) {
        if (typeof hostDependencies[dependencyName] !== 'function') {
            throw new TypeError(`L2TP enabled startup requires ${dependencyName} to be a function`);
        }
    }
    if (
        typeof hostDependencies.secretBox.encrypt !== 'function'
        || typeof hostDependencies.secretBox.decrypt !== 'function'
    ) {
        throw new TypeError('L2TP enabled startup requires secretBox encrypt/decrypt functions');
    }
    if (
        typeof hostDependencies.secretKey !== 'string'
        || hostDependencies.secretKey.trim().length === 0
    ) {
        throw new TypeError('L2TP enabled startup requires a non-empty secretKey');
    }
    if (typeof hostDependencies.clock.now !== 'function') {
        throw new TypeError('L2TP enabled startup requires clock.now');
    }
    if (
        typeof hostDependencies.workerId !== 'string'
        || hostDependencies.workerId.trim().length === 0
    ) {
        throw new TypeError('L2TP enabled startup requires a non-empty workerId');
    }
    if (!Number.isSafeInteger(hostDependencies.leaseMs) || hostDependencies.leaseMs <= 0) {
        throw new TypeError('L2TP enabled startup requires leaseMs to be a positive integer');
    }
    if (
        !Number.isSafeInteger(hostDependencies.workerLifecycle.intervalMs)
        || hostDependencies.workerLifecycle.intervalMs <= 0
    ) {
        throw new TypeError(
            'L2TP enabled startup requires workerLifecycle.intervalMs to be a positive integer',
        );
    }
    if (
        typeof hostDependencies.workerLifecycle.timer.setInterval !== 'function'
        || typeof hostDependencies.workerLifecycle.timer.clearInterval !== 'function'
    ) {
        throw new TypeError(
            'L2TP enabled startup requires workerLifecycle.timer setInterval/clearInterval functions',
        );
    }
    if (typeof hostDependencies.workerLifecycle.logger.error !== 'function') {
        throw new TypeError('L2TP enabled startup requires workerLifecycle.logger.error');
    }
}

function createL2tpStartupLifecycle({
    config,
    hostDependencies = {},
    createPanelHost,
} = {}) {
    const enabled = readEnabled(config);
    if (enabled) assertEnabledDependencies(hostDependencies);
    const hostFactory = createPanelHost
        ?? require('./createL2tpPanelHost').createL2tpPanelHost;
    const host = hostFactory({
        ...hostDependencies,
        workerLifecycle: {
            ...hostDependencies.workerLifecycle,
            enabled,
        },
    });
    let started = false;
    let stopped = false;
    let stopPromise;

    return {
        start() {
            if (enabled && !started && !stopped) {
                host.start();
                started = true;
            }
            return lifecycleState({ enabled, started, stopped });
        },
        stop() {
            if (stopPromise === undefined) {
                stopped = true;
                stopPromise = Promise.resolve(enabled ? host.stop() : undefined)
                    .then(() => lifecycleState({ enabled, started, stopped }));
            }
            return stopPromise;
        },
    };
}

module.exports = {
    createL2tpStartupLifecycle,
};
