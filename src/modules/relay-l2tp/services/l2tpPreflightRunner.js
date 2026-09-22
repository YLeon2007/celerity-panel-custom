'use strict';

const { randomBytes: defaultRandomBytes } = require('node:crypto');

const {
    sanitizePreflightResult,
} = require('./l2tpPreflightResult');

const PREFLIGHT_OPERATION_BYTES = 12;
const PREFLIGHT_DESIRED_FIELDS = Object.freeze([
    'clientCidr',
    'localAddress',
    'poolStart',
    'poolEnd',
    'dnsServers',
    'tproxyPort',
    'fwmark',
    'routeTable',
]);

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity._id ?? entity.id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function preflightDesired(desired) {
    return PREFLIGHT_DESIRED_FIELDS.reduce((result, field) => {
        result[field] = Array.isArray(desired[field]) ? [...desired[field]] : desired[field];
        return result;
    }, {});
}

function isNonArrayObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasValidatedDesiredShape(desired) {
    return isNonArrayObject(desired)
        && desired.desiredState === 'installed'
        && typeof desired.clientCidr === 'string'
        && typeof desired.localAddress === 'string'
        && typeof desired.poolStart === 'string'
        && typeof desired.poolEnd === 'string'
        && Array.isArray(desired.dnsServers)
        && desired.dnsServers.length > 0
        && desired.dnsServers.every(server => typeof server === 'string')
        && Number.isSafeInteger(desired.tproxyPort)
        && Number.isSafeInteger(desired.fwmark)
        && Number.isSafeInteger(desired.routeTable);
}

function hasValidatedInstallContext(context) {
    if (!isNonArrayObject(context) || !isNonArrayObject(context.relay)) return false;
    const relayId = entityId(context.relay);
    const nodeId = entityId(context.node);
    return relayId !== null
        && relayId.length > 0
        && relayId === nodeId
        && (context.relay.role ?? context.relay.cascadeRole) === 'relay'
        && hasValidatedDesiredShape(context.desired)
        && isNonArrayObject(context.routeGroup)
        && isNonArrayObject(context.relayGroupPlan)
        && Number.isSafeInteger(context.topologyRevision)
        && context.topologyRevision >= 0;
}

function failure(code) {
    return {
        ok: false,
        checks: [],
        error: { code },
    };
}

class L2tpPreflightRunner {
    #transportResolver;
    #randomBytes;

    constructor({ transportResolver, randomBytes = defaultRandomBytes } = {}) {
        if (typeof transportResolver !== 'function') {
            throw new TypeError('L2tpPreflightRunner requires transportResolver');
        }
        if (typeof randomBytes !== 'function') {
            throw new TypeError('L2tpPreflightRunner requires randomBytes');
        }
        this.#transportResolver = transportResolver;
        this.#randomBytes = randomBytes;
    }

    async run(context) {
        if (!hasValidatedInstallContext(context)) {
            return failure('PREFLIGHT_CONTEXT_INVALID');
        }

        let operationId;
        try {
            const entropy = this.#randomBytes(PREFLIGHT_OPERATION_BYTES);
            if (!Buffer.isBuffer(entropy) || entropy.length !== PREFLIGHT_OPERATION_BYTES) {
                return failure('PREFLIGHT_OPERATION_ID_FAILED');
            }
            operationId = `preflight-${entropy.toString('hex')}`;
            if (!/^preflight-[0-9a-f]{24}$/.test(operationId)) {
                return failure('PREFLIGHT_OPERATION_ID_FAILED');
            }
        } catch {
            return failure('PREFLIGHT_OPERATION_ID_FAILED');
        }
        const nodeId = entityId(context.relay);
        let transport;
        try {
            transport = await this.#transportResolver({ operationId, nodeId });
        } catch {
            return failure('PREFLIGHT_TRANSPORT_UNAVAILABLE');
        }
        if (
            !transport
            || typeof transport.uploadRootFile !== 'function'
            || typeof transport.runArtifactCommand !== 'function'
        ) {
            return failure('PREFLIGHT_TRANSPORT_UNAVAILABLE');
        }
        const content = `${JSON.stringify(preflightDesired(context.desired))}\n`;

        try {
            await transport.uploadRootFile({
                operationId,
                type: 'desired',
                path: 'desired.json',
                content,
                owner: 'root',
                group: 'root',
                mode: 0o600,
            });
        } catch {
            return failure('PREFLIGHT_UPLOAD_FAILED');
        }

        let result;
        try {
            result = await transport.runArtifactCommand({
                operationId,
                command: 'preflight',
            });
        } catch {
            return failure('PREFLIGHT_COMMAND_FAILED');
        }

        return sanitizePreflightResult(result) ?? failure('PREFLIGHT_RESPONSE_INVALID');
    }
}

function createL2tpPreflightRunner(dependencies) {
    const runner = new L2tpPreflightRunner(dependencies);
    return runner.run.bind(runner);
}

module.exports = {
    L2tpPreflightRunner,
    PREFLIGHT_DESIRED_FIELDS,
    PREFLIGHT_OPERATION_BYTES,
    createL2tpPreflightRunner,
};
