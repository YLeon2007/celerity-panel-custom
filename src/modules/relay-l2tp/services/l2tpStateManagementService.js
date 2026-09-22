'use strict';

const { randomBytes: defaultRandomBytes } = require('node:crypto');
const { isIP } = require('node:net');

const defaultSecretBox = require('./secretBoxService');

const GENERATED_PSK_BYTES = 32;
const MAX_DNS_SERVERS = 4;
const MAX_UINT32 = 0xffff_ffff;
const SAFE_RESULT_FIELDS = Object.freeze([
    '_id',
    'node',
    'desiredState',
    'status',
    'routeGroup',
    'clientCidr',
    'localAddress',
    'poolStart',
    'poolEnd',
    'dnsServers',
    'tproxyPort',
    'fwmark',
    'routeTable',
    'routingMode',
    'secretRevision',
    'operationId',
    'appliedTopologyRevision',
    'activePathKey',
    'lastVerifiedAt',
    'lastErrorCode',
    'lastError',
    'createdAt',
    'updatedAt',
]);

class L2tpStateManagementError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'L2tpStateManagementError';
        this.code = code;
        Object.assign(this, details);
    }
}

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity._id ?? entity.id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function nodeRole(node) {
    return node?.cascadeRole ?? node?.role ?? null;
}

function parseIpv4(value) {
    if (typeof value !== 'string') return null;
    const octets = value.split('.');
    if (octets.length !== 4 || octets.some(octet => !/^(0|[1-9]\d{0,2})$/.test(octet))) {
        return null;
    }
    const numbers = octets.map(Number);
    if (numbers.some(octet => octet > 255)) return null;
    return numbers.reduce((address, octet) => (address * 256) + octet, 0);
}

function parseCanonicalClientCidr(value) {
    if (typeof value !== 'string') return null;
    const match = value.match(/^([^/]+)\/(\d|[12]\d|3[0-2])$/);
    if (!match) return null;
    const address = parseIpv4(match[1]);
    if (address === null) return null;
    const prefix = Number(match[2]);
    const blockSize = 2 ** (32 - prefix);
    const first = Math.floor(address / blockSize) * blockSize;
    if (address !== first) return null;
    return { first, last: first + blockSize - 1 };
}

function isCanonicalIpLiteral(value) {
    if (typeof value !== 'string' || value.length === 0 || /\s/.test(value)) return false;
    if (parseIpv4(value) !== null) return true;
    if (isIP(value) !== 6) return false;
    try {
        return new URL(`http://[${value}]/`).hostname === `[${value}]`;
    } catch {
        return false;
    }
}

function validationError(code, message, field, details = {}) {
    return new L2tpStateManagementError(code, message, { field, ...details });
}

function validateDesiredInput(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw validationError(
            'INVALID_DESIRED_STATE',
            'L2TP desired-state configuration is required',
            'input',
        );
    }

    const clientRange = parseCanonicalClientCidr(input.clientCidr);
    if (!clientRange) {
        throw validationError(
            'INVALID_CLIENT_CIDR',
            'clientCidr must be a canonical IPv4 network CIDR',
            'clientCidr',
        );
    }

    const localAddress = parseIpv4(input.localAddress);
    if (
        localAddress === null
        || localAddress < clientRange.first
        || localAddress > clientRange.last
    ) {
        throw validationError(
            'INVALID_LOCAL_ADDRESS',
            'localAddress must be a canonical IPv4 address within clientCidr',
            'localAddress',
        );
    }

    const poolStart = parseIpv4(input.poolStart);
    const poolEnd = parseIpv4(input.poolEnd);
    if (
        poolStart === null
        || poolEnd === null
        || poolStart > poolEnd
        || poolStart < clientRange.first
        || poolEnd > clientRange.last
        || (localAddress >= poolStart && localAddress <= poolEnd)
    ) {
        throw validationError(
            'INVALID_CLIENT_POOL',
            'The client pool must be an ordered canonical IPv4 range within clientCidr and exclude localAddress',
            'pool',
        );
    }

    if (
        !Array.isArray(input.dnsServers)
        || input.dnsServers.length === 0
        || input.dnsServers.length > MAX_DNS_SERVERS
        || new Set(input.dnsServers).size !== input.dnsServers.length
        || input.dnsServers.some(server => !isCanonicalIpLiteral(server))
    ) {
        throw validationError(
            'INVALID_DNS_SERVERS',
            'dnsServers must contain one to four unique canonical IP address literals',
            'dnsServers',
        );
    }

    if (!Number.isSafeInteger(input.tproxyPort) || input.tproxyPort < 1 || input.tproxyPort > 65535) {
        throw validationError(
            'INVALID_TPROXY_PORT',
            'tproxyPort must be an integer from 1 through 65535',
            'tproxyPort',
        );
    }
    if (!Number.isSafeInteger(input.fwmark) || input.fwmark < 1 || input.fwmark > MAX_UINT32) {
        throw validationError(
            'INVALID_FWMARK',
            'fwmark must be a positive 32-bit integer',
            'fwmark',
        );
    }
    if (!Number.isSafeInteger(input.routeTable) || input.routeTable < 1 || input.routeTable > MAX_UINT32) {
        throw validationError(
            'INVALID_ROUTE_TABLE',
            'routeTable must be a positive 32-bit integer',
            'routeTable',
        );
    }
}

function validatePskRequest(input) {
    const generatePsk = input.generatePsk === true;
    const hasPsk = typeof input.psk === 'string';
    if (generatePsk === hasPsk) {
        throw validationError(
            'PSK_SOURCE_REQUIRED',
            'Provide exactly one PSK source: psk or generatePsk',
            'psk',
        );
    }
    if (
        hasPsk
        && (
            input.psk.trim().length === 0
            || input.psk.length > 1024
            || /["\r\n]/.test(input.psk)
        )
    ) {
        throw validationError(
            'INVALID_PSK',
            'The supplied PSK cannot be stored safely',
            'psk',
        );
    }
}

function safeState(state) {
    if (!state || typeof state !== 'object') return state;
    return SAFE_RESULT_FIELDS.reduce((result, field) => {
        if (state[field] !== undefined) {
            result[field] = Array.isArray(state[field]) ? [...state[field]] : state[field];
        }
        return result;
    }, {});
}

class L2tpStateManagementService {
    constructor({
        repository,
        secretBox = defaultSecretBox,
        secretKey,
        randomBytes = defaultRandomBytes,
    }) {
        if (!repository) throw new TypeError('repository is required');
        if (!secretBox || typeof secretBox.encrypt !== 'function' || typeof secretBox.decrypt !== 'function') {
            throw new TypeError('secretBox with encrypt/decrypt is required');
        }
        if (typeof secretKey !== 'string' || secretKey.length === 0) {
            throw new TypeError('secretKey is required');
        }
        if (typeof randomBytes !== 'function') throw new TypeError('randomBytes is required');
        this.repository = repository;
        this.secretBox = secretBox;
        this.secretKey = secretKey;
        this.randomBytes = randomBytes;
    }

    async configureRelay(nodeId, input) {
        const selectedNodeId = entityId(nodeId);
        if (!selectedNodeId) {
            throw validationError('NODE_REQUIRED', 'A relay node is required', 'nodeId');
        }
        validateDesiredInput(input);
        validatePskRequest(input);

        const routeGroupId = entityId(input.routeGroupId);
        if (!routeGroupId) {
            throw validationError(
                'ROUTE_GROUP_REQUIRED',
                'An explicit L2TP route group is required',
                'routeGroupId',
            );
        }

        const node = await this.repository.findNodeById(selectedNodeId);
        if (!node) {
            throw new L2tpStateManagementError('NODE_NOT_FOUND', 'The L2TP node was not found');
        }
        if (nodeRole(node) !== 'relay') {
            throw new L2tpStateManagementError(
                'NODE_NOT_RELAY',
                'L2TP desired state can only be configured for relay nodes',
            );
        }

        const routeGroup = await this.repository.findRouteGroupById(routeGroupId);
        if (!routeGroup) {
            throw new L2tpStateManagementError(
                'ROUTE_GROUP_NOT_FOUND',
                'The requested L2TP route group was not found',
            );
        }

        const psk = input.generatePsk === true
            ? this.randomBytes(GENERATED_PSK_BYTES).toString('base64url')
            : input.psk;
        let pskEncrypted;
        try {
            pskEncrypted = this.secretBox.encrypt(psk, this.secretKey);
        } catch {
            throw new L2tpStateManagementError(
                'PSK_ENCRYPTION_FAILED',
                'The L2TP PSK could not be encrypted',
            );
        }

        const state = await this.repository.configureRelay({
            node: selectedNodeId,
            desiredState: 'installed',
            routeGroup: routeGroupId,
            clientCidr: input.clientCidr,
            localAddress: input.localAddress,
            poolStart: input.poolStart,
            poolEnd: input.poolEnd,
            dnsServers: [...input.dnsServers],
            tproxyPort: input.tproxyPort,
            fwmark: input.fwmark,
            routeTable: input.routeTable,
            routingMode: 'route-group',
            pskEncrypted,
        });
        return safeState(state);
    }

    async reconcileVerifiedOperation({ operation, verifiedAt } = {}) {
        if (!operation || typeof operation !== 'object' || operation.kind !== 'install') {
            throw new L2tpStateManagementError(
                'INVALID_OPERATION_KIND',
                'Only a verified L2TP install operation can reconcile relay state',
            );
        }

        const operationId = entityId(operation);
        const nodeId = entityId(operation.node);
        const plan = operation.plan;
        if (
            !operationId
            || !nodeId
            || entityId(plan?.operationId) !== operationId
            || entityId(plan?.relayId) !== nodeId
        ) {
            throw new L2tpStateManagementError(
                'OPERATION_IDENTITY_MISMATCH',
                'The verified L2TP operation identity does not match its install plan',
            );
        }

        const credentialRevision = plan.desired?.credentialRevision;
        if (!Number.isSafeInteger(credentialRevision) || credentialRevision < 1) {
            throw new L2tpStateManagementError(
                'CREDENTIAL_REVISION_MISMATCH',
                'The verified L2TP operation credential revision is invalid',
            );
        }
        if (!Number.isSafeInteger(plan.topologyRevision) || plan.topologyRevision < 0) {
            throw new L2tpStateManagementError(
                'INVALID_TOPOLOGY_REVISION',
                'The verified L2TP operation topology revision is invalid',
            );
        }
        if (typeof plan.selectedPathKey !== 'string' || plan.selectedPathKey.length === 0) {
            throw new L2tpStateManagementError(
                'INVALID_ACTIVE_PATH',
                'The verified L2TP operation active path is invalid',
            );
        }
        if (!(verifiedAt instanceof Date) || Number.isNaN(verifiedAt.getTime())) {
            throw new L2tpStateManagementError(
                'INVALID_VERIFICATION_TIME',
                'The verified L2TP operation timestamp is invalid',
            );
        }

        const state = await this.repository.markInstalledAfterVerification({
            node: nodeId,
            operationId,
            credentialRevision,
            topologyRevision: plan.topologyRevision,
            activePathKey: plan.selectedPathKey,
            verifiedAt,
        });
        if (!state) {
            throw new L2tpStateManagementError(
                'L2TP_STATE_RECONCILIATION_REJECTED',
                'The relay L2TP desired state changed before reconciliation',
            );
        }
        return safeState(state);
    }

    async resolveOperationSecrets(operation) {
        if (!operation || typeof operation !== 'object' || operation.kind !== 'install') {
            throw new L2tpStateManagementError(
                'INVALID_OPERATION_KIND',
                'PSK resolution is only available for L2TP install execution',
            );
        }
        if (operation.secret !== undefined && operation.secret !== 'psk') {
            throw new L2tpStateManagementError(
                'INVALID_SECRET_KIND',
                'Only the L2TP install PSK can be resolved',
            );
        }

        const nodeId = entityId(operation.nodeId ?? operation.node);
        if (!nodeId) {
            throw new L2tpStateManagementError(
                'INVALID_OPERATION_NODE',
                'The L2TP operation does not identify a relay node',
            );
        }
        const credentialRevision = operation.credentialRevision
            ?? operation.plan?.desired?.credentialRevision;
        if (!Number.isSafeInteger(credentialRevision) || credentialRevision < 1) {
            throw new L2tpStateManagementError(
                'CREDENTIAL_REVISION_MISMATCH',
                'The L2TP operation credential revision is invalid',
            );
        }

        const state = await this.repository.findExecutionStateByNodeId(nodeId);
        if (!state) {
            throw new L2tpStateManagementError(
                'RELAY_L2TP_STATE_NOT_FOUND',
                'The relay L2TP desired state was not found',
            );
        }
        if (entityId(state.node) !== nodeId) {
            throw new L2tpStateManagementError(
                'RELAY_L2TP_STATE_MISMATCH',
                'The relay L2TP desired state does not match the operation node',
            );
        }
        if (state.desiredState !== 'installed') {
            throw new L2tpStateManagementError(
                'DESIRED_STATE_NOT_INSTALLED',
                'The relay L2TP desired state is not installed',
            );
        }
        if (state.secretRevision !== credentialRevision) {
            throw new L2tpStateManagementError(
                'CREDENTIAL_REVISION_MISMATCH',
                'The L2TP operation credential revision is stale',
            );
        }
        if (typeof state.pskEncrypted !== 'string' || state.pskEncrypted.length === 0) {
            throw new L2tpStateManagementError(
                'PSK_NOT_CONFIGURED',
                'The relay L2TP PSK is not configured',
            );
        }

        try {
            const psk = this.secretBox.decrypt(state.pskEncrypted, this.secretKey);
            if (typeof psk !== 'string' || psk.length === 0) throw new Error('empty PSK');
            return { psk };
        } catch {
            throw new L2tpStateManagementError(
                'PSK_DECRYPTION_FAILED',
                'The relay L2TP PSK could not be decrypted',
            );
        }
    }
}

module.exports = {
    GENERATED_PSK_BYTES,
    L2tpStateManagementError,
    L2tpStateManagementService,
    SAFE_RESULT_FIELDS,
};
