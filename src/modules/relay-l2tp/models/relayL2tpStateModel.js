const mongoose = require('mongoose');

const DESIRED_STATES = ['absent', 'installed'];
const STATUSES = [
    'not_installed',
    'queued',
    'preflight',
    'installing',
    'installed',
    'degraded',
    'drifted',
    'removing',
    'error',
    'role_lost',
];

const relayL2tpStateSchema = new mongoose.Schema({
    node: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HyNode',
        required: true,
        unique: true,
        index: true,
    },
    desiredState: {
        type: String,
        enum: DESIRED_STATES,
        default: 'absent',
        required: true,
    },
    status: {
        type: String,
        enum: STATUSES,
        default: 'not_installed',
        required: true,
    },

    pskEncrypted: { type: String, default: '', select: false },
    pskHint: { type: String, default: '' },
    secretRevision: { type: Number, default: 0 },

    clientCidr: { type: String, default: '10.66.0.0/24' },
    localAddress: { type: String, default: '10.66.0.1' },
    poolStart: { type: String, default: '' },
    poolEnd: { type: String, default: '' },
    dnsServers: { type: [String], default: ['9.9.9.9'] },
    mtu: { type: Number, default: null },
    mru: { type: Number, default: null },

    tproxyPort: { type: Number, default: null },
    fwmark: { type: Number, default: null },
    routeTable: { type: Number, default: null },
    routingMode: {
        type: String,
        enum: ['route-group'],
        default: 'route-group',
    },
    routeGroup: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'CascadeRouteGroup',
        required() {
            return this.desiredState === 'installed' || this.status === 'installed';
        },
        default: null,
    },
    appliedTopologyRevision: { type: Number, default: null },
    activePathKey: { type: String, default: '' },

    managedVersion: { type: String, default: '' },
    configFingerprint: { type: String, default: '' },
    backupId: { type: String, default: '' },
    operationId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'L2tpOperation',
        default: null,
    },
    installedAt: { type: Date, default: null },
    lastVerifiedAt: { type: Date, default: null },
    lastSyncAt: { type: Date, default: null },
    lastErrorCode: { type: String, default: '' },
    lastError: { type: String, default: '' },
}, { timestamps: true });

module.exports = mongoose.model('RelayL2tpState', relayL2tpStateSchema);
