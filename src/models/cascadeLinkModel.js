/**
 * Cascade link model — represents a reverse-proxy tunnel between two Xray nodes.
 *
 * Portal (entry) accepts client traffic and proxies it via reverse tunnel.
 * Bridge (exit) initiates the tunnel to Portal and releases traffic to the internet.
 */

const mongoose = require('mongoose');
const { CASCADE_TRANSPORTS, KCP_HEADERS, KCP_NUMERIC_FIELDS, isKcpSecurity, sanitizeKcpInput } = require('../utils/cascadeTransport');
const { normalizeRebuildExitNodeId } = require('../modules/relay-l2tp/domain/rebuildPortalExit');

const lifecycleSchema = new mongoose.Schema({
    state: { type: String, enum: ['deleting'], required: true },
    deleteJobId: { type: mongoose.Schema.Types.ObjectId, required: true },
    desiredVersion: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
}, { _id: false, versionKey: false, strict: 'throw' });

const appliedLinkSchema = new mongoose.Schema({
    listener: { type: mongoose.Schema.Types.ObjectId, required: true },
    mode: { type: String, enum: ['reverse', 'forward'], required: true },
    protocol: { type: String, enum: ['vless', 'vmess'], required: true },
    port: { type: Number, min: 1, max: 65535, validate: Number.isInteger, required: true },
    uuid: { type: String, match: /^\S+$/, required: true },
}, { _id: false, versionKey: false, strict: 'throw' });

const reverseObservationSchema = new mongoose.Schema({
    version: { type: Number, enum: [1], required: true },
    generation: { type: String, match: /^[a-f0-9]{64}$/, required: true },
    observedAt: { type: Date, required: true },
    established: { type: Boolean, required: true },
}, { _id: false, versionKey: false, strict: 'throw' });

const rebuildExitSchema = new mongoose.Schema({
    nodeId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HyNode',
        cast: value => new mongoose.Types.ObjectId(normalizeRebuildExitNodeId(value)),
    },
    relayGeo: {
        type: Boolean,
        default: true,
        cast: value => {
            if (typeof value !== 'boolean') throw new TypeError('relayGeo must be a boolean');
            return value;
        },
        validate: value => value !== null,
    },
}, { _id: false, versionKey: false, strict: 'throw' });

function hideRebuildSecrets(_doc, row) {
    delete row.kcpPassword;
    delete row.rebuildVlessKeyEnvelope;
    delete row._rebuildVless;
    delete row.rebuildApplied;
    delete row.rebuildDesiredEdited;
    delete row.rebuildApplyEpoch;
    delete row.rebuildAppliedMainSha256;
    delete row.rebuildReverseObservation;
    delete row.rebuildKcpApplied;
    return row;
}

function kcpField(field, options) {
    return {
        ...options,
        // Mongoose's default casts would accept e.g. true -> 1 or '0x14' -> 20.
        cast: value => {
            const { fields, error } = sanitizeKcpInput({ [field]: value });
            if (error) throw new mongoose.Error.CastError(options.type.name, value, field);
            return fields[field];
        },
        validate: value => value !== null,
    };
}

const cascadeLinkSchema = new mongoose.Schema({
    name: { type: String, required: true },

    // reverse = Xray reverse-proxy (Bridge initiates tunnel TO Portal)
    // forward = proxySettings.tag chaining (Portal connects TO Bridge)
    mode: { type: String, enum: ['reverse', 'forward'], default: 'reverse' },

    portalNode: { type: mongoose.Schema.Types.ObjectId, ref: 'HyNode', required: true },
    bridgeNode: { type: mongoose.Schema.Types.ObjectId, ref: 'HyNode', required: true },

    tunnelUuid: { type: String, required: true },
    // Only the guarded rebuild key initializer writes this versioned AEAD
    // envelope. CRUD/list queries and document serialization omit it.
    rebuildVlessKeyEnvelope: {
        type: String,
        select: false,
        validate: {
            validator: value => /^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{22}$/.test(value),
            message: 'REBUILD_LINK_KEY_INVALID',
        },
    },
    tunnelPort: { type: Number, default: 10086 },
    tunnelDomain: { type: String, default: 'reverse.tunnel.internal' },
    tunnelProtocol: { type: String, enum: ['vless', 'vmess'], default: 'vless' },
    tunnelSecurity: { type: String, enum: ['none', 'tls', 'reality'], default: 'none' },
    // Rebuild supplies the effective default; Classic must not write this field.
    tunnelEncryption: { type: String, enum: ['vless-enc', 'none'] },
    // Rebuild-only SNI; Classic tunnel generation/CRUD do not consume it.
    rebuildTlsServerName: { type: String, default: undefined },
    // Rebuild selects a node; the scoped graph resolves the current tunnel.
    rebuildExit: { type: rebuildExitSchema, default: undefined, validate: value => value === null || value.nodeId !== undefined },
    tunnelTransport: {
        type: String, enum: CASCADE_TRANSPORTS, default: 'tcp',
        validate: {
            // Partial query updates are checked against the effective pair at
            // the management boundary; a document has both fields here.
            validator(value) {
                return value !== 'kcp' || !(this instanceof mongoose.Document) || isKcpSecurity(this.tunnelSecurity);
            },
            message: 'mKCP requires none or TLS security',
        },
    },

    // TCP settings
    tcpFastOpen: { type: Boolean, default: true },
    tcpKeepAlive: { type: Number, default: 100 },
    tcpNoDelay: { type: Boolean, default: true },

    // WebSocket settings
    wsPath: { type: String, default: '/cascade' },
    wsHost: { type: String, default: '' },

    // gRPC settings
    grpcServiceName: { type: String, default: 'cascade' },

    // SplitHTTP (XHTTP) settings
    xhttpPath: { type: String, default: '/cascade' },
    xhttpHost: { type: String, default: '' },
    xhttpMode: { type: String, enum: ['auto', 'packet-up', 'stream-up', 'stream-one'], default: 'auto' },

    // Sparse, public tuning only. Apply defaults on the wire so existing
    // non-mKCP rows/documents do not acquire extra fields on save.
    ...Object.fromEntries(Object.entries(KCP_NUMERIC_FIELDS).map(([field, bounds]) =>
        [field, kcpField(field, { type: Number, ...bounds })])),
    kcpHeader: kcpField('kcpHeader', { type: String, enum: KCP_HEADERS }),

    // REALITY security settings (used when tunnelSecurity = 'reality')
    realityDest: { type: String, default: '' },
    realitySni: { type: [String], default: [] },
    realityPrivateKey: { type: String, default: '' },
    realityPublicKey: { type: String, default: '' },
    realityShortIds: { type: [String], default: [''] },
    realityFingerprint: { type: String, default: 'random' },

    // MUX settings for tunnel outbound
    muxEnabled: { type: Boolean, default: false },
    muxConcurrency: { type: Number, default: 8 },

    // Geo-routing: route specific domains/IPs through this bridge instead of the default
    geoRouting: {
        enabled: { type: Boolean, default: false },
        domains: [{ type: String }],
        geoip:   [{ type: String }],
    },

    // Lower priority value = preferred; also determines chain order for forward mode
    priority: { type: Number, default: 100 },

    active: { type: Boolean, default: true },
    // Keep endpoints available to a fresh operator Apply until both halves of
    // a rebuild DELETE have passed readback. No startup recovery consumes it.
    rebuildDelete: { type: Boolean, default: undefined },
    // null = a newly created Rebuild draft; absent = legacy, not proof of a
    // never-applied draft. Only successful Apply readback writes a descriptor.
    rebuildAppliedExit: { type: rebuildExitSchema, select: false, default: undefined,
        validate: value => value === null || value?.nodeId != null },
    rebuildApplied: { type: appliedLinkSchema, select: false, default: undefined },
    // Display-only: a saved Rebuild edit not yet settled by Apply.
    rebuildDesiredEdited: { type: Boolean, select: false },
    rebuildApplyEpoch: { type: String, select: false, match: /^[a-f0-9]{32}$/ },
    rebuildAppliedMainSha256: { type: String, select: false, match: /^[a-f0-9]{64}$/ },
    rebuildReverseObservation: { type: reverseObservationSchema, select: false },
    rebuildKcpApplied: { type: String, select: false, match: /^[a-f0-9]{64}$/ },
    // Metadata only. Startup must never infer a fresh deploy from this flag.
    autoDeploy: { type: Boolean, default: false },
    // The old descriptor remains intact until operation-owned cleanup/readback
    // settles. Never overload tunnel health or infer deletion from pending.
    lifecycle: { type: lifecycleSchema, default: undefined },
    // Server-issued only at trusted create; legacy documents remain ungranted.
    classicLifecycleGrant: {
        type: String,
        select: false,
        validate: value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value),
    },
    status: {
        type: String,
        enum: ['pending', 'staged', 'deployed', 'online', 'offline', 'error'],
        default: 'pending',
    },
    lastError: { type: String, default: '' },
    lastHealthCheck: { type: Date, default: null },
    latencyMs: { type: Number, default: null },
}, {
    timestamps: true,
    toJSON: { transform: hideRebuildSecrets },
    toObject: { transform: hideRebuildSecrets },
});

cascadeLinkSchema.index({ portalNode: 1 });
cascadeLinkSchema.index({ bridgeNode: 1 });
cascadeLinkSchema.index({ active: 1, status: 1 });

const CascadeLink = mongoose.model('CascadeLink', cascadeLinkSchema);

// Same-session writer injected into TopologyIntentService.deleteIntentWriter.
// This marker is not a cleanup receipt and grants no authority to delete a row.
function createDeleteIntentWriter({ CascadeLink: Link = CascadeLink } = {}) {
    return Object.freeze({ db: Link.db,
        async markDeleting({ session, linkId, desiredVersion, jobId }) {
            if (!session) throw new TypeError('Delete marker requires the admission transaction session');
            const { linkDesiredVersion } = require('../modules/relay-l2tp/services/topologyIntentService');
            const current = await Link.findById(linkId).session(session).lean();
            if (!current || linkDesiredVersion(current) !== desiredVersion) return { matchedCount: 0 };
            if (current.lifecycle) {
                // A fresh explicit DELETE may supersede only a terminal local
                // validation refusal whose admission transaction never bound an
                // operation. Preserve that failed job; never retry UNKNOWN work.
                const { TopologyCreateIntent: Intent, TopologyOperation: Operation, NodeOperationLock: Lock } = Link.db.models || {};
                if (current.lifecycle.state !== 'deleting' || current.lifecycle.desiredVersion !== desiredVersion
                    || [Intent, Operation, Lock].some(Model => !Model || Model.db !== Link.db)) return { matchedCount: 0 };
                const prior = await Intent.findById(current.lifecycle.deleteJobId).session(session).lean();
                if (!prior || prior.version !== 2 || prior.kind !== 'link.delete' || prior.status !== 'failed'
                    || prior.errorCode !== 'INVALID_TOPOLOGY_DEPLOYMENT' || prior.attempts !== 1
                    || String(prior.linkId) !== String(linkId) || prior.desiredVersion !== desiredVersion
                    || prior.operationId !== undefined || prior.operationIdempotencyKey !== undefined
                    || prior.leaseOwner || prior.leaseUntil || !prior.resourceNodeIds?.length
                    || await Operation.findOne({ kind: 'link.delete', linkId: String(linkId) }).session(session).lean()
                    || await Lock.findOne({ node: { $in: prior.resourceNodeIds } }).session(session).lean()) return { matchedCount: 0 };
                return Link.updateOne({ _id: linkId, lifecycle: current.lifecycle }, {
                    $set: { lifecycle: { state: 'deleting', deleteJobId: jobId, desiredVersion } },
                }, { session, runValidators: true });
            }
            return Link.updateOne({ _id: linkId, lifecycle: { $exists: false } }, {
                $set: { lifecycle: { state: 'deleting', deleteJobId: jobId, desiredVersion } },
            }, { session, runValidators: true });
        },
    });
}

module.exports = CascadeLink;
module.exports.createDeleteIntentWriter = createDeleteIntentWriter;
