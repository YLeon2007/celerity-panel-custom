'use strict';
const mongoose = require('mongoose');
const { common, immutable } = require('./topologyExecutionBindingContract');
// The permanent alias reservation also retains the held-authority empty-head
// attestation for first provisioning. It is never inferred from a missing row.
const schema = new mongoose.Schema({ ...common(),
    provisioningReceipt: { type: mongoose.Schema.Types.Mixed, immutable: true },
}, { strict: 'throw', versionKey: false });
schema.index({ nodeId: 1, targetProfile: 1 }, { unique: true });
schema.index({ 'nodeIdentity.machineId': 1, targetProfile: 1 }, { unique: true });
schema.index({ 'nodeIdentity.sshHostKeySha256': 1, targetProfile: 1 }, { unique: true });
// Conservative one-shot enrollment: no physical or SSH-listener aliases,
// including cross-profile aliases and a different SSH username on one listener.
// Provisioning must resolve clones/reused host keys before this can be enabled.
schema.index({ 'nodeIdentity.machineId': 1 }, { unique: true });
schema.index({ 'nodeIdentity.sshHostKeySha256': 1 }, { unique: true });
schema.index({ 'endpoint.ip': 1, 'endpoint.port': 1 }, { unique: true });
immutable(schema);
module.exports = mongoose.model('TopologyExecutionEnrollment', schema);
