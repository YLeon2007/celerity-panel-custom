'use strict';
const mongoose = require('mongoose');
const { common, immutable } = require('./topologyExecutionBindingContract');
// Pre-existing non-initial runner head only. No default and no 'none' adoption.
const schema = new mongoose.Schema(common(), { strict: 'throw', versionKey: false });
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
