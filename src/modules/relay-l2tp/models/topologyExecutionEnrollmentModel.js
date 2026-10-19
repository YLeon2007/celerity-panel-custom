'use strict';
const mongoose = require('mongoose');
const { common, immutable } = require('./topologyExecutionBindingContract');
// Pre-existing non-initial runner head only. No default and no 'none' adoption.
const schema = new mongoose.Schema(common(), { strict: 'throw', versionKey: false });
schema.index({ nodeId: 1, targetProfile: 1 }, { unique: true });
schema.index({ 'nodeIdentity.machineId': 1, targetProfile: 1 }, { unique: true });
schema.index({ 'nodeIdentity.sshHostKeySha256': 1, targetProfile: 1 }, { unique: true });
immutable(schema);
module.exports = mongoose.model('TopologyExecutionEnrollment', schema);
