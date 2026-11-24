'use strict';

const { parseDest, clearRealityGuardObservations, forgetRealityGuardObservation } = require('../services/realityGuardService');
const { classifyRealityGuardDest, summarizeRealityGuardDests } = require('./realityGuardDest');

const MODES = Object.freeze(['off', 'notify']);
const MODE_PATH = 'xray.realityGuard.mode';
const PROFILE_FIELDS = 'cascadeRole role useCustomConfig xray.security xray.realityDest xray.extraInbounds';

function eligibleRole(role) {
    return role === 'standalone' || role === 'portal';
}

// Existing cards must already have a persisted role before they can opt in.
const guardRoleOnUpdate = (stored, requested) => stored === undefined || requested === undefined ? stored : requested;

function effectiveMode(mode) {
    return MODES.includes(mode) ? mode : 'off';
}

function clientRealityInbounds(xray) {
    return [xray, ...(Array.isArray(xray?.extraInbounds) ? xray.extraInbounds : [])]
        .filter(inbound => inbound?.security === 'reality');
}

// Use the service parser as the authority for persisted policy and rendering.
// This is a syntax-only call: no DNS, TLS or node connection is attempted.
function destState(xray) {
    return summarizeRealityGuardDests(clientRealityInbounds(xray).map(inbound => inbound.realityDest),
        dest => classifyRealityGuardDest(dest, parseDest));
}

const publicRealityInbounds = xray => clientRealityInbounds(xray).filter(inbound => parseDest(inbound.realityDest));

async function isGloballyEnabled() {
    try {
        // Native driver read: do not buffer a disconnected Mongoose query,
        // apply Boolean casting/defaults, or create the settings singleton.
        const Settings = require('./settingsModel');
        const row = await Settings.collection.collection?.findOne({ _id: 'settings' }, {
            projection: { _id: 0, 'realityGuard.enabled': 1 },
            readPreference: 'primary', readConcern: { level: 'majority' }, timeoutMS: 5000,
        });
        if (row?.realityGuard?.enabled === true) return true;
    } catch { /* fail closed */ }
    clearRealityGuardObservations();
    return false;
}

class RealityGuardInputError extends Error {
    constructor(field) {
        super(field === 'Auto' ? 'Automatic replacement is unavailable with cc-agent 1.5.1' : `Invalid Reality Guard ${field}`);
        this.localeKey = field === 'Auto' ? 'nodes.realityGuardModeAutoHint' : `nodes.realityGuardInvalid${field}`;
    }
}

class RealityGuardConflictError extends Error {
    constructor() { super('Reality Guard changed during this edit. Reload the node before saving.'); }
}

function guardModeCAS(rawNode) {
    const mode = rawNode.xray?.realityGuard?.mode;
    if (mode === undefined) return { [MODE_PATH]: { $exists: false } };
    // Match the stored BSON value, not the cast String or effective policy.
    // Expression equality does not match individual array elements.
    return { [MODE_PATH]: { $exists: true }, $expr: { $eq: [`$${MODE_PATH}`, { $literal: mode }] } };
}

// Explicit write paths may take policy only, never check/rotation state.
function readPolicy(input) {
    if (input === undefined) return {};
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new RealityGuardInputError('Policy');
    if (!Object.hasOwn(input, 'mode')) return {};
    if (input.mode === 'auto') throw new RealityGuardInputError('Auto');
    if (!MODES.includes(input.mode)) throw new RealityGuardInputError('Mode');
    return { mode: input.mode };
}

function rejectDottedGuard(input, prefix) {
    if (input && Object.keys(input).some(key => key.startsWith(prefix + '.'))) throw new RealityGuardInputError('Policy');
}

function readXrayPolicy(xray) {
    rejectDottedGuard(xray, 'realityGuard');
    return readPolicy(xray?.realityGuard);
}

function supportsGuard(node) {
    const role = node?.get ? node.get('role') : node?.role;
    return node?.type === 'xray' && (node.useCustomConfig === undefined || node.useCustomConfig === false)
        && eligibleRole(node.cascadeRole) && (role === undefined || role === node.cascadeRole);
}

function assertGuardModeAllowed(mode, node) {
    if (mode !== undefined && (node.type !== 'xray'
        || (mode === 'notify' && (!supportsGuard(node) || !publicRealityInbounds(node.xray).length)))) {
        throw new RealityGuardInputError('Target');
    }
}

// A standalone policy edit never enters a runtime/config writer. Bind the
// observed profile and one qualifying inbound so a racing role/target edit
// cannot admit notify on a now-ineligible profile.
async function saveGuardMode(id, mode) {
    const Node = require('./hyNodeModel');
    const response = query => query.select('-ssh.password -ssh.privateKey').populate('groups', 'name color');
    if (mode === undefined) return response(Node.findById(id));
    const node = await Node.findById(id).select(`type ${PROFILE_FIELDS} ${MODE_PATH}`).lean();
    if (!node) return null;
    assertGuardModeAllowed(mode, node);
    const filter = { _id: id, type: 'xray', ...guardModeCAS(node) };
    for (const key of ['cascadeRole', 'role', 'useCustomConfig']) {
        filter[key] = node[key] === undefined ? { $exists: false } : node[key];
    }
    if (mode === 'notify') {
        const inbound = publicRealityInbounds(node.xray)[0];
        if (inbound === node.xray) Object.assign(filter, { 'xray.security': 'reality', 'xray.realityDest': inbound.realityDest });
        else filter['xray.extraInbounds'] = { $elemMatch: { security: 'reality', realityDest: inbound.realityDest } };
    }
    const changed = mode !== effectiveMode(node.xray?.realityGuard?.mode);
    const saved = await response(changed
        ? Node.findOneAndUpdate(filter, { $set: { [MODE_PATH]: mode } }, { new: true, timestamps: false })
        : Node.findOne(filter));
    if (!saved) throw new RealityGuardConflictError();
    if (changed) forgetRealityGuardObservation(id);
    return saved;
}

// Explicit create policy is checked against schema defaults for missing Xray fields.
function withNewRealityGuard(data, xray = data.xray) {
    const guard = readXrayPolicy(xray);
    if (xray?.realityGuard === undefined) return data;
    assertGuardModeAllowed(guard.mode, { ...data, xray: { security: 'reality', realityDest: 'www.google.com:443', ...xray } });
    return data.type === 'xray' ? { ...data, xray: { ...data.xray, realityGuard: guard } } : data;
}

module.exports = { MODES, MODE_PATH, PROFILE_FIELDS, effectiveMode, supportsGuard, destState, publicRealityInbounds, isGloballyEnabled,
    RealityGuardInputError, RealityGuardConflictError, guardModeCAS, guardRoleOnUpdate,
    readPolicy, readXrayPolicy, rejectDottedGuard, assertGuardModeAllowed, saveGuardMode, withNewRealityGuard };
