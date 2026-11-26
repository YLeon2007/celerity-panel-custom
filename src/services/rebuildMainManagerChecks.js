'use strict';

const authorityReason = 'REBUILD_MAIN_AUTHORITY_UNPROVED';
const fields = [
    'RequiredBy', 'RequisiteOf', 'BoundBy', 'UpheldBy', 'ConsistsOf', 'TriggeredBy',
    'PropagatesStopTo', 'PropagatesReloadTo', 'StopPropagatedFrom', 'OnSuccess', 'OnFailure',
    'StopWhenUnneeded', 'RefuseManualStop', 'RefuseManualStart', 'Requires', 'BindsTo',
    'Wants', 'Conflicts', 'ConflictedBy', 'ActiveState', 'PartOf', 'Triggers', 'Upholds', 'Requisite',
];
const allowed = new Set(['list-jobs', 'active-invocations', 'shutdown.target:ActiveState',
    ...['cc-agent.service', 'xray.service'].flatMap(unit => fields.map(field => `${unit}:${field}`))]);

// Diagnostics are all-or-nothing, copied from own data items without coercion.
function projectManagerChecks(value) {
    if (!Array.isArray(value)) return;
    const count = Object.getOwnPropertyDescriptor(value, 'length')?.value;
    if (!Number.isSafeInteger(count) || count < 1 || count > allowed.size) return;
    const checks = new Set();
    for (let i = 0; i < count; i++) {
        const token = Object.getOwnPropertyDescriptor(value, i)?.value;
        if (!allowed.has(token)) return;
        checks.add(token);
    }
    return Object.freeze([...checks]);
}

module.exports = { authorityReason, projectManagerChecks };
