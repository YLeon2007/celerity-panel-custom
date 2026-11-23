'use strict';

const code = 'REBUILD_RETIRE_NEIGHBOR_REFUSED';
const refusals = new WeakMap();

function checkNeighborRefusal(error, inventoryName) {
    if (error?.code !== 'REBUILD_L2TP_APPLY_NETWORK_REFUSED' || error.remoteOutcomeUncertain
        || error.outcome !== undefined || error.retryAllowed === false) return error;
    // Only the inventory card supplies the label. Disallow control/bidi and
    // path/markup delimiters; the UI treats the result as text, not HTML.
    const name = typeof inventoryName === 'string' && !/[\\/]/.test(inventoryName)
        ? inventoryName.replace(/[^\p{L}\p{M}\p{N} ._()#–—-]/gu, ' ').replace(/ +/g, ' ').trim() : '';
    const neighborName = Array.from(name).slice(0, 80).join('').trimEnd() || null;
    const reason = error.reason === 'RUNTIME_FOREIGN_CHANGE' ? 'RUNTIME_FOREIGN_CHANGE' : 'APPLY_NETWORK_REFUSED';
    const refusal = Object.assign(new Error(code), { code });
    refusals.set(refusal, Object.freeze({ code, neighborName, reason }));
    return refusal;
}

const neighborRefusalForError = error => refusals.get(error);
module.exports = { checkNeighborRefusal, neighborRefusalForError };
