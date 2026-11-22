'use strict';
const assert = require('node:assert/strict');

// Model the command prologue at the wire boundary; the transport tests also
// exercise the emitted prologue with an actual shell and a disposable file.
function rebuildApplyMachineGuard(command) {
    if (!command.startsWith('c3_machine_bytes=')) return { command };
    const match = /case "\$c3_machine_bytes" in '((?: [0-9a-f]{2}){32})'\|'\1 0a'\) ;; \*\) printf '%s\\n' REBUILD_APPLY_MACHINE_ID_MISMATCH >&2; exit 70;; esac; /.exec(command);
    assert.ok(match, 'malformed machine guard');
    const end = match.index + match[0].length;
    return {
        preamble: command.slice(0, end), command: command.slice(end),
        accepts(machineId) { return match[1].replaceAll(' ', '') === Buffer.from(machineId).toString('hex'); },
    };
}
module.exports = { rebuildApplyMachineGuard };
