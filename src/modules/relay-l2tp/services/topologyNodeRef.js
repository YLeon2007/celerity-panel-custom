'use strict';

// Legacy single-portal plans use `portal`; fan-in plans number portals in
// sorted source order. A ref must agree with its role at every trust boundary.
function validNodeRef(role, nodeRef) {
    if (typeof nodeRef !== 'string') return false;
    if (role === 'portal') return /^portal(?:-[1-9][0-9]*)?$/.test(nodeRef);
    if (role === 'relay') return /^relay-[1-9][0-9]*$/.test(nodeRef);
    if (role === 'bridge') return /^bridge(?:-[1-9][0-9]*)?$/.test(nodeRef);
    return false;
}

module.exports = { validNodeRef };
