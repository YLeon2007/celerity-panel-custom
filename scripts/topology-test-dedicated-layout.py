#!/usr/bin/env python3
"""Directory producer for the dedicated TEST guest's non-root Xray runtime.
Call from the owned guest provisioner; never chmod the host or secret files.
Only traversal is granted, not directory listing. Existing file modes stay exact.
"""
import os,stat
# /usr is bind-ro; /usr/local is the guest's writable /local bind mount.
TRAVERSAL=('', 'etc', 'local', 'local/bin', 'local/etc', 'local/etc/xray', 'local/etc/xray-bridge')
def produce(root):
    changes=[]
    for relative in TRAVERSAL:
        path=os.path.join(root,relative)
        os.makedirs(path,mode=0o711,exist_ok=True)
        before=stat.S_IMODE(os.stat(path).st_mode)
        after=before|0o011
        if before!=after:os.chmod(path,after)
        changes.append({'path':relative or '/','before':oct(before),'after':oct(after)})
    return changes
