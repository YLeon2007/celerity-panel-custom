#!/usr/bin/env python3
"""Canonical sshd configuration for the owned dedicated TEST provisioner.
The migration plans exactly one missing OpenSSH internal-sftp declaration;
it never changes keys, authentication, endpoint, machine/boot or profiles.
"""
import hashlib,json
SFTP='Subsystem sftp internal-sftp\n'
BASE='Port 22\nListenAddress 0.0.0.0\nHostKey /etc/ssh/ssh_host_ed25519_key\nAuthorizedKeysFile /root/.ssh/authorized_keys\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nPidFile /run/sshd.pid\nPrintMotd no\n'
def config():return BASE+SFTP
def sha(b):return hashlib.sha256(b).hexdigest()
def plan(current,provision):
    if current!=BASE.encode() or sha(current)!=provision.get('sshdConfigSha256') or 'sshdSftpMigration'in provision:
        raise ValueError('DEDICATED_SSHD_MIGRATION_CONFLICT')
    updated=config().encode();old=json.dumps(provision,separators=(',',':')).encode()
    receipt={'version':1,'kind':'enable-internal-sftp','previousConfigSha256':sha(current),'currentConfigSha256':sha(updated),'previousProvisionSha256':sha(old)}
    return updated,{**provision,'sshdConfigSha256':sha(updated),'sshdSftpMigration':receipt}
