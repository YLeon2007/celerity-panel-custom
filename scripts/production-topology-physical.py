#!/usr/bin/python3 -I -B
"""PROD-only attach/observe/original holder. No arm, thaw, DDL or runner replay.
Uses the existing guard's SCM_RIGHTS/OFD protocol, NOT the finite maintenance
broker or its lifetime. Exclusion is independently established and retained by
that resident guard; this process never creates a new global writer barrier.
"""
import base64, importlib.util, json, os, select, socket, stat, sys, time, uuid
from contextlib import ExitStack
from pathlib import Path
from typing import Any
sys.dont_write_bytecode = True
POLICY='/etc/celerity/topology-production-node.json'
CORE='/usr/local/libexec/c3-prod-maintenance/authority_helper.py'
EFFECTS='/usr/local/libexec/c3-production-original-effects.py'
SELF='/usr/local/libexec/c3-production-physical.py'
ROOT='/var/lib/celerity/production-physical'
PROD={'target':'production','hostIdentity':'lm1.infograd.online'}

def load(p) -> dict[str, Any]:
    ns: dict[str, Any]={'__name__':'c3_private_module'}
    exec(compile(Path(p).read_bytes(),p,'exec'),ns)
    return ns

def serve():
    c=load(CORE); need=c['need']; sha=c['sha']; canonical=c['canonical']; trusted=c['trusted']; decode=c['decode']
    # Fixed root-controlled sources are verified before importing effects or
    # accepting a frame. No command/path from the wire selects executable code.
    raw=c['private_read'](POLICY); p=decode(raw)
    need(p['version']==1 and p['serverContext']==PROD and p['kind'] in ('host','node'))
    need(p['guardChallenge']['serverContext']==PROD and sha(canonical(p['guardChallenge']))==p['guardChallengeSha256'])
    need(str(uuid.UUID(p['maintenanceId']))==p['maintenanceId'])
    for name in (CORE,EFFECTS,SELF):
        trusted(name); need(sha(Path(name).read_bytes())==p['codePins'][name])
    e=load(EFFECTS)
    class Scope:
        # Reuse ONLY the established low-level peer identity and SCM_RIGHTS
        # exchange implementation. Never instantiate HeldAuthority, convert its
        # 300s schema scope, extend its deadline or change maintenance behavior.
        _identity=c['HeldAuthority']._identity
        _exchange=c['HeldAuthority']._exchange
        def __init__(self):
            self.uid=0; self.root=Path('/'); self.guards=[]; self.until=0; self.poisoned=False
            need(isinstance(p['guards'],list) and 1<=len(p['guards'])<=32)
            need(len({g['holderId'] for g in p['guards']})==len(p['guards']))
            for pin in p['guards']:
                need(c['exact'](pin,'socket pid startTicks executableSha256 argvSha256 holderId lock sources'))
                need([s['path'] for s in pin['sources']]==[CORE,'/usr/local/libexec/c3-prod-maintenance/exclusion_guard.py'])
                need(Path('/proc/'+str(pin['pid'])+'/cmdline').read_bytes()==
                    b'/usr/bin/python3.13\x00-I\x00/usr/local/libexec/c3-prod-maintenance/exclusion_guard.py\x00')
                trusted(pin['socket']); trusted(pin['lock']['path'])
                self.challenge_sha=p['guardChallengeSha256']
                self.policy={'generation':p['maintenanceId']}
                self.until=time.monotonic()+2
                g={'pin':pin,'socket':socket.socket(socket.AF_UNIX),'fd':None,'pidfd':None}
                self.guards.append(g); g['socket'].settimeout(self.remaining()); g['socket'].connect(pin['socket'])
                import struct
                pid,uid,_=struct.unpack('3i',g['socket'].getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                need(pid==pin['pid'] and uid==0)
                g['pidfd']=os.pidfd_open(pid); self._identity(g); self._exchange(g,'attach',True); self._identity(g)
            self.check()
        def remaining(self):
            n=self.until-time.monotonic(); need(n>0 and not self.poisoned); return min(n,2)
        def check(self):
            need(not self.poisoned); self.until=time.monotonic()+2
            try:
                for g in self.guards:
                    self._identity(g); self._exchange(g,'check'); self._identity(g)
                for g in self.guards:need(not select.select([g['socket']],[],[],0)[0])
                # Exact original process TREE inventory must be independently
                # accepted. Frozen processes do not satisfy this absence check.
                need(p['oldBackend']['processes'] and all(type(x['pid']) is int and x['pid']>1 and isinstance(x['startTicks'],str) and x['startTicks'].isdigit() for x in p['oldBackend']['processes']))
                need(len({x['pid'] for x in p['oldBackend']['processes']})==len(p['oldBackend']['processes'])
                     and {'pid':p['oldBackend']['pid'],'startTicks':p['oldBackend']['processStartTime']} in p['oldBackend']['processes'])
                for x in p['oldBackend']['processes']:
                    try:
                        s=Path('/proc/'+str(x['pid'])+'/stat').read_text().rsplit(')',1)[1].split()[19]
                        need(s!=x['startTicks'])
                    except FileNotFoundError:pass
            except BaseException:self.poisoned=True;raise
    scope=Scope()
    def physical():
        machine=Path('/etc/machine-id').read_text().strip(); boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        key=Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
        return {'machineId':machine,'bootId':boot,'sshHostKeySha256':sha(base64.b64decode(key[1],validate=True))}
    def check():
        scope.check(); need(physical()==p['physical'])
        for name in (CORE,EFFECTS,SELF):
            trusted(name); need(sha(Path(name).read_bytes())==p['codePins'][name])
        # Real sshd supplies the execution server endpoint. Normal production
        # SSH/SFTP is retained; no c3-test-runner/2222/preinstalled bypass.
        connection=os.environ.get('SSH_CONNECTION','').split()
        need(len(connection)==4 and connection[2]==p['endpoint']['ip'] and int(connection[3])==p['endpoint']['port'])
        need(p['endpoint']['username']=='root' and os.getuid()==0)
    def current(profile):
        snap=holder.snapshot(profile)
        return {'source':'node-readback','configSha256':snap['files']['config']['sha256'],
                'unitSha256':snap['files']['unit']['sha256'],'serviceActive':snap['service']['ActiveState'],
                'serviceEnabled':snap['service']['UnitFileState']}
    def pristine():
        return all(not os.path.lexists(x) for x in ('/var/lib/celerity/topology/fences/'+p['targetProfile'],
            '/var/lib/celerity/topology/operations','/var/lib/celerity/topology/backups'))
    class Holder(e['OriginalEffects']):
        execution_context='lm1.infograd.online'
        def __init__(self):
            self.fs=e['Files'](); self.system=e['System'](); self.fixture=None
            self.accepted={'xraySha256':p.get('xraySha256')}; self.deadline: float | None=None
            self.locks=tuple(g['fd'] for g in scope.guards); self.runner=ExitStack()
            self.physical={'nodeId':p.get('nodeId'),'bootId':p['physical']['bootId']}
            self.original=None; self.generation=None; self.epoch=None; self.restored=False; self.prepared=None; self.intent=None
        def checkpoint(self):
            check(); need(self.deadline is not None and time.monotonic()<self.deadline)
            if self.original is not None:need(self.fs.read(ROOT+'/originals.json')[0]==self.bundle)
            if self.generation is not None:need(self.fs.read_json(ROOT+'/binding.json')==
                {'epoch':self.epoch,'bundleSha256':sha(self.bundle),'ownerGeneration':self.generation})
            if self.intent is not None:need(self.fs.read_json(ROOT+'/restore.json')==self.intent)
            if self.prepared is not None:
                if self.prepared['journalSha256'] is None:need(pristine())
                else:self.terminal(p['targetProfile'],self.prepared['journalSha256'])
        def snapshot_pin(self,s):
            return {'files':{k:{a:b for a,b in v.items() if a!='data'} for k,v in s['files'].items()},
                    'service':s['service'],'runtimeSha256':sha(canonical(s['runtime']))}
        def view(self):
            self.checkpoint()
            return {'epoch':self.epoch,'bundleSha256':sha(self.bundle),'ownerGeneration':self.generation,
                    'phase':'restored-held' if self.restored else 'captured-held','readback':current(p['targetProfile'])}
        def capture(self):
            self.checkpoint(); need(self.original is None); self.fs.private(ROOT)
            need(all(self.fs.absent(ROOT+'/'+n) for n in ('originals.json','originals.json.next','binding.json','restore.json','restore.json.next')))
            need(pristine())
            snapshots={profile:self.snapshot(profile) for profile in p['profiles']}
            need(current(p['targetProfile'])==p['originalSnapshot'])
            self.epoch=str(uuid.uuid4())
            self.original={'version':1,'epoch':self.epoch,'physical':p['physical'],'nodeId':p['nodeId'],
                           'targetProfile':p['targetProfile'],'guardsSha256':sha(canonical(p['guards'])),
                           'codePins':p['codePins'],'profiles':snapshots}
            self.bundle=canonical(self.original); self.fs.atomic(ROOT+'/originals.json',self.bundle,new=True)
            return self.view()
        def attach(self,accepted):
            # Explicit independently accepted durable epoch, under the SAME
            # original guard/OFD identity. Never recapture current config or
            # reconstruct from an owner/DB receipt or an uncertain restore.
            self.checkpoint(); need(self.original is None and self.fs.absent(ROOT+'/restore.json'))
            self.bundle=self.fs.read(ROOT+'/originals.json')[0]; o=decode(self.bundle)
            need(sha(self.bundle)==accepted['bundleSha256'] and o['epoch']==accepted['epoch']
                 and o['physical']==p['physical'] and o['nodeId']==p['nodeId'] and o['targetProfile']==p['targetProfile']
                 and o['guardsSha256']==sha(canonical(p['guards'])) and o['codePins']==p['codePins'])
            b=self.fs.read_json(ROOT+'/binding.json')
            need(b=={'epoch':o['epoch'],'bundleSha256':sha(self.bundle),'ownerGeneration':accepted['ownerGeneration']})
            self.original=o; self.epoch=o['epoch']; self.generation=b['ownerGeneration']; return self.view()
        def bind(self,generation):
            self.checkpoint(); need(self.original is not None and self.generation is None and str(uuid.UUID(generation))==generation)
            need(self.snapshot(p['targetProfile'])==self.original['profiles'][p['targetProfile']])
            self.generation=generation
            self.fs.atomic(ROOT+'/binding.json',canonical({'epoch':self.epoch,'bundleSha256':sha(self.bundle),'ownerGeneration':generation}),new=True)
            return self.view()
        def read_current(self):
            self.checkpoint()
            jp=e['runner_journal'](p['targetProfile'])
            if not os.path.lexists(jp):need(pristine()); digest=None
            else:
                raw=self.fs.read(jp)[0]; digest=sha(raw); self.terminal(p['targetProfile'],digest)
            return {**self.snapshot_pin(self.snapshot(p['targetProfile'])),'journalSha256':digest}
        def prepare(self,value):
            self.checkpoint(); need(self.prepared is None and not self.restored and value['epoch']==self.epoch and value['ownerGeneration']==self.generation)
            need(self.fs.absent(ROOT+'/restore.json'))
            if value['current']['journalSha256'] is not None:
                fd=self.runner.enter_context(self.fs.lock(e['runner_lock'](p['targetProfile']))); self.locks=(*self.locks,fd)
            else:need(pristine())
            now=self.read_current(); need(now==value['current'])
            for profile in p['profiles']:
                if profile!=p['targetProfile']:need(self.snapshot(profile)==self.original['profiles'][profile])
            self.prepared=now; return self.view()
        def restore(self):
            self.checkpoint(); need(self.prepared is not None and not self.restored and self.intent is None)
            need(self.read_current()==self.prepared)
            self.intent={'epoch':self.epoch,'ownerGeneration':self.generation,'bundleSha256':sha(self.bundle),'phase':'restoring-retained'}
            self.fs.atomic(ROOT+'/restore.json',canonical(self.intent),new=True)
            self.restore_profile(p['targetProfile'],self.original['profiles'][p['targetProfile']],self.prepared)
            self.restored=True; self.verify()
            self.intent={**self.intent,'phase':'verified-retained'}; self.fs.atomic(ROOT+'/restore.json',canonical(self.intent))
            return self.view()
        def verify(self):
            self.checkpoint(); need(self.restored)
            for profile,snapshot in self.original['profiles'].items():need(self.snapshot(profile)==snapshot)
            return self.view()
    holder=Holder()
    def observation():
        check(); result={'serverContext':PROD,'kind':p['kind'],'policySha256':sha(raw),'physical':physical(),
                         'endpoint':p['endpoint'],'maintenanceId':p['maintenanceId'],'held':True}
        result['oldBackend']={k:p['oldBackend'][k] for k in ('instanceId','pid','processStartTime')}
        if p['kind']=='node':
            profile=p['targetProfile']; jp=e['runner_journal'](profile)
            journal=None if not os.path.lexists(jp) else holder.fs.read_json(jp)
            need(not os.path.lexists(str(Path(jp).with_name('journal.next'))))
            if journal is not None:need(journal['version']==2 and journal['executionContext']=='lm1.infograd.online'
                and journal['nodeId']==p['nodeId'] and journal['bootId']==p['physical']['bootId'])
            result.update({'nodeId':p['nodeId'],'targetProfile':profile,'current':current(profile),'journal':journal,'pristine':pristine() if journal is None else False})
        return result
    seen=set()
    while True:
        line=sys.stdin.buffer.readline(131073)
        if not line:break
        need(len(line)<=131072); q=decode(line)
        need(set(q)=={'nonce','action','value'} and q['nonce'] not in seen); seen.add(q['nonce']); need(len(seen)<=100000)
        value=q['value']; action=q['action']; check()
        holder.deadline=time.monotonic()+(115 if action in ('prepare','restore') else 90 if action=='capture' else 30)
        result=None
        if action=='observe':result=observation()
        elif action=='observe-unclosed' and p['kind']=='node':
            # Snapshot the verified generation under the actual runner lock. A
            # busy writer, missing lock, pending journal or restore is unknown.
            need(value is None and holder.original is not None and holder.generation is not None)
            need(holder.prepared is None and not holder.restored and holder.fs.absent(ROOT+'/restore.json'))
            with holder.fs.lock(e['runner_lock'](p['targetProfile'])):
                holder.checkpoint()
                result=observation()
                holder.checkpoint()
            result['runnerIdle']=True
        elif p['kind']=='node':
            if action=='profile':
                # Fixed-path, read-only import input under the same live exclusion.
                # Profile bytes stay on the private authenticated SSH channel.
                need(value is None)
                snap=holder.snapshot(p['targetProfile'])
                result={'configBase64':snap['files']['config']['data']}
            elif action=='capture':result=holder.capture()
            elif action=='attach':result=holder.attach(value)
            elif action=='bind':result=holder.bind(value['ownerGeneration'])
            elif action=='current':result=holder.read_current()
            elif action=='prepare':result=holder.prepare(value)
            elif action=='restore':result=holder.restore()
            elif action=='verify':result=holder.verify()
            elif action=='read':result=holder.view()
            elif action=='release':
                holder.verify(); holder.runner.close(); holder.locks=tuple(g['fd'] for g in scope.guards)
                result={'phase':'handback-released','epoch':holder.epoch,'ownerGeneration':holder.generation}
        need(result is not None); check()
        sys.stdout.write(json.dumps({'nonce':q['nonce'],'result':result},separators=(',',':'))+'\n');sys.stdout.flush()
    # EOF never releases resident exclusion or clears private originals/history.
    return 0
if __name__=='__main__':
    try:status=serve()
    except Exception:status=1
    sys.exit(status)
