"""Finite, retained dedicated TEST originals producer. No generic Engine, DB, or replay.
Installed next to the dedicated observer; ONLY its continuously held writer OFD
constructs this class. Private original bytes never enter protocol output.
"""
import base64, fcntl, hashlib, json, os, time, uuid
from contextlib import ExitStack

ROOT='/var/lib/celerity/dedicated-test'
BUNDLE=ROOT+'/originals.json'
INTENT=ROOT+'/original-restore.json'
EFFECTS='/usr/local/libexec/celerity-test-original-effects.py'
SELF='/usr/local/libexec/celerity-test-dedicated-originals.py'
OBSERVER='/usr/local/libexec/celerity-test-dedicated-node'
XRAY='/usr/local/bin/xray'

def load_effects(read):
    ns={'__name__':'celerity_original_effects'}
    exec(compile(read(EFFECTS),'<installed-original-effects>','exec'),ns)
    return ns

def make_holder(observer, writer_fd, read):
    e=load_effects(read)
    need=e['need']; canonical=e['canonical']; sha=e['sha']; decode=e['decode']
    class DedicatedOriginalHolder(e['OriginalEffects']):
        def __init__(self):
            self.fs=e['Files'](); self.system=e['System'](); self.fixture=None
            self.writer_fd=writer_fd; self.locks=(writer_fd,); self.runner_stack=None
            self.lock_paths={ROOT+'/writer.lock':writer_fd}
            self.deadline=None; self.accepted={}; self.original=None; self.binding=None
            self.physical=None; self.epoch=None; self.poisoned=False; self.intent=None
            self.current=None; self.restored=False; self.released=False

        def identity(self, v):
            # Actual process/runtime/OFD identity, not a historical receipt.
            statraw=read('/proc/self/stat').decode(); start=statraw[statraw.rfind(')')+2:].split()[19]
            lock=os.fstat(self.writer_fd)
            return {'nodeId':v['provision']['nodeId'],'machineId':v['provision']['machineId'],
                    'bootId':v['bootId'],'targetProfile':v['provision']['targetProfile'],
                    'provisionSha256':sha(canonical(v['provision'])), 'pid':os.getpid(),'start':start,
                    'pidNamespace':os.stat('/proc/self/ns/pid').st_ino,
                    'mountNamespace':os.stat('/proc/self/ns/mnt').st_ino,
                    'writerLock':{'dev':lock.st_dev,'ino':lock.st_ino},
                    'codePins':{p:sha(self.fs.read(p,128*1024*1024)[0]) for p in (SELF,EFFECTS,OBSERVER,XRAY)}}

        def checkpoint(self):
            need(not self.poisoned and not self.released and self.physical is not None,'ORIGINAL_HOLDER_LOST_RETAINED')
            v=observer({'nonce':str(uuid.uuid4())})
            need(self.identity(v)==self.physical,'ORIGINAL_IDENTITY_DRIFT_RETAINED')
            other='xray-main' if self.physical['targetProfile']=='xray-bridge' else 'xray-bridge'
            need(not os.path.lexists('/var/lib/celerity/topology/fences/'+other),'PRESERVED_PROFILE_GENERATION_RETAINED')
            for path,fd in self.lock_paths.items():
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.fs.opened(path) as current:
                    a,b=os.fstat(fd),os.fstat(current)
                    need((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino),'ORIGINAL_OFD_REPLACED_RETAINED')
            if self.original is not None:
                need(self.fs.absent(BUNDLE+'.next') and self.fs.read(BUNDLE)[0]==self.bundle_raw,'ORIGINAL_CACHE_DRIFT_RETAINED')
            if self.current is not None:
                need(v['runnerIdle'] is True,'RUNNER_IN_FLIGHT_RETAINED')
                self.terminal(self.physical['targetProfile'],self.current['journalSha256'])
                other='xray-main' if self.physical['targetProfile']=='xray-bridge' else 'xray-bridge'
                saved=self.original['profiles'][other]
                need(self.service(other)==saved['service'],'PRESERVED_PROFILE_DRIFT_RETAINED')
                for name,path in zip(('config','unit'),e['profile_paths'](other)):
                    need(self.fs.info(path)=={k:v for k,v in saved['files'][name].items() if k!='data'},'PRESERVED_PROFILE_DRIFT_RETAINED')
            if self.intent is not None:
                need(self.fs.absent(INTENT+'.next') and self.fs.read_json(INTENT)==self.intent,'RESTORE_INTENT_DRIFT_RETAINED')
            return v

        def view(self):
            v=self.checkpoint(); p=self.physical['targetProfile']
            return {'epoch':self.epoch,'holder':self.physical,'bundleSha256':sha(self.bundle_raw),
                    'ownerGeneration':self.binding,'phase':'restored-held' if self.restored else 'captured-held',
                    'readback':v['current'][p]}

        def capture(self):
            need(self.original is None and self.physical is None,'ORIGINAL_CAPTURE_ONCE_REQUIRED')
            self.fs.private(ROOT)
            need(all(self.fs.absent(p) for p in (BUNDLE,BUNDLE+'.next',INTENT,INTENT+'.next')),'ORIGINAL_EPOCH_ALREADY_EXISTS_RETAINED')
            v=observer({'nonce':str(uuid.uuid4())}); p=v['provision']['targetProfile']
            need(v['journal'] is None and v['runnerIdle'] is True and v['current'][p]==v['provision']['originalSnapshot'], 'CAPTURE_AFTER_ADOPTION_FORBIDDEN')
            # This criterion needs an actual classic-serving baseline, not {}+inactive.
            need(v['current'][p]['serviceActive']=='active','CLASSIC_SERVING_BASELINE_REQUIRED')
            self.physical=self.identity(v); self.epoch=str(uuid.uuid4())
            self.deadline=time.monotonic()+90
            self.accepted={'xraySha256':self.physical['codePins'][XRAY]}
            self.checkpoint()
            profiles={p:self.snapshot(p) for p in ('xray-main','xray-bridge')}
            self.checkpoint()
            self.original={'version':1,'epoch':self.epoch,'holder':self.physical,'profiles':profiles}
            self.bundle_raw=canonical(self.original)
            self.fs.atomic(BUNDLE,self.bundle_raw,new=True)
            need(self.fs.read(BUNDLE)[0]==self.bundle_raw,'ORIGINAL_CAPTURE_READBACK_FAILED')
            return self.view()

        def bind(self, generation):
            self.checkpoint(); need(self.binding is None and self.current is None,'ORIGINAL_BIND_ONCE_REQUIRED')
            need(isinstance(generation,str) and str(uuid.UUID(generation))==generation,'OWNER_GENERATION_REQUIRED')
            p=self.physical['targetProfile']
            need(self.snapshot(p)==self.original['profiles'][p],'ORIGINAL_CHANGED_BEFORE_ADOPT')
            self.binding=generation
            return self.view()

        def pin_snapshot(self, snapshot):
            return {'files':{k:{a:b for a,b in v.items() if a!='data'} for k,v in snapshot['files'].items()},
                    'service':snapshot['service'],'runtimeSha256':sha(canonical(snapshot['runtime']))}

        def read_current(self):
            self.checkpoint(); self.deadline=time.monotonic()+30
            p=self.physical['targetProfile']; raw=self.fs.read(e['runner_journal'](p))[0]
            self.terminal(p,sha(raw))
            return {**self.pin_snapshot(self.snapshot(p)),'journalSha256':sha(raw)}

        def prepare(self, request):
            # App caller must already close future dispatch and join current calls.
            # Real runner OFDs + exact independently accepted CURRENT are then held.
            need(set(request)=={'epoch','ownerGeneration','current'} and request['epoch']==self.epoch
                 and request['ownerGeneration']==self.binding and self.binding is not None
                 and self.current is None and not self.restored,'RESTORE_SCOPE_OR_REPLAY_REFUSED')
            self.checkpoint(); p=self.physical['targetProfile']; current=request['current']
            need(set(current)=={'files','service','runtimeSha256','journalSha256'} and set(current['files'])=={'config','unit'},'EXACT_CURRENT_REQUIRED')
            need(self.fs.absent(INTENT) and self.fs.absent(INTENT+'.next'),'RESTORE_REPLAY_FORBIDDEN')
            stack=ExitStack(); self.runner_stack=stack
            fd=stack.enter_context(self.fs.lock(e['runner_lock'](p)))
            self.lock_paths[e['runner_lock'](p)]=fd; self.locks=tuple(self.lock_paths.values())
            self.deadline=time.monotonic()+120
            self.terminal(p,current['journalSha256'])
            now=self.snapshot(p)
            need(self.pin_snapshot(now)=={k:v for k,v in current.items() if k!='journalSha256'},'CURRENT_READBACK_MISMATCH_RETAINED')
            # Validate every preserved profile and fixed CURRENT before first intent/effect.
            other='xray-main' if p=='xray-bridge' else 'xray-bridge'
            need(self.snapshot(other)==self.original['profiles'][other],'PRESERVED_RUNTIME_DRIFT_RETAINED')
            self.current=json.loads(json.dumps(current)); self.checkpoint()
            return self.view()

        def restore(self):
            need(self.current is not None and not self.restored and self.intent is None,'RESTORE_REPLAY_FORBIDDEN')
            self.checkpoint(); p=self.physical['targetProfile']; current=self.current
            need(self.fs.absent(INTENT) and self.fs.absent(INTENT+'.next'),'RESTORE_REPLAY_FORBIDDEN')
            need(self.pin_snapshot(self.snapshot(p))=={k:v for k,v in current.items() if k!='journalSha256'},'CURRENT_READBACK_MISMATCH_RETAINED')
            self.intent={'version':1,'epoch':self.epoch,'holder':self.physical,
                         'ownerGeneration':self.binding,'bundleSha256':sha(self.bundle_raw),
                         'currentSha256':sha(canonical(current)),'phase':'restoring-retained'}
            self.fs.atomic(INTENT,canonical(self.intent),new=True)
            need(self.fs.read_json(INTENT)==self.intent,'RESTORE_INTENT_READBACK_FAILED')
            self.checkpoint()
            self.restore_profile(p,self.original['profiles'][p],current)
            need(self.snapshot(p)==self.original['profiles'][p],'RESTORE_EXACT_READBACK_FAILED')
            self.checkpoint()
            intent={**self.intent,'phase':'verified-retained'}
            self.fs.atomic(INTENT,canonical(intent)); self.intent=intent
            self.restored=True
            return self.verify()

        def verify(self):
            need(self.restored and self.current is not None,'RESTORED_HELD_REQUIRED')
            self.checkpoint(); self.deadline=time.monotonic()+30
            for p,original in self.original['profiles'].items():
                need(self.snapshot(p)==original,'RESTORE_EXACT_READBACK_FAILED')
            return self.view()

        def release(self):
            # Only the trusted unchanged public handback caller invokes this AFTER
            # majority confirmation. It never starts a writer or erases history.
            self.verify(); self.runner_stack.close(); self.runner_stack=None
            self.lock_paths={ROOT+'/writer.lock':self.writer_fd}; self.locks=(self.writer_fd,)
            self.released=True
            return {'phase':'handback-released','epoch':self.epoch,'ownerGeneration':self.binding}

        def request(self, value):
            try:
                action=value['action']
                if action=='capture' and set(value)=={'action'}:return self.capture()
                if action=='bind' and set(value)=={'action','ownerGeneration'}:return self.bind(value['ownerGeneration'])
                if action=='current' and set(value)=={'action'}:return self.read_current()
                if action=='prepare':return self.prepare({k:v for k,v in value.items() if k!='action'})
                if action=='restore' and set(value)=={'action'}:return self.restore()
                if action=='verify' and set(value)=={'action'}:return self.verify()
                if action=='read' and set(value)=={'action'}:return self.view()
                if action=='release' and set(value)=={'action'}:return self.release()
                need(False,'ORIGINAL_ACTION_REFUSED')
            except BaseException:
                self.poisoned=True
                # Do not close runner OFDs, clear intent, reconstruct cache, or retry.
                raise
    return DedicatedOriginalHolder()
