#!/usr/bin/env python3
"""Finite, read-only dedicated TEST node observation under an owned runtime lock.
Not usable on a shared host: a real nspawn PID/mount runtime and provisioning
record are mandatory. The Xray v2 journal is observed, never edited/adopted.
"""
import fcntl,hashlib,json,os,re,stat,subprocess,sys
ROOT='/var/lib/celerity/dedicated-test'
def read(p):
    f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NOATIME)
    try:
        s=os.fstat(f)
        if not stat.S_ISREG(s.st_mode) or s.st_size>4194304:raise RuntimeError('UNSAFE_FILE')
        return os.read(f,4194305)
    finally:os.close(f)
def run(a):
    p=subprocess.run(a,capture_output=True,text=True,timeout=10)
    if p.returncode:raise RuntimeError('READBACK_FAILED')
    return p.stdout.strip()
def observe(request):
    provision=json.loads(read(ROOT+'/provision.json'))
    if read('/run/systemd/container').strip()!=b'systemd-nspawn':raise RuntimeError('DEDICATED_RUNTIME_REQUIRED')
    if os.stat('/proc/1/ns/pid').st_ino==provision['hostPidNamespace']:raise RuntimeError('PRIVATE_PID_RUNTIME_REQUIRED')
    if read('/etc/machine-id').decode().strip()!=provision['machineId']:raise RuntimeError('MACHINE_CHANGED')
    if run(['systemctl','is-active','sshd.service'])!='active':raise RuntimeError('SSH_NOT_READY')
    # Provisioning pins the complete sole authorized-key inventory. No hidden
    # password authentication/second backend or host alias is accepted.
    if hashlib.sha256(read('/root/.ssh/authorized_keys')).hexdigest()!=provision['authorizedKeysSha256']:raise RuntimeError('CREDENTIAL_WRITERS_CHANGED')
    if hashlib.sha256(read('/etc/ssh/sshd_config')).hexdigest()!=provision['sshdConfigSha256']:raise RuntimeError('SSH_SCOPE_CHANGED')
    boot=read('/proc/sys/kernel/random/boot_id').decode().strip()
    current={}
    for profile,unit,path in [('xray-main','xray.service','/usr/local/etc/xray/config.json'),('xray-bridge','xray-bridge.service','/usr/local/etc/xray-bridge/config.json')]:
        unitpath='/etc/systemd/system/'+unit
        props=dict(line.split('=',1)for line in run(['systemctl','show',unit,'-p','FragmentPath','-p','DropInPaths','-p','ActiveState','-p','UnitFileState','-p','Job']).splitlines())
        if props['FragmentPath']!=unitpath or props['DropInPaths'] or props['Job']:raise RuntimeError('UNOWNED_UNIT')
        current[profile]={'source':'node-readback','configSha256':hashlib.sha256(read(path)).hexdigest(),'unitSha256':hashlib.sha256(read(unitpath)).hexdigest(),'serviceActive':props['ActiveState'],'serviceEnabled':props['UnitFileState']}
    profile=provision['targetProfile'];journal='/var/lib/celerity/topology/fences/'+profile+'/journal.json'
    state=None
    if os.path.lexists(journal.rsplit('/',1)[0]+'/journal.next'):raise RuntimeError('UNKNOWN_RETAINED')
    if os.path.lexists(journal):
        state=json.loads(read(journal))
        if state['version']!=2 or state['nodeId']!=provision['nodeId'] or state['executionContext']!='test.infograd.online' or state['bootId']!=boot:raise RuntimeError('JOURNAL_BINDING_CHANGED')
    else:
        # No missing-journal adoption: only a genuinely pristine provisioned
        # runtime may have no journal, operations or backups.
        for p in ['/var/lib/celerity/topology/fences/'+profile,'/var/lib/celerity/topology/operations','/var/lib/celerity/topology/backups']:
            if os.path.lexists(p):raise RuntimeError('PRISTINE_STATE_UNPROVEN')
    bootstrap_pristine=all(not os.path.lexists(p) for p in [
        '/usr/local/bin/celerity-topology-node-runner-v2',
        '/usr/local/bin/.celerity-topology-node-runner-v2.upload',
        '/usr/local/bin/.celerity-topology-node-runner-v2.next']) and state is None
    # Absence alone is not continuation authority. Include exact original
    # profile/unit state; the held server repository additionally validates
    # failed operation, immutable bindings, owners, enrollment and retained locks.
    bootstrap_pristine=bootstrap_pristine and current[profile]==provision['originalSnapshot']
    runner_idle=True
    for pid in os.listdir('/proc'):
        if not pid.isdigit():continue
        try:
            with open('/proc/'+pid+'/cmdline','rb')as f:cmd=f.read(65536)
        except FileNotFoundError:continue
        if b'celerity-topology-node-runner-v2' in cmd:bootstrap_pristine=False;runner_idle=False
    result={'nonce':request['nonce'],'provision':provision,'bootId':boot,'current':current,'journal':state,'bootstrapPristine':bootstrap_pristine,'runnerIdle':runner_idle}
    # Narrow empty-PPP producer evidence for the retained verified TEST suffix.
    # Packages/default ipsec.conf are not installation; never alter either here.
    ppp_units=run(['systemctl','show','xl2tpd.service','strongswan-starter.service','strongswan.service','-p','ActiveState','-p','MainPID'])
    result['l2tpUnconfigured']=not any(os.path.exists(p) for p in ['/etc/xl2tpd/xl2tpd.conf','/etc/ppp/options.xl2tpd']) and not any(p.startswith('ppp') for p in os.listdir('/sys/class/net')) and all(x in ('','ActiveState=inactive','MainPID=0') for x in ppp_units.splitlines())
    if 'noDispatch' in request:
        b=request['noDispatch']
        if set(b)!=set(['nodeId','operationId','generation','backupId','targetProfile']):raise RuntimeError('RESERVATION_INVALID')
        if b['nodeId']!=provision['nodeId'] or b['targetProfile']!=profile or not re.fullmatch('[a-f0-9]{24}',b['operationId']) or not re.fullmatch('[a-f0-9-]{36}',b['generation']) or not re.fullmatch('topology-[a-f0-9]{64}',b['backupId']):raise RuntimeError('RESERVATION_INVALID')
        head=state.get('generations',{}).get(state.get('head'),{}) if state else {}
        applied=head
        closes=[x.get('receipt',{}) for x in head.get('commands',{}).values() if x.get('command')=='close' and x.get('state')=='completed']
        if head.get('phase')=='closed' and len(closes)==1 and closes[0].get('terminalOutcome')=='cancelled' and len(head.get('commands',{}))==1:
            applied=state['generations'].get(head['binding']['predecessorGeneration'],{})
        settled=head.get('phase')=='closed' and applied.get('phase')=='closed' and applied.get('binding',{}).get('candidateHash')=='sha256:'+current[profile]['configSha256'] and current[profile]['serviceActive']=='active'
        if not runner_idle or state is None or b['generation'] in state['generations'] or not (current[profile]==provision['originalSnapshot'] or settled):raise RuntimeError('RESERVATION_EFFECT_UNPROVEN')
        if any(g.get('binding',{}).get('operationId')==b['operationId'] for g in state['generations'].values()):raise RuntimeError('RESERVATION_EFFECT_UNPROVEN')
        for p in ['/var/lib/celerity/topology/operations/'+b['operationId'],'/var/lib/celerity/topology/backups/'+b['backupId']]:
            if os.path.lexists(p):raise RuntimeError('RESERVATION_EFFECT_UNPROVEN')
        result['noDispatch']={**b,'bootId':boot,'runnerIdle':True,'generationAbsent':True,'operationAbsent':True,'backupAbsent':True}
    return result
def cancel_prepare(b):
    # Dedicated TEST only, no config write, no command replay. Original unknown
    # prepare remains in its command record; append a distinct actual close proof.
    provision=json.loads(read(ROOT+'/provision.json'));profile=provision['targetProfile']
    if b.get('executionContext')!='test.infograd.online' or b.get('nodeId')!=provision['nodeId'] or b.get('targetProfile')!=profile:raise RuntimeError('CANCEL_BINDING_CHANGED')
    boot=read('/proc/sys/kernel/random/boot_id').decode().strip()
    if b.get('bootId')!=boot:raise RuntimeError('CANCEL_BOOT_CHANGED')
    froot='/var/lib/celerity/topology/fences/'+profile
    os.makedirs(froot,mode=0o700,exist_ok=True)
    lock=os.open(froot+'/lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if os.path.lexists(froot+'/journal.next'):raise RuntimeError('CANCEL_UNKNOWN_JOURNAL')
        paths={'xray-main':('xray.service','/usr/local/etc/xray/config.json'),'xray-bridge':('xray-bridge.service','/usr/local/etc/xray-bridge/config.json')}
        unit,path=paths[profile];unitpath='/etc/systemd/system/'+unit
        props=dict(x.split('=',1)for x in run(['systemctl','show',unit,'-p','ActiveState','-p','UnitFileState','-p','MainPID','-p','Job']).splitlines())
        snapshot={'source':'node-readback','configSha256':hashlib.sha256(read(path)).hexdigest(),'unitSha256':hashlib.sha256(read(unitpath)).hexdigest(),'serviceActive':props['ActiveState'],'serviceEnabled':props['UnitFileState']}
        if snapshot!=provision['originalSnapshot'] or props['MainPID']!='0' or props['Job']:raise RuntimeError('CANCEL_CONFIG_EFFECT_UNPROVEN')
        binding={k:b[k]for k in ['operationId','nodeId','candidateHash','backupId','targetProfile','executionContext','attemptId','generation','predecessorGeneration']}
        jp=froot+'/journal.json';prior=None
        if os.path.exists(jp):
            j=json.loads(read(jp));g=j['generations'].get(b['generation']);prior=json.loads(json.dumps(g))
            if j['bootId']!=boot or j['head']!=b['generation'] or not g or g['binding']!=binding or g['phase']!='prepare-running':raise RuntimeError('CANCEL_PHASE_UNPROVEN')
            if g['commands']!={b['commandIds']['prepare']:{'command':'prepare','state':'running'}}:raise RuntimeError('CANCEL_COMMAND_UNPROVEN')
            op='/var/lib/celerity/topology/operations/'+b['operationId']+'/'+profile;back='/var/lib/celerity/topology/backups/'+b['backupId']+'/'+profile
            if os.listdir(op)!=['candidate.json'] or os.listdir(back)!=[]:raise RuntimeError('CANCEL_PREPARE_EFFECT_UNPROVEN')
            if 'sha256:'+hashlib.sha256(read(op+'/candidate.json')).hexdigest()!=b['candidateHash']:raise RuntimeError('CANCEL_CANDIDATE_CHANGED')
        else:
            if b['predecessorGeneration']!='none':raise RuntimeError('CANCEL_PREDECESSOR_UNPROVEN')
            for p in ['/var/lib/celerity/topology/operations','/var/lib/celerity/topology/backups']:
                if os.path.lexists(p):raise RuntimeError('CANCEL_PRISTINE_UNPROVEN')
            j={'version':2,'bootId':boot,'nodeId':b['nodeId'],'executionContext':b['executionContext'],'head':b['generation'],'generations':{}}
            g={'binding':binding,'phase':'new','commands':{}};j['generations'][b['generation']]=g
        receipt={**binding,'ok':True,'command':'status','commandId':b['commandIds']['close'],'protocolVersion':2,'completion':'completed','phase':'closed','terminal':True,'ownershipRetained':True,'terminalOutcome':'cancelled','bootId':boot,'systemdJob':'not-applicable','serviceState':'not-applicable','completedCommand':'close'}
        # Persist the original unknown command untouched, with separate explicit
        # quiescence/no-config-effect reconciliation. Never claim old prepare PASS.
        g['bootstrapCancellation']={'kind':'uncommitted-prepare-validation','original':prior,'profileReadback':snapshot}
        g['phase']='closed';g['commands'][b['commandIds']['close']]={'state':'completed','command':'close','receipt':{**receipt,'command':'close'}}
        tmp=froot+'/journal.next';fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w')as f:json.dump(j,f,separators=(',',':'),sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,jp);fd=os.open(froot,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        fresh=json.loads(read(jp));stored=fresh['generations'][b['generation']]['commands'][b['commandIds']['close']]['receipt']
        if stored!={**receipt,'command':'close'}:raise RuntimeError('CANCEL_READBACK_UNCONFIRMED')
        return receipt
    finally:os.close(lock)
def native_close_absent(b, request):
    # Use the existing runner's native new -> close transition. This observer
    # never manufactures a receipt or edits a journal. An interrupted close is
    # read by its exact command ID; it is never replayed.
    fields=['operationId','nodeId','candidateHash','backupId','targetProfile','executionContext','attemptId','generation','predecessorGeneration']
    before=observe(request);j=before['journal'];profile=b['targetProfile']
    if b['nodeId']!=before['provision']['nodeId'] or b['executionContext']!='test.infograd.online' or b['bootId']!=before['bootId'] or profile!=before['provision']['targetProfile']:
        raise RuntimeError('CLOSE_BINDING_CHANGED')
    prior=j and j['generations'].get(b['predecessorGeneration'])
    if not prior or prior['phase']!='closed' or prior['binding']['candidateHash']!='sha256:'+before['current'][profile]['configSha256'] or before['current'][profile]['serviceActive']!='active' or not before['runnerIdle']:
        raise RuntimeError('CLOSE_PREDECESSOR_UNPROVEN')
    g=j['generations'].get(b['generation'])
    if g is None:
        reservation={k:b[k] for k in ['nodeId','operationId','generation','backupId','targetProfile']}
        observe({**request,'noDispatch':reservation})
        if j['head']!=b['predecessorGeneration']:raise RuntimeError('CLOSE_HEAD_CHANGED')
        command='close'
    else:
        if j['head']!=b['generation'] or g['phase']!='closed' or g['binding']!={k:b[k] for k in fields} or set(g['commands'])!={b['commandIds']['close']}:
            raise RuntimeError('CLOSE_OUTCOME_RETAINED')
        command='status'
    names=['operation-id','node-id','candidate-hash','backup-id','target-profile','execution-context','attempt-id','generation','predecessor-generation']
    args=['/usr/local/bin/celerity-topology-node-runner-v2','--command',command]
    for key,name in zip(fields,names):args+=['--'+name,b[key]]
    args+=['--command-id',b['commandIds']['close']]
    p=subprocess.run(args,capture_output=True,text=True,timeout=10)
    if p.returncode or p.stderr:raise RuntimeError('NATIVE_CLOSE_RETAINED')
    closed=json.loads(p.stdout)
    if command=='close':
        args[2]='status'
        p=subprocess.run(args,capture_output=True,text=True,timeout=10)
        if p.returncode or p.stderr:raise RuntimeError('NATIVE_CLOSE_STATUS_RETAINED')
        status=json.loads(p.stdout)
        if status!={**closed,'command':'status'}:raise RuntimeError('NATIVE_CLOSE_STATUS_CHANGED')
        closed=status
    after=observe(request)
    if after['current']!=before['current'] or not after['runnerIdle']:raise RuntimeError('CLOSE_EFFECT_CHANGED')
    return closed

def main():
    if read('/run/systemd/container').strip()!=b'systemd-nspawn':raise RuntimeError('DEDICATED_RUNTIME_REQUIRED')
    s=os.lstat(ROOT)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o077:raise RuntimeError('UNOWNED_RUNTIME')
    provision=json.loads(read(ROOT+'/provision.json'))
    if os.stat('/proc/1/ns/pid').st_ino==provision['hostPidNamespace']:raise RuntimeError('PRIVATE_PID_RUNTIME_REQUIRED')
    lock=os.open(ROOT+'/writer.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    originals=None
    for line in sys.stdin:
        request=json.loads(line)
        if 'originals' in request:
            if originals is None:
                scope={'__name__':'celerity_dedicated_originals'}
                exec(compile(read('/usr/local/libexec/celerity-test-dedicated-originals.py'),'<installed-dedicated-originals>','exec'),scope)
                originals=scope['make_holder'](observe,lock,read)
            value={'nonce':request['nonce'],'originals':originals.request(request['originals'])}
        elif 'cancelPrepare' in request:
            observe(request) # exact runtime/provision/key/unit checks still apply
            value={'nonce':request['nonce'],'terminalProof':cancel_prepare(request['cancelPrepare'])}
        elif 'nativeCloseAbsent' in request:
            value={'nonce':request['nonce'],'terminalProof':native_close_absent(request['nativeCloseAbsent'],request)}
        else:value=observe(request)
        print(json.dumps(value,separators=(',',':')),flush=True)
if __name__=='__main__':
    try:main()
    except Exception:
        print('DEDICATED_TEST_OBSERVATION_REFUSED',file=sys.stderr);sys.exit(1)
