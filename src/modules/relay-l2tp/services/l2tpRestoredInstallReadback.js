'use strict';

// Read-only reconciliation of a known returned rollback failure. The backup is
// never printed; every managed byte/mode and every changed runtime effect must
// already equal the backup. This does not execute rollback or retry install.
function restoredInstallProbe(operationId) {
    if (!/^[a-f0-9]{24}$/.test(operationId)) throw Error('INVALID_OPERATION_ID');
    return `import os,json,stat,hashlib,subprocess
operation_id=${JSON.stringify(operationId)}
p='/var/lib/celerity/l2tp/operations/'+operation_id

def read(path):
 f=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(f)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0:raise ValueError()
  return os.read(f,8388609),stat.S_IMODE(s.st_mode)
 finally:os.close(f)
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=10)
 return r.returncode,r.stdout
try:
 raw,_=read(p+'/backup.json');backup=json.loads(raw)
 allowed={'etc/ipsec.d/celerity-l2tp.conf','etc/ipsec.secrets','etc/xl2tpd/xl2tpd.conf','etc/ppp/options.xl2tpd','etc/ppp/chap-secrets','etc/nftables.d/celerity-l2tp.nft','usr/local/etc/xray/config.json'}
 if set(x['path']for x in backup['files'])|set(backup['absent'])!=allowed:raise ValueError()
 for x in backup['files']:
  b,mode=read('/'+x['path'])
  if b!=x['content'].encode() or mode!=x['mode']:raise ValueError()
 for x in backup['absent']:
  if os.path.lexists('/'+x):raise ValueError()
 state=p+'/state/'
 firewall=json.loads(read(state+'firewall.applied.json')[0]);xr=json.loads(read(state+'xray.before.json')[0]);services=json.loads(read(state+'l2tp-services.before.json')[0])
 rc,s=run(['nft','-j','list','tables'])
 if rc or any(x.get('table',{}).get('family')=='inet' and x.get('table',{}).get('name')=='celerity_l2tp'for x in json.loads(s)['nftables']):raise ValueError()
 rc,s=run(['ip','-j','-4','rule','list'])
 if rc or any(x.get('priority')==firewall['priority'] or str(x.get('table'))==str(firewall['routeTable'])for x in json.loads(s)):raise ValueError()
 rc,s=run(['ip','-j','-4','route','show','table','all'])
 if rc or any(str(x.get('table'))==str(firewall['routeTable'])for x in json.loads(s)):raise ValueError()
 for unit,expected in {**services,'xray.service':xr['wasActive']}.items():
  rc,s=run(['systemctl','show',unit,'--value','-p','ActiveState'])
  if s.strip()!=('active'if expected else'inactive'):raise ValueError()
 for proc in os.listdir('/proc'):
  if proc.isdigit() and int(proc)!=os.getpid():
   try:cmd=open('/proc/'+proc+'/cmdline','rb').read()
   except OSError:continue
   if operation_id.encode() in cmd and any(x in cmd for x in [b'celerity-l2tp',b'rollback.sh',b'activate-xray.sh']):raise ValueError()
 sidecar,_=read('/usr/local/etc/xray-bridge/config.json')
 print(json.dumps({'ok':True,'operationId':operation_id,'backupSha256':hashlib.sha256(raw).hexdigest(),'sidecarSha256':hashlib.sha256(sidecar).hexdigest(),'managedPaths':7,'firewallRestored':True,'servicesRestored':True,'runnerIdle':True}))
except Exception:
 print(json.dumps({'ok':False,'operationId':operation_id}))
`;
}
module.exports = { restoredInstallProbe };
