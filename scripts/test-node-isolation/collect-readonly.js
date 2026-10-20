'use strict';
// Run on TEST panel backend with its existing environment; read-only, fixed targets.
// stdout contains only physical/process/unit metadata, never SSH credentials/argv.
const { MongoClient, ObjectId } = require('mongodb');
const { Client } = require('ssh2');
const { createHash } = require('node:crypto');
const cryptoService = require('/app/src/services/cryptoService');
const targets = Object.freeze({
  '6ab18adc63913ebd4a917471': '132.243.230.19',
  '6ab93ad2646b4b7d2f43c907': '94.103.2.186',
  '6ab18d9c63913ebd4a917670': '50.114.160.63',
  '6ab4b53bc4c0304573e06c72': '104.143.201.72',
});
const python = String.raw`
import base64, hashlib, json, os, pathlib, subprocess

def command(args):
    r = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}, timeout=15)
    if r.returncode: raise RuntimeError('READONLY_COMMAND_FAILED')
    return r.stdout.decode()

def sha(data): return hashlib.sha256(data).hexdigest()

processes=[]
for e in pathlib.Path('/proc').iterdir():
    if not e.name.isdecimal(): continue
    try:
        raw=(e/'stat').read_text(); rest=raw[raw.rfind(')')+2:].split()
        try: exe=os.readlink(e/'exe')
        except FileNotFoundError: continue
        processes.append({'pid':int(e.name),'start':rest[19],'ppid':int(rest[1]),
                          'exe':exe,'cgroup':(e/'cgroup').read_text().strip()})
    except (FileNotFoundError,ProcessLookupError): pass
units=command(['/usr/bin/systemctl','list-units','--all','--no-legend','--plain','--no-pager','--type=service,socket,timer,scope'])
files=command(['/usr/bin/systemctl','list-unit-files','--no-legend','--no-pager','--type=service,socket,timer'])
metadata=command(['/usr/bin/systemctl','show','--no-pager','--all','--property=Id,LoadState,ActiveState,SubState,ControlGroup,MainPID,Job,FragmentPath,DropInPaths,KillMode'])
scheduler={}
for root in ['/etc/crontab','/etc/cron.d','/etc/cron.hourly','/etc/cron.daily','/etc/cron.weekly',
             '/etc/cron.monthly','/var/spool/cron','/var/spool/at','/etc/letsencrypt/renewal-hooks']:
    p=pathlib.Path(root)
    for f in ([p] if p.is_file() else p.rglob('*') if p.is_dir() else []):
        if f.is_file(): scheduler[str(f)]=sha(f.read_bytes())
key=pathlib.Path('/etc/ssh/ssh_host_ed25519_key.pub').read_bytes().split()
print(json.dumps({'machineId':pathlib.Path('/etc/machine-id').read_text().strip(),
 'bootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
 'localEd25519RawKeySha256':sha(base64.b64decode(key[1],validate=True)),
 'processes':processes,'units':units,'unitFiles':files,'unitMetadata':metadata,
 'schedulerFileDigests':scheduler,
 'jobs':command(['/usr/bin/systemctl','list-jobs','--no-legend','--no-pager'])}))
`;
const command = '/usr/bin/python3 -I -c ' + "'" + python.replace(/'/g, "'\\''") + "'";
function inspect(node) {
  return new Promise((resolve, reject) => {
    const conn = new Client(); let handshakeRawKeySha256; let ended = false;
    const timer = setTimeout(() => finish(new Error('READONLY_DEADLINE')), 60000);
    function finish(error, data) {
      if (ended) return; ended = true; clearTimeout(timer); conn.destroy();
      if (error) reject(new Error('READONLY_NODE_FAILED')); else resolve(data);
    }
    conn.on('error', () => finish(new Error('READONLY_SSH_FAILED')));
    conn.on('ready', () => conn.exec(command, (err, stream) => {
      if (err) return finish(err);
      let stdout = ''; let stderr = '';
      stream.on('data', data => { stdout += data; if (stdout.length > 2000000) finish(new Error('OUTPUT_LIMIT')); });
      stream.stderr.on('data', data => { stderr += data; });
      stream.on('close', code => {
        if (code !== 0 || stderr) return finish(new Error('READONLY_REMOTE_FAILED'));
        try {
          const physical = JSON.parse(stdout);
          if (physical.localEd25519RawKeySha256 !== handshakeRawKeySha256) return finish(new Error('HOSTKEY_DISAGREES'));
          finish(null, {nodeId: String(node._id), endpoint: {ip: node.ip, port: 22, username: 'root'},
            handshakeRawKeySha256, physical});
        } catch { finish(new Error('INVALID_READONLY_REPLY')); }
      });
      stream.end();
    }));
    const cfg = {host: node.ip, port: 22, username: 'root', readyTimeout: 15000,
      algorithms: {serverHostKey: ['ssh-ed25519']},
      hostVerifier: raw => { handshakeRawKeySha256 = createHash('sha256').update(raw).digest('hex'); return true; }};
    if (node.ssh?.privateKey) cfg.privateKey = cryptoService.decryptPrivateKey(node.ssh.privateKey);
    else if (node.ssh?.password) cfg.password = cryptoService.decryptSafe(node.ssh.password);
    else return finish(new Error('NO_EXISTING_CREDENTIAL'));
    conn.connect(cfg);
  });
}
(async () => {
  if (process.env.PANEL_DOMAIN !== 'test.infograd.online') throw new Error('WRONG_TEST_HOST');
  const client = new MongoClient(process.env.MONGO_URI, {serverSelectionTimeoutMS: 5000, retryReads: false, retryWrites: false});
  try {
    await client.connect();
    const nodes = await client.db().collection('hynodes').find({_id: {$in: Object.keys(targets).map(id => new ObjectId(id))}},
      {maxTimeMS: 4000}).toArray();
    if (nodes.length !== 4) throw new Error('FIXED_INVENTORY_MISSING');
    for (const node of nodes) {
      if (node.ip !== targets[String(node._id)] || node.ssh?.port !== 22 || node.ssh?.username !== 'root') throw new Error('FIXED_ENDPOINT_DRIFT');
    }
    const results = [];
    for (const node of nodes) {
      try { results.push(await inspect(node)); }
      catch { results.push({nodeId: String(node._id), error: 'READONLY_NODE_FAILED'}); }
    }
    console.log(JSON.stringify({diagnosticOnly: true, notAuthority: true, trustOnFirstObservation: true,
      sharedPanelHostExcluded: true, results}));
    if (results.some(r => r.error)) process.exitCode = 1;
  } finally { await client.close(); }
})().catch(() => {console.error(JSON.stringify({error: 'READONLY_INVENTORY_FAILED'})); process.exitCode = 1;});
