#!/usr/bin/env bash
set -euo pipefail
cd /home/leon/c3-anyorder-browser-assets-20261104
out=browser-assets-wave8
# Invoke through the bounded hermes-heavy command documented in report.md.
node -e "if(!require('fs').readFileSync('/proc/self/cgroup','utf8').includes('/hermes-heavy-'))throw Error('bounded heavy scope required');if(require('fs').existsSync('node_modules')&&require('fs').lstatSync('node_modules').isSymbolicLink())throw Error('private node_modules required')"
log=${BUILD_LOG_PATH:-$out/build-replay.log}
[[ ! -e "$log" ]] || { printf 'Refusing to overwrite existing build log: %s\n' "$log" >&2; exit 2; }
exec >"$log" 2>&1
printf 'Build start '; date -u --iso-8601=seconds
printf 'Isolation\n'; node -e "process.stdout.write(require('fs').readFileSync('/proc/self/cgroup'))"
node --version; npm --version
sha256sum package-lock.json > "$out/lock.before.sha256"
# No project install hooks exist. Lock dependencies may run their own native install hooks.
npm ci --no-audit --no-fund --prefer-offline --fetch-retries=1 --fetch-timeout=60000
sha256sum -c "$out/lock.before.sha256"
npm ls --all --json > "$out/installed-tree.json"
node - <<'JS' > "$out/dependency-evidence.json"
const fs=require('fs'),crypto=require('crypto');
const lock=JSON.parse(fs.readFileSync('package-lock.json'));
const installed=JSON.parse(fs.readFileSync('node_modules/.package-lock.json'));
const rows=Object.entries(installed.packages).map(([p,v])=>({path:p,version:v.version,integrity:v.integrity||null,resolved:v.resolved||null,lockVersion:lock.packages[p]?.version,matches:lock.packages[p]?.version===v.version}));
if(rows.some(r=>!r.matches))throw Error('installed/lock version mismatch');
console.log(JSON.stringify({node:process.version,lockSha256:crypto.createHash('sha256').update(fs.readFileSync('package-lock.json')).digest('hex'),packages:rows.length,integrityPresent:rows.filter(r=>r.integrity).length,rows},null,2));
JS
npm run build:assets
node - <<'JS'
const fs=require('fs'),crypto=require('crypto');
const key=crypto.createHash('sha256').update(fs.readFileSync('public/js/network.min.js')).digest('hex').slice(0,16);
for(const file of ['views/nodes.ejs','views/network.ejs']) {
  const source=fs.readFileSync(file,'utf8');
  if(!/network\.min\.js\?v=[a-f0-9]+/.test(source))throw Error('Missing network cache reference '+file);
  fs.writeFileSync(file,source.replace(/network\.min\.js\?v=[a-f0-9]+/g,'network.min.js?v='+key));
}
JS
node scripts/test-network-ui.js
node scripts/test-network-layout-preservation.js
node --test scripts/test-network-edit-ui.js
node --test scripts/test-network-anyorder-ui.js
sha256sum package-lock.json public/js/network.js public/js/network.min.js public/css/style.min.css public/css/network.min.css > "$out/assets.sha256"
sha256sum -c "$out/lock.before.sha256"
printf 'Build end '; date -u --iso-8601=seconds
