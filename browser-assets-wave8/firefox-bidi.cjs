'use strict';
// Native installed Firefox, unmodified sandbox, disposable profile, loopback BiDi.
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const sleep = ms => new Promise(r => setTimeout(r, ms));
class Firefox {
  async start(root) {
    this.profile = fs.mkdtempSync(path.join(root, 'firefox-wave8-'));
    fs.writeFileSync(path.join(this.profile, 'user.js'), [
      ['browser.shell.checkDefaultBrowser', false], ['browser.startup.homepage_override.mstone', 'ignore'],
      ['datareporting.policy.dataSubmissionEnabled', false], ['toolkit.telemetry.enabled', false],
      ['browser.newtabpage.enabled', false], ['browser.startup.page', 0],
      ['app.update.auto', false], ['browser.safebrowsing.downloads.enabled', false],
    ].map(([k,v]) => `user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});`).join('\n'));
    this.log = '';
    this.child = spawn('/usr/bin/firefox-esr', ['--headless', '--no-remote', '--profile', this.profile,
      '--remote-debugging-port', '0', 'about:blank'], { env: { ...process.env, MOZ_HEADLESS: '1' }, stdio:['ignore','pipe','pipe'] });
    this.startPid = this.child.pid;
    for (const stream of [this.child.stdout,this.child.stderr]) stream.on('data', b => { this.log += b; });
    for (let i=0;i<200 && !/WebDriver BiDi listening on (ws:\/\/[^\s]+)/.test(this.log);i++) {
      if(this.child.exitCode!==null) throw Error(this.log); await sleep(50);
    }
    const url = this.log.match(/WebDriver BiDi listening on (ws:\/\/[^\s]+)/)?.[1];
    if(!url) throw Error('Firefox BiDi readiness timeout: '+this.log);
    this.socket = new WebSocket(url.endsWith('/session') ? url : url.replace(/\/$/,'')+'/session');
    this.pending = new Map(); this.seq=0; this.events=[];
    this.socket.addEventListener('message', e => {
      const msg=JSON.parse(e.data);
      if(msg.id && this.pending.has(msg.id)) { const p=this.pending.get(msg.id); this.pending.delete(msg.id); clearTimeout(p.timer);
        msg.type==='error' ? p.reject(Error(JSON.stringify(msg))) : p.resolve(msg.result); }
      else this.events.push(msg);
    });
    await once(this.socket, 'open');
    this.session = await this.send('session.new', { capabilities:{ alwaysMatch:{ acceptInsecureCerts:false } } });
    await this.send('session.subscribe',{events:['log.entryAdded','browsingContext.userPromptOpened','network.responseCompleted']});
    const tree=await this.send('browsingContext.getTree',{}); this.context=tree.contexts[0].context;
    await this.send('browsingContext.setViewport',{context:this.context,viewport:{width:1440,height:1000},devicePixelRatio:1});
    return this;
  }
  send(method,params={}) { return new Promise((resolve,reject)=>{ const id=++this.seq; const timer=setTimeout(()=>{this.pending.delete(id);reject(Error('BiDi timeout '+method));},30000);
    this.pending.set(id,{resolve,reject,timer}); this.socket.send(JSON.stringify({id,method,params})); }); }
  async evaluate(expression) {
    const r=await this.send('script.evaluate',{expression:`(async()=>JSON.stringify(await (${expression})))()`,target:{context:this.context},awaitPromise:true});
    if(r.type!=='success')throw Error(JSON.stringify(r));
    return r.result.value===undefined?undefined:JSON.parse(r.result.value);
  }
  async navigate(url) { return this.send('browsingContext.navigate',{context:this.context,url,wait:'complete'}); }
  async click(selector) {
    const q=JSON.stringify(selector);
    await this.evaluate(`(()=>{const e=document.querySelector(${q});if(!e)throw Error('Missing '+${q});e.scrollIntoView({block:'center',behavior:'instant'});return true;})()`);
    let p;
    // Wait for modal transitions, scroll and async warning layout to stabilize;
    // a native pointer must hit the intended control, not its old coordinates.
    for(let i=0;i<30;i++){
      await sleep(80);
      p=await this.evaluate(`(()=>{const e=document.querySelector(${q}),r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2,t=document.elementFromPoint(x,y);return {x,y,disabled:e.disabled,width:r.width,height:r.height,hit:!!t&&(t===e||e.contains(t)),hitElement:t?{tag:t.tagName,id:t.id,className:typeof t.className==='string'?t.className:''}:null};})()`);
      if(p.hit&&!p.disabled&&p.width&&p.height)break;
    }
    if(p.disabled||!p.width||!p.height||!p.hit)throw Error('Button unavailable '+selector+JSON.stringify(p));
    return this.pointer(p.x,p.y);
  }
  async pointer(x,y) { return this.send('input.performActions',{context:this.context,actions:[{type:'pointer',id:'mouse',parameters:{pointerType:'mouse'},actions:[
    {type:'pointerMove',x:Math.round(x),y:Math.round(y),duration:30,origin:'viewport'},
    {type:'pointerDown',button:0},{type:'pointerUp',button:0}]}]}); }
  async fill(selector,value) { return this.evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});e.value=${JSON.stringify(value)};e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));return e.value;})()`); }
  async wait(expression, ms=15000) { const start=Date.now();while(Date.now()-start<ms){if(await this.evaluate(expression))return;await sleep(100);}throw Error('Browser wait timeout '+expression); }
  async close() {
    if(this.socket?.readyState===1){try{await this.send('browser.close');}catch{}this.socket.close();}
    if(this.child && this.child.exitCode===null && this.child.signalCode===null){const exited=once(this.child,'exit');this.child.kill('SIGTERM');await Promise.race([exited,sleep(5000)]);if(this.child.exitCode===null && this.child.signalCode===null){this.child.kill('SIGKILL');await exited;}}
    if(this.profile)fs.rmSync(this.profile,{recursive:true,force:true});
    return {pid:this.startPid,exitCode:this.child?.exitCode,signalCode:this.child?.signalCode,profileRemoved:this.profile?!fs.existsSync(this.profile):true};
  }
}
module.exports={Firefox,sleep};
if(require.main===module)(async()=>{const b=await new Firefox().start(process.env.TMPDIR);try{console.log(JSON.stringify(b.session));console.log(await b.evaluate('navigator.userAgent'));}finally{console.log(await b.close());}})().catch(e=>{console.error(e);process.exitCode=1;});
