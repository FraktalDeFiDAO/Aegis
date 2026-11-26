#!/usr/bin/env node
// Real Chromium + extension + Go bridge on an isolated profile and local fixtures.
// No user profile, external site, or real account is accessed.
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const http=require('node:http');
const net=require('node:net');
const {spawn}=require('node:child_process');
const {createHash,randomBytes}=require('node:crypto');
const assert=require('node:assert/strict');
const {setTimeout:delay}=require('node:timers/promises');

const root=path.resolve(__dirname,'..');
const binary=path.resolve(process.argv[2]||path.join(root,'aegis'));
const chromium=process.env.AEGIS_TEST_CHROMIUM||'/usr/bin/chromium';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const children=[];
let temp,server,bridge,cdp;
let cliEnv={};
async function until(check,label,timeout=30000){const deadline=Date.now()+timeout;while(Date.now()<deadline){const value=await check();if(value)return value;await delay(100);}throw new Error('Timed out: '+label);}
async function freePort(){const s=net.createServer();await new Promise(resolve=>s.listen(0,'127.0.0.1',resolve));const p=s.address().port;await new Promise(resolve=>s.close(resolve));return p;}
function start(command,args,env={}){
 const child=spawn(command,args,{env:{...process.env,...env},stdio:['ignore','ignore','pipe'],detached:true});
 child.ownProcessGroup=true;child.log='';child.stderr.on('data',data=>{child.log=(child.log+data.toString()).slice(-12000)});children.push(child);return child;
}
async function run(command,args,expectSuccess=true){
 const child=spawn(command,args,{env:{...process.env,...cliEnv},stdio:['ignore','pipe','pipe']});children.push(child);let stdout='',stderr='';
 child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);
 const result=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code)=>resolve({code,stdout,stderr}));});
 if(expectSuccess)assert.equal(result.code,0,`CLI failed: ${stderr}\n${stdout}`);return result;
}
class RPC{
 static async connect(url,token=null){const rpc=new RPC();rpc.socket=new WebSocket(url);rpc.pending=new Map();rpc.id=0;
  rpc.socket.addEventListener('message',event=>{const msg=JSON.parse(event.data);if(!msg.id)return;const pending=rpc.pending.get(String(msg.id));if(pending){rpc.pending.delete(String(msg.id));clearTimeout(pending.timer);(msg.error&&msg.type!=='result')?pending.reject(new Error(JSON.stringify(msg.error))):pending.resolve(msg.result??msg)}});
  rpc.socket.addEventListener('close',()=>{for(const p of rpc.pending.values()){clearTimeout(p.timer);p.reject(new Error('WebSocket closed'))}rpc.pending.clear()});
  await new Promise((resolve,reject)=>{rpc.socket.addEventListener('open',resolve,{once:true});rpc.socket.addEventListener('error',reject,{once:true})});
  if(token!==null){try{await rpc.authenticate(token)}catch(error){rpc.close();throw error}}
  return rpc;
 }
 authenticate(token){const id='hello-'+(++this.id);return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.pending.delete(id);reject(new Error('Bridge hello timeout'))},5000);this.pending.set(id,{resolve,reject,timer});this.socket.send(JSON.stringify({id,type:'hello',client:'aegis',version:1,token}))})}
 call(method,params={},sessionId){const id=String(++this.id);return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.pending.delete(id);reject(new Error('RPC timeout: '+method))},25000);this.pending.set(id,{resolve,reject,timer});this.socket.send(JSON.stringify({id:Number(id),method,params,...(sessionId?{sessionId}:{})}))})}
 command(command,params={},tabId){const id='test-'+(++this.id);return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.pending.delete(id);reject(new Error('Browser command timeout: '+command))},30000);this.pending.set(id,{resolve:msg=>msg.success?resolve(msg.data):reject(new Error(JSON.stringify(msg))),reject,timer});this.socket.send(JSON.stringify({id,type:'command',command,params,tabId,timeout:25000,version:1}))})}
 close(){this.socket.close()}
}

async function main(){
 temp=await fs.mkdtemp(path.join(os.tmpdir(),'aegis-browser-e2e-'));
 cliEnv={XDG_CONFIG_HOME:path.join(temp,'config')};
 const source=path.join(temp,'local file.bin');const second=path.join(temp,'empty.bin');await fs.writeFile(second,Buffer.alloc(0));const payload=randomBytes(512*1024+37);await fs.writeFile(source,payload);
 let received=null;
 server=http.createServer(async(req,res)=>{
  if(req.url==='/download'){res.writeHead(200,{'content-type':'application/octet-stream','content-disposition':'attachment; filename="fixture.bin"','content-length':payload.length});res.end(payload);return;}
  if(req.url==='/upload'&&req.method==='POST'){const hash=createHash('sha256');let size=0;for await(const chunk of req){hash.update(chunk);size+=chunk.length;}received={sha256:hash.digest('hex'),size};res.setHeader('content-type','application/json');res.end(JSON.stringify(received));return;}
  const port=server.address().port;
  if(req.url==='/frame'){res.setHeader('content-type','text/html');res.end('<!doctype html><h1 id="frame-title">Cross-origin frame</h1><input id="frame-file" type="file"><textarea id="frame-text"></textarea>');return;}
  res.setHeader('content-type','text/html');res.end(`<!doctype html><title>Aegis browser fixture</title><style>body{min-height:2000px}#submit{position:absolute;left:20px;top:90px;width:120px;height:40px}#native{position:absolute;left:160px;top:90px;width:140px;height:40px}</style><input id="file" type="file" multiple><textarea id="text"></textarea><button id="submit">Upload</button><button id="native">Trusted click</button><button id="confirm" style="position:absolute;left:320px;top:90px;width:120px;height:40px">Confirm</button><div id="dialog-result"></div><div id="drag" draggable="true" style="position:absolute;left:20px;top:150px;width:60px;height:40px;background:red">Drag</div><div id="drop" style="position:absolute;left:200px;top:150px;width:100px;height:40px;background:green">Drop</div><div id="drop-result"></div><form id="keyboard"><input id="key-input"><button type="submit">Submit</button></form><div id="key-result"></div><div id="result"></div><div id="trusted"></div><div id="shadow"></div><console-policy-declaration><console-button-set><div class="_nghost-test"><button aria-label="Start Privacy policy declaration" id="privacy-declaration">Start declaration</button></div></console-button-set></console-policy-declaration><console-policy-declaration><console-button-set><div class="_nghost-other"><button aria-label="Start Ads declaration" id="ads-declaration">Start declaration</button></div></console-button-set></console-policy-declaration><button aria-label="Disabled declaration" disabled>Start declaration</button><input id="fixture-secret" type="password" value="never-print-this"><div id="declaration-selected"></div><iframe id="child" src="http://localhost:${port}/frame"></iframe><script>document.querySelector('#privacy-declaration').onclick=()=>document.querySelector('#declaration-selected').textContent='privacy';document.querySelector('#ads-declaration').onclick=()=>document.querySelector('#declaration-selected').textContent='ads';document.querySelector('#submit').onclick=async()=>{const file=document.querySelector('#file').files[0];const r=await fetch('/upload',{method:'POST',body:file});document.querySelector('#result').textContent=await r.text()};document.querySelector('#confirm').onclick=()=>document.querySelector('#dialog-result').textContent=String(confirm('Aegis fixture confirmation'));document.querySelector('#drag').ondragstart=e=>e.dataTransfer.setData('text/plain','aegis-drag');document.querySelector('#drop').ondragover=e=>e.preventDefault();document.querySelector('#drop').ondrop=e=>{e.preventDefault();document.querySelector('#drop-result').textContent=e.dataTransfer.getData('text/plain')+':'+e.isTrusted};document.querySelector('#keyboard').onsubmit=e=>{e.preventDefault();document.querySelector('#key-result').textContent=String(e.isTrusted)+':'+document.querySelector('#key-input').value};document.querySelector('#native').onclick=e=>document.querySelector('#trusted').textContent=String(e.isTrusted);document.querySelector('#shadow').attachShadow({mode:'open'}).innerHTML='<input id="shadow-input">';</script>`);
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const fixtureURL=`http://127.0.0.1:${server.address().port}/`;
 const bridgePort=await freePort();const bridgeURL=`ws://127.0.0.1:${bridgePort}/ws?client=aegis`;
 const go=start(binary,['connect','serve','--port',String(bridgePort)],{XDG_CONFIG_HOME:path.join(temp,'config')});
 await until(async()=>{if(go.exitCode!==null)throw new Error(go.log);try{return(await fetch(`http://127.0.0.1:${bridgePort}/health`)).ok}catch{return false}},'bridge startup');
 const runtimeState=JSON.parse(await fs.readFile(path.join(temp,'config','aegis','connector','runtime.json'),'utf8'));const bridgeToken=runtimeState.token;assert.equal(typeof bridgeToken,'string');assert.ok(bridgeToken.length>=32);
 const extension=path.join(temp,'extension');await fs.cp(path.join(root,'extension'),extension,{recursive:true});
 const manifest=JSON.parse(await fs.readFile(path.join(extension,'manifest.chrome.json'),'utf8'));
 const workerFile=path.join(extension,'background.js');
 await fs.writeFile(workerFile,(await fs.readFile(workerFile,'utf8')).replace('const DEFAULT_PORT = 9876;',`const DEFAULT_PORT = ${bridgePort};`).replace("let bridgeToken = '';",`let bridgeToken = ${JSON.stringify(bridgeToken)};`).replace("bridgeToken = c.token || '';",'bridgeToken = c.token || bridgeToken;').replace("mode: 'manual-approve', //","mode: 'unattended', //"));
 // Test-only profile uses a dedicated bridge and explicit fixture policy. It cannot launch a user's native host.
 manifest.permissions=manifest.permissions.filter(p=>p!=='nativeMessaging');await fs.writeFile(path.join(extension,'manifest.json'),JSON.stringify(manifest));
 const profile=path.join(temp,'profile');await fs.mkdir(profile);
 const chrome=start(chromium,['--headless=new','--no-sandbox',`--user-data-dir=${profile}`,`--load-extension=${extension}`,`--disable-extensions-except=${extension}`,'--remote-debugging-port=0','--no-first-run','--no-default-browser-check','--disable-dev-shm-usage','--disable-background-networking','--disable-component-update','--disable-sync',fixtureURL]);
 const devtools=await until(async()=>{if(chrome.exitCode!==null)throw new Error(chrome.log);try{return(await fs.readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')}catch{return false}},'Chromium startup');
 await until(async()=>{const health=await(await fetch(`http://127.0.0.1:${bridgePort}/health`)).json();return health.extensionConnected},'extension handshake');
 const browserCDP=await RPC.connect(`ws://127.0.0.1:${devtools[0]}${devtools[1]}`);cdp=browserCDP;
 await fs.mkdir(path.join(temp,'downloads'));
 await browserCDP.call('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:path.join(temp,'downloads')});
 await assert.rejects(RPC.connect(bridgeURL,'wrong-token'),/permission_denied|authentication failed/);
 console.log('PASS wrong controller credential rejected');
 bridge=await RPC.connect(bridgeURL,bridgeToken);
 console.log('PASS isolated extension/bridge startup');
 const implementation=await bridge.command('extension.info');assert.equal(implementation.version,'1.1.2');assert.equal(implementation.features.strictCssTargets,true);
 const tabs=await bridge.command('listTabs');const tab=tabs.tabs.find(t=>t.url===fixtureURL);assert.ok(tab,'Fixture tab is missing');
 await until(async()=>{try{return(await bridge.command('querySelector',{selector:'#file',frameId:0},tab.id)).found}catch{return false}},'fixture content script');
 const workspace=await bridge.command('createTabGroup',{tabIds:[tab.id],title:'Aegis',color:'blue'},tab.id);
 const taskTab=await bridge.command('newTab',{url:fixtureURL,active:false},tab.id);
 assert.equal(taskTab.groupId,workspace.groupId);
 const taskInfo=await bridge.command('getTabInfo',{},taskTab.tabId);
 assert.equal(taskInfo.groupId,workspace.groupId);assert.equal(taskInfo.windowId,tab.windowId);
 assert.ok((await bridge.command('target.get')).targetSet.tabs.includes(taskTab.tabId));
 await bridge.command('closeTab',{tabId:taskTab.tabId},tab.id);
 console.log('PASS new task tabs inherit the native Aegis group and window');
 const frames=await bridge.command('listFrames',{},tab.id);const child=frames.frames.find(f=>f.url.includes('/frame'));assert.ok(child,'Cross-origin frame missing');
 await bridge.command('switchFrame',{frameId:child.frameId},tab.id);
 assert.equal((await bridge.command('getElementText',{selector:'#frame-title'},tab.id)).text,'Cross-origin frame');
 assert.equal((await bridge.command('getTitle',{frameId:0},tab.id)).title,'Aegis browser fixture');
 await bridge.command('fill',{frameId:child.frameId,selector:'#frame-text',value:'Frame text'},tab.id);
 assert.equal((await bridge.command('getElementAttribute',{frameId:child.frameId,selector:'#frame-text',attribute:'id'},tab.id)).value,'frame-text');
 await bridge.command('switchMain',{},tab.id);
 await bridge.command('fill',{frameId:0,selector:'#shadow >>> #shadow-input',value:'Shadow text'},tab.id);
 console.log('PASS explicit main/cross-origin frame targeting, textarea and open-shadow-root interaction');
 const declarations=await bridge.command('querySelectorAll',{frameId:0,selector:'console-policy-declaration button'},tab.id);
 assert.equal(declarations.count,2);
 const privacy=declarations.elements.find(el=>el.ariaLabel==='Start Privacy policy declaration');
 assert.equal(privacy.accessibleName,'Start Privacy policy declaration');assert.equal(privacy.role,'button');assert.equal(privacy.disabled,false);
 assert.ok(privacy.selector.includes('aria-label'));
 await assert.rejects(bridge.command('click',{frameId:0,selector:'console-policy-declaration button',strict:true},tab.id),/matched 2/);
 assert.equal((await bridge.command('getElementText',{frameId:0,selector:'#declaration-selected'},tab.id)).text,'');
 await bridge.command('click',{frameId:0,selector:privacy.selector,strict:true},tab.id);
 assert.equal((await bridge.command('getElementText',{frameId:0,selector:'#declaration-selected'},tab.id)).text,'privacy');
 await assert.rejects(bridge.command('click',{frameId:0,selector:'button[aria-label="Disabled declaration"]',strict:true},tab.id),/disabled/);
 const secret=await bridge.command('querySelector',{frameId:0,selector:'#fixture-secret'},tab.id);assert.equal(secret.value,null);assert.equal(secret.valueRedacted,true);
 console.log('PASS nested Angular-style controls: ARIA metadata, unique native-button selection, ambiguity/disabled rejection and secret redaction');

 // Go streaming upload targets an actual cross-origin frame, then verifies SHA-256 in the browser.
 bridge.close();await delay(50);
 await run(binary,['connect','--connector','--bridge-url',bridgeURL,'upload','--tab-id',String(tab.id),'--frame-id',String(child.frameId),'--selector','#frame-file','--file',source]);
 bridge=await RPC.connect(bridgeURL,bridgeToken);
 console.log('PASS local-file streaming into cross-origin iframe with SHA-256 verification');
 // Browser-backed path upload: local bytes never enter a JSON/base64 command.
 bridge.close();await delay(50);
 await run(binary,['connect','--connector','--bridge-url',bridgeURL,'upload','--tab-id',String(tab.id),'--selector','#file','--file',source,'--file',second]);
 bridge=await RPC.connect(bridgeURL,bridgeToken);await bridge.command('click',{frameId:0,selector:'#submit'},tab.id);
 await until(()=>received,'server receipt');assert.equal(received.sha256,sha(payload));assert.equal(received.size,payload.length);
 console.log('PASS native multi-file selection (including empty file) and exact bytes received by HTTP server');
 await bridge.command('input.click',{x:200,y:110},tab.id);
 assert.equal((await bridge.command('getElementText',{frameId:0,selector:'#trusted'},tab.id)).text,'true');
 await bridge.command('input.type',{frameId:0,selector:'#text',text:'Trusted input'},tab.id);
 await bridge.command('input.type',{frameId:0,selector:'#key-input',text:'Keyboard submission'},tab.id);
 await bridge.command('input.key',{key:'Enter'},tab.id);
 assert.equal((await bridge.command('getElementText',{frameId:0,selector:'#key-result'},tab.id)).text,'true:Keyboard submission');
 const screenshot=await bridge.command('screenshot.fullPage',{fullPage:true},tab.id);const png=Buffer.from(screenshot.screenshot,'base64');assert.ok(png.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])));assert.ok(png.readUInt32BE(20)>=2000,'Screenshot did not cover full page');
 console.log('PASS trusted mouse/text input and single-PNG full-page capture');
 const opened=await bridge.command('input.click',{x:370,y:110},tab.id);assert.equal(opened.dialogPending,true);
 assert.equal((await bridge.command('dialog.get',{},tab.id)).dialog.type,'confirm');
 await bridge.command('dialog.handle',{accept:false},tab.id);
 await until(async()=>{try{return(await bridge.command('getElementText',{frameId:0,selector:'#dialog-result'},tab.id)).text==='false'}catch{return false}},'native confirm dismissal');
 console.log('PASS observed native JavaScript dialog, explicit dismissal and resulting page state');
 await bridge.command('input.drag',{from:{x:40,y:170},to:{x:240,y:170}},tab.id);
 assert.equal((await bridge.command('getElementText',{frameId:0,selector:'#drop-result'},tab.id)).text,'aegis-drag:true');
 console.log('PASS HTML5 drag-and-drop with trusted browser events');
 bridge.close();await delay(50);const downloaded=path.join(temp,'retrieved.bin');
 await run(binary,['connect','--connector','--bridge-url',bridgeURL,'download','--tab-id',String(tab.id),'--url',fixtureURL+'download','--output',downloaded]);
 assert.equal(sha(await fs.readFile(downloaded)),sha(payload));
 console.log('PASS browser download start, completion tracking, local retrieval and SHA-256');
 // Verify policy is a real gate in this isolated profile, without changing the user's policy.
 bridge=await RPC.connect(bridgeURL,bridgeToken);await bridge.command('policy.set',{policy:{mode:'manual-approve',defaultGateSensitive:true}},tab.id);await assert.rejects(bridge.command('download.start',{url:fixtureURL+'download'},tab.id),/permission_denied/);
 bridge.close();await delay(50);
 const rejectedFile=path.join(temp,'rejected.json');
 const rejected=await run(binary,['connect','--connector','--bridge-url',bridgeURL,'send','--command','click','--params',JSON.stringify({tabId:tab.id,selector:'#native'}),'--output',rejectedFile],false);
 assert.notEqual(rejected.code,0);assert.equal(JSON.parse(await fs.readFile(rejectedFile,'utf8')).success,false);
 console.log('PASS local policy denial is preserved and CLI saved errors return nonzero');
 bridge=await RPC.connect(bridgeURL,bridgeToken);
 const blockedWorkflow={id:'policy-regression',steps:[{command:'click',params:{selector:'#native',frameId:0}}]};
 await assert.rejects(bridge.command('workflow.run',{workflow:blockedWorkflow},tab.id),/permission_denied/);
 await assert.rejects(bridge.command('workflow.run',{workflow:blockedWorkflow,continueOnError:true},tab.id),/workflow_failed/);
 console.log('PASS workflow replay enforces each command policy and reports failed steps as failure');

 console.log('All browser connector integration checks passed.');
}

(async()=>{try{await main()}catch(error){console.error(error.stack);for(const child of children)if(child.log)console.error(child.log.slice(-2500));process.exitCode=1}finally{
 bridge?.close();cdp?.close();for(const child of children)if(child.exitCode===null){try{child.ownProcessGroup?process.kill(-child.pid,'SIGTERM'):child.kill('SIGTERM')}catch{}}
 await Promise.all(children.map(child=>child.exitCode===null?new Promise(resolve=>{child.once('exit',resolve);setTimeout(()=>{child.kill('SIGKILL');resolve()},2000).unref()}):Promise.resolve()));
 if(server)await new Promise(resolve=>server.close(resolve));
 if(temp){if(process.env.AEGIS_KEEP_TEST_PROFILE)console.log('Test profile: '+temp);else await fs.rm(temp,{recursive:true,force:true,maxRetries:10,retryDelay:100});}
}})();
