#!/usr/bin/env node
// Capture a genuine, sanitized 1280x800 approval screenshot in isolated Chromium.
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const net = require('node:net');
const {spawn} = require('node:child_process');
const {setTimeout: delay} = require('node:timers/promises');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '..');
const binary = path.resolve(process.argv[2] || path.join(root, 'aegis'));
const chromium = process.env.AEGIS_TEST_CHROMIUM || '/usr/bin/chromium';
const output = path.join(root, 'docs/chrome-web-store/assets/screenshot-01.png');
const children = [];
let temp, server, cdp, controller;

async function until(check, label, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await delay(100);
  }
  throw new Error('Timed out: ' + label);
}
async function freePort() {
  const listener = net.createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return port;
}
function start(command, args, env = {}) {
  const child = spawn(command, args, {env: {...process.env, ...env}, stdio: ['ignore', 'ignore', 'pipe'], detached: true});
  child.log = '';
  child.stderr.on('data', data => { child.log = (child.log + data.toString()).slice(-8000); });
  children.push(child);
  return child;
}
class RPC {
  static async connect(url, token) {
    const rpc = new RPC();
    rpc.id = 0;
    rpc.pending = new Map();
    rpc.socket = new WebSocket(url);
    rpc.socket.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      if (!message.id) return;
      const pending = rpc.pending.get(String(message.id));
      if (!pending) return;
      rpc.pending.delete(String(message.id));
      clearTimeout(pending.timer);
      if (message.error && message.type !== 'result') pending.reject(new Error(JSON.stringify(message.error)));
      else pending.resolve(message.result ?? message);
    });
    rpc.socket.addEventListener('close', () => {
      for (const pending of rpc.pending.values()) { clearTimeout(pending.timer); pending.reject(new Error('WebSocket closed')); }
      rpc.pending.clear();
    });
    await new Promise((resolve, reject) => {
      rpc.socket.addEventListener('open', resolve, {once: true});
      rpc.socket.addEventListener('error', reject, {once: true});
    });
    if (token) await rpc.command('hello', {client: 'aegis', version: 1, token}, true);
    return rpc;
  }
  call(method, params = {}, sessionId) {
    const id = String(++this.id);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('RPC timeout: ' + method)); }, 15000);
      this.pending.set(id, {resolve, reject, timer});
      this.socket.send(JSON.stringify({id: Number(id), method, params, ...(sessionId ? {sessionId} : {})}));
    });
  }
  command(command, params = {}, hello = false, tabId = 0) {
    const id = 'capture-' + (++this.id);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('Command timeout: ' + command)); }, 15000);
      this.pending.set(id, {resolve: message => {
        if (hello) resolve(message);
        else if (message.success) resolve(message.data);
        else reject(new Error(JSON.stringify(message)));
      }, reject, timer});
      this.socket.send(JSON.stringify(hello ? {id, type: 'hello', ...params} : {id, type: 'command', command, params, tabId, timeout: 12000, version: 1}));
    });
  }
  close() { this.socket.close(); }
}

async function main() {
  temp = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-store-screenshot-'));
  const configHome = path.join(temp, 'config');
  server = http.createServer((req, res) => {
    res.setHeader('content-type', 'text/html');
    res.end('<!doctype html><title>Isolated Aegis Demo</title><style>body{font-family:sans-serif;background:#101827;color:#d8e2f0;padding:48px}textarea{width:480px;height:100px}</style><h1>Isolated product demonstration</h1><p>No account or real website data is used.</p><textarea id="demo">Sanitized example</textarea>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const fixture = `http://127.0.0.1:${server.address().port}/`;
  const port = await freePort();
  const bridge = start(binary, ['connect', 'serve', '--port', String(port)], {XDG_CONFIG_HOME: configHome});
  await until(async () => { if (bridge.exitCode !== null) throw new Error(bridge.log); try { return (await fetch(`http://127.0.0.1:${port}/health`)).ok; } catch { return false; } }, 'bridge');
  const state = JSON.parse(await fs.readFile(path.join(configHome, 'aegis/connector/runtime.json'), 'utf8'));
  const extension = path.join(temp, 'extension');
  await fs.cp(path.join(root, 'extension'), extension, {recursive: true});
  const worker = path.join(extension, 'background.js');
  await fs.writeFile(worker, (await fs.readFile(worker, 'utf8'))
    .replace('const DEFAULT_PORT = 9876;', `const DEFAULT_PORT = ${port};`)
    .replace("let bridgeToken = '';", `let bridgeToken = ${JSON.stringify(state.token)};`)
    .replace("bridgeToken = c.token || '';", 'bridgeToken = c.token || bridgeToken;'));
  const manifest = JSON.parse(await fs.readFile(path.join(extension, 'manifest.chrome.json'), 'utf8'));
  manifest.permissions = manifest.permissions.filter(permission => permission !== 'nativeMessaging');
  await fs.writeFile(path.join(extension, 'manifest.json'), JSON.stringify(manifest));
  const profile = path.join(temp, 'profile');
  const chrome = start(chromium, ['--headless=new', '--no-sandbox', `--user-data-dir=${profile}`, `--load-extension=${extension}`, `--disable-extensions-except=${extension}`, '--remote-debugging-port=0', '--window-size=1280,800', '--no-first-run', '--no-default-browser-check', '--disable-dev-shm-usage', '--disable-background-networking', '--disable-component-update', '--disable-sync', fixture]);
  const devtools = await until(async () => { if (chrome.exitCode !== null) throw new Error(chrome.log); try { return (await fs.readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n'); } catch { return false; } }, 'Chromium');
  await until(async () => (await (await fetch(`http://127.0.0.1:${port}/health`)).json()).extensionConnected, 'extension');
  cdp = await RPC.connect(`ws://127.0.0.1:${devtools[0]}${devtools[1]}`);
  controller = await RPC.connect(`ws://127.0.0.1:${port}/ws?client=aegis`, state.token);
  const tabs = await controller.command('listTabs');
  const tab = tabs.tabs.find(item => item.url === fixture);
  assert.ok(tab);
  const workerTarget = (await cdp.call('Target.getTargets')).targetInfos.find(target => target.type === 'service_worker' && target.url.includes('/background.js'));
  const popup = await cdp.call('Target.createTarget', {url: workerTarget.url.replace(/background\.js.*$/, 'popup.html')});
  const popupSession = (await cdp.call('Target.attachToTarget', {targetId: popup.targetId, flatten: true})).sessionId;
  const pending = controller.command('fill', {selector: '#demo', value: 'Approved demonstration'}, false, tab.id);
  pending.catch(() => {});
  await until(async () => {
    const result = await cdp.call('Runtime.evaluate', {expression: "document.querySelector('#approval-list .btn-connect') !== null", returnByValue: true}, popupSession);
    return result.result?.value === true;
  }, 'approval popup');
  await cdp.call('Emulation.setDeviceMetricsOverride', {width: 1280, height: 800, deviceScaleFactor: 1, mobile: false}, popupSession);
  await cdp.call('Runtime.evaluate', {expression: "document.body.style.width='640px';document.body.style.margin='48px auto';document.body.style.boxShadow='0 20px 80px #0008'"}, popupSession);
  await delay(200);
  const capture = await cdp.call('Page.captureScreenshot', {format: 'png', fromSurface: true}, popupSession);
  const png = Buffer.from(capture.data, 'base64');
  assert.equal(png.readUInt32BE(16), 1280);
  assert.equal(png.readUInt32BE(20), 800);
  await fs.mkdir(path.dirname(output), {recursive: true});
  await fs.writeFile(output, png);
  console.log(output);
}

(async () => {
  try { await main(); }
  catch (error) { console.error(error.stack); for (const child of children) if (child.log) console.error(child.log); process.exitCode = 1; }
  finally {
    controller?.close(); cdp?.close();
    for (const child of children) if (child.exitCode === null) { try { process.kill(-child.pid, 'SIGTERM'); } catch {} }
    await delay(250);
    if (server) await new Promise(resolve => server.close(resolve));
    if (temp) await fs.rm(temp, {recursive: true, force: true, maxRetries: 5, retryDelay: 100});
  }
})();
