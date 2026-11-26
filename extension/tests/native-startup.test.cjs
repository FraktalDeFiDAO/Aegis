const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function harness({failure = false, synchronousFailure = false} = {}) {
  const messages = [], disconnects = [], sockets = [], sent = [];
  let launches = 0;
  const port = {
    onMessage: {addListener: fn => messages.push(fn)},
    onDisconnect: {addListener: fn => disconnects.push(fn)},
    postMessage: msg => { assert.deepEqual(JSON.parse(JSON.stringify(msg)), {type:'start', port:9876}); if(failure) queueMicrotask(() => disconnects.forEach(fn => fn())); },
    disconnect: () => {},
  };
  const runtime = {
    getManifest: () => ({permissions:['nativeMessaging']}),
    connectNative: name => { assert.equal(name,'com.aegis.bridge'); launches++; if(synchronousFailure) throw new Error('not installed'); return port; },
    lastError: failure ? {message:'not installed'} : undefined,
  };
  const context = vm.createContext({chrome:{runtime}, setTimeout,clearTimeout,log:()=>{},scheduleReconnect:()=>{},notifyPopup:()=>{},flushEventQueue:()=>{},detectCapabilities:()=>({}),
    WebSocket: class {
      static OPEN=1; static CONNECTING=0;
      constructor(url){this.url=url;this.readyState=0;sockets.push(this);}
      send(data){sent.push(JSON.parse(data));}
    },
  });
  const source = fs.readFileSync(path.join(__dirname,'../background.js'),'utf8');
  const start = source.indexOf('function ensureNativeBridge()');
  const end = source.indexOf('function scheduleReconnect()',start);
  const helloStart = source.indexOf('function sendHello()');
  const helloEnd = source.indexOf('function detectCapabilities()',helloStart);
  vm.runInContext(`let nativePort=null,nativeReadyPort=0,nativeStarting=null,nativeError='',bridgeHost='127.0.0.1',bridgeWsPort=0,bridgeToken='',connectionEnabled=true,ws=null,reconnectDelay=1000,helloAcked=false,lastEventSeq=0; const DEFAULT_PORT=9876,RECONNECT_BASE_MS=1000,PROTOCOL_VERSION=1; ${source.slice(start,end)} ${source.slice(helloStart,helloEnd)}`, context);
  return {context,sockets,sent,launches:()=>launches,ready:(portNumber,token='test-token') => messages.forEach(fn=>fn({type:'ready',host:'127.0.0.1',port:portNumber,token})),run:code=>vm.runInContext(code,context)};
}

test('concurrent startup uses one native host and the returned bridge port', async()=>{
  const h=harness();
  const a=h.run('connectToBridge()'), b=h.run('connectToBridge()');
  assert.equal(h.launches(),1);
  h.ready(43210);
  await Promise.all([a,b]);
  assert.equal(h.sockets.length,1);
  assert.equal(h.sockets[0].url,'ws://127.0.0.1:43210/ws?client=extension');
});

test('native host credential is included in the authenticated hello',async()=>{
  const h=harness();
  const pending=h.run('connectToBridge()');
  h.ready(43210,'native-secret');
  await pending;
  h.sockets[0].readyState=1;
  h.sockets[0].onopen();
  assert.equal(h.sent.length,1);
  assert.equal(h.sent[0].type,'hello');
  assert.equal(h.sent[0].token,'native-secret');
  assert.equal(h.sockets[0].url.includes('native-secret'),false);
});

test('native ready response without a credential is rejected',async()=>{
  const h=harness();
  const pending=h.run('connectToBridge()');
  h.ready(9876,'');
  await pending;
  assert.equal(h.sockets.length,0);
  assert.match(h.run('nativeError'),/credential/i);
});

test('missing native host falls back to manual bridge',async()=>{
  const h=harness({failure:true});
  await h.run('connectToBridge()');
  assert.equal(h.sockets[0].url,'ws://127.0.0.1:9876/ws?client=extension');
  assert.equal(h.run('nativeError'),'not installed');
});

test('synchronous startup failure can be retried',async()=>{
  const h=harness({synchronousFailure:true});
  await h.run('ensureNativeBridge()');
  await h.run('ensureNativeBridge()');
  assert.equal(h.launches(),2);
});

test('disconnect while host starts prevents a WebSocket connection',async()=>{
  const h=harness();
  const pending=h.run('connectToBridge()');
  h.run('connectionEnabled=false');
  h.ready(9876);
  await pending;
  assert.equal(h.sockets.length,0);
});

test('lost WebSocket releases the native port so a dead reused bridge can restart',async()=>{
  const h=harness();
  const pending=h.run('connectToBridge()');
  h.ready(9876);
  await pending;
  h.sockets[0].onclose({code:1006,reason:''});
  assert.equal(h.run('nativeReadyPort'),0);
  assert.equal(h.run('nativePort'),null);
  const retry=h.run('connectToBridge()');
  assert.equal(h.launches(),2);
  h.ready(9876);
  await retry;
  assert.equal(h.sockets.length,2);
});
