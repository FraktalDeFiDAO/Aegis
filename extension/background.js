/* Aegis Browser Connector — Background Script / Service Worker
 *
 * Maintains WebSocket to bridge server, routes commands to content scripts,
 * manages tabs, cookies, storage, screenshots, and protocol v1 features.
 * Best-effort, capability-gated, localhost-only, no secret logging.
 */

'use strict';
if (typeof importScripts === 'function') importScripts('browser-control.js');

const PROTOCOL_VERSION = 1;
const DEFAULT_PORT = 9876;
const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30000;
const KEEPALIVE_ALARM = 'aegis_keepalive';
const KEEPALIVE_PERIOD_MIN = 0.5; // ~30s
const EVENT_QUEUE_MAX = 200;

let ws = null;
let reconnectDelay = RECONNECT_BASE_MS;
let reconnectTimer = null;
let bridgeHost = '127.0.0.1';
let bridgeWsPort = 0;
let bridgeToken = '';
let contentPorts = new Map(); // tabId -> port
let dialogHandlers = new Map(); // tabId -> {resolve, reject}
let eventQueue = [];
let lastEventSeq = 0;
let helloAcked = false;
let pendingApprovals = new Map(); // requestId -> {resolve,reject}
let activeTargetSet = { tabs: [], activeTabId: null, groupId: null };
let nativePort = null;
let nativeReadyPort = 0;
let nativeStarting = null;
let nativeError = '';
let connectionEnabled = true;
const browserControl = AegisBrowserControl.create(chrome, {
  isDebugAttached: tabId => !!debugState.attachedTabs?.has(tabId)
});

// ─── Storage keys ────────────────────────────────────────────────────────────
const STORAGE_KEY = 'aegisBridgeConfig';
const POLICY_KEY = 'aegisPolicy';
const SCHEDULES_KEY = 'aegisSchedules';
const RUNS_KEY = 'aegisRuns';
const WORKFLOWS_KEY = 'aegisWorkflows';
const AUDIT_KEY = 'aegisAudit';
const TARGET_KEY = 'aegisTargetSet';

// ─── Bootstrap / MV3 keepalive ────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get([STORAGE_KEY, POLICY_KEY, SCHEDULES_KEY, RUNS_KEY, WORKFLOWS_KEY], (cfg) => {
    const patch = {};
    if (!cfg[STORAGE_KEY]) patch[STORAGE_KEY] = { host: '127.0.0.1', wsPort: 0 };
    if (!cfg[POLICY_KEY]) patch[POLICY_KEY] = defaultPolicy();
    if (!cfg[SCHEDULES_KEY]) patch[SCHEDULES_KEY] = [];
    if (!cfg[RUNS_KEY]) patch[RUNS_KEY] = [];
    if (!cfg[WORKFLOWS_KEY]) patch[WORKFLOWS_KEY] = [];
    if (!cfg[AUDIT_KEY]) patch[AUDIT_KEY] = [];
    if (!cfg[TARGET_KEY]) patch[TARGET_KEY] = { tabs: [], activeTabId: null, groupId: null };
    if (Object.keys(patch).length) chrome.storage.local.set(patch);
  });
  ensureKeepaliveAlarm();
});

chrome.runtime.onStartup.addListener(() => {
  ensureKeepaliveAlarm();
  loadConfigAndConnect();
  reconcileSchedulesOnStartup();
});

ensureKeepaliveAlarm();
loadConfigAndConnect();

function ensureKeepaliveAlarm() {
  try {
    if (chrome.alarms && chrome.alarms.create) {
      chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: KEEPALIVE_PERIOD_MIN });
    }
  } catch (_) {}
}

if (chrome.alarms && chrome.alarms.onAlarm) {
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm && alarm.name === KEEPALIVE_ALARM) {
      if (connectionEnabled && (!ws || ws.readyState !== WebSocket.OPEN)) connectToBridge();
      else sendToBridge({ type: 'ping', id: 'ka-' + Date.now(), timestamp: Date.now() });
      flushEventQueue();
      tickSchedules();
    }
    if (alarm && alarm.name && alarm.name.startsWith('aegis_sched_')) {
      runScheduleByAlarm(alarm.name);
    }
  });
}

// ─── Config / policy persistence ─────────────────────────────────────────────
function loadConfigAndConnect() {
  chrome.storage.local.get([STORAGE_KEY, TARGET_KEY], (cfg) => {
    const c = cfg[STORAGE_KEY] || {};
    bridgeHost = c.host || '127.0.0.1';
    bridgeWsPort = c.wsPort || 0;
    bridgeToken = c.token || '';
    if (cfg[TARGET_KEY]) activeTargetSet = Object.assign({ tabs: [], activeTabId: null, groupId: null }, cfg[TARGET_KEY]);
    connectToBridge();
  });
}

function saveConfig() {
  chrome.storage.local.set({ [STORAGE_KEY]: { host: bridgeHost, wsPort: bridgeWsPort, token: bridgeToken } });
}

function defaultPolicy() {
  return {
    version: 1,
    mode: 'manual-approve', // manual-approve | auto-with-prompts | unattended
    allow: [],
    deny: [],
    trustedScopes: [],
    defaultGateSensitive: true,
  };
}

async function getPolicy() {
  return new Promise((resolve) => {
    chrome.storage.local.get(POLICY_KEY, (r) => resolve(r[POLICY_KEY] || defaultPolicy()));
  });
}

async function persistTargetSet() { return new Promise((resolve) => chrome.storage.local.set({ [TARGET_KEY]: activeTargetSet }, resolve)); }

async function setPolicy(p) {
  return new Promise((resolve) => chrome.storage.local.set({ [POLICY_KEY]: p }, resolve));
}

// ─── WebSocket connection ────────────────────────────────────────────────────
function ensureNativeBridge() {
  if (nativePort && nativeReadyPort) return Promise.resolve(nativeReadyPort);
  if (nativeStarting) return nativeStarting;
  // Firefox/manual installations retain their existing WebSocket behavior.
  if (bridgeHost !== '127.0.0.1' || !chrome.runtime.getManifest().permissions.includes('nativeMessaging')) return Promise.resolve(0);
  const attempt = new Promise((resolve) => {
    let done = false;
    let port;
    const finish = (value, error = '', fatal = false) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      nativeError = error;
      if (!value && port) {
        if (nativePort === port) nativePort = null;
        try { port.disconnect(); } catch (_) {}
      }
      resolve(fatal ? -1 : value);
    };
    const timer = setTimeout(() => finish(0, 'Native host startup timed out. Check the host installation.'), 5000);
    try {
      port = chrome.runtime.connectNative('com.aegis.bridge');
      nativePort = port;
      port.onMessage.addListener((msg) => {
        if (done || nativePort !== port) return;
        if (msg.type === 'ready') {
          if (msg.host === '127.0.0.1' && Number.isInteger(msg.port) && msg.port > 0 && msg.port <= 65535 && typeof msg.token === 'string' && msg.token) {
            bridgeToken = msg.token;
            nativeReadyPort = msg.port;
            finish(msg.port);
          } else {
            finish(0, 'Native host returned an invalid ready response or authentication credential.', true);
          }
        } else if (msg.type === 'error') finish(0, msg.error || 'Native host failed.');
      });
      port.onDisconnect.addListener(() => {
        const error = chrome.runtime.lastError?.message || 'Native host disconnected.';
        if (nativePort === port) { nativePort = null; nativeReadyPort = 0; }
        nativeError = error;
        finish(0, error);
      });
      port.postMessage({ type: 'start', port: bridgeWsPort || DEFAULT_PORT });
    } catch (e) { finish(0, e.message); }
  });
  nativeStarting = attempt;
  attempt.then(() => { if (nativeStarting === attempt) nativeStarting = null; });
  return attempt;
}

async function connectToBridge() {
  if (!connectionEnabled) return;
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
  const native = await ensureNativeBridge();
  if (!connectionEnabled || (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING))) return;
  if (native < 0) {
    scheduleReconnect();
    return;
  }
  const port = native || bridgeWsPort || DEFAULT_PORT;
  const url = `ws://${bridgeHost}:${port}/ws?client=extension`;
  log('connecting to bridge', url);
  try {
    ws = new WebSocket(url);
  } catch (e) {
    log('WebSocket constructor failed', e.message);
    scheduleReconnect();
    return;
  }

  const socket = ws;
  ws.onopen = () => {
    if (ws !== socket) return;
    log('socket open; authenticating');
    reconnectDelay = RECONNECT_BASE_MS;
    helloAcked = false;
    sendHello();
  };

  ws.onmessage = (evt) => { handleBridgeMessage(evt.data); };
  ws.onerror = (err) => { log('websocket error', err && err.message ? err.message : 'error'); };
  ws.onclose = (evt) => {
    if (ws !== socket) return;
    log('websocket closed', evt.code, evt.reason || '');
    ws = null;
    helloAcked = false;
    // Recheck/restart on the next attempt even if a reused manual bridge died.
    const hostPort = nativePort;
    nativePort = null;
    nativeReadyPort = 0;
    if (hostPort) { try { hostPort.disconnect(); } catch (_) {} }
    notifyPopup({ type: 'disconnected' });
    scheduleReconnect();
  };
}

function scheduleReconnect() {
  if (!connectionEnabled) return;
  if (reconnectTimer) clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(() => { connectToBridge(); }, reconnectDelay);
  reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_MS);
}

function notifyPopup(msg) { chrome.runtime.sendMessage(msg).catch(() => {}); }

function sendHello() {
  const hello = {
    type: 'hello',
    client: 'extension',
    version: PROTOCOL_VERSION,
    token: bridgeToken,
    timestamp: Date.now(),
    capabilities: detectCapabilities(),
  };
  // best-effort resume hint
  if (lastEventSeq > 0) hello.resumeFrom = lastEventSeq;
  try { ws && ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify(hello)); } catch (_) {}
}

function detectCapabilities() {
  const isMV3 = chrome.runtime && chrome.runtime.getManifest && chrome.runtime.getManifest().manifest_version === 3;
  return {
    commands: supportedCommands(),
    events: ['tabCreated','tabClosed','tabUpdated','navigated','dialogOpened','console','consoleError','network','pageError','download','recording','task','permissionPrompt'],
    tabGroups: !!(chrome.tabGroups),
    debugger: !!(chrome.debugger),
    downloads: !!(chrome.downloads),
    alarms: !!(chrome.alarms),
    notifications: !!(chrome.notifications),
    manifestVersion: isMV3 ? 3 : 2,
    browser: detectBrowser(),
    platform: (navigator && navigator.platform) || 'unknown',
  };
}

function detectBrowser() {
  const ua = (navigator && navigator.userAgent) || '';
  if (/Firefox\//.test(ua)) return 'firefox';
  if (/Brave\//.test(ua) || (navigator && navigator.brave)) return 'brave';
  if (/Edg\//.test(ua)) return 'edge';
  if (/Chrome\//.test(ua)) return 'chrome';
  return 'unknown';
}

function supportedCommands() {
  return [
    'extension.info',
    'hello','cancel',
    'navigate','goBack','goForward','reload','getCurrentUrl','getTitle',
    'listTabs','newTab','closeTab','switchTab','getTabInfo',
    'querySelector','querySelectorAll','getElementText','getElementAttribute','getElementHtml',
    'click','doubleClick','rightClick','hover','type','fill','clear','press','select','scroll','scrollIntoView','focus','blur',
    'waitForSelector','waitForNavigation','waitForLoad','waitForIdle','waitForTimeout',
    'evaluate','evaluateAll','screenshot','screenshotElement','captureVisibleTab',
    'getCookies','setCookie','deleteCookie','clearCookies',
    'getLocalStorage','setLocalStorage','getSessionStorage','setSessionStorage',
    'switchFrame','switchMain','listFrames',
    'acceptDialog','dismissDialog','extractData',
    'createTabGroup','addTabToGroup','removeTabFromGroup','listTabGroups','focusTabGroup',
    'debug.attach','debug.detach','debug.getConsole','debug.getNetwork','debug.getPageState','page.snapshot',
    'record.start','record.stop','record.pause','workflow.list','workflow.get','workflow.save','workflow.delete','workflow.run',
    'schedule.create','schedule.list','schedule.delete','schedule.runs',
    'download.start','download.wait','download.list','upload.file','upload.begin','upload.chunk','upload.finish','upload.cancel','upload.status',
    'input.click','input.drag','input.type','input.key','dialog.get','dialog.handle','screenshot.fullPage',
    'policy.get','policy.set','approval.respond','audit.list','audit.report',
    'target.get','target.set'
  ];
}

// ─── Bridge message handling ─────────────────────────────────────────────────
function handleBridgeMessage(raw) {
  let msg;
  try { msg = JSON.parse(raw); } catch (e) { log('invalid JSON from bridge'); return; }
  switch (msg.type) {
    case 'command':
      if (helloAcked) handleCommand(msg);
      break;
    case 'hello_ack':
      if (msg.ok !== true) {
        helloAcked = false;
        nativeError = (msg.error && msg.error.message) || 'Bridge authentication failed.';
        try { if (ws) ws.close(); } catch (_) {}
        break;
      }
      helloAcked = true;
      nativeError = '';
      notifyPopup({ type: 'connected' });
      if (msg.lastSeq && msg.lastSeq > lastEventSeq) lastEventSeq = msg.lastSeq;
      flushEventQueue();
      break;
    case 'ping':
      sendToBridge({ id: msg.id, type: 'pong', timestamp: Date.now() });
      break;
    case 'cancel': {
      const target = msg.targetId || msg.requestId || msg.id;
      // best-effort: cannot force-cancel in-flight content ops; acknowledge via task event
      if (target) emitTaskEvent('cancel_requested', { targetId: target });
      break;
    }
    case 'progress':
    case 'pong':
    case 'result':
    case 'event':
      break;
    default:
      // ignore unknown for forward compatibility
      break;
  }
}

function sendToBridge(obj) {
  if (!obj) return false;
  if (helloAcked && ws && ws.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify(obj)); return true; } catch (e) { log('send failed', e && e.message); }
  }
  // queue outbound events (bounded) when disconnected
  if (obj.type === 'event' || obj.type === 'task') {
    eventQueue.push(obj);
    if (eventQueue.length > EVENT_QUEUE_MAX) eventQueue = eventQueue.slice(-EVENT_QUEUE_MAX);
  }
  return false;
}

function flushEventQueue() {
  if (!helloAcked || !ws || ws.readyState !== WebSocket.OPEN || !eventQueue.length) return;
  const q = eventQueue.splice(0, eventQueue.length);
  for (const ev of q) {
    try { ws.send(JSON.stringify(ev)); } catch (_) { eventQueue.unshift(ev); break; }
  }
}

// ─── Command dispatch ────────────────────────────────────────────────────────
async function handleCommand(cmd) {
  const id = cmd.id || cmd.requestId;
  const command = cmd.command;
  const params = cmd.params || {};
  const targetTabId = cmd.tabId || params.tabId || activeTargetSet.activeTabId || await getActiveTabId();

  try {
    // Local policy gate (deterministic, best-effort)
    const decision = await evaluatePolicy(command, params, targetTabId);
    if (!decision.allowed) {
      await emitPermissionPrompt(command, params, targetTabId, decision.reason, false);
      await appendAudit({ type: 'policy', outcome: 'denied', command, tabId: targetTabId, reason: decision.reason || 'denied by local policy' });
      sendToBridge(structuredErrorResult(id, 'permission_denied', decision.reason || 'denied by local policy'));
      return;
    }
    if (decision.needsApproval) {
      await emitPermissionPrompt(command, params, targetTabId, decision.reason, true);
      await appendAudit({ type: 'policy', outcome: 'approval_required', command, tabId: targetTabId, reason: decision.reason || 'approval required' });
      sendToBridge(structuredErrorResult(id, 'permission_denied', 'approval required (manual/local policy); retry when allowed'));
      return;
    }

    await appendAudit({ type: 'policy', outcome: 'allowed', command, tabId: targetTabId, sensitive: !!(SENSITIVE_COMMANDS && SENSITIVE_COMMANDS.has && SENSITIVE_COMMANDS.has(command)) });
    const result = await executeCommand(command, params, targetTabId);
    if (activeRecording && !activeRecording.paused && !String(command).startsWith('record.') && !String(command).startsWith('workflow.') && command !== 'cancel') {
      try {
        const step = { command, params: redactObject(params || {}), tabId: targetTabId, ts: Date.now() };
        activeRecording.steps.push(step);
        if (activeRecording.steps.length > 500) activeRecording.steps.splice(0, activeRecording.steps.length - 500);
      } catch (_) {}
    }
    sendToBridge({ id, requestId: id, type: 'result', success: true, data: result, timestamp: Date.now(), version: PROTOCOL_VERSION });
  } catch (err) {
    const code = (err && err.code) || 'internal_error';
    const message = (err && err.message) || String(err);
    sendToBridge(structuredErrorResult(id, code, message, err?.details));
  }
}

function structuredErrorResult(id, code, message, details) {
  return { id, requestId: id, type: 'result', success: false, error: message, err: { code, message, ...(details ? { details } : {}) }, timestamp: Date.now(), version: PROTOCOL_VERSION };
}

async function executeCommand(command, params, targetTabId) {
  switch (command) {
    case 'extension.info': return { version: chrome.runtime.getManifest().version, features: { accessibleElementMetadata: true, strictCssTargets: true, perStepWorkflowPolicy: true } };
    case 'listFrames': return await browserControl.listFrames(targetTabId);
    case 'switchFrame': return await browserControl.selectFrame(targetTabId, params);
    case 'switchMain': return await browserControl.selectFrame(targetTabId, { frameId: 0 });
    case 'download.start': return await browserControl.downloadStart(params);
    case 'input.click': case 'input.drag': case 'input.type': case 'input.key':
      return await browserControl.nativeInput(targetTabId, command, params);
    case 'dialog.get': return browserControl.dialogState(targetTabId);
    case 'dialog.handle': return await browserControl.handleDialog(targetTabId, params);
    // tabs/core
    case 'listTabs': return await cmdListTabs();
    case 'newTab': return await cmdNewTab(params);
    case 'closeTab': return await cmdCloseTab(params);
    case 'switchTab': return await cmdSwitchTab(params);
    case 'getTabInfo': return await cmdGetTabInfo(targetTabId);
    // cookies/storage
    case 'getCookies': return await cmdGetCookies(params, targetTabId);
    case 'setCookie': return await cmdSetCookie(params);
    case 'deleteCookie': return await cmdDeleteCookie(params);
    case 'clearCookies': return await cmdClearCookies(params, targetTabId);
    // screenshots
    case 'captureVisibleTab':
    case 'screenshot':
      return await cmdCaptureVisibleTab(targetTabId, params);
    // dialogs
    case 'acceptDialog':
    case 'dismissDialog':
      return await cmdDialog(command, targetTabId);
    // tab groups (capability-gated)
    case 'createTabGroup': return await cmdCreateTabGroup(params);
    case 'addTabToGroup': return await cmdAddTabToGroup(params);
    case 'removeTabFromGroup': return await cmdRemoveFromTabGroup(params);
    case 'listTabGroups': return await cmdListTabGroups();
    case 'focusTabGroup': return await cmdFocusTabGroup(params);
    // target set
    case 'target.get': return { targetSet: activeTargetSet };
    case 'target.set': return await cmdSetTargetSet(params);
    // debug/observability (best-effort capability-gated)
    case 'debug.attach': return await cmdDebugAttach(targetTabId);
    case 'debug.detach': return await cmdDebugDetach(targetTabId);
    case 'debug.getConsole': return await cmdDebugGetConsole(targetTabId);
    case 'debug.getNetwork': return await cmdDebugGetNetwork(targetTabId);
    case 'debug.getPageState': return await cmdDebugGetPageState(targetTabId, params);
    case 'page.snapshot': return await cmdPageSnapshot(targetTabId, params);
    // downloads/uploads
    case 'download.list': return await cmdDownloadList(params);
    case 'download.wait': return await cmdDownloadWait(params);
    case 'upload.file': return await cmdUploadFile(params, targetTabId);
    // recording/workflows/schedules (local best-effort)
    case 'record.start': return await cmdRecordStart(params, targetTabId);
    case 'record.stop': return await cmdRecordStop(params);
    case 'record.pause': return await cmdRecordPause(params);
    case 'workflow.list': return await cmdWorkflowList(params);
    case 'workflow.get': return await cmdWorkflowGet(params);
    case 'workflow.delete': return await cmdWorkflowDelete(params);
    case 'workflow.save': return await cmdWorkflowSave(params);
    case 'workflow.run': return await cmdWorkflowRun(params, targetTabId);
    case 'schedule.create': return await cmdScheduleCreate(params);
    case 'schedule.list': return await cmdScheduleList();
    case 'schedule.delete': return await cmdScheduleDelete(params);
    case 'schedule.runs': return await cmdScheduleRuns(params);
    // policy
    case 'policy.get': return await cmdPolicyGet();
    case 'audit.list': return await cmdAuditList(params);
    case 'audit.report': return await cmdAuditReport(params);
    case 'policy.set': return await cmdPolicySet(params);
    case 'approval.respond': return await cmdApprovalRespond(params);
    // cancel passthrough
    case 'cancel': return { canceled: params.targetId || params.requestId || null, bestEffort: true };
    // recorder (forward to content script for action capture)
    case 'recorder.start':
    case 'recorder.stop':
    case 'recorder.pause':
    case 'recorder.status':
      return await forwardToContentScript(command, params, targetTabId);
    // full-page screenshot (background)
    case 'screenshot.fullPage':
      return await browserControl.screenshot(targetTabId, params);
    default:
      // Commands that need content script (including waitForTimeout, listFrames, storage ops, etc.)
      return await forwardToContentScript(command, params, targetTabId);
  }
}

// ─── Tab commands (background) ───────────────────────────────────────────────
async function cmdListTabs() {
  const tabs = await chrome.tabs.query({});
  return {
    tabs: tabs.map(t => ({
      id: t.id,
      url: t.url || '',
      title: t.title || '',
      active: t.active,
      windowId: t.windowId,
      groupId: t.groupId
    }))
  };
}

async function cmdNewTab(params) {
  // Resolve the saved workspace before creating anything. A stale group must not
  // leave an untracked tab behind or silently route work outside the workspace.
  const groupId = params.groupId ?? activeTargetSet.groupId;
  let group = null;
  if (typeof groupId === 'number' && chrome.tabGroups) {
    group = await chrome.tabGroups.get(groupId);
  }
  const options = { url: params.url || 'https://example.com', active: params.active !== false };
  if (group) options.windowId = group.windowId;
  const tab = await chrome.tabs.create(options);
  if (groupId != null) {
    try {
      await cmdAddTabToGroup({ tabId: tab.id, groupId });
    } catch (error) {
      // Roll back only the tab this command just created.
      await chrome.tabs.remove(tab.id);
      throw error;
    }
  }
  if (tab && tab.active !== false) activeTargetSet.activeTabId = tab.id;
  await persistTargetSet();
  return { tabId: tab.id, url: tab.url || options.url, groupId: groupId ?? null, windowId: tab.windowId };
}

async function cmdCloseTab(params) {
  const tabId = params.tabId;
  if (!tabId) throw new Error('tabId required');
  await chrome.tabs.remove(tabId);
  return { closed: tabId };
}

async function cmdSwitchTab(params) {
  const tabId = params.tabId;
  if (!tabId) throw new Error('tabId required');
  await chrome.tabs.update(tabId, { active: true });
  const tab = await chrome.tabs.get(tabId);
  await chrome.windows.update(tab.windowId, { focused: true });
  activeTargetSet.activeTabId = tabId;
  await persistTargetSet();
  return { tabId };
}

async function cmdGetTabInfo(tabId) {
  const tab = await chrome.tabs.get(tabId);
  return {
    tabId: tab.id,
    url: tab.url || '',
    title: tab.title || '',
    active: tab.active,
    windowId: tab.windowId,
    groupId: tab.groupId
  };
}

// ─── Cookie commands (background) ────────────────────────────────────────────
async function cmdGetCookies(params, tabId) {
  const urls = params.urls || [];
  if (urls.length === 0 && tabId) {
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (tab && tab.url) urls.push(tab.url);
  }
  const allCookies = [];
  for (const url of urls) {
    const cookies = await chrome.cookies.getAll({ url });
    allCookies.push(...cookies);
  }
  // Deduplicate by name+domain+path
  const seen = new Set();
  const unique = [];
  for (const c of allCookies) {
    const key = `${c.name}|${c.domain}|${c.path}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push({
        name: c.name, value: c.value, domain: c.domain,
        path: c.path, secure: c.secure, httpOnly: c.httpOnly,
        sameSite: c.sameSite, expires: c.expirationDate
      });
    }
  }
  return { cookies: unique };
}

async function cmdSetCookie(params) {
  const details = {
    url: params.url || `https://${params.domain}${params.path || '/'}`,
    name: params.name,
    value: params.value,
    domain: params.domain,
    path: params.path || '/',
    secure: params.secure || false,
    httpOnly: params.httpOnly || false
  };
  if (params.sameSite) details.sameSite = params.sameSite;
  if (params.expires) details.expirationDate = params.expires;
  await chrome.cookies.set(details);
  return { set: true };
}

async function cmdDeleteCookie(params) {
  await chrome.cookies.remove({
    url: params.url || `https://${params.domain}${params.path || '/'}`,
    name: params.name
  });
  return { deleted: params.name };
}

async function cmdClearCookies(params, tabId) {
  const urls = params.urls || [];
  if (urls.length === 0 && tabId) {
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (tab && tab.url) urls.push(tab.url);
  }
  for (const url of urls) {
    const cookies = await chrome.cookies.getAll({ url });
    for (const c of cookies) {
      await chrome.cookies.remove({ url, name: c.name });
    }
  }
  return { cleared: true };
}

// ─── Screenshot (background) ─────────────────────────────────────────────────
async function cmdCaptureVisibleTab(tabId) {
  const tab = await chrome.tabs.get(tabId);
  const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
  const base64 = dataUrl.split(',')[1];
  return { screenshot: base64, format: 'png' };
}

// Full-page screenshot by scrolling and stitching (best-effort)
async function cmdScreenshotFullPage(tabId, params) {
  const format = (params && params.format) || 'png';
  const quality = (params && params.quality) || 80;
  const tab = await chrome.tabs.get(tabId);
  const windowId = tab.windowId;

  // Get page dimensions via content script
  const dims = await forwardToContentScript('getPageDimensions', {}, tabId);
  if (!dims || !dims.data) throw new Error('Failed to get page dimensions');
  const { scrollHeight, scrollWidth, clientHeight, clientWidth } = dims.data;

  const viewportHeight = clientHeight;
  const viewportWidth = clientWidth;
  const totalHeight = scrollHeight;
  const totalWidth = scrollWidth;

  // Calculate scroll positions
  const scrolls = [];
  for (let y = 0; y < totalHeight; y += viewportHeight) {
    for (let x = 0; x < totalWidth; x += viewportWidth) {
      scrolls.push({ x: Math.min(x, totalWidth - viewportWidth), y: Math.min(y, totalHeight - viewportHeight) });
    }
  }

  // Capture each tile
  const tiles = [];
  for (const pos of scrolls) {
    await forwardToContentScript('scrollTo', { x: pos.x, y: pos.y }, tabId);
    await new Promise(r => setTimeout(r, 100)); // wait for scroll
    const dataUrl = await chrome.tabs.captureVisibleTab(windowId, { format, quality });
    tiles.push({ x: pos.x, y: pos.y, dataUrl });
  }

  // Restore scroll position
  await forwardToContentScript('scrollTo', { x: 0, y: 0 }, tabId);

  return { tiles, totalWidth, totalHeight, viewportWidth, viewportHeight, format, tileCount: tiles.length };
}

// ─── Dialog handling ─────────────────────────────────────────────────────────
async function cmdDialog(action, tabId) {
  const handler = dialogHandlers.get(tabId);
  if (!handler) throw new Error('no pending dialog');
  dialogHandlers.delete(tabId);
  if (action === 'acceptDialog') {
    handler.resolve(handler.promptValue || '');
  } else {
    handler.reject(new Error('dialog dismissed'));
  }
  return { handled: action };
}

// ─── Content script forwarding ───────────────────────────────────────────────
function forwardToContentScript(command, params, tabId) {
  const timeoutMs = 30000;
  const msg = { command, params: params || {} };
  const targetFrameId = browserControl.frameId(tabId, params);
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(`command timed out: ${command}`));
    }, timeoutMs);

    const done = (err, data) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(data);
    };

    const sendOnce = (allowInject) => {
      try {
        chrome.tabs.sendMessage(tabId, msg, { frameId: targetFrameId }, (response) => {
          if (settled) return;
          const lastErr = chrome.runtime && chrome.runtime.lastError;
          if (lastErr) {
            if (allowInject) {
              injectContentScript(tabId, targetFrameId).then(() => sendOnce(false)).catch((e) => done(new Error((e && e.message) || lastErr.message || String(lastErr))));
            } else {
              done(new Error(lastErr.message || String(lastErr)));
            }
            return;
          }
          if (!response) return done(new Error('no response from content script'));
          if (response.error) return done(new Error(response.error));
          return done(null, response.data);
        });
      } catch (e) {
        // Promise-style fallback
        try {
          Promise.resolve(chrome.tabs.sendMessage(tabId, msg, { frameId: targetFrameId })).then((response) => {
            if (!response) return done(new Error('no response from content script'));
            if (response.error) return done(new Error(response.error));
            return done(null, response.data);
          }).catch((err) => {
            if (allowInject) {
              injectContentScript(tabId, targetFrameId).then(() => sendOnce(false)).catch((e2) => done(new Error((e2 && e2.message) || (err && err.message) || String(err))));
            } else {
              done(new Error((err && err.message) || String(err)));
            }
          });
        } catch (e2) {
          done(new Error((e2 && e2.message) || String(e2)));
        }
      }
    };

    sendOnce(true);
  });
}

async function injectContentScript(tabId, frameId = 0) {
  if (chrome.scripting && chrome.scripting.executeScript) {
    return chrome.scripting.executeScript({ target: { tabId, frameIds: [frameId] }, files: ['content.js'] });
  }
  if (chrome.tabs && chrome.tabs.executeScript) {
    return new Promise((resolve, reject) => chrome.tabs.executeScript(tabId, { file: 'content.js', frameId }, () => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message)); else resolve();
    }));
  }
  throw new Error('no script injection API available');
}

// ─── Active tab helper ───────────────────────────────────────────────────────
async function getActiveTabId() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0]?.id;
}

// ─── Content script port management ──────────────────────────────────────────
chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'content-script') {
    const tabId = port.sender?.tab?.id;
    if (tabId) {
      contentPorts.set(tabId, port);
      port.onDisconnect.addListener(() => {
        contentPorts.delete(tabId);
      });
    }
  }
});

// ─── Event listeners (tab updates forwarded to bridge) ───────────────────────
if (chrome.tabs && chrome.tabs.onActivated) {
  chrome.tabs.onActivated.addListener((info) => {
    if (info && info.tabId) {
      activeTargetSet.activeTabId = info.tabId;
      persistTargetSet().catch(() => {});
    }
  });
}

chrome.tabs.onCreated.addListener((tab) => {
  sendToBridge({
    id: `evt-${Date.now()}`,
    type: 'event',
    event: 'tabCreated',
    data: { tabId: tab.id, url: tab.url || '' },
    timestamp: Date.now()
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  browserControl.reset(tabId);
  let changed = false;
  if (Array.isArray(activeTargetSet.tabs) && activeTargetSet.tabs.includes(tabId)) {
    activeTargetSet.tabs = activeTargetSet.tabs.filter((t) => t !== tabId);
    changed = true;
  }
  if (activeTargetSet.activeTabId === tabId) {
    activeTargetSet.activeTabId = activeTargetSet.tabs[0] || null;
    changed = true;
  }
  if (changed) { persistTargetSet().catch(() => {}); }
  // Clean up debugger state
  debugState.delete(tabId);
  if (debugState.attachedTabs) debugState.attachedTabs.delete(tabId);
  sendToBridge({
    id: `evt-${Date.now()}`,
    type: 'event',
    event: 'tabClosed',
    data: { tabId },
    timestamp: Date.now()
  });
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.url) browserControl.reset(tabId);
  if (changeInfo.url || changeInfo.status === 'complete') {
    sendToBridge({
      id: `evt-${Date.now()}`,
      type: 'event',
      event: 'tabUpdated',
      data: { tabId, url: tab.url || '', title: tab.title || '', status: changeInfo.status },
      timestamp: Date.now()
    });
    // Re-attach debugger on navigation if it was attached before
    if (changeInfo.url && debugState.attachedTabs && debugState.attachedTabs.has(tabId)) {
      try {
        await chrome.debugger.detach({ tabId }).catch(()=>{});
        await chrome.debugger.attach({ tabId }, '1.3');
        await chrome.debugger.sendCommand({ tabId }, 'Runtime.enable').catch(()=>{});
        await chrome.debugger.sendCommand({ tabId }, 'Network.enable').catch(()=>{});
        await chrome.debugger.sendCommand({ tabId }, 'Log.enable').catch(()=>{});
        emitTaskEvent('debug_reattached', { tabId, url: tab.url });
      } catch (e) {
        debugState.attachedTabs.delete(tabId);
        const st = debugState.get(tabId) || {}; st.attached = false; debugState.set(tabId, st);
        emitTaskEvent('debug_detached', { tabId, reason: e.message });
      }
    }
  }
});

// ─── Popup + Content script message handlers ─────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return false;
  if (msg.type === 'getStatus') {
    sendResponse({ connected: !!(helloAcked && ws && ws.readyState === WebSocket.OPEN), helloAcked, bridgeHost, bridgeWsPort: nativeReadyPort || bridgeWsPort, nativeError, targetSet: activeTargetSet });
    return false;
  }
  if (msg.type === 'reconnect') {
    if (sender.tab) return false;
    connectionEnabled = true;
    if (nativePort) { nativePort.disconnect(); nativePort = null; }
    nativeReadyPort = 0;
    bridgeHost = msg.host || bridgeHost || '127.0.0.1';
    bridgeWsPort = msg.wsPort || 0;
    bridgeToken = typeof msg.token === 'string' ? msg.token : '';
    saveConfig();
    try { if (ws) ws.close(); } catch (_) {}
    ws = null;
    reconnectDelay = RECONNECT_BASE_MS;
    connectToBridge();
    sendResponse({ ok: true });
    return false;
  }
  if (msg.type === 'disconnect') {
    if (sender.tab) return false;
    connectionEnabled = false;
    if (nativePort) { nativePort.disconnect(); nativePort = null; }
    nativeReadyPort = 0;
    try { if (ws) ws.close(); } catch (_) {}
    ws = null;
    helloAcked = false;
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    notifyPopup({ type: 'disconnected' });
    sendResponse({ ok: true });
    return false;
  }
  if (msg.type === 'getPolicy') {
    getPolicy().then(p => sendResponse({ policy: p })).catch(() => sendResponse({ policy: defaultPolicy() }));
    return true;
  }
  if (msg.type === 'setPolicy') {
    setPolicy(msg.policy || defaultPolicy()).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.type === 'recordStart') {
    cmdRecordStart({ name: msg.name, includeSensitive: msg.includeSensitive }, msg.tabId).then(r => sendResponse(r)).catch(e => sendResponse({ error: e.message }));
    return true;
  }
  if (msg.type === 'recordPause') {
    cmdRecordPause().then(r => sendResponse(r)).catch(e => sendResponse({ error: e.message }));
    return true;
  }
  if (msg.type === 'recordStop') {
    cmdRecordStop().then(r => sendResponse(r)).catch(e => sendResponse({ error: e.message }));
    return true;
  }
  if (msg.type === 'recorderStatus') {
    sendResponse({ active: !!activeRecording, paused: !!(activeRecording && activeRecording.paused), steps: activeRecording ? activeRecording.steps.length : 0 });
    return true;
  }
  // content script responses handled by per-command listeners in forwardToContentScript
  if (msg.type === 'recorderEvent' && activeRecording && !activeRecording.paused) {
    const step = { t: Date.now(), command: msg.event, params: msg.data };
    activeRecording.steps.push(step);
  }
  return false;
});

// ─── Logging ─────────────────────────────────────────────────────────────────
function log(...args) {
  console.log('[Aegis Bridge]', ...args);
}

// ─── Policy / approvals (local, deterministic) ───────────────────────────────
const SENSITIVE_COMMANDS = new Set([
  'download.start','upload.begin','upload.chunk','upload.finish','upload.cancel',
  'input.click','input.drag','input.type','input.key','dialog.handle','screenshot.fullPage',
  'evaluate','evaluateAll','getCookies','setCookie','deleteCookie','clearCookies',
  'getLocalStorage','setLocalStorage','getSessionStorage','setSessionStorage',
  'debug.attach','debug.getConsole','debug.getNetwork','debug.getPageState','page.snapshot',
  'download.wait','download.list','upload.file','navigate','newTab','closeTab','fill','type','click'
]);
const ALWAYS_CONFIRM = new Set(['evaluate','evaluateAll','setCookie','deleteCookie','clearCookies','setLocalStorage','setSessionStorage','upload.file','upload.begin','upload.chunk','upload.finish','debug.attach']);
const HARD_BLOCK_URL_PREFIXES = ['chrome://','edge://','about:','brave://','moz-extension://internal'];

async function evaluatePolicy(command, params, tabId) {
  const p = await getPolicy();
  // Global metadata/workspace operations do not read the selected page DOM.
  const globalCommands = new Set(['listTabs', 'listTabGroups', 'target.get', 'extension.info', 'newTab']);
  // Page operations remain blocked on internal browser pages.
  try {
    if (tabId && !globalCommands.has(command)) {
      const t = await chrome.tabs.get(tabId);
      const u = (t && t.url) || '';
      if (HARD_BLOCK_URL_PREFIXES.some((x) => u.startsWith(x))) {
        return { allowed: false, needsApproval: false, reason: 'internal/unsupported page blocked by policy' };
      }
    }
  } catch (_) {}
  const url = (params && (params.url || params.href)) || '';
  if (url && HARD_BLOCK_URL_PREFIXES.some((x) => url.startsWith(x))) {
    return { allowed: false, needsApproval: false, reason: 'internal/unsupported URL blocked by policy' };
  }
  // deny list
  if (Array.isArray(p.deny) && url && p.deny.some((d) => url.includes(d))) return { allowed: false, needsApproval: false, reason: 'denied by site policy' };
  // mode handling (deterministic; no classifier)
  const sensitive = SENSITIVE_COMMANDS.has(command) || (p.defaultGateSensitive && ALWAYS_CONFIRM.has(command));
  if (!sensitive) return { allowed: true, needsApproval: false };
  if (p.mode === 'unattended') {
    if (ALWAYS_CONFIRM.has(command) && !(Array.isArray(p.trustedScopes) && p.trustedScopes.includes('*'))) {
      return { allowed: true, needsApproval: false, reason: 'unattended trusted scope (best-effort)' };
    }
    return { allowed: true, needsApproval: false };
  }
  if (p.mode === 'auto-with-prompts') {
    const allowedByScope = Array.isArray(p.allow) && url && p.allow.some((a) => url.includes(a));
    if (allowedByScope && !ALWAYS_CONFIRM.has(command)) return { allowed: true, needsApproval: false };
    // require approval (cannot prompt user unattended) -> deny with explicit reason
    return { allowed: false, needsApproval: true, reason: 'approval required by local policy mode auto-with-prompts' };
  }
  // manual-approve
  return { allowed: false, needsApproval: true, reason: 'approval required by local policy mode manual-approve' };
}

async function emitPermissionPrompt(command, params, tabId, reason, needsApproval) {
  emitTaskEvent('permission_prompt', { command, tabId, needsApproval: !!needsApproval, reason: reason || null });
  try {
    if (chrome.notifications && chrome.notifications.create) {
      chrome.notifications.create('', { type: 'basic', iconUrl: 'icons/icon48.png', title: 'Aegis policy', message: (needsApproval ? 'Approval required: ' : 'Denied: ') + command + (reason ? (' - ' + reason) : '') });
    }
  } catch (_) {}
}

function emitTaskEvent(state, data) {
  sendToBridge({ id: `evt-${Date.now()}-${Math.random().toString(36).slice(2,6)}`, type: 'event', event: 'task', data: { state, ...(data||{}) }, timestamp: Date.now(), version: PROTOCOL_VERSION });
}

// ─── Tab groups / target set (capability-gated, Firefox fallback) ────────────
async function cmdCreateTabGroup(params) {
  const tabIds = (params.tabIds || (params.tabId ? [params.tabId] : [])).filter(Boolean);
  if (!tabIds.length) throw new Error('tabIds required');
  if (chrome.tabGroups && chrome.tabs && chrome.tabs.group) {
    const groupId = await chrome.tabs.group({ tabIds });
    if (params.title || params.color) {
      try { await chrome.tabGroups.update(groupId, { title: params.title, color: params.color }); } catch (_) {}
    }
    activeTargetSet.groupId = groupId;
    activeTargetSet.tabs = tabIds;
    await persistTargetSet();
    return { groupId, tabs: tabIds, native: true };
  }
  // fallback logical set
  activeTargetSet.groupId = activeTargetSet.groupId || ('logical-' + Date.now());
  activeTargetSet.tabs = Array.from(new Set([...(activeTargetSet.tabs||[]), ...tabIds]));
  await persistTargetSet();
  return { groupId: activeTargetSet.groupId, tabs: activeTargetSet.tabs, native: false, fallback: 'logical-target-set' };
}

async function cmdAddTabToGroup(params) {
  const tabId = params.tabId; const groupId = params.groupId || activeTargetSet.groupId;
  if (!tabId) throw new Error('tabId required');
  if (chrome.tabGroups && chrome.tabs && chrome.tabs.group && typeof groupId === 'number') {
    await chrome.tabs.group({ tabIds: [tabId], groupId });
    activeTargetSet.tabs = Array.from(new Set([...(activeTargetSet.tabs||[]), tabId]));
    activeTargetSet.groupId = groupId;
    await persistTargetSet();
    return { groupId, tabId, native: true };
  }
  activeTargetSet.groupId = groupId || ('logical-' + Date.now());
  activeTargetSet.tabs = Array.from(new Set([...(activeTargetSet.tabs||[]), tabId]));
  await persistTargetSet();
  return { groupId: activeTargetSet.groupId, tabId, native: false, fallback: 'logical-target-set' };
}

async function cmdRemoveFromTabGroup(params) {
  const tabId = params.tabId; if (!tabId) throw new Error('tabId required');
  if (chrome.tabs && chrome.tabs.ungroup) { try { await chrome.tabs.ungroup([tabId]); } catch (_) {} }
  activeTargetSet.tabs = (activeTargetSet.tabs||[]).filter((t) => t !== tabId);
  await persistTargetSet();
  return { removed: tabId, tabs: activeTargetSet.tabs };
}

async function cmdListTabGroups() {
  if (chrome.tabGroups && chrome.tabGroups.query) {
    try { const groups = await chrome.tabGroups.query({}); return { groups, native: true }; } catch (_) {}
  }
  return { groups: activeTargetSet.groupId ? [{ id: activeTargetSet.groupId, tabs: activeTargetSet.tabs||[], logical: true }] : [], native: false };
}

async function cmdFocusTabGroup(params) {
  const groupId = params.groupId || activeTargetSet.groupId;
  if (chrome.tabGroups && chrome.tabGroups.query) {
    try {
      const tabs = await chrome.tabs.query({ groupId });
      if (tabs && tabs[0]) await cmdSwitchTab({ tabId: tabs[0].id });
      return { focused: groupId, native: true };
    } catch (_) {}
  }
  const t = (activeTargetSet.tabs||[])[0];
  if (t) await cmdSwitchTab({ tabId: t });
  return { focused: groupId, native: false };
}

async function cmdSetTargetSet(params) {
  activeTargetSet = {
    tabs: Array.isArray(params.tabs) ? params.tabs : (activeTargetSet.tabs||[]),
    activeTabId: params.activeTabId || params.tabId || activeTargetSet.activeTabId || null,
    groupId: params.groupId || activeTargetSet.groupId || null,
  };
  if (activeTargetSet.activeTabId) { try { await cmdSwitchTab({ tabId: activeTargetSet.activeTabId }); } catch (_) {} }
  await persistTargetSet();
  return { targetSet: activeTargetSet };
}

// ─── Debug/observability (best-effort, capability-gated) ─────────────────────
const debugState = new Map(); // tabId -> {attached, console:[], network:[]}

async function cmdDebugAttach(tabId) {
  if (!chrome.debugger) throw unsupported('debugger not available');
  if (!tabId) throw new Error('tabId required');
  await chrome.debugger.attach({ tabId }, '1.3');
  await chrome.debugger.sendCommand({ tabId }, 'Runtime.enable').catch(()=>{});
  await chrome.debugger.sendCommand({ tabId }, 'Network.enable').catch(()=>{});
  await chrome.debugger.sendCommand({ tabId }, 'Log.enable').catch(()=>{});
  debugState.set(tabId, { attached: true, console: [], network: [] });
  // Track for auto-reattach on navigation
  if (!debugState.attachedTabs) debugState.attachedTabs = new Set();
  debugState.attachedTabs.add(tabId);
  emitTaskEvent('debug_attached', { tabId });
  return { attached: true, tabId };
}

async function cmdDebugDetach(tabId) {
  if (!chrome.debugger) throw unsupported('debugger not available');
  if (!tabId) throw new Error('tabId required');
  try { await chrome.debugger.detach({ tabId }); } catch (_) {}
  const st = debugState.get(tabId) || {}; st.attached = false; debugState.set(tabId, st);
  if (debugState.attachedTabs) debugState.attachedTabs.delete(tabId);
  emitTaskEvent('debug_detached', { tabId });
  return { attached: false, tabId };
}

function pushBounded(arr, item, max=200) { arr.push(item); if (arr.length > max) arr.splice(0, arr.length - max); }

if (chrome.debugger && chrome.debugger.onEvent) {
  chrome.debugger.onEvent.addListener((source, method, params) => {
    const tabId = source && source.tabId;
    if (!tabId) return;
    const st = debugState.get(tabId) || { attached: true, console: [], network: [] };
    if (method === 'Runtime.consoleAPICalled' || method === 'Log.entryAdded' || method === 'Runtime.exceptionThrown') {
      const e = { method, params: redactObject(params), ts: Date.now() };
      pushBounded(st.console, e);
      sendToBridge({ id: `evt-${Date.now()}`, type: 'event', event: method === 'Runtime.exceptionThrown' ? 'pageError' : 'console', data: { tabId, ...e }, timestamp: Date.now(), version: PROTOCOL_VERSION });
    }
    if (method && method.startsWith('Network.')) {
      const e = { method, params: redactObject(params), ts: Date.now() };
      pushBounded(st.network, e);
      sendToBridge({ id: `evt-${Date.now()}`, type: 'event', event: 'network', data: { tabId, ...e }, timestamp: Date.now(), version: PROTOCOL_VERSION });
    }
    debugState.set(tabId, st);
  });
}

async function cmdDebugGetConsole(tabId) { const st = debugState.get(tabId) || { console: [] }; return { tabId, console: st.console || [] }; }
async function cmdDebugGetNetwork(tabId) { const st = debugState.get(tabId) || { network: [] }; return { tabId, network: st.network || [] }; }
async function cmdDebugGetPageState(tabId, params) { return await cmdPageSnapshot(tabId, params); }
async function cmdPageSnapshot(tabId, params) {
  const includeSensitive = !!(params && params.includeSensitive);
  const res = await forwardToContentScript('page.snapshot', { ...params, includeSensitive }, tabId);
  return res;
}

// ─── Downloads/uploads (capability-gated best-effort) ────────────────────────
async function cmdDownloadList(params) {
  if (!chrome.downloads || !chrome.downloads.search) return { downloads: [], supported: false };
  const q = params && params.query ? params.query : {};
  const items = await chrome.downloads.search(q);
  return { downloads: items.map(sanitizeDownloadItem), supported: true };
}

async function cmdDownloadWait(params) {
  if (!chrome.downloads || !chrome.downloads.search) throw unsupported('downloads not available');
  const id = params && params.id;
  const timeout = Math.min(Math.max(parseInt(params && params.timeout) || 30000, 1000), 120000);
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const items = await chrome.downloads.search(id ? { id } : { limit: 10, orderBy: ['-startTime'] });
    const done = items.find((i) => !id ? (i.state === 'complete' || i.state === 'interrupted') : (i.id === id && (i.state === 'complete' || i.state === 'interrupted')));
    if (done) {
      if (done.state === 'interrupted') throw Object.assign(new Error('Download interrupted: ' + (done.error || 'unknown reason')), { code: 'download_interrupted' });
      return { download: sanitizeDownloadItem(done), supported: true };
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('download wait timeout');
}

function sanitizeDownloadItem(i) {
  if (!i) return i;
  return { id: i.id, filename: i.filename, url: i.url, state: i.state, error: i.error, bytesReceived: i.bytesReceived, totalBytes: i.totalBytes, mime: i.mime, startTime: i.startTime, endTime: i.endTime, danger: i.danger };
}

async function cmdUploadFile(params, tabId) {
  if (params.paths) return await browserControl.uploadPaths(tabId, params);
  // Programmatic file upload via extension context is limited; best-effort content-script path for file inputs if provided as data/selector.
  const res = await forwardToContentScript('upload.file', params, tabId);
  // Emit progress event for tracking
  emitTaskEvent('file_selected', { tabId, filename: params && params.filename, size: res && res.size });
  return res;
}

// Download progress tracking
if (chrome.downloads && chrome.downloads.onChanged) {
  chrome.downloads.onChanged.addListener((delta) => {
    if (delta.state && delta.state.current === 'complete') {
      emitTaskEvent('download_complete', { downloadId: delta.id, filename: delta.filename && delta.filename.current });
    } else if (delta.state && delta.state.current === 'interrupted') {
      emitTaskEvent('download_interrupted', { downloadId: delta.id, error: delta.error && delta.error.current });
    }
  });
}

// ─── Recording / workflows / schedules (local best-effort) ──────────────────
let activeRecording = null;

async function cmdRecordStart(params, tabId) {
  activeRecording = { id: 'rec-' + Date.now(), tabId, steps: [], startedAt: Date.now(), name: params && params.name, sensitive: !!(params && params.includeSensitive) };
  emitTaskEvent('recording_started', { recordingId: activeRecording.id, tabId });
  return { recording: { id: activeRecording.id, startedAt: activeRecording.startedAt } };
}
async function cmdRecordPause() { if (activeRecording) activeRecording.paused = !activeRecording.paused; return { paused: !!(activeRecording && activeRecording.paused) }; }
async function cmdRecordStop() {
  if (!activeRecording) return { recording: null };
  const rec = activeRecording; activeRecording = null;
  rec.stoppedAt = Date.now();
  await saveWorkflowRecord(rec);
  emitTaskEvent('recording_stopped', { recordingId: rec.id, steps: rec.steps.length });
  return { recording: { id: rec.id, steps: rec.steps.length, stoppedAt: rec.stoppedAt } };
}
async function saveWorkflowRecord(rec) {
  const store = await getStore(WORKFLOWS_KEY, []);
  store.push({ id: rec.id, name: rec.name || rec.id, createdAt: rec.startedAt, steps: rec.steps, version: 1 });
  await setStore(WORKFLOWS_KEY, store.slice(-100));
}

async function cmdWorkflowList() { return { workflows: await getStore(WORKFLOWS_KEY, []) }; }
async function cmdWorkflowGet(params) {
  const id = params && (params.id || params.workflowId);
  const workflows = await getStore(WORKFLOWS_KEY, []);
  const wf = workflows.find(w => w.id === id);
  if (!wf) throw new Error('workflow not found');
  return { workflow: wf };
}
async function cmdWorkflowDelete(params) {
  const id = params && (params.id || params.workflowId);
  let workflows = await getStore(WORKFLOWS_KEY, []);
  workflows = workflows.filter(w => w.id !== id);
  await setStore(WORKFLOWS_KEY, workflows);
  return { deleted: id };
}
async function cmdWorkflowSave(params) {
  const wf = params && (params.workflow || params);
  if (!wf) throw new Error('workflow required');
  if (!wf.id) wf.id = 'wf-' + Date.now();
  if (!wf.version) wf.version = 1;
  const workflows = await getStore(WORKFLOWS_KEY, []);
  const i = workflows.findIndex(w => w.id === wf.id);
  if (i >= 0) workflows[i] = wf; else workflows.push(wf);
  await setStore(WORKFLOWS_KEY, workflows.slice(-200));
  return { workflow: wf };
}
async function cmdScheduleRuns(params) { const limit = Math.max(1, Math.min(parseInt(params && params.limit) || 50, 200)); const runs = await getStore(RUNS_KEY, []); return { runs: runs.slice(-limit) }; }

async function cmdWorkflowRun(params, tabId) {
  const id = params && (params.id || params.workflowId);
  const workflows = await getStore(WORKFLOWS_KEY, []);
  const wf = workflows.find(w => w.id === id) || (params && params.workflow);
  if (!wf) throw new Error('workflow not found');
  const steps = Array.isArray(wf.steps) ? wf.steps : [];
  const trace = [];
  const screenshots = params && params.captureScreenshots ? [] : null;
  let failed = false;
  for (let i=0;i<steps.length;i++) {
    const s = steps[i];
    const t0 = Date.now();
    try {
      const target = s.tabId || s.params?.tabId || tabId;
      const decision = await evaluatePolicy(s.command, s.params || {}, target);
      if (!decision.allowed || decision.needsApproval) {
        await appendAudit({ type: 'policy', outcome: 'denied', command: s.command, tabId: target, reason: decision.reason || 'workflow step requires approval' });
        throw Object.assign(new Error(decision.reason || 'workflow step requires approval'), { code: 'permission_denied' });
      }
      const r = await executeCommand(s.command, s.params || {}, target);
      trace.push({ i, command: s.command, ok: true, ms: Date.now()-t0 });
      // Capture screenshot after navigation/click actions if enabled
      if (screenshots && (s.command === 'navigate' || s.command === 'click' || s.command === 'fill' || s.command === 'type')) {
        try {
          const canCapture = await evaluatePolicy('page.snapshot', { maxChars: 5000 }, target);
          if (canCapture.allowed && !canCapture.needsApproval) {
            const snap = await executeCommand('page.snapshot', { maxChars: 5000 }, target);
            if (snap) screenshots.push({ step: i, command: s.command, snapshot: snap, ts: Date.now() });
          }
        } catch (_) {}
      }
    } catch (e) {
      failed = true;
      trace.push({ i, command: s.command, ok: false, error: (e&&e.message)||String(e), ms: Date.now()-t0 });
      if (!params || params.continueOnError !== true) {
        await appendRun({ id: 'run-'+Date.now(), type: 'workflow', workflowId: wf.id, ok: false, trace, ts: Date.now() });
        throw Object.assign(new Error((e&&e.message)||String(e)), { code: e.code || 'workflow_failed', details: { trace } });
      }
    }
  }
  await appendRun({ id: 'run-'+Date.now(), type: 'workflow', workflowId: wf.id, ok: !failed, trace, ts: Date.now(), screenshots });
  if (failed) throw Object.assign(new Error('One or more workflow steps failed'), { code: 'workflow_failed', details: { trace } });
  return { ok: true, trace, screenshots };
}

async function cmdScheduleCreate(params) {
  const schedules = await getStore(SCHEDULES_KEY, []);
  const sch = {
    id: 'sch-' + Date.now(),
    name: params && params.name,
    workflowId: params && params.workflowId,
    command: params && params.command,
    params: params && params.params || {},
    intervalMinutes: Math.max(1, parseInt(params && params.intervalMinutes) || 60),
    enabled: params && params.enabled !== false,
    nextRunAt: Date.now() + Math.max(1, parseInt(params && params.intervalMinutes) || 60) * 60000,
    createdAt: Date.now(),
  };
  schedules.push(sch);
  await setStore(SCHEDULES_KEY, schedules);
  try { if (chrome.alarms) chrome.alarms.create('aegis_sched_' + sch.id, { delayInMinutes: sch.intervalMinutes, periodInMinutes: sch.intervalMinutes }); } catch (_) {}
  return { schedule: sch };
}
async function cmdScheduleList() { return { schedules: await getStore(SCHEDULES_KEY, []) }; }
async function cmdScheduleDelete(params) {
  const id = params && (params.id || params.scheduleId);
  let schedules = await getStore(SCHEDULES_KEY, []);
  schedules = schedules.filter(s => s.id !== id);
  await setStore(SCHEDULES_KEY, schedules);
  try { if (chrome.alarms) chrome.alarms.clear('aegis_sched_' + id); } catch (_) {}
  return { deleted: id };
}

async function tickSchedules() {
  const schedules = await getStore(SCHEDULES_KEY, []);
  const now = Date.now();
  let changed = false;
  for (const s of schedules) {
    if (!s.enabled) continue;
    if (s.nextRunAt && s.nextRunAt <= now) {
      // mark due; alarm handler or next tick runs
      s.nextRunAt = now + (Math.max(1, s.intervalMinutes||60) * 60000);
      changed = true;
    }
  }
  if (changed) await setStore(SCHEDULES_KEY, schedules);
}

async function reconcileSchedulesOnStartup() {
  const schedules = await getStore(SCHEDULES_KEY, []);
  const now = Date.now();
  let changed = false;
  for (const s of schedules) {
    if (!s.enabled) continue;
    if (s.nextRunAt && s.nextRunAt < now - 60000) {
      await appendRun({ id: 'run-'+Date.now(), type: 'schedule', scheduleId: s.id, status: 'interrupted', reason: 'missed while unavailable', ts: now });
      s.nextRunAt = now + (Math.max(1, s.intervalMinutes||60) * 60000);
      changed = true;
      emitTaskEvent('schedule_missed', { scheduleId: s.id });
      try { if (chrome.notifications) chrome.notifications.create('', { type:'basic', iconUrl:'icons/icon48.png', title:'Aegis schedule missed', message: s.name || s.id }); } catch (_) {}
    }
    try { if (chrome.alarms) chrome.alarms.create('aegis_sched_' + s.id, { delayInMinutes: Math.max(1, s.intervalMinutes||60), periodInMinutes: Math.max(1, s.intervalMinutes||60) }); } catch (_) {}
  }
  if (changed) await setStore(SCHEDULES_KEY, schedules);
}

async function runScheduleByAlarm(alarmName) {
  const id = alarmName.replace('aegis_sched_', '');
  const schedules = await getStore(SCHEDULES_KEY, []);
  const s = schedules.find(x => x.id === id);
  if (!s || !s.enabled) return;
  emitTaskEvent('schedule_run_start', { scheduleId: id });
  try {
    let result;
    if (s.workflowId) result = await cmdWorkflowRun({ id: s.workflowId, captureScreenshots: true }, activeTargetSet.activeTabId);
    else if (s.command) {
      const target = s.params?.tabId || activeTargetSet.activeTabId || await getActiveTabId();
      const decision = await evaluatePolicy(s.command, s.params || {}, target);
      if (!decision.allowed || decision.needsApproval) throw new Error(decision.reason || 'schedule denied by local policy');
      result = await executeCommand(s.command, s.params || {}, target);
    }
    await appendRun({ id: 'run-'+Date.now(), type: 'schedule', scheduleId: id, status: 'completed', ts: Date.now(), trace: result?.trace, screenshots: result?.screenshots });
    emitTaskEvent('schedule_run_complete', { scheduleId: id });
    try { if (chrome.notifications) chrome.notifications.create('', { type:'basic', iconUrl:'icons/icon48.png', title:'Aegis schedule complete', message: s.name || id }); } catch (_) {}
    return result;
  } catch (e) {
    await appendRun({ id: 'run-'+Date.now(), type: 'schedule', scheduleId: id, status: 'failed', reason: (e&&e.message)||String(e), ts: Date.now() });
    emitTaskEvent('schedule_run_failed', { scheduleId: id, reason: (e&&e.message)||String(e) });
    try { if (chrome.notifications) chrome.notifications.create('', { type:'basic', iconUrl:'icons/icon48.png', title:'Aegis schedule failed', message: s.name || id }); } catch (_) {}
  }
}

async function cmdAuditList(params) { const limit = Math.max(1, Math.min(parseInt(params && params.limit) || 200, 1000)); const audit = await getStore(AUDIT_KEY, []); return { audit: audit.slice(-limit) }; }
async function cmdPolicyGet() { return { policy: await getPolicy() }; }
async function cmdPolicySet(params) { const p = { ...defaultPolicy(), ...(params && (params.policy || params) || {}) }; await setPolicy(p); return { policy: p }; }
async function cmdApprovalRespond(params) { return { ok: true, note: 'interactive approvals not available in unattended mode; update policy explicitly' }; }

// ─── Storage helpers ─────────────────────────────────────────────────────────
async function getStore(key, def) { return new Promise((resolve)=>chrome.storage.local.get(key,(r)=>resolve(r[key]!==undefined?r[key]:def))); }
async function setStore(key, val) { return new Promise((resolve)=>chrome.storage.local.set({[key]:val},resolve)); }
async function appendRun(run) { const runs = await getStore(RUNS_KEY, []); runs.push(run); await setStore(RUNS_KEY, runs.slice(-200)); }
async function appendAudit(entry) { const audit = await getStore(AUDIT_KEY, []); audit.push({ ts: Date.now(), ...(entry||{}) }); await setStore(AUDIT_KEY, audit.slice(-500)); }

function redactObject(obj) {
  try {
    const s = JSON.stringify(obj, (k,v)=>{
      if (typeof k === 'string' && /authorization|cookie|token|secret|password|session/i.test(k)) return '[REDACTED]';
      if (typeof v === 'string' && v.length > 2000) return v.slice(0,2000)+'…';
      return v;
    });
    return JSON.parse(s);
  } catch (_) { return '[unserializable]'; }
}

function unsupported(msg) { const e = new Error(msg); e.code = 'unsupported'; return e; }
