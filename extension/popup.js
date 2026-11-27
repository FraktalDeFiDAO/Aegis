/* Aegis Browser Connector — Popup Script */

'use strict';

const STORAGE_KEY = 'aegisBridgeConfig';

// ─── Init ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  const cfg = await getConfig();
  document.getElementById('host-input').value = cfg.host || '127.0.0.1';
  document.getElementById('port-input').value = cfg.wsPort || '';
  document.getElementById('token-input').value = cfg.token || '';

  // Bind button handlers (no inline onclick — MV3 CSP)
  document.getElementById('btn-connect').addEventListener('click', connect);
  document.getElementById('btn-disconnect').addEventListener('click', disconnect);
  const saveBtn = document.getElementById('btn-save-policy');
  if (saveBtn) saveBtn.addEventListener('click', savePolicy);
  document.getElementById('btn-clear-data')?.addEventListener('click', clearStoredData);
  document.getElementById('btn-recorder-start')?.addEventListener('click', recorderStart);
  document.getElementById('btn-recorder-pause')?.addEventListener('click', recorderPause);
  document.getElementById('btn-recorder-stop')?.addEventListener('click', recorderStop);

  // Listen for connection state from background
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'connected') { updateUI(true); refreshPolicy(); }
    if (msg.type === 'disconnected') updateUI(false);
    if (msg.type === 'approvalRequested' || msg.type === 'approvalResolved') refreshApprovals();
  });

  // Check current state — background auto-connects on startup
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'getStatus' });
    if (resp && resp.nativeError && !resp.connected) {
      const status = document.getElementById('native-status');
      status.hidden = false;
      status.textContent = `Automatic bridge startup: ${resp.nativeError} Install the Aegis native host or start the bridge manually.`;
    }
    if (resp && resp.connected) {
      updateUI(true);
      if (resp.targetSet) updateTargetInfo(resp.targetSet);
    } else {
      updateUI(null);
    }
    await refreshPolicy();
    await refreshApprovals();
  } catch (e) {
    updateUI(null);
  }
});

// ─── Config ──────────────────────────────────────────────────────────────────
function getConfig() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEY, (result) => {
      resolve(result[STORAGE_KEY] || { host: '127.0.0.1', wsPort: 0 });
    });
  });
}

function setConfig(cfg) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEY]: cfg }, resolve);
  });
}

// ─── Actions ─────────────────────────────────────────────────────────────────
async function connect() {
  const host = document.getElementById('host-input').value.trim() || '127.0.0.1';
  const port = parseInt(document.getElementById('port-input').value) || 0;
  const token = document.getElementById('token-input').value.trim();

  await setConfig({ host, wsPort: port, token });

  // Tell background to reconnect
  chrome.runtime.sendMessage({ type: 'reconnect', host, wsPort: port, token });

  updateUI(null); // show connecting state
}

async function disconnect() {
  chrome.runtime.sendMessage({ type: 'disconnect' });
  updateUI(false);
}

// ─── UI ──────────────────────────────────────────────────────────────────────
function updateUI(connected) {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  const url = document.getElementById('bridge-url');
  const btnConnect = document.getElementById('btn-connect');
  const btnDisconnect = document.getElementById('btn-disconnect');
  const hostInput = document.getElementById('host-input');
  const portInput = document.getElementById('port-input');
  const tokenInput = document.getElementById('token-input');

  if (connected === null) {
    dot.className = 'dot connecting';
    text.textContent = 'Connecting...';
    url.textContent = `${hostInput.value}:${portInput.value || '?'}`;
    btnConnect.disabled = true;
    btnDisconnect.style.display = 'none';
  } else if (connected) {
    dot.className = 'dot connected';
    text.textContent = 'Connected';
    url.textContent = `${hostInput.value}:${portInput.value || 'auto'}`;
    btnConnect.style.display = 'none';
    btnDisconnect.style.display = 'block';
    btnDisconnect.disabled = false;
    hostInput.disabled = true;
    portInput.disabled = true;
    tokenInput.disabled = true;
  } else {
    dot.className = 'dot disconnected';
    text.textContent = 'Disconnected';
    url.textContent = '--';
    btnConnect.style.display = 'block';
    btnConnect.disabled = false;
    btnDisconnect.style.display = 'none';
    hostInput.disabled = false;
    portInput.disabled = false;
    tokenInput.disabled = false;
  }
}

async function refreshPolicy() {
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'getPolicy' });
    const p = (resp && resp.policy) || {};
    const mode = p.mode || 'manual-approve';
    const el = document.getElementById('policy-mode');
    if (el) el.textContent = mode;
    const sel = document.getElementById('policy-select');
    if (sel) sel.value = mode;
    const scopes = document.getElementById('trusted-scopes');
    if (scopes && document.activeElement !== scopes) scopes.value = Array.isArray(p.trustedScopes) ? p.trustedScopes.join(', ') : '';
  } catch (_) {}
}

function updateTargetInfo(ts) {
  const el = document.getElementById('target-info');
  if (!el) return;
  const tabs = Array.isArray(ts && ts.tabs) ? ts.tabs.length : 0;
  const active = ts && ts.activeTabId ? ts.activeTabId : 'none';
  el.textContent = `${tabs} tabs · active ${active}`;
}

async function savePolicy() {
  const sel = document.getElementById('policy-select');
  const msg = document.getElementById('policy-msg');
  const mode = sel ? sel.value : 'manual-approve';
  try {
    const current = await chrome.runtime.sendMessage({ type: 'getPolicy' });
    const trustedScopes = (document.getElementById('trusted-scopes')?.value || '').split(/[\n,]/).map(value => value.trim()).filter(Boolean);
    const policy = Object.assign({}, (current && current.policy) || {}, { mode, trustedScopes });
    await chrome.runtime.sendMessage({ type: 'setPolicy', policy });
    if (msg) { msg.textContent = 'Saved'; msg.style.color = '#00d4aa'; }
    await refreshPolicy();
  } catch (e) {
    if (msg) { msg.textContent = 'Save failed'; msg.style.color = '#e74c3c'; }
  }
}

async function refreshApprovals() {
  const card = document.getElementById('approval-card');
  const list = document.getElementById('approval-list');
  if (!card || !list) return;
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'getApprovals' });
    const approvals = (resp && resp.approvals) || [];
    card.style.display = approvals.length ? 'block' : 'none';
    list.replaceChildren();
    for (const approval of approvals) {
      const row = document.createElement('div');
      row.style.cssText = 'margin:8px 0;padding:8px;border:1px solid #0f3460;border-radius:6px';
      row.dataset.approvalId = approval.id;
      const text = document.createElement('div');
      text.style.cssText = 'font-size:11px;margin-bottom:6px';
      text.textContent = `${approval.command} · tab ${approval.tabId || 'unknown'} · ${approval.reason}`;
      const approve = document.createElement('button');
      approve.className = 'btn btn-connect';
      approve.style.cssText = 'padding:6px;font-size:11px;margin-right:6px';
      approve.textContent = 'Approve once';
      approve.addEventListener('click', () => resolveApproval(approval.id, true));
      const deny = document.createElement('button');
      deny.className = 'btn btn-disconnect';
      deny.style.cssText = 'padding:6px;font-size:11px';
      deny.textContent = 'Deny';
      deny.addEventListener('click', () => resolveApproval(approval.id, false));
      row.append(text, approve, deny);
      list.append(row);
    }
  } catch (_) {}
}

async function resolveApproval(id, approved) {
  await chrome.runtime.sendMessage({ type: 'resolveApproval', id, approved });
  await refreshApprovals();
}

async function clearStoredData() {
  if (!window.confirm('Delete stored workflows, recordings, schedules, run history, audit history, and target state?')) return;
  await chrome.runtime.sendMessage({ type: 'clearLocalData' });
  await refreshPolicy();
}

// ─── Recorder UI ─────────────────────────────────────────────────────────────
async function refreshRecorder() {
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'recorderStatus' });
    const active = resp && resp.active;
    const card = document.getElementById('recorder-card');
    if (card) card.style.display = active ? 'block' : 'block'; // always show
    const dot = document.getElementById('recorder-dot');
    const txt = document.getElementById('recorder-text');
    const steps = document.getElementById('recorder-steps');
    const btnStart = document.getElementById('btn-recorder-start');
    const btnPause = document.getElementById('btn-recorder-pause');
    const btnStop = document.getElementById('btn-recorder-stop');
    if (active) {
      dot.className = 'dot connected';
      txt.textContent = 'Recording' + (resp.paused ? ' (Paused)' : '');
      btnStart.style.display = 'none';
      btnPause.style.display = 'block';
      btnPause.textContent = resp.paused ? 'Resume' : 'Pause';
      btnStop.style.display = 'block';
    } else {
      dot.className = 'dot disconnected';
      txt.textContent = 'Inactive';
      btnStart.style.display = 'block';
      btnPause.style.display = 'none';
      btnStop.style.display = 'none';
    }
    if (steps) steps.textContent = resp && resp.steps ? resp.steps : '0';
  } catch (e) {
    console.warn('recorder status failed', e);
  }
}

async function recorderStart() {
  const name = document.getElementById('recorder-name').value || 'workflow-' + Date.now();
  const sensitive = document.getElementById('recorder-sensitive').checked;
  const msg = document.getElementById('recorder-msg');
  try {
    await chrome.runtime.sendMessage({ type: 'recordStart', name, includeSensitive: sensitive });
    if (msg) { msg.textContent = 'Recording started'; msg.style.color = '#00d4aa'; }
    await refreshRecorder();
  } catch (e) {
    if (msg) { msg.textContent = 'Start failed: ' + e.message; msg.style.color = '#e74c3c'; }
  }
}

async function recorderPause() {
  const msg = document.getElementById('recorder-msg');
  try {
    await chrome.runtime.sendMessage({ type: 'recordPause' });
    if (msg) { msg.textContent = 'Toggled pause'; msg.style.color = '#00d4aa'; }
    await refreshRecorder();
  } catch (e) {
    if (msg) { msg.textContent = 'Pause failed: ' + e.message; msg.style.color = '#e74c3c'; }
  }
}

async function recorderStop() {
  const msg = document.getElementById('recorder-msg');
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'recordStop' });
    if (msg) { msg.textContent = 'Saved: ' + (resp.recording && resp.recording.id) + ' (' + (resp.recording && resp.recording.steps) + ' steps)'; msg.style.color = '#00d4aa'; }
    await refreshRecorder();
  } catch (e) {
    if (msg) { msg.textContent = 'Stop failed: ' + e.message; msg.style.color = '#e74c3c'; }
  }
}

// Initialize recorder status on load
setTimeout(() => refreshRecorder(), 200);
