/* Aegis Browser Connector — Content Script
 *
 * Executes DOM operations within the page context.
 * Receives commands from background.js via chrome.runtime.sendMessage.
 */

'use strict';

(() => {
  // Versioned guard permits updated content code after an extension reload.
  if (window.__aegisContentScriptVersion === '1.1.2') return;
  window.__aegisContentScriptVersion = '1.1.2';
  window.__aegisContentScriptLoaded = true;

  // ─── Command registry ──────────────────────────────────────────────────────
  const handlers = {};

  function on(command, fn) {
    handlers[command] = fn;
  }

  const transfers = new Map();
  const MAX_STREAM_BYTES = 256 * 1024 * 1024;
  function dropTransfer(id) {
    const state = transfers.get(id);
    if (state?.timer) clearTimeout(state.timer);
    return transfers.delete(id);
  }
  function touchTransfer(id, state) {
    state.updated = Date.now();
    if (state.timer) clearTimeout(state.timer);
    state.timer = setTimeout(() => dropTransfer(id), 120000);
  }
  function transfer(id) {
    const state = transfers.get(id);
    if (!state || Date.now() - state.updated > 120000) { dropTransfer(id); throw new Error('upload transfer missing or expired'); }
    touchTransfer(id, state);
    return state;
  }
  on('upload.begin', params => {
    for (const [id,state] of transfers) if (Date.now()-state.updated > 120000) dropTransfer(id);
    if (transfers.size >= 4) throw new Error('too many active upload transfers');
    if (typeof params.filename !== 'string' || !params.filename || !Number.isSafeInteger(params.size) || params.size < 0 || params.size > MAX_STREAM_BYTES) throw new Error('filename and size between 0 and 256 MiB required');
    const el = resolveElement(params);
    if (!el || el.tagName !== 'INPUT' || el.type !== 'file' || el.disabled) throw new Error('enabled file input required');
    const id = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2,'0')).join('');
    transfers.set(id, { el, filename: params.filename, mimeType: params.mimeType || 'application/octet-stream', size: params.size, offset: 0, chunks: [], updated: Date.now() });
    touchTransfer(id, transfers.get(id));
    return { transferId: id, nextOffset: 0, maxChunkBytes: 262144 };
  });
  on('upload.chunk', params => {
    const state = transfer(params.transferId);
    if (params.offset !== state.offset) throw new Error('upload offset mismatch; inspect upload.status before retrying');
    if (typeof params.content !== 'string' || params.content.length > 349528) throw new Error('base64 chunk exceeds 256 KiB');
    const raw = atob(params.content);
    if (raw.length > 262144 || state.offset + raw.length > state.size) throw new Error('chunk exceeds declared transfer size');
    state.chunks.push(Uint8Array.from(raw, char => char.charCodeAt(0)));
    state.offset += raw.length;
    return { nextOffset: state.offset };
  });
  on('upload.status', params => { const state = transfer(params.transferId); return { nextOffset: state.offset, size: state.size }; });
  on('upload.cancel', params => ({ canceled: dropTransfer(params.transferId) }));
  on('upload.finish', async params => {
    const state = transfer(params.transferId);
    try {
      if (state.offset !== state.size) throw new Error('upload is incomplete');
      if (!state.el.isConnected) throw new Error('file input was replaced during transfer');
      const file = new File(state.chunks, state.filename, { type: state.mimeType });
      let sha256;
      if (params.sha256) {
        if (!/^[a-f0-9]{64}$/i.test(params.sha256) || !crypto.subtle) throw new Error('valid SHA-256 and secure-origin WebCrypto are required');
        sha256 = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', await file.arrayBuffer())), b => b.toString(16).padStart(2,'0')).join('');
        if (sha256 !== params.sha256.toLowerCase()) throw new Error('upload SHA-256 mismatch');
      }
      const data = new DataTransfer(); data.items.add(file); state.el.files = data.files;
      state.el.dispatchEvent(new Event('input', { bubbles: true }));
      state.el.dispatchEvent(new Event('change', { bubbles: true }));
      return { selected: true, serverConfirmed: false, filename: file.name, size: file.size, sha256 };
    } finally { dropTransfer(params.transferId); }
  });

  // ─── Navigation ────────────────────────────────────────────────────────────
  on('navigate', (params) => {
    window.location.href = params.url;
    return { navigating: params.url };
  });

  on('goBack', () => { window.history.back(); return { back: true }; });
  on('goForward', () => { window.history.forward(); return { forward: true }; });
  on('reload', (params) => { window.location.reload(); return { reloaded: true }; });
  on('getCurrentUrl', () => ({ url: window.location.href }));
  on('getTitle', () => ({ title: document.title }));

  // ─── Element queries ───────────────────────────────────────────────────────
  on('querySelector', (params) => {
    const el = query(params.selector);
    if (!el) return { found: false };
    return { found: true, ...serializeElement(el) };
  });

  on('querySelectorAll', (params) => {
    const els = query(params.selector, true);
    return { count: els.length, elements: Array.from(els).map(serializeElement) };
  });

  on('getElementText', (params) => {
    const el = resolveElement(params);
    return { text: el ? el.innerText || el.textContent || '' : '' };
  });

  on('getElementAttribute', (params) => {
    const el = resolveElement(params);
    if (!el) return { value: null };
    return { value: params.attribute ? el.getAttribute(params.attribute) : null };
  });

  on('getElementHtml', (params) => {
    const el = resolveElement(params);
    return { html: el ? el.innerHTML : '' };
  });

  on('getElementBoundingBox', (params) => {
    const el = resolveElement(params);
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    return { x: rect.x, y: rect.y, width: rect.width, height: rect.height, top: rect.top, left: rect.left };
  });

  // ─── Interaction ───────────────────────────────────────────────────────────
  on('click', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found: ' + (params.selector || params.xpath));
    el.scrollIntoView({ block: 'center', behavior: 'instant' });
    el.click();
    return { clicked: true };
  });

  on('doubleClick', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    el.scrollIntoView({ block: 'center', behavior: 'instant' });
    el.dispatchEvent(new MouseEvent('dblclick', { bubbles: true, cancelable: true }));
    return { doubleClicked: true };
  });

  on('rightClick', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    el.scrollIntoView({ block: 'center', behavior: 'instant' });
    el.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true }));
    return { rightClicked: true };
  });

  on('hover', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    el.scrollIntoView({ block: 'center', behavior: 'instant' });
    el.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    el.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
    return { hovered: true };
  });

  on('focus', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    el.focus();
    return { focused: true };
  });

  on('blur', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    el.blur();
    return { blurred: true };
  });

  on('type', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    el.scrollIntoView({ block: 'center', behavior: 'instant' });
    el.focus();
    const value = params.value || '';
    for (const char of value) {
      el.dispatchEvent(new KeyboardEvent('keydown', { key: char, bubbles: true }));
      if (el.isContentEditable) el.textContent += char;
      else el.value = (el.value || '') + char;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new KeyboardEvent('keyup', { key: char, bubbles: true }));
    }
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return { typed: value.length };
  });

  on('fill', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    el.scrollIntoView({ block: 'center', behavior: 'instant' });
    el.focus();
    const proto = el.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
    const nativeSet = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
    if (el.isContentEditable) {
      el.textContent = params.value || '';
    } else if (nativeSet) {
      nativeSet.call(el, params.value || '');
    } else {
      el.value = params.value || '';
    }
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return { filled: true };
  });

  on('clear', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    el.value = '';
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return { cleared: true };
  });

  on('press', (params) => {
    const el = resolveElement(params) || document.activeElement;
    if (!el) throw new Error('no active element');
    const key = params.key || params.value || '';
    const opts = { key, code: `Key${key.toUpperCase()}`, bubbles: true, cancelable: true };
    if (params.modifiers) {
      opts.ctrlKey = params.modifiers.includes('ctrl');
      opts.shiftKey = params.modifiers.includes('shift');
      opts.altKey = params.modifiers.includes('alt');
      opts.metaKey = params.modifiers.includes('meta');
    }
    el.dispatchEvent(new KeyboardEvent('keydown', opts));
    el.dispatchEvent(new KeyboardEvent('keypress', opts));
    el.dispatchEvent(new KeyboardEvent('keyup', opts));
    return { pressed: key };
  });

  on('select', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    if (el.tagName === 'SELECT') {
      el.value = params.value;
      el.dispatchEvent(new Event('change', { bubbles: true }));
      return { selected: params.value };
    }
    throw new Error('element is not a select');
  });

  on('check', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    if (el.type === 'checkbox' || el.type === 'radio') {
      el.checked = true;
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
    return { checked: true };
  });

  on('uncheck', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    if (el.type === 'checkbox' || el.type === 'radio') {
      el.checked = false;
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
    return { unchecked: true };
  });

  on('scroll', (params) => {
    const el = resolveElement(params) || document.documentElement;
    const x = parseInt(params.x) || 0;
    const y = parseInt(params.y) || 0;
    el.scrollBy(x, y);
    return { scrolled: true, x, y };
  });

  on('scrollIntoView', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    el.scrollIntoView({ block: 'center', behavior: 'instant' });
    return { scrolledIntoView: true };
  });

  // ─── Wait ──────────────────────────────────────────────────────────────────
  on('waitForSelector', (params) => {
    return new Promise((resolve, reject) => {
      const timeout = parseInt(params.timeout) || 30000;
      const selector = params.selector;
      const el = document.querySelector(selector);
      if (el) return resolve({ found: true, ...serializeElement(el) });

      const observer = new MutationObserver(() => {
        const el = document.querySelector(selector);
        if (el) {
          observer.disconnect();
          clearTimeout(timer);
          resolve({ found: true, ...serializeElement(el) });
        }
      });
      observer.observe(document.body, { childList: true, subtree: true });

      const timer = setTimeout(() => {
        observer.disconnect();
        reject(new Error(`waitForSelector timed out: ${selector}`));
      }, timeout);
    });
  });

  on('waitForLoad', () => {
    return new Promise((resolve) => {
      if (document.readyState === 'complete' || document.readyState === 'interactive') {
        return resolve({ ready: true });
      }
      window.addEventListener('load', () => resolve({ ready: true }), { once: true });
    });
  });

  on('waitForIdle', (params) => {
    const delay = parseInt(params.delay) || 500;
    return new Promise((resolve) => {
      let timer;
      const observer = new MutationObserver(() => {
        clearTimeout(timer);
        timer = setTimeout(() => {
          observer.disconnect();
          resolve({ idle: true });
        }, delay);
      });
      observer.observe(document.body, { childList: true, subtree: true, attributes: true });
      // Start the idle timer
      timer = setTimeout(() => {
        observer.disconnect();
        resolve({ idle: true });
      }, delay);
    });
  });

  on('waitForTimeout', (params) => {
    const ms = parseInt(params.duration) || parseInt(params.timeout) || 1000;
    return new Promise((resolve) => setTimeout(() => resolve({ waited: ms }), ms));
  });

  // ─── JavaScript execution ──────────────────────────────────────────────────
  on('evaluate', (params) => {
    const script = params.script || params.expression || '';
    const fn = new Function(script);
    const result = fn();
    return { result: result !== undefined ? String(result) : null };
  });

  on('evaluateAll', (params) => {
    const script = params.script || params.expression || '';
    const results = [];
    document.querySelectorAll(params.selector || '*').forEach((el, i) => {
      try {
        const fn = new Function('el', 'index', script);
        results.push({ index: i, result: String(fn(el, i)) });
      } catch (e) {
        results.push({ index: i, error: e.message });
      }
    });
    return { results };
  });

  // ─── Screenshot (element only; full page uses background captureVisibleTab) ─
  on('screenshotElement', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('element not found');
    const rect = el.getBoundingClientRect();
    return {
      x: rect.x, y: rect.y,
      width: rect.width, height: rect.height,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight
    };
  });

  // ─── Storage ───────────────────────────────────────────────────────────────
  on('getLocalStorage', (params) => {
    const data = {};
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (params.prefix && !key.startsWith(params.prefix)) continue;
      data[key] = localStorage.getItem(key);
    }
    return { data };
  });

  on('setLocalStorage', (params) => {
    for (const [k, v] of Object.entries(params.data || {})) {
      localStorage.setItem(k, v);
    }
    return { set: true };
  });

  on('getSessionStorage', (params) => {
    const data = {};
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (params.prefix && !key.startsWith(params.prefix)) continue;
      data[key] = sessionStorage.getItem(key);
    }
    return { data };
  });

  on('setSessionStorage', (params) => {
    for (const [k, v] of Object.entries(params.data || {})) {
      sessionStorage.setItem(k, v);
    }
    return { set: true };
  });

  // ─── Frames ────────────────────────────────────────────────────────────────
  on('switchFrame', (params) => {
    const selector = params.selector;
    const frames = document.querySelectorAll('iframe');
    for (const frame of frames) {
      if (frame.matches(selector) || frame.name === selector || frame.id === selector) {
        return { frameFound: true, src: frame.src, name: frame.name };
      }
    }
    return { frameFound: false };
  });

  on('switchMain', () => ({ main: true }));
  on('listFrames', () => {
    const frames = document.querySelectorAll('iframe');
    return {
      frames: Array.from(frames).map((f, i) => ({
        index: i,
        src: f.src || '',
        name: f.name || '',
        id: f.id || ''
      }))
    };
  });

  // ─── Extract ───────────────────────────────────────────────────────────────
  on('extractData', (params) => {
    const rules = params.rules || [];
    const results = {};
    for (const rule of rules) {
      const { name, selector, attribute, regex } = rule;
      if (selector) {
        const el = document.querySelector(selector);
        if (el) {
          let value = attribute ? el.getAttribute(attribute) : (el.innerText || el.textContent || '');
          if (regex) {
            const match = value.match(new RegExp(regex));
            results[name] = match ? match[1] || match[0] : null;
          } else {
            results[name] = value;
          }
        } else {
          results[name] = null;
        }
      }
    }
    return results;
  });

  // ─── Page snapshot / debug helpers (bounded, redacted by default) ─────────
  on('page.snapshot', (params) => {
    const max = Math.min(parseInt(params && params.maxChars) || 20000, 100000);
    const includeSensitive = !!(params && params.includeSensitive);
    const redact = (s) => includeSensitive ? s : String(s||'').replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/ig,'[REDACTED_EMAIL]').replace(/\b\d{12,19}\b/g,'[REDACTED_NUMBER]');
    const html = redact((document.documentElement && document.documentElement.outerHTML) || '').slice(0, max);
    const title = document.title || '';
    const url = location.href;
    const meta = Array.from(document.querySelectorAll('meta[name],meta[property]')).slice(0,50).map(m=>({name:m.getAttribute('name')||m.getAttribute('property'), content: redact(m.getAttribute('content')||'')}));
    const headings = Array.from(document.querySelectorAll('h1,h2,h3')).slice(0,50).map(h=>redact((h.innerText||'').trim()).slice(0,200));
    const forms = Array.from(document.querySelectorAll('form')).slice(0,20).map(f=>({action:f.action, method:f.method, inputs: Array.from(f.querySelectorAll('input,textarea,select')).slice(0,30).map(i=>({name:i.name,type:i.type,tag:i.tagName.toLowerCase()}))}));
    return { url, title, meta, headings, forms, html, truncated: ((document.documentElement&&document.documentElement.outerHTML)||'').length > max };
  });

  // ─── Upload helper (best-effort) ──────────────────────────────────────────
  on('upload.file', (params) => {
    const el = resolveElement(params);
    if (!el) throw new Error('file input not found');
    if (el.tagName !== 'INPUT' || el.type !== 'file') throw new Error('target is not a file input');
    // Extension content scripts cannot set File objects from arbitrary local paths for security; support pre-provided data URLs/base64 text payloads as best-effort.
    if (params && params.content && params.filename) {
      try {
        const data = params.content;
        const byteString = data.startsWith('data:') ? atob(data.split(',')[1]||'') : atob(data);
        const ab = new ArrayBuffer(byteString.length);
        const ia = new Uint8Array(ab);
        for (let i=0;i<byteString.length;i++) ia[i]=byteString.charCodeAt(i);
        const blob = new Blob([ab], { type: params.mimeType || 'application/octet-stream' });
        const file = new File([blob], params.filename, { type: params.mimeType || 'application/octet-stream' });
        const dt = new DataTransfer();
        dt.items.add(file);
        el.files = dt.files;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        return { selected: true, serverConfirmed: false, filename: params.filename, size: file.size };
      } catch (e) {
        throw new Error('upload failed: ' + (e && e.message ? e.message : String(e)));
      }
    }
    throw new Error('upload.file requires selector and content+filename (base64/dataURL); local path injection not supported by browser security model');
  });

  on('waitForNavigation', (params) => {
    const timeout = Math.min(parseInt(params && params.timeout) || 30000, 120000);
    return new Promise((resolve, reject) => {
      const start = location.href;
      const t = setTimeout(()=>{ window.removeEventListener('beforeunload', onNav); resolve({ navigated: location.href !== start, url: location.href, timeout: true }); }, timeout);
      function onNav(){ clearTimeout(t); setTimeout(()=>resolve({ navigated: true, url: location.href }), 250); }
      window.addEventListener('beforeunload', onNav, { once: true });
    });
  });

  on('getPageDimensions', () => ({
    scrollHeight: document.body.scrollHeight,
    scrollWidth: document.body.scrollWidth,
    clientHeight: document.documentElement.clientHeight,
    clientWidth: document.documentElement.clientWidth
  }));

  on('scrollTo', (params) => {
    window.scrollTo(params.x || 0, params.y || 0);
    return { scrolled: true };
  });


  // ─── Helpers ───────────────────────────────────────────────────────────────
  function query(selector, all = false) {
    if (typeof selector !== 'string' || !selector.trim()) throw new Error('CSS selector required');
    const parts = selector.split('>>>').map(part => part.trim());
    let root = document;
    for (let i=0; i<parts.length-1; i++) {
      const host = root.querySelector(parts[i]);
      if (!host?.shadowRoot) return all ? [] : null;
      root = host.shadowRoot;
    }
    return all ? root.querySelectorAll(parts[parts.length-1]) : root.querySelector(parts[parts.length-1]);
  }
  function resolveElement(params) {
    if (params.strict === true && !params.selector) throw new Error('strict targeting requires a CSS selector');
    if (params.selector) {
      if (params.strict === true) {
        const matches = query(params.selector, true);
        if (matches.length !== 1) throw new Error('strict selector must match exactly one element; matched ' + matches.length);
        if (matches[0].disabled || matches[0].getAttribute('aria-disabled') === 'true' || matches[0].closest('fieldset[disabled]')) throw new Error('strict target is disabled');
        const style = window.getComputedStyle(matches[0]);
        if (!matches[0].getClientRects().length || style.visibility === 'hidden' || style.visibility === 'collapse') throw new Error('strict target is not visible');
        return matches[0];
      }
      return query(params.selector);
    }
    if (params.xpath) {
      const result = document.evaluate(params.xpath, document, null,
        XPathResult.FIRST_ORDERED_NODE_TYPE, null);
      return result.singleNodeValue;
    }
    if (params.index !== undefined) {
      const els = document.querySelectorAll(params.selector || '*');
      return els[params.index] || null;
    }
    return null;
  }

  function serializeElement(el) {
    const rect = el.getBoundingClientRect();
    const ariaLabel = el.getAttribute('aria-label');
    const labelledBy = el.getAttribute('aria-labelledby');
    const root = el.getRootNode?.() || document;
    const labelledText = (labelledBy || '').split(/\s+/).map(id => root.getElementById?.(id)?.textContent || '').join(' ').trim();
    const labelText = el.labels?.length ? Array.from(el.labels, label => label.textContent || '').join(' ').trim() : '';
    const sensitive = el.type === 'password' || /password|secret|token|one.time.code|credit.card|cvc/i.test([el.name,el.id,el.autocomplete].join(' '));
    return {
      tagName: el.tagName?.toLowerCase(),
      id: el.id || null,
      className: el.className || null,
      text: (el.innerText || el.textContent || '').substring(0, 500),
      ariaLabel: ariaLabel || null,
      accessibleName: (labelledText || ariaLabel || labelText || el.innerText || el.textContent || el.getAttribute('title') || el.getAttribute('placeholder') || '').replace(/\s+/g,' ').trim().substring(0,500),
      role: el.getAttribute('role') || (el.tagName === 'BUTTON' ? 'button' : el.tagName === 'A' && el.hasAttribute('href') ? 'link' : null),
      disabled: !!(el.disabled || el.getAttribute('aria-disabled') === 'true' || el.closest('fieldset[disabled]')),
      checked: 'checked' in el ? !!el.checked : el.getAttribute('aria-checked'),
      value: sensitive ? null : el.value || null,
      valueRedacted: sensitive,
      type: el.type || null,
      href: el.href || null,
      src: el.src || null,
      selector: cssSelector(el),
      boundingBox: {
        x: rect.x, y: rect.y,
        width: rect.width, height: rect.height
      }
    };
  }

  function cssSelector(el) {
    const root = el.getRootNode?.();
    const local = localCssSelector(el);
    return root?.host ? cssSelector(root.host) + ' >>> ' + local : local;
  }

  function localCssSelector(el) {
    const root = el.getRootNode?.() || document;
    const ariaLabel = el.getAttribute('aria-label');
    if (ariaLabel) {
      const candidate = el.tagName.toLowerCase() + '[aria-label="' + CSS.escape(ariaLabel) + '"]';
      if (root.querySelectorAll(candidate).length === 1) return candidate;
    }
    if (el.id) return `#${CSS.escape(el.id)}`;
    const parts = [];
    while (el && el.nodeType === Node.ELEMENT_NODE) {
      let selector = el.nodeName.toLowerCase();
      if (el.id) {
        selector = `#${CSS.escape(el.id)}`;
        parts.unshift(selector);
        break;
      }
      if (el.className && typeof el.className === 'string') {
        const cls = el.className.trim().split(/\s+/).map(c => `.${CSS.escape(c)}`).join('');
        selector += cls;
      }
      const parent = el.parentElement;
      if (parent) {
        const siblings = Array.from(parent.children).filter(c => c.nodeName === el.nodeName);
        if (siblings.length > 1) {
          const idx = siblings.indexOf(el) + 1;
          selector += `:nth-of-type(${idx})`;
        }
      }
      parts.unshift(selector);
      el = el.parentElement;
    }
    return parts.join(' > ');
  }

  // ─── Message listener from background ──────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg.command) return false;

    const handler = handlers[msg.command];
    if (!handler) {
      sendResponse({ id: msg.id, error: `unknown command: ${msg.command}` });
      return false;
    }

    // Handle async handlers (return Promises)
    Promise.resolve(handler(msg.params || {}))
      .then((data) => {
        sendResponse({ id: msg.id, data });
      })
      .catch((err) => {
        sendResponse({ id: msg.id, error: err.message || String(err) });
      });

    return true; // keep channel open for async response
  });

  // ─── Recorder: capture user actions for workflow recording ──────────────────
  let recorderActive = false;
  let recorderTabId = null;
  let recorderSensitive = false;

  function recorderEvent(type, data) {
    if (!recorderActive) return;
    chrome.runtime.sendMessage({ type: 'recorderEvent', event: type, data });
  }

  // Click/interaction capture
  document.addEventListener('click', (e) => recorderEvent('click', { selector: cssSelector(e.target) }), true);
  document.addEventListener('dblclick', (e) => recorderEvent('doubleClick', { selector: cssSelector(e.target) }), true);
  document.addEventListener('contextmenu', (e) => recorderEvent('rightClick', { selector: cssSelector(e.target) }), true);

  // Input capture
  document.addEventListener('input', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') {
      const isSensitive = e.target.type === 'password' || /pass|secret|token|credit|card|cvv/i.test(e.target.name || '');
      recorderEvent('fill', { selector: cssSelector(e.target), value: isSensitive && !recorderSensitive ? '[REDACTED]' : e.target.value, sensitive: isSensitive });
    }
  }, true);

  // Navigation capture
  window.addEventListener('beforeunload', () => recorderEvent('navigate', { url: location.href }), true);
  window.addEventListener('load', () => recorderEvent('load', { url: location.href }), true);

  // Scroll capture (debounced)
  let scrollTimer = null;
  document.addEventListener('scroll', (e) => {
    if (scrollTimer) clearTimeout(scrollTimer);
    scrollTimer = setTimeout(() => recorderEvent('scroll', { x: window.scrollX, y: window.scrollY }), 300);
  }, true);

  // Select change
  document.addEventListener('change', (e) => {
    if (e.target.tagName === 'SELECT') {
      recorderEvent('select', { selector: cssSelector(e.target), value: e.target.value });
    }
  }, true);

  // Checkbox/radio
  document.addEventListener('change', (e) => {
    if (e.target.type === 'checkbox' || e.target.type === 'radio') {
      recorderEvent(e.target.checked ? 'check' : 'uncheck', { selector: cssSelector(e.target) });
    }
  }, true);

  // Recorder control commands
  on('recorder.start', (params) => {
    recorderActive = true;
    recorderTabId = params && params.tabId;
    recorderSensitive = !!(params && params.includeSensitive);
    return { started: true };
  });

  on('recorder.stop', () => {
    recorderActive = false;
    return { stopped: true };
  });

  on('recorder.pause', () => {
    recorderActive = !recorderActive;
    return { paused: !recorderActive };
  });

  on('recorder.status', () => ({ active: recorderActive, tabId: recorderTabId }));

  // ─── Report dialog to background ───────────────────────────────────────────
  const origAlert = window.alert;
  const origConfirm = window.confirm;
  const origPrompt = window.prompt;

  window.alert = function(message) {
    chrome.runtime.sendMessage({ type: 'dialog', dialogType: 'alert', message });
    origAlert.call(window, message);
  };
  window.confirm = function(message) {
    chrome.runtime.sendMessage({ type: 'dialog', dialogType: 'confirm', message });
    return origConfirm.call(window, message);
  };
  window.prompt = function(message, defaultVal) {
    chrome.runtime.sendMessage({ type: 'dialog', dialogType: 'prompt', message, promptValue: defaultVal });
    return origPrompt.call(window, message, defaultVal);
  };

  console.log('[Aegis] content script loaded on', window.location.href);
})();
