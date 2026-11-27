/* Browser-backed file transfers, explicit frames, and trusted input.
 * Loaded by the MV3 worker and the Firefox background page. */
'use strict';

globalThis.AegisBrowserControl = {
  create(api, options = {}) {
    const frames = new Map(), locks = new Map(), dialogs = new Map(), dialogWaiters = new Map(), owned = new Set(), drags = new Map();
    const invalid = message => Object.assign(new Error(message), { code: 'invalid_request' });
    const unsupported = message => Object.assign(new Error(message), { code: 'unsupported' });
    const frameId = (tabId, params = {}) => {
      const id = params.frameId ?? frames.get(tabId) ?? 0;
      if (!Number.isInteger(id) || id < 0) throw invalid('frameId must be a nonnegative integer');
      return id;
    };
    async function listFrames(tabId) {
      if (!api.webNavigation?.getAllFrames) throw unsupported('webNavigation permission/API is required for frame discovery');
      return { frames: await api.webNavigation.getAllFrames({ tabId }), selectedFrameId: frameId(tabId) };
    }
    async function selectFrame(tabId, params) {
      const id = frameId(tabId, params);
      const result = await listFrames(tabId);
      if (!result.frames.some(frame => frame.frameId === id)) throw invalid('frameId does not exist in the target tab');
      frames.set(tabId, id);
      return { tabId, frameId: id, selected: true };
    }
    function reset(tabId) { frames.delete(tabId); dialogs.delete(tabId); }
    const send = (tabId, method, params = {}) => api.debugger.sendCommand({ tabId }, method, params);
    if (api.debugger?.onDetach) api.debugger.onDetach.addListener(source => {
      owned.delete(source.tabId); dialogs.delete(source.tabId); drags.delete(source.tabId);
    });
    if (api.debugger?.onEvent) api.debugger.onEvent.addListener((source, method, params) => {
      if (method === 'Input.dragIntercepted') drags.set(source.tabId, params.data);
      if (method === 'Page.javascriptDialogOpening') {
        const dialog = { type: params.type, message: params.message, url: params.url, defaultPrompt: params.defaultPrompt };
        dialogs.set(source.tabId, dialog);
        dialogWaiters.get(source.tabId)?.({ dialogPending: true, dialog });
      }
      if (method === 'Page.javascriptDialogClosed') dialogs.delete(source.tabId);
    });
    async function debug(tabId, operation) {
      if (!api.debugger) throw unsupported('This command requires Chromium debugger support');
      const previous = locks.get(tabId) || Promise.resolve();
      const work = previous.catch(() => {}).then(async () => {
        if (!owned.has(tabId) && !options.isDebugAttached?.(tabId)) {
          await api.debugger.attach({ tabId }, '1.3');
          owned.add(tabId);
        }
        try {
          await send(tabId, 'Page.enable');
          const pendingDialog = new Promise(resolve => dialogWaiters.set(tabId, resolve));
          return await Promise.race([operation(), pendingDialog]);
        } finally {
          dialogWaiters.delete(tabId);
          // Keep the session alive until an explicitly handled native JS dialog closes.
          if (owned.has(tabId) && !dialogs.has(tabId)) {
            owned.delete(tabId);
            await api.debugger.detach({ tabId }).catch(() => {});
          }
        }
      });
      locks.set(tabId, work);
      try { return await work; } finally { if (locks.get(tabId) === work) locks.delete(tabId); }
    }
    async function context(tabId, params) {
      const result = await send(tabId, 'Page.getFrameTree');
      const flat = [];
      function walk(node) { flat.push(node.frame); (node.childFrames || []).forEach(walk); }
      walk(result.frameTree);
      let target = result.frameTree.frame;
      const id = frameId(tabId, params);
      if (id !== 0) {
        if (!api.webNavigation?.getFrame) throw unsupported('Frame lookup is unavailable');
        const selected = await api.webNavigation.getFrame({ tabId, frameId: id });
        if (!selected) throw invalid('Target frame was removed or navigated');
        const matches = flat.filter(frame => frame.url === selected.url);
        if (matches.length !== 1) throw unsupported('Debugger frame is ambiguous/unavailable; use upload streaming or an explicit frame-aware DOM command');
        target = matches[0];
      }
      try {
        const world = await send(tabId, 'Page.createIsolatedWorld', { frameId: target.id, worldName: 'aegis-control' });
        return world.executionContextId;
      } catch (error) { throw unsupported('Debugger cannot access this frame; use frame-targeted content commands or upload streaming: ' + error.message); }
    }
    async function element(tabId, params) {
      if (typeof params.selector !== 'string' || !params.selector) throw invalid('selector is required');
      const executionContextId = await context(tabId, params);
      const expression = `(() => { let root = document; const parts = ${JSON.stringify(params.selector)}.split('>>>').map(s => s.trim()); for (let i=0;i<parts.length;i++) { const el=root.querySelector(parts[i]); if(!el) return null; if(i===parts.length-1) return el; root=el.shadowRoot; if(!root) return null; } })()`;
      const result = await send(tabId, 'Runtime.evaluate', { expression, contextId: executionContextId, returnByValue: false });
      if (result.exceptionDetails || !result.result?.objectId || result.result.subtype === 'null') throw invalid('Target element was not found');
      return result.result.objectId;
    }
    async function uploadPaths(tabId, params) {
      if (!Array.isArray(params.paths) || !params.paths.length || params.paths.some(path => typeof path !== 'string' || !path.startsWith('/') || path.includes('\0'))) throw invalid('paths must contain explicit absolute local filenames');
      return debug(tabId, async () => {
        const objectId = await element(tabId, params);
        try {
          const check = await send(tabId, 'Runtime.callFunctionOn', { objectId, functionDeclaration: 'function(){return {file:this.tagName==="INPUT"&&this.type==="file",multiple:this.multiple,disabled:this.disabled}}', returnByValue: true });
          const info = check.result?.value;
          if (!info?.file || info.disabled || (params.paths.length > 1 && !info.multiple)) throw invalid('Target must be an enabled file input supporting the supplied number of files');
          await send(tabId, 'DOM.setFileInputFiles', { objectId, files: params.paths });
          const result = await send(tabId, 'Runtime.callFunctionOn', { objectId, functionDeclaration: 'function(){return Array.from(this.files||[]).map(f=>({name:f.name,size:f.size,type:f.type,lastModified:f.lastModified}))}', returnByValue: true });
          return { selected: true, serverConfirmed: false, files: result.result.value };
        } finally { await send(tabId, 'Runtime.releaseObject', { objectId }).catch(() => {}); }
      });
    }
    async function downloadStart(params) {
      if (!api.downloads?.download) throw unsupported('downloads permission/API is unavailable');
      let url;
      try { url = new URL(params.url); } catch (_) { throw invalid('A valid download URL is required'); }
      if (!['https:', 'http:', 'blob:', 'data:'].includes(url.protocol)) throw invalid('Unsupported download URL scheme');
      const details = { url: url.href, saveAs: false, conflictAction: 'uniquify' };
      if (params.filename) details.filename = params.filename;
      const id = await api.downloads.download(details);
      return { id, started: true };
    }
    async function nativeInput(tabId, command, params) {
      return debug(tabId, async () => {
        if (command === 'input.type') {
          if (typeof params.text !== 'string') throw invalid('text is required');
          if (params.selector) {
            const objectId = await element(tabId, params);
            try { await send(tabId, 'Runtime.callFunctionOn', { objectId, functionDeclaration: 'function(){this.focus()}' }); }
            finally { await send(tabId, 'Runtime.releaseObject', { objectId }).catch(() => {}); }
          }
          await send(tabId, 'Input.insertText', { text: params.text });
          return { inserted: true };
        }
        if (command === 'input.key') {
          if (typeof params.key !== 'string' || !params.key) throw invalid('key is required');
          if (params.modifiers && (!Array.isArray(params.modifiers) || params.modifiers.some(key => !['alt','ctrl','meta','shift'].includes(key)))) throw invalid('modifiers must contain alt, ctrl, meta, or shift');
          const modifiers = (params.modifiers || []).reduce((n, key) => n | ({ alt: 1, ctrl: 2, meta: 4, shift: 8 }[key] || 0), 0);
          const codes = { Enter: 13, Tab: 9, Escape: 27, Backspace: 8, Delete: 46, ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, ' ': 32 };
          const event = { key: params.key, code: params.code || params.key, modifiers, windowsVirtualKeyCode: codes[params.key] || (params.key.length === 1 ? params.key.toUpperCase().charCodeAt(0) : 0) };
          const text = !(modifiers & 7) ? (params.key === 'Enter' ? '\r' : params.key.length === 1 ? params.key : '') : '';
          await send(tabId, 'Input.dispatchKeyEvent', { ...event, type: text ? 'keyDown' : 'rawKeyDown', ...(text ? { text, unmodifiedText: text } : {}) });
          await send(tabId, 'Input.dispatchKeyEvent', { ...event, type: 'keyUp' });
          return { pressed: true };
        }
        const point = value => value && Number.isFinite(value.x) && Number.isFinite(value.y) && value.x >= 0 && value.y >= 0;
        const from = command === 'input.drag' ? params.from : params;
        if (!point(from) || (command === 'input.drag' && !point(params.to))) throw invalid('Viewport coordinates x/y (and from/to for drag) are required');
        const button = params.button || 'left';
        if (!['left', 'right', 'middle'].includes(button)) throw invalid('Invalid mouse button');
        const buttons = {left:1,right:2,middle:4}[button];
        if (command === 'input.drag') { drags.delete(tabId); await send(tabId, 'Input.setInterceptDrags', { enabled: true }); }
        await send(tabId, 'Input.dispatchMouseEvent', { type: 'mouseMoved', x: from.x, y: from.y });
        await send(tabId, 'Input.dispatchMouseEvent', { type: 'mousePressed', x: from.x, y: from.y, button, buttons, clickCount: 1 });
        let destination = from;
        try {
          if (command === 'input.drag') {
            destination = params.to;
            for (let step = 1; step <= 20; step++) {
              await send(tabId, 'Input.dispatchMouseEvent', { type: 'mouseMoved', x: from.x + (destination.x-from.x)*step/20, y: from.y + (destination.y-from.y)*step/20, button, buttons });
              const data = drags.get(tabId);
              if (data) {
                for (const type of ['dragEnter','dragOver','drop']) await send(tabId, 'Input.dispatchDragEvent', { type, x: destination.x, y: destination.y, data });
                break;
              }
            }
          }
        } finally {
          try { await send(tabId, 'Input.dispatchMouseEvent', { type: 'mouseReleased', x: destination.x, y: destination.y, button, buttons: 0, clickCount: 1 }); }
          finally { if (command === 'input.drag') { drags.delete(tabId); await send(tabId, 'Input.setInterceptDrags', { enabled: false }); } }
        }
        return { dispatched: true };
      });
    }
    async function handleDialog(tabId, params) {
      if (typeof params.accept !== 'boolean') throw invalid('accept must be explicitly true or false');
      if (!dialogs.has(tabId)) throw invalid('No observed JavaScript dialog; attach debugger before opening it');
      await send(tabId, 'Page.handleJavaScriptDialog', { accept: params.accept, promptText: params.promptText || '' });
      dialogs.delete(tabId);
      if (owned.has(tabId)) { owned.delete(tabId); await api.debugger.detach({ tabId }).catch(() => {}); }
      return { handled: true, accepted: params.accept };
    }
    return { frameId, listFrames, selectFrame, reset, uploadPaths, downloadStart, nativeInput, handleDialog,
      dialogState: tabId => ({ dialog: dialogs.get(tabId) || null }),
      screenshot: (tabId, params) => debug(tabId, async () => {
        const capture = { format: 'png', captureBeyondViewport: params.fullPage !== false, fromSurface: true };
        if (params.fullPage !== false) {
          const metrics = await send(tabId, 'Page.getLayoutMetrics');
          const size = metrics.cssContentSize || metrics.contentSize;
          if (!size || size.width <= 0 || size.height <= 0 || size.width*size.height > 100000000) throw invalid('Full-page screenshot dimensions are unavailable or exceed 100 megapixels');
          capture.clip = { x: 0, y: 0, width: Math.ceil(size.width), height: Math.ceil(size.height), scale: 1 };
        }
        const result = await send(tabId, 'Page.captureScreenshot', capture);
        return { screenshot: result.data, format: 'png', fullPage: params.fullPage !== false };
      }) };
  }
};
