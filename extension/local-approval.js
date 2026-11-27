/* Local-only approval queue. Controllers request work; only extension UI resolves it. */
'use strict';

globalThis.AegisLocalApproval = {
  create({ timeoutMs = 20000, onPrompt = () => {}, onResolved = () => {} } = {}) {
    const pending = new Map();
    let counter = 0;

    function finish(id, approved, reason) {
      const entry = pending.get(id);
      if (!entry) return false;
      pending.delete(id);
      clearTimeout(entry.timer);
      const outcome = { approved, reason };
      entry.resolve(outcome);
      onResolved(entry.public, outcome);
      return true;
    }

    function authorize(command, tabId, decision) {
      if (!decision.needsApproval) return Promise.resolve(decision);
      const id = `approval-${Date.now()}-${++counter}`;
      const publicEntry = { id, command, tabId: tabId || null, reason: decision.reason || 'approval required' };
      const promise = new Promise((resolve) => {
        const entry = { public: publicEntry, resolve, timer: null };
        entry.timer = setTimeout(() => finish(id, false, 'approval_timeout'), timeoutMs);
        pending.set(id, entry);
      });
      onPrompt(publicEntry);
      return promise.then((outcome) => {
        if (outcome.approved) {
          return { allowed: true, needsApproval: false, approvalId: id, reason: 'approved in extension popup' };
        }
        const errors = {
          approval_timeout: ['approval_timeout', 'approval timed out'],
          controller_disconnected: ['disconnected', 'controller disconnected before approval'],
          local_data_cleared: ['permission_denied', 'approval canceled because local task data was cleared'],
        };
        const [errorCode, reason] = errors[outcome.reason] || ['permission_denied', 'approval denied in extension popup'];
        return { allowed: false, needsApproval: false, approvalId: id, errorCode, reason };
      });
    }

    return {
      authorize,
      list: () => Array.from(pending.values(), entry => entry.public),
      resolve: (id, approved) => finish(id, approved, approved ? 'approved' : 'denied'),
      cancelAll: (reason = 'controller_disconnected') => {
        for (const id of Array.from(pending.keys())) finish(id, false, reason);
      },
    };
  },
};
