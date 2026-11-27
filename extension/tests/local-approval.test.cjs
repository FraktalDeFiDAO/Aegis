const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function harness(timeoutMs = 20) {
  const source = fs.readFileSync(require('node:path').join(__dirname, '../local-approval.js'), 'utf8');
  const prompted = [], resolved = [];
  const context = vm.createContext({setTimeout, clearTimeout});
  vm.runInContext(source, context);
  const approval = vm.runInContext(`AegisLocalApproval.create({timeoutMs:${timeoutMs},onPrompt:entry=>${JSON.stringify(prompted)}.push(entry),onResolved:(entry,outcome)=>${JSON.stringify(resolved)}.push({entry,outcome})})`, context);
  return {approval, prompted, resolved};
}

test('local approval allows only the requested command after explicit approval', async () => {
  const h = harness();
  const pending = h.approval.authorize('click', 42, {allowed: false, needsApproval: true, reason: 'manual policy'});
  assert.equal(h.approval.list().length, 1);
  assert.deepEqual(Object.keys(h.approval.list()[0]).sort(), ['command', 'id', 'reason', 'tabId']);
  const id = h.approval.list()[0].id;
  assert.equal(h.approval.resolve(id, true), true);
  const result = await pending;
  assert.equal(result.allowed, true);
  assert.equal(result.approvalId, id);
  assert.equal(h.approval.resolve(id, true), false);
});

test('denial and timeout never authorize work', async () => {
  const h = harness(5);
  const denied = h.approval.authorize('setCookie', 7, {allowed: false, needsApproval: true});
  h.approval.resolve(h.approval.list()[0].id, false);
  assert.equal((await denied).allowed, false);
  assert.equal((await denied).errorCode, 'permission_denied');
  const timedOut = await h.approval.authorize('upload.file', 7, {allowed: false, needsApproval: true});
  assert.equal(timedOut.allowed, false);
  assert.equal(timedOut.errorCode, 'approval_timeout');
});

test('disconnect cancels every pending approval', async () => {
  const h = harness(1000);
  const pending = h.approval.authorize('debug.attach', 9, {allowed: false, needsApproval: true});
  h.approval.cancelAll();
  assert.equal((await pending).allowed, false);
  assert.equal((await pending).errorCode, 'disconnected');
  assert.equal(h.approval.list().length, 0);
});
