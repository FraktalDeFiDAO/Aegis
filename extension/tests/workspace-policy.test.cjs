const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname,'../background.js'),'utf8');
const section = (a,b) => source.slice(source.indexOf(a),source.indexOf(b,source.indexOf(a)));

test('workspace tab creation uses the group window, and rolls back grouping failures',async()=>{
 const created=[], removed=[];let fail=false;
 const context=vm.createContext({chrome:{tabGroups:{get:async id=>{if(id===99)throw Error('stale group');return {windowId:7}}},tabs:{create:async options=>{created.push(options);return {id:42,windowId:7,active:true}},remove:async id=>removed.push(id)}},activeTargetSet:{groupId:8},persistTargetSet:async()=>{},cmdAddTabToGroup:async()=>{if(fail)throw Error('group failed')}});
 vm.runInContext(section('async function cmdNewTab','async function cmdCloseTab'),context);
 const result=await vm.runInContext("cmdNewTab({url:'https://example.com'})",context);
 assert.equal(result.groupId,8);assert.equal(created[0].windowId,7);
 await assert.rejects(vm.runInContext('cmdNewTab({groupId:99})',context),/stale group/);assert.equal(created.length,1);
 fail=true;await assert.rejects(vm.runInContext('cmdNewTab({})',context),/group failed/);assert.deepEqual(removed,[42]);
});

test('global metadata ignores selected internal pages, page operations and internal destinations stay blocked',async()=>{
 const context=vm.createContext({getPolicy:async()=>({mode:'manual-approve'}),chrome:{tabs:{get:async()=>({url:'chrome://settings'})}}});
 vm.runInContext(section('const SENSITIVE_COMMANDS','async function emitPermissionPrompt'),context);
 for(const command of ['listTabs','listTabGroups','target.get','extension.info'])assert.equal((await vm.runInContext(`evaluatePolicy('${command}',{},1)`,context)).allowed,true);
 assert.match((await vm.runInContext("evaluatePolicy('getTitle',{},1)",context)).reason,/internal/);
 assert.match((await vm.runInContext("evaluatePolicy('newTab',{url:'chrome://settings'},1)",context)).reason,/internal/);
 assert.equal((await vm.runInContext("evaluatePolicy('newTab',{url:'https://example.com'},1)",context)).needsApproval,true);
});

test('scheduled direct commands cannot bypass policy',async()=>{
 const runs=[];let executed=false;
 const context=vm.createContext({SCHEDULES_KEY:'s',getStore:async()=>[{id:'test',enabled:true,command:'click',params:{tabId:4}}],activeTargetSet:{activeTabId:1},emitTaskEvent:()=>{},evaluatePolicy:async(command,params,id)=>{assert.equal(id,4);return {allowed:false,reason:'denied'}} ,executeCommand:async()=>{executed=true},appendRun:async r=>runs.push(r),chrome:{},Date});
 vm.runInContext(section('async function runScheduleByAlarm','async function cmdAuditList'),context);
 await vm.runInContext("runScheduleByAlarm('aegis_sched_test')",context);
 assert.equal(executed,false);assert.equal(runs[0].status,'failed');assert.equal(runs[0].reason,'denied');
});
