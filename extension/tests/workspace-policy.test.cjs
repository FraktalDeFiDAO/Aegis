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

test('controller cannot self-grant or execute arbitrary evaluation',async()=>{
 const context=vm.createContext({getPolicy:async()=>({mode:'unattended',trustedScopes:['*']}),chrome:{tabs:{get:async()=>({url:'https://example.com/'})}},URL});
 vm.runInContext(section('const SENSITIVE_COMMANDS','async function emitPermissionPrompt'),context);
 for(const command of ['policy.set','approval.respond','evaluate','evaluateAll']){
   const decision=await vm.runInContext(`evaluatePolicy('${command}',{},1)`,context);
   assert.equal(decision.allowed,false);assert.equal(decision.needsApproval,false);
 }
});

test('unattended mode requires exact trusted origin and path scope',async()=>{
 const context=vm.createContext({getPolicy:async()=>({mode:'unattended',trustedScopes:['https://example.com/app']}),chrome:{tabs:{get:async id=>({url:id===1?'https://example.com/app/form':id===2?'https://example.com/application':'https://example.com.evil.test/app'})}},URL});
 vm.runInContext(section('const SENSITIVE_COMMANDS','async function emitPermissionPrompt'),context);
 assert.equal((await vm.runInContext("evaluatePolicy('click',{},1)",context)).allowed,true);
 assert.equal((await vm.runInContext("evaluatePolicy('click',{},2)",context)).needsApproval,true);
 assert.equal((await vm.runInContext("evaluatePolicy('click',{},3)",context)).needsApproval,true);
 assert.equal((await vm.runInContext("evaluatePolicy('getElementText',{},2)",context)).needsApproval,true);
});

test('cookie values are omitted unless explicitly included',async()=>{
 const context=vm.createContext({chrome:{tabs:{get:async()=>({url:'https://example.com/'})},cookies:{getAll:async()=>[{name:'sid',value:'secret-value',domain:'example.com',path:'/'}]}}});
 vm.runInContext(section('async function cmdGetCookies','async function cmdSetCookie'),context);
 const redacted=JSON.parse(JSON.stringify(await vm.runInContext("cmdGetCookies({},1)",context)));
 assert.equal(Object.hasOwn(redacted.cookies[0],'value'),false);assert.equal(redacted.cookies[0].valueRedacted,true);
 const included=await vm.runInContext("cmdGetCookies({includeValues:true},1)",context);
 assert.equal(included.cookies[0].value,'secret-value');assert.equal(included.cookies[0].valueRedacted,false);
});

test('persisted record redaction catches common secret shapes',()=>{
 const context=vm.createContext({});
 vm.runInContext(section('function redactObject','function unsupported'),context);
 const input={authorization:'Bearer abc.def',nested:{jwt:'eyJabcdefgh.abcdefgh.abcdefgh'},safe:'ordinary'};
 const result=vm.runInContext(`redactObject(${JSON.stringify(input)})`,context);
 const serialized=JSON.stringify(result);
 assert.equal(serialized.includes('abc.def'),false);assert.equal(serialized.includes('eyJabcdefgh'),false);assert.equal(result.safe,'ordinary');
});

test('schedule parameters are redacted before persistence',async()=>{
 let stored;
 const context=vm.createContext({SCHEDULES_KEY:'schedules',getStore:async()=>[],setStore:async(_key,value)=>{stored=value},redactObject:value=>JSON.parse(JSON.stringify(value,(key,item)=>/password|token|secret/i.test(key)?'[REDACTED]':item)),chrome:{alarms:{create:()=>{}}},Date,parseInt});
 vm.runInContext(section('async function cmdScheduleCreate','async function cmdScheduleList'),context);
 await vm.runInContext("cmdScheduleCreate({name:'test',command:'fill',params:{password:'do-not-store',safe:'ok'}})",context);
 assert.equal(stored[0].params.password,'[REDACTED]');assert.equal(stored[0].params.safe,'ok');
});

test('scheduled direct commands cannot bypass policy',async()=>{
 const runs=[];let executed=false;
 const context=vm.createContext({SCHEDULES_KEY:'s',getStore:async()=>[{id:'test',enabled:true,command:'click',params:{tabId:4}}],activeTargetSet:{activeTabId:1},emitTaskEvent:()=>{},authorizeCommand:async(command,params,id)=>{assert.equal(id,4);return {allowed:false,reason:'denied'}} ,executeCommand:async()=>{executed=true},appendRun:async r=>runs.push(r),chrome:{},Date});
 vm.runInContext(section('async function runScheduleByAlarm','async function cmdAuditList'),context);
 await vm.runInContext("runScheduleByAlarm('aegis_sched_test')",context);
 assert.equal(executed,false);assert.equal(runs[0].status,'failed');assert.equal(runs[0].reason,'denied');
});
