const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

function setup(){
 const sent=[],events=[];let attached=0,detached=0;
 const api={webNavigation:{getAllFrames:async()=>[{frameId:0,url:'https://example.test/'},{frameId:7,url:'https://frame.test/'}],getFrame:async()=>({url:'https://frame.test/'})},
  downloads:{download:async details=>{sent.push(['download',details]);return 19;}},
  debugger:{onEvent:{addListener:fn=>events.push(fn)},attach:async()=>{attached++},detach:async()=>{detached++},sendCommand:async(target,method,params)=>{
   sent.push([method,params]);
   if(method==='Page.getFrameTree')return {frameTree:{frame:{id:'main',url:'https://example.test/'},childFrames:[{frame:{id:'child',url:'https://frame.test/'}}]}};
   if(method==='Page.createIsolatedWorld')return {executionContextId:3};
   if(method==='Runtime.evaluate')return {result:{objectId:'input'}};
   if(method==='Runtime.callFunctionOn')return {result:{value:params.functionDeclaration.includes('multiple')?{file:true,multiple:true,disabled:false}:[{name:'large.aab',size:900000000}]}};
   return {};
  }}};
 const context=vm.createContext({URL});
 vm.runInContext(fs.readFileSync(path.join(__dirname,'../browser-control.js'),'utf8'),context);
 const control=context.AegisBrowserControl.create(api);
 return {control,sent,api,events,attached:()=>attached,detached:()=>detached};
}
test('frame 0 overrides a selected child and invalid/missing frames fail',async()=>{
 const h=setup();await h.control.selectFrame(1,{frameId:7});
 assert.equal(h.control.frameId(1),7);assert.equal(h.control.frameId(1,{frameId:0}),0);
 await assert.rejects(h.control.selectFrame(1,{frameId:8}),/does not exist/);
 assert.throws(()=>h.control.frameId(1,{frameId:-1}),/nonnegative/);
 h.control.reset(1);assert.equal(h.control.frameId(1),0);
});
test('native upload sends file paths without loading large file bytes',async()=>{
 const h=setup();const result=await h.control.uploadPaths(1,{selector:'input[type=file]',paths:['/tmp/large.aab']});
 assert.equal(result.selected,true);assert.equal(result.serverConfirmed,false);
 const command=h.sent.find(([method])=>method==='DOM.setFileInputFiles');
 assert.deepEqual(Array.from(command[1].files),['/tmp/large.aab']);
 assert.equal(h.attached(),1);assert.equal(h.detached(),1);
});
test('failed input selection detaches owned debugger session',async()=>{
 const h=setup();await assert.rejects(h.control.uploadPaths(1,{selector:'',paths:['/tmp/file']}),/selector/);
 assert.equal(h.detached(),1);
});
test('download start rejects privileged URLs before invoking downloads API',async()=>{
 const h=setup();await assert.rejects(h.control.downloadStart({url:'file:///etc/passwd'}),/scheme/);
 assert.equal(h.sent.length,0);
 assert.equal((await h.control.downloadStart({url:'https://example.test/file'})).id,19);
});
test('dialog handling requires an observed dialog and explicit accept decision',async()=>{
 const h=setup();await assert.rejects(h.control.handleDialog(1,{accept:true}),/No observed/);
 h.events[0]({tabId:1},'Page.javascriptDialogOpening',{type:'confirm',message:'Continue?'});
 await assert.rejects(h.control.handleDialog(1,{}),/explicitly/);
 await h.control.handleDialog(1,{accept:false});
 assert.equal(h.sent.find(([method])=>method==='Page.handleJavaScriptDialog')[1].accept,false);
});
